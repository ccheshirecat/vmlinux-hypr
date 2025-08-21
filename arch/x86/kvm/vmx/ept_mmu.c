/* HYPR EPT MMU Helper Functions
 *
 * Implements MMU operations for EPT table management and population.
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/vmx.h>
#include "../mmu/mmu_internal.h"
#include "vmx.h"
#include "vmx_ept_swap.h"

/* EPT page table entry bits */
#define EPT_READABLE    (1ULL << 0)
#define EPT_WRITABLE    (1ULL << 1)
#define EPT_EXECUTABLE  (1ULL << 2)
#define EPT_MEM_TYPE_SHIFT 3
#define EPT_MEM_TYPE_MASK  (0x7ULL << EPT_MEM_TYPE_SHIFT)
#define EPT_IGNORE_PAT  (1ULL << 6)
#define EPT_ACCESSED    (1ULL << 8)
#define EPT_DIRTY       (1ULL << 9)

/* EPT memory types */
#define EPT_MEM_TYPE_UC 0
#define EPT_MEM_TYPE_WC 1
#define EPT_MEM_TYPE_WT 4
#define EPT_MEM_TYPE_WP 5
#define EPT_MEM_TYPE_WB 6

/* Page size flags */
#define EPT_PAGE_SIZE_2M (1ULL << 7)
#define EPT_PAGE_SIZE_1G (1ULL << 7)

/* Level definitions */
#define EPT_LEVEL_PML4  4
#define EPT_LEVEL_PDPT  3
#define EPT_LEVEL_PD    2
#define EPT_LEVEL_PT    1

/* Number of entries per page table */
#define EPT_ENTRIES_PER_PAGE 512

/* Snapshot header structure */
struct ept_snapshot_header {
	u64 magic;           /* "HYPRVMO\0" */
	u64 version;
	u64 memory_size;     /* Total guest memory size */
	u64 page_count;      /* Number of populated pages */
	u64 flags;
	u64 reserved[3];
};

/* Snapshot page entry */
struct ept_snapshot_page {
	u64 gpa;            /* Guest physical address */
	u64 flags;          /* Page flags (permissions, etc) */
	u8 data[4096];      /* Page data */
};

/* Allocate an EPT page table page */
static struct kvm_mmu_page *ept_alloc_page(struct kvm *kvm, gfn_t gfn, int level)
{
	struct kvm_mmu_page *sp;
	
	sp = kmem_cache_zalloc(mmu_page_header_cache, GFP_KERNEL_ACCOUNT);
	if (!sp)
		return NULL;
	
	sp->gfn = gfn;
	sp->role.level = level;
	sp->role.direct = 1;
	sp->role.ad_disabled = 0;
	sp->role.guest_mode = 0;
	sp->spt = (u64 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	
	if (!sp->spt) {
		kmem_cache_free(mmu_page_header_cache, sp);
		return NULL;
	}
	
	return sp;
}

/* Free an EPT page table page */
void kvm_mmu_free_page(struct kvm_mmu_page *sp)
{
	if (!sp)
		return;
	
	if (sp->spt)
		free_page((unsigned long)sp->spt);
	
	kmem_cache_free(mmu_page_header_cache, sp);
}
EXPORT_SYMBOL_GPL(kvm_mmu_free_page);

/* Allocate a new EPT page */
struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm *kvm, struct kvm_mmu_page *parent, 
					 int level)
{
	return ept_alloc_page(kvm, 0, level);
}
EXPORT_SYMBOL_GPL(kvm_mmu_alloc_page);

/* Create EPT entry */
static u64 ept_create_entry(u64 pfn, int level, bool writable, bool executable)
{
	u64 entry = 0;
	
	/* Set base permissions */
	entry |= EPT_READABLE;
	if (writable)
		entry |= EPT_WRITABLE;
	if (executable)
		entry |= EPT_EXECUTABLE;
	
	/* Set memory type to write-back */
	entry |= (EPT_MEM_TYPE_WB << EPT_MEM_TYPE_SHIFT);
	
	/* Set page size bit for large pages */
	if (level == EPT_LEVEL_PD)
		entry |= EPT_PAGE_SIZE_2M;
	else if (level == EPT_LEVEL_PDPT)
		entry |= EPT_PAGE_SIZE_1G;
	
	/* Set physical address */
	entry |= (pfn << PAGE_SHIFT);
	
	return entry;
}

/* Walk EPT tables and create entries as needed */
static u64 *ept_walk_addr(struct kvm *kvm, u64 *root, gpa_t gpa, int target_level)
{
	u64 *table = root;
	int level;
	
	for (level = EPT_LEVEL_PML4; level > target_level; level--) {
		int index = (gpa >> (12 + 9 * (level - 1))) & 0x1ff;
		u64 entry = table[index];
		
		if (!(entry & EPT_READABLE)) {
			/* Need to allocate new table */
			struct kvm_mmu_page *new_table;
			
			new_table = ept_alloc_page(kvm, 0, level - 1);
			if (!new_table)
				return NULL;
			
			/* Create entry pointing to new table */
			entry = ept_create_entry(__pa(new_table->spt) >> PAGE_SHIFT, 
						level, true, true);
			table[index] = entry;
		}
		
		/* Move to next level */
		table = __va(entry & PAGE_MASK);
	}
	
	/* Return pointer to entry at target level */
	int index = (gpa >> (12 + 9 * (target_level - 1))) & 0x1ff;
	return &table[index];
}

/* Populate EPT entry for a single page */
static int ept_populate_page(struct kvm *kvm, u64 *root, gpa_t gpa, 
			      void *page_data, u64 flags)
{
	u64 *entry_ptr;
	struct page *page;
	u64 hpa;
	
	/* Allocate host page */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	
	/* Copy data to page */
	if (page_data) {
		void *dst = kmap_atomic(page);
		memcpy(dst, page_data, PAGE_SIZE);
		kunmap_atomic(dst);
	} else {
		clear_page(page_address(page));
	}
	
	/* Get host physical address */
	hpa = page_to_phys(page);
	
	/* Walk EPT tables to find/create entry */
	entry_ptr = ept_walk_addr(kvm, root, gpa, EPT_LEVEL_PT);
	if (!entry_ptr) {
		__free_page(page);
		return -ENOMEM;
	}
	
	/* Create EPT entry */
	*entry_ptr = ept_create_entry(hpa >> PAGE_SHIFT, EPT_LEVEL_PT,
				      flags & EPT_WRITABLE,
				      flags & EPT_EXECUTABLE);
	
	return 0;
}

/* Populate EPT tables from snapshot data */
int kvm_mmu_populate_ept_from_snapshot(struct kvm *kvm, struct kvm_mmu_page *root,
				       void *snapshot_data, size_t snapshot_size)
{
	struct ept_snapshot_header *header;
	struct ept_snapshot_page *page_entry;
	u8 *data_ptr;
	u64 pages_processed = 0;
	int ret = 0;
	
	if (snapshot_size < sizeof(struct ept_snapshot_header))
		return -EINVAL;
	
	header = (struct ept_snapshot_header *)snapshot_data;
	
	/* Validate magic number */
	if (header->magic != 0x004F4D5652505948ULL) { /* "HYPRVMO\0" */
		pr_err("EPT: Invalid snapshot magic: 0x%llx\n", header->magic);
		return -EINVAL;
	}
	
	/* Validate version */
	if (header->version != 1) {
		pr_err("EPT: Unsupported snapshot version: %llu\n", header->version);
		return -EINVAL;
	}
	
	/* Calculate expected size */
	size_t expected_size = sizeof(struct ept_snapshot_header) + 
			      (header->page_count * sizeof(struct ept_snapshot_page));
	
	if (snapshot_size < expected_size) {
		pr_err("EPT: Snapshot size mismatch: got %zu, expected %zu\n",
		       snapshot_size, expected_size);
		return -EINVAL;
	}
	
	/* Process each page in the snapshot */
	data_ptr = (u8 *)snapshot_data + sizeof(struct ept_snapshot_header);
	
	while (pages_processed < header->page_count) {
		page_entry = (struct ept_snapshot_page *)data_ptr;
		
		/* Validate GPA */
		if (page_entry->gpa >= header->memory_size) {
			pr_err("EPT: Invalid GPA in snapshot: 0x%llx\n", 
			       page_entry->gpa);
			ret = -EINVAL;
			break;
		}
		
		/* Populate the page */
		ret = ept_populate_page(kvm, root->spt, page_entry->gpa,
					page_entry->data, page_entry->flags);
		if (ret) {
			pr_err("EPT: Failed to populate page at GPA 0x%llx: %d\n",
			       page_entry->gpa, ret);
			break;
		}
		
		pages_processed++;
		data_ptr += sizeof(struct ept_snapshot_page);
		
		/* Yield CPU periodically to avoid soft lockups */
		if (pages_processed % 1000 == 0) {
			cond_resched();
		}
	}
	
	if (ret == 0) {
		pr_info("EPT: Successfully populated %llu pages from snapshot\n",
			pages_processed);
	}
	
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_mmu_populate_ept_from_snapshot);

/* Note: ept_sync_context is defined in vmx_ops.h, removed duplicate */

/* Free all pages in an EPT hierarchy */
static void ept_free_table(u64 *table, int level)
{
	int i;
	
	if (!table || level < EPT_LEVEL_PT)
		return;
	
	if (level > EPT_LEVEL_PT) {
		/* Recursively free child tables */
		for (i = 0; i < EPT_ENTRIES_PER_PAGE; i++) {
			u64 entry = table[i];
			
			if (entry & EPT_READABLE) {
				u64 *child = __va(entry & PAGE_MASK);
				ept_free_table(child, level - 1);
			}
		}
	} else {
		/* Free data pages at leaf level */
		for (i = 0; i < EPT_ENTRIES_PER_PAGE; i++) {
			u64 entry = table[i];
			
			if (entry & EPT_READABLE) {
				struct page *page = pfn_to_page(entry >> PAGE_SHIFT);
				__free_page(page);
			}
		}
	}
	
	/* Free this table page */
	free_page((unsigned long)table);
}

/* Clean up an entire EPT hierarchy */
void ept_cleanup_root(struct kvm_mmu_page *root)
{
	if (!root || !root->spt)
		return;
	
	ept_free_table(root->spt, EPT_LEVEL_PML4);
	kvm_mmu_free_page(root);
}
EXPORT_SYMBOL_GPL(ept_cleanup_root);