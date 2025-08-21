/* HYPR NPT MMU Helper Functions for AMD
 *
 * Implements MMU operations for NPT table management on AMD processors.
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/svm.h>
#include "../mmu/mmu_internal.h"
#include "svm.h"
#include "svm_npt_swap.h"

/* NPT page table entry bits (AMD-specific) */
#define NPT_PRESENT     (1ULL << 0)
#define NPT_WRITABLE    (1ULL << 1)
#define NPT_USER        (1ULL << 2)
#define NPT_ACCESSED    (1ULL << 5)
#define NPT_DIRTY       (1ULL << 6)
#define NPT_LARGE       (1ULL << 7)  /* PS bit for 2MB/1GB pages */
#define NPT_NX          (1ULL << 63) /* No-execute bit */

/* Page size flags */
#define NPT_PAGE_SIZE_2M (1ULL << 7)
#define NPT_PAGE_SIZE_1G (1ULL << 7)

/* Level definitions */
#define NPT_LEVEL_PML4  4
#define NPT_LEVEL_PDPT  3
#define NPT_LEVEL_PD    2
#define NPT_LEVEL_PT    1

/* Number of entries per page table */
#define NPT_ENTRIES_PER_PAGE 512

/* Snapshot header structure */
struct npt_snapshot_header {
	u64 magic;           /* "HYPRAMD\0" */
	u64 version;
	u64 memory_size;     /* Total guest memory size */
	u64 entry_count;     /* Number of page entries */
	u64 flags;
	u64 reserved[3];
};

struct npt_snapshot_page {
	u64 gpa;            /* Guest physical address */
	u64 flags;          /* Page flags (permissions, etc) */
	u8 data[4096];      /* Page data */
};

/* Allocate an NPT page table page */
static struct kvm_mmu_page *npt_alloc_page(struct kvm *kvm, gfn_t gfn, int level)
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

/* Create NPT entry - simpler than EPT! */
static u64 npt_create_entry(u64 pfn, int level, bool writable, bool executable)
{
	u64 entry = 0;
	
	/* Set physical address */
	entry = (pfn << PAGE_SHIFT) & ~0xFFF;
	
	/* Set permission bits */
	entry |= NPT_PRESENT;
	entry |= NPT_USER;  /* Always allow user access */
	
	if (writable)
		entry |= NPT_WRITABLE;
	
	if (!executable)
		entry |= NPT_NX;
	
	/* Set page size bit for large pages */
	if (level == NPT_LEVEL_PD || level == NPT_LEVEL_PDPT)
		entry |= NPT_LARGE;
	
	return entry;
}

/* Map a guest physical address in NPT tables */
static int npt_map_gpa(struct kvm *kvm, struct kvm_mmu_page *pml4,
		       u64 gpa, u64 hpa, int level, bool writable, bool executable)
{
	u64 *pml4e, *pdpte, *pde, *pte;
	struct kvm_mmu_page *pdpt_page, *pd_page, *pt_page;
	int pml4_index, pdpt_index, pd_index, pt_index;
	
	/* Calculate indices */
	pml4_index = (gpa >> 39) & 0x1FF;
	pdpt_index = (gpa >> 30) & 0x1FF;
	pd_index = (gpa >> 21) & 0x1FF;
	pt_index = (gpa >> 12) & 0x1FF;
	
	/* PML4 entry */
	pml4e = &pml4->spt[pml4_index];
	if (!(*pml4e & NPT_PRESENT)) {
		pdpt_page = npt_alloc_page(kvm, 0, NPT_LEVEL_PDPT);
		if (!pdpt_page)
			return -ENOMEM;
		*pml4e = __pa(pdpt_page->spt) | NPT_PRESENT | NPT_WRITABLE | NPT_USER;
	}
	
	/* PDPT entry */
	pdpte = &((u64 *)__va(*pml4e & ~0xFFF))[pdpt_index];
	
	/* 1GB page */
	if (level == NPT_LEVEL_PDPT) {
		*pdpte = npt_create_entry(hpa >> PAGE_SHIFT, level, writable, executable);
		return 0;
	}
	
	if (!(*pdpte & NPT_PRESENT)) {
		pd_page = npt_alloc_page(kvm, 0, NPT_LEVEL_PD);
		if (!pd_page)
			return -ENOMEM;
		*pdpte = __pa(pd_page->spt) | NPT_PRESENT | NPT_WRITABLE | NPT_USER;
	}
	
	/* PD entry */
	pde = &((u64 *)__va(*pdpte & ~0xFFF))[pd_index];
	
	/* 2MB page */
	if (level == NPT_LEVEL_PD) {
		*pde = npt_create_entry(hpa >> PAGE_SHIFT, level, writable, executable);
		return 0;
	}
	
	if (!(*pde & NPT_PRESENT)) {
		pt_page = npt_alloc_page(kvm, 0, NPT_LEVEL_PT);
		if (!pt_page)
			return -ENOMEM;
		*pde = __pa(pt_page->spt) | NPT_PRESENT | NPT_WRITABLE | NPT_USER;
	}
	
	/* PT entry (4KB page) */
	pte = &((u64 *)__va(*pde & ~0xFFF))[pt_index];
	*pte = npt_create_entry(hpa >> PAGE_SHIFT, NPT_LEVEL_PT, writable, executable);
	
	return 0;
}

/* Populate NPT tables from snapshot data */
int kvm_mmu_populate_npt_from_snapshot(struct kvm *kvm, struct kvm_mmu_page *root,
				       void *snapshot_data, size_t snapshot_size)
{
	struct npt_snapshot_header *header;
	struct npt_snapshot_page *page_entry;
	u8 *data_ptr;
	u64 i;
	int ret = 0;
	
	header = (struct npt_snapshot_header *)snapshot_data;
	
	/* Validate header */
	if (header->magic != 0x444D415250594848ULL) { /* "HYPRAMD\0" */
		pr_err("Invalid NPT snapshot magic: 0x%llx\n", header->magic);
		return -EINVAL;
	}
	
	if (header->version != 1) {
		pr_err("Unsupported NPT snapshot version: %llu\n", header->version);
		return -EINVAL;
	}
	
	data_ptr = (u8 *)snapshot_data + sizeof(*header);
	
	/* Process each page entry */
	for (i = 0; i < header->entry_count; i++) {
		page_entry = (struct npt_snapshot_page *)data_ptr;
		
		/* Map the page in NPT tables */
		ret = npt_map_gpa(kvm, root, page_entry->gpa,
				 virt_to_phys(page_entry->data),
				 NPT_LEVEL_PT,  /* 4KB pages for now */
				 !!(page_entry->flags & NPT_WRITABLE),
				 !(page_entry->flags & NPT_NX));
		
		if (ret) {
			pr_err("Failed to map GPA 0x%llx: %d\n", page_entry->gpa, ret);
			break;
		}
		
		data_ptr += sizeof(*page_entry);
	}
	
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_mmu_populate_npt_from_snapshot);

/* Free all pages in an NPT hierarchy */
static void npt_free_table(u64 *table, int level)
{
	int i;
	
	if (!table || level < NPT_LEVEL_PT)
		return;
	
	for (i = 0; i < NPT_ENTRIES_PER_PAGE; i++) {
		u64 entry = table[i];
		
		if (!(entry & NPT_PRESENT))
			continue;
		
		/* Skip large pages */
		if ((level == NPT_LEVEL_PD || level == NPT_LEVEL_PDPT) && 
		    (entry & NPT_LARGE))
			continue;
		
		/* Recursively free child tables */
		if (level > NPT_LEVEL_PT) {
			u64 *child = __va(entry & ~0xFFF);
			npt_free_table(child, level - 1);
			free_page((unsigned long)child);
		}
	}
}

/* Clean up NPT root table */
void npt_cleanup_root(struct kvm_mmu_page *root)
{
	if (!root)
		return;
	
	npt_free_table(root->spt, NPT_LEVEL_PML4);
	kvm_mmu_free_page(root);
}
EXPORT_SYMBOL_GPL(npt_cleanup_root);