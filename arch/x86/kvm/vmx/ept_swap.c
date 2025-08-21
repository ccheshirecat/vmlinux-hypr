/* HYPR EPT Swap Implementation for KVM/VMX
 *
 * Implements atomic EPT (Extended Page Tables) swapping for temporal scaling.
 * Allows replacing entire guest physical memory mappings in microseconds.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <uapi/linux/kvm_hypr.h>
#include <asm/vmx.h>
#include <asm/vmm_control.h>
#include "../mmu/mmu_internal.h"
#include "vmx.h"
#include "vmcs.h"
#include "vmcs12.h"
#include "mmu.h"
#include "capabilities.h"
#include "vmx_ept_swap.h"

/* EPT pointer validation masks */
#define EPT_POINTER_MT_MASK 0x7ULL
#define EPT_POINTER_PWL_MASK 0x38ULL
#define EPT_POINTER_RESERVED_MASK 0xfff0000000000f80ULL
#define EPT_POINTER_PAGE_MASK 0xffffffffff000ULL
#define EPT_POINTER_AD_ENABLED (1ULL << 6)

/* EPT memory types */
#define EPT_MT_UC 0
#define EPT_MT_WC 1
#define EPT_MT_WT 4
#define EPT_MT_WP 5
#define EPT_MT_WB 6

/* EPT page walk lengths */
#define EPT_PWL_4_LEVEL 3
#define EPT_PWL_5_LEVEL 4

/* Debug logging */
static bool ept_swap_debug __read_mostly;
module_param(ept_swap_debug, bool, 0644);

#define ept_swap_dbg(fmt, ...) \
  do { \
    if (ept_swap_debug) \
      pr_info("EPT_SWAP: " fmt, ##__VA_ARGS__); \
  } while (0)

/* Validate EPT pointer format according to Intel SDM */
static bool vmx_valid_eptp(u64 eptp) {
  u64 mt, pwl;

  /* Check memory type (bits 2:0) */
  mt = eptp & EPT_POINTER_MT_MASK;
  if (mt != EPT_MT_UC && mt != EPT_MT_WB) {
    ept_swap_dbg("Invalid EPT memory type: %llu\n", mt);
    return false;
  }

  /* Check page walk length (bits 5:3) */
  pwl = (eptp >> 3) & 0x7;
  if (pwl != EPT_PWL_4_LEVEL && pwl != EPT_PWL_5_LEVEL) {
    ept_swap_dbg("Invalid EPT page walk length: %llu\n", pwl);
    return false;
  }

  /* Check reserved bits */
  if (eptp & EPT_POINTER_RESERVED_MASK) {
    ept_swap_dbg("Reserved bits set in EPTP: 0x%llx\n", eptp);
    return false;
  }

  /* Physical address must be page-aligned */
  if (eptp & 0xfff) {
    ept_swap_dbg("EPTP not page-aligned: 0x%llx\n", eptp);
    return false;
  }

  /* Check if physical address is valid */
  if ((eptp & EPT_POINTER_PAGE_MASK) >> PAGE_SHIFT >= max_pfn) {
    ept_swap_dbg("EPTP physical address out of range: 0x%llx\n", eptp);
    return false;
  }

  return true;
}

/* Get current EPT pointer from VMCS */
int vmx_get_eptp(struct kvm_vcpu *vcpu, u64 *eptp) {
  struct vcpu_vmx *vmx = to_vmx(vcpu);

  if (!enable_ept) {
    ept_swap_dbg("EPT not enabled\n");
    return -EOPNOTSUPP;
  }

  if (!vmx->loaded_vmcs) {
    ept_swap_dbg("VMCS not loaded for vCPU %d\n", vcpu->vcpu_id);
    return -EINVAL;
  }

  /* Ensure we're on the right CPU */
  if (vcpu->cpu != smp_processor_id()) {
    ept_swap_dbg("vCPU %d not loaded on current CPU\n", vcpu->vcpu_id);
    return -EINVAL;
  }

  *eptp = vmcs_read64(EPT_POINTER);
  ept_swap_dbg("vCPU %d: Current EPTP = 0x%llx\n", vcpu->vcpu_id, *eptp);

  return 0;
}

/* Set new EPT pointer in VMCS - must be called with vCPU paused */
int vmx_set_eptp(struct kvm_vcpu *vcpu, u64 new_eptp) {
  struct vcpu_vmx *vmx = to_vmx(vcpu);
  u64 old_eptp;

  if (!enable_ept) {
    ept_swap_dbg("EPT not enabled\n");
    return -EOPNOTSUPP;
  }

  if (!vmx_valid_eptp(new_eptp)) {
    ept_swap_dbg("Invalid EPTP: 0x%llx\n", new_eptp);
    return -EINVAL;
  }

  if (!vmx->loaded_vmcs) {
    ept_swap_dbg("VMCS not loaded for vCPU %d\n", vcpu->vcpu_id);
    return -EINVAL;
  }

  /* Ensure we're on the right CPU */
  if (vcpu->cpu != smp_processor_id()) {
    ept_swap_dbg("vCPU %d not loaded on current CPU\n", vcpu->vcpu_id);
    return -EINVAL;
  }

  /* Save old EPTP for debugging */
  old_eptp = vmcs_read64(EPT_POINTER);

  /* Write new EPTP to VMCS */
  vmcs_write64(EPT_POINTER, new_eptp);

  /* Invalidate EPT mappings */
  if (cpu_has_vmx_invept_global()) {
    struct {
      u64 eptp;
      u64 gpa;
    } operand = {new_eptp, 0};
    asm volatile("invept %0, %1"
                 : /* No outputs */
                 : "m"(operand), "r"((unsigned long)VMX_EPT_EXTENT_GLOBAL)
                 : "memory");
  }

  /* Flush TLB - critical for correctness */
  kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);

  /* Memory barrier to ensure EPTP write is visible */
  smp_wmb();

  ept_swap_dbg("vCPU %d: Swapped EPTP 0x%llx -> 0x%llx\n", vcpu->vcpu_id,
               old_eptp, new_eptp);

  return 0;
}

/* Check if all vCPUs are paused via VMM control page */
static bool all_vcpus_paused(struct kvm *kvm) {
  struct kvm_vcpu *vcpu;
  unsigned long i;
  int paused_count = 0;

  if (!vmm_control_page_ptr) {
    ept_swap_dbg("VMM control page not mapped\n");
    return false;
  }

  /* Check magic number */
  if (vmm_control_page_ptr->magic != VMM_CONTROL_PAGE_MAGIC) {
    ept_swap_dbg("Invalid VMM control page magic: 0x%llx\n",
                 vmm_control_page_ptr->magic);
    return false;
  }

  /* Verify each vCPU is in PAUSED state */
  kvm_for_each_vcpu(i, vcpu, kvm) {
    struct vcpu_control_block *control;

    if (i >= MAX_VCPUS) {
      ept_swap_dbg("vCPU %lu exceeds MAX_VCPUS\n", i);
      return false;
    }

    control = &vmm_control_page_ptr->vcpus[i];
    if (READ_ONCE(control->state) != VCPU_STATE_PAUSED) {
      ept_swap_dbg("vCPU %lu not paused (state=%u)\n", i, control->state);
      return false;
    }
    paused_count++;
  }

  ept_swap_dbg("All %d vCPUs are paused\n", paused_count);
  return true;
}

/* Per-vCPU EPT swap worker */
struct ept_swap_work {
  struct kvm_vcpu *vcpu;
  u64 new_eptp;
  int result;
  struct completion done;
  call_single_data_t csd;
};

static void ept_swap_on_cpu(void *data) {
  struct ept_swap_work *work = container_of(data, struct ept_swap_work, csd);
  struct kvm_vcpu *vcpu = work->vcpu;

  /* Load the vCPU on this CPU */
  vcpu_load(vcpu);

  /* Perform the EPT swap */
  work->result = vmx_set_eptp(vcpu, work->new_eptp);

  /* Unload the vCPU */
  vcpu_put(vcpu);

  complete(&work->done);
}

/* Perform atomic EPT swap across all vCPUs */
int kvm_vm_ioctl_ept_swap_all(struct kvm *kvm, u64 new_eptp) {
  struct kvm_vcpu *vcpu;
  struct ept_swap_work *works;
  unsigned long i, nr_vcpus;
  int ret = 0;
  ktime_t start_time;

  start_time = ktime_get();

  /* Validate new EPTP */
  if (!vmx_valid_eptp(new_eptp)) {
    ept_swap_dbg("Invalid EPTP for swap: 0x%llx\n", new_eptp);
    return -EINVAL;
  }

  /* Count vCPUs */
  nr_vcpus = 0;
  kvm_for_each_vcpu(i, vcpu, kvm) nr_vcpus++;

  if (nr_vcpus == 0) {
    ept_swap_dbg("No vCPUs to swap\n");
    return -EINVAL;
  }

  /* Allocate work structures */
  works = kcalloc(nr_vcpus, sizeof(*works), GFP_KERNEL);
  if (!works) return -ENOMEM;

  /* Lock the VM */
  mutex_lock(&kvm->lock);

  /* Verify all vCPUs are paused */
  if (!all_vcpus_paused(kvm)) {
    ept_swap_dbg("Not all vCPUs are paused\n");
    ret = -EBUSY;
    goto out_unlock;
  }

  /* Initialize work for each vCPU */
  i = 0;
  kvm_for_each_vcpu(i, vcpu, kvm) {
    works[i].vcpu = vcpu;
    works[i].new_eptp = new_eptp;
    works[i].result = 0;
    init_completion(&works[i].done);
    works[i].csd.func = ept_swap_on_cpu;
    works[i].csd.info = &works[i].csd;

    /* Schedule work on the CPU where the vCPU should run */
    if (vcpu->cpu >= 0) {
      smp_call_function_single_async(vcpu->cpu, &works[i].csd);
    } else {
      /* vCPU not assigned to a CPU, do it locally */
      ept_swap_on_cpu(&works[i].csd);
    }
  }

  /* Wait for all swaps to complete */
  for (i = 0; i < nr_vcpus; i++) {
    wait_for_completion(&works[i].done);
    if (works[i].result != 0) {
      ept_swap_dbg("EPT swap failed for vCPU %d: %d\n", works[i].vcpu->vcpu_id,
                   works[i].result);
      ret = works[i].result;
    }
  }

  /* Global memory barrier to ensure all EPT changes are visible */
  smp_mb();

  if (ret == 0) {
    u64 elapsed_us = ktime_us_delta(ktime_get(), start_time);
    ept_swap_dbg("EPT swap completed successfully in %llu us\n", elapsed_us);
  }

out_unlock:
  mutex_unlock(&kvm->lock);
  kfree(works);
  return ret;
}

/* Create new EPT tables from guest memory snapshot */
int vmx_create_ept_from_snapshot(struct kvm *kvm, void *snapshot_data,
                                 size_t snapshot_size, u64 *new_eptp) {
  struct kvm_mmu_page *root;
  hpa_t root_hpa;
  u64 eptp;
  int ret;

  if (!enable_ept) return -EOPNOTSUPP;

  /* Allocate root EPT page */
  root = kvm_mmu_alloc_page(kvm, NULL, 0);
  if (!root) return -ENOMEM;

  root_hpa = __pa(root->spt);

  /* Build EPTP value */
  eptp = root_hpa | VMX_EPTP_MT_WB | VMX_EPTP_PWL_4;

  if (enable_ept_ad_bits) eptp |= EPT_POINTER_AD_ENABLED;

  /* Populate EPT tables from snapshot */
  ret = kvm_mmu_populate_ept_from_snapshot(kvm, root, snapshot_data,
                                           snapshot_size);
  if (ret) {
    kvm_mmu_free_page(root);
    return ret;
  }

  *new_eptp = eptp;
  ept_swap_dbg("Created new EPT from snapshot: EPTP=0x%llx\n", eptp);

  return 0;
}

/* Prepare EPT tables for swap (pre-build while VM runs) */
int vmx_prepare_ept_swap(struct kvm *kvm, struct kvm_ept_prepare *prepare) {
  u64 new_eptp;
  int ret;

  /* Create EPT from snapshot */
  ret = vmx_create_ept_from_snapshot(kvm, (void *)prepare->snapshot_addr,
                                     prepare->snapshot_size, &new_eptp);
  if (ret) return ret;

  /* Store prepared EPTP */
  prepare->prepared_eptp = new_eptp;

  ept_swap_dbg("Prepared EPT for swap: EPTP=0x%llx\n", new_eptp);
  return 0;
}

/* Helper to get MMU page from virtual address */
static inline struct kvm_mmu_page *page_header(void *virt)
{
  struct page *page = virt_to_page(virt);
  return (struct kvm_mmu_page *)page_private(page);
}

/* Clean up prepared EPT tables */
void vmx_cleanup_prepared_ept(struct kvm *kvm, u64 eptp) {
  hpa_t root_hpa = eptp & EPT_POINTER_PAGE_MASK;
  struct kvm_mmu_page *root;

  if (!root_hpa) return;

  root = page_header(__va(root_hpa));
  kvm_mmu_free_page(root);

  ept_swap_dbg("Cleaned up prepared EPT: EPTP=0x%llx\n", eptp);
}

/* EPT swap initialization - called from vmx.c */
int vmx_ept_swap_setup(void) {
  if (!enable_ept) {
    pr_info("EPT swap: EPT not enabled\n");
    return -EOPNOTSUPP;
  }

  pr_info("HYPR EPT swap support initialized\n");
  return 0;
}

void vmx_ept_swap_cleanup(void) {
  pr_info("HYPR EPT swap support unloaded\n");
}
