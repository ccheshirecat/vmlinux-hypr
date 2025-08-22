/* HYPR NPT Swap Implementation for KVM/SVM (AMD)
 *
 * Implements atomic NPT (Nested Page Tables) swapping for temporal scaling on AMD.
 * Equivalent to Intel's EPT swap but for AMD EPYC/Ryzen processors.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/kthread.h>
#include <linux/sched/rt.h>
#include <linux/delay.h>
#include <uapi/linux/kvm_hypr.h>
#include <asm/svm.h>
#include <asm/vmm_control.h>
#include "../mmu/mmu_internal.h"
#include "svm.h"
#include "svm_npt_swap.h"

/* NPT Control Register (nCR3) validation masks */
#define NPT_CR3_RESERVED_MASK 0xFFF0000000000F80ULL
#define NPT_CR3_PAGE_MASK     0xFFFFFFFFFFFFF000ULL

/* Micro-batching executor state for AMD */
struct hypr_npt_executor {
    struct task_struct *thread;
    int cpu;
    bool running;
    struct kvm *kvm;
    u64 *npt_list;        /* Array of prepared nCR3 values */
    int num_views;
};

static DEFINE_PER_CPU(struct hypr_npt_executor, npt_executors);

/* Debug logging */
static bool npt_swap_debug __read_mostly;
module_param(npt_swap_debug, bool, 0644);

#define npt_swap_dbg(fmt, ...) \
  do { \
    if (npt_swap_debug) \
      pr_info("NPT_SWAP: " fmt, ##__VA_ARGS__); \
  } while (0)

/* Validate nCR3 (NPT pointer) format */
static bool svm_valid_ncr3(u64 ncr3) {
  /* Check reserved bits */
  if (ncr3 & NPT_CR3_RESERVED_MASK) {
    npt_swap_dbg("Reserved bits set in nCR3: 0x%llx\n", ncr3);
    return false;
  }

  /* Physical address must be page-aligned */
  if (ncr3 & 0xFFF) {
    npt_swap_dbg("nCR3 not page-aligned: 0x%llx\n", ncr3);
    return false;
  }

  return true;
}

/* Get current NPT pointer from VMCB */
int svm_get_ncr3(struct kvm_vcpu *vcpu, u64 *ncr3) {
  struct vcpu_svm *svm = to_svm(vcpu);

  if (!npt_enabled) {
    npt_swap_dbg("NPT not enabled\n");
    return -EOPNOTSUPP;
  }

  if (!svm->vmcb) {
    npt_swap_dbg("VMCB not loaded for vCPU %d\n", vcpu->vcpu_id);
    return -EINVAL;
  }

  *ncr3 = svm->vmcb->control.nested_cr3;
  npt_swap_dbg("vCPU %d: Got nCR3 0x%llx\n", vcpu->vcpu_id, *ncr3);
  
  return 0;
}
/* Don't export - accessed via kvm_x86_ops */

/* Set new NPT pointer in VMCB - optimized for fast path */
int svm_set_ncr3(struct kvm_vcpu *vcpu, u64 new_ncr3) {
  struct vcpu_svm *svm = to_svm(vcpu);
  u64 old_ncr3;

  if (!npt_enabled) {
    npt_swap_dbg("NPT not enabled\n");
    return -EOPNOTSUPP;
  }

  if (!svm_valid_ncr3(new_ncr3)) {
    npt_swap_dbg("Invalid nCR3: 0x%llx\n", new_ncr3);
    return -EINVAL;
  }

  /* Save old nCR3 */
  old_ncr3 = svm->vmcb->control.nested_cr3;

  /* Set new nCR3 */
  svm->vmcb->control.nested_cr3 = new_ncr3;
  
  /* Mark VMCB dirty for both NPT and ASID */
  vmcb_mark_dirty(svm->vmcb, VMCB_NPT | VMCB_ASID);

  /* Use hardware TLB flush on next VMRUN - MUCH faster than manual flush */
  svm->vmcb->control.tlb_ctl = 1;  /* Hardware auto-flush */

  /* Memory barrier to ensure changes are visible */
  smp_wmb();

  npt_swap_dbg("vCPU %d: Fast NPT swap 0x%llx -> 0x%llx\n", 
               vcpu->vcpu_id, old_ncr3, new_ncr3);

  return 0;
}
/* Don't export - accessed via kvm_x86_ops */

/* Check if all vCPUs are paused via VMM control page (AMD) */
static bool all_vcpus_paused_amd(struct kvm *kvm) {
  struct kvm_vcpu *vcpu;
  unsigned long i;
  int paused_count = 0;

  if (!vmm_control_page_ptr) {
    npt_swap_dbg("VMM control page not mapped\n");
    return false;
  }

  /* Check magic number */
  if (vmm_control_page_ptr->magic != VMM_CONTROL_PAGE_MAGIC) {
    npt_swap_dbg("Invalid VMM control page magic: 0x%llx\n",
                 vmm_control_page_ptr->magic);
    return false;
  }

  /* Verify each vCPU is in PAUSED state */
  kvm_for_each_vcpu(i, vcpu, kvm) {
    struct vcpu_control_block *control;

    if (i >= MAX_VCPUS) {
      npt_swap_dbg("vCPU %lu exceeds MAX_VCPUS\n", i);
      return false;
    }

    control = &vmm_control_page_ptr->vcpus[i];
    if (READ_ONCE(control->state) != VCPU_STATE_PAUSED) {
      npt_swap_dbg("vCPU %lu not paused (state=%u)\n", i, control->state);
      paused_count++;
    }
  }

  npt_swap_dbg("All %d vCPUs are paused\n", paused_count);
  return true;
}

/* Per-vCPU NPT swap worker */
struct npt_swap_work {
  struct kvm_vcpu *vcpu;
  u64 new_ncr3;
  int result;
  struct completion done;
  call_single_data_t csd;
};

static void npt_swap_on_cpu(void *data) {
  struct npt_swap_work *work = container_of(data, struct npt_swap_work, csd);
  struct kvm_vcpu *vcpu = work->vcpu;

  /* Load the vCPU on this CPU */
  vcpu_load(vcpu);

  /* Perform the NPT swap */
  work->result = svm_set_ncr3(vcpu, work->new_ncr3);

  /* Unload the vCPU */
  vcpu_put(vcpu);

  complete(&work->done);
}

/* Perform atomic NPT swap across all vCPUs (AMD) */
int kvm_vm_ioctl_npt_swap_all(struct kvm *kvm, u64 new_ncr3) {
  struct kvm_vcpu *vcpu;
  struct npt_swap_work *works;
  unsigned long i, nr_vcpus;
  int ret = 0;
  ktime_t start_time;

  start_time = ktime_get();

  /* Validate new nCR3 */
  if (!svm_valid_ncr3(new_ncr3)) {
    npt_swap_dbg("Invalid nCR3 for swap: 0x%llx\n", new_ncr3);
    return -EINVAL;
  }

  /* Count vCPUs */
  nr_vcpus = 0;
  kvm_for_each_vcpu(i, vcpu, kvm) nr_vcpus++;

  if (nr_vcpus == 0) {
    npt_swap_dbg("No vCPUs to swap\n");
    return -EINVAL;
  }

  /* Allocate work structures */
  works = kcalloc(nr_vcpus, sizeof(*works), GFP_KERNEL);
  if (!works) {
    npt_swap_dbg("Failed to allocate work structures\n");
    return -ENOMEM;
  }

  mutex_lock(&kvm->lock);

  /* Verify all vCPUs are paused */
  if (!all_vcpus_paused_amd(kvm)) {
    npt_swap_dbg("Not all vCPUs are paused, aborting swap\n");
    ret = -EBUSY;
    goto out_unlock;
  }

  /* Initialize work for each vCPU */
  i = 0;
  kvm_for_each_vcpu(i, vcpu, kvm) {
    works[i].vcpu = vcpu;
    works[i].new_ncr3 = new_ncr3;
    works[i].result = 0;
    init_completion(&works[i].done);
    works[i].csd.func = npt_swap_on_cpu;
    works[i].csd.info = &works[i].csd;

    /* Schedule work on the CPU where the vCPU should run */
    if (vcpu->cpu >= 0) {
      smp_call_function_single_async(vcpu->cpu, &works[i].csd);
    } else {
      /* vCPU not assigned to a CPU, do it locally */
      npt_swap_on_cpu(&works[i].csd);
    }
  }

  /* Wait for all swaps to complete */
  for (i = 0; i < nr_vcpus; i++) {
    wait_for_completion(&works[i].done);
    if (works[i].result != 0) {
      npt_swap_dbg("NPT swap failed for vCPU %d: %d\n", 
                   works[i].vcpu->vcpu_id, works[i].result);
      ret = works[i].result;
    }
  }

  /* Global memory barrier */
  smp_mb();

  if (ret == 0) {
    u64 elapsed_us = ktime_us_delta(ktime_get(), start_time);
    npt_swap_dbg("NPT swap completed successfully in %llu us\n", elapsed_us);
  }

out_unlock:
  mutex_unlock(&kvm->lock);
  kfree(works);
  return ret;
}
/* Note: Don't export - accessed via kvm_x86_ops */

/* Helper to get MMU page from virtual address */
static inline struct kvm_mmu_page *page_header(void *virt)
{
  struct page *page = virt_to_page(virt);
  return (struct kvm_mmu_page *)page_private(page);
}

/* Create new NPT tables from guest memory snapshot */
int svm_create_npt_from_snapshot(struct kvm *kvm, void *snapshot_data,
                                 size_t snapshot_size, u64 *new_ncr3) {
  struct kvm_mmu_page *root;
  hpa_t root_hpa;
  u64 ncr3;
  int ret;

  if (!npt_enabled) return -EOPNOTSUPP;

  /* Allocate root NPT page */
  root = kvm_mmu_alloc_page(kvm, NULL, 0);
  if (!root) return -ENOMEM;

  root_hpa = __pa(root->spt);

  /* Build nCR3 value - simpler than Intel EPTP! */
  ncr3 = root_hpa;  /* Just the physical address, no flags needed */

  /* Populate NPT tables from snapshot */
  ret = kvm_mmu_populate_npt_from_snapshot(kvm, root, snapshot_data,
                                           snapshot_size);
  if (ret) {
    kvm_mmu_free_page(root);
    return ret;
  }

  *new_ncr3 = ncr3;
  npt_swap_dbg("Created new NPT from snapshot: nCR3=0x%llx\n", ncr3);

  return 0;
}
/* Don't export - accessed via kvm_x86_ops */

/* Prepare NPT tables for swap (pre-build while VM runs) */
int svm_prepare_npt_swap(struct kvm *kvm, struct kvm_ept_prepare *prepare) {
  u64 new_ncr3;
  int ret;

  /* Create NPT from snapshot */
  ret = svm_create_npt_from_snapshot(kvm, (void *)prepare->snapshot_addr,
                                     prepare->snapshot_size, &new_ncr3);
  if (ret) return ret;

  /* Store prepared nCR3 */
  prepare->prepared_eptp = new_ncr3;  /* Same field, different meaning */

  npt_swap_dbg("Prepared NPT for swap: nCR3=0x%llx\n", new_ncr3);
  return 0;
}
/* Don't export - accessed via kvm_x86_ops */

/* Clean up prepared NPT tables */
void svm_cleanup_prepared_npt(struct kvm *kvm, u64 ncr3) {
  hpa_t root_hpa = ncr3 & NPT_CR3_PAGE_MASK;
  struct kvm_mmu_page *root;

  if (!root_hpa) return;

  root = page_header(__va(root_hpa));
  kvm_mmu_free_page(root);

  npt_swap_dbg("Cleaned up prepared NPT: nCR3=0x%llx\n", ncr3);
}
/* Don't export - accessed via kvm_x86_ops */

/* AMD NPT micro-batching executor thread */
static int npt_executor_thread(void *data)
{
    struct hypr_npt_executor *state = data;
    struct kvm *kvm = state->kvm;
    struct kvm_vcpu *vcpu;
    struct vcpu_control_block *vcpu_ctrl;
    struct hypr_swap_control *swap;
    struct vcpu_svm *svm;
    unsigned long i;
    u64 desired_gen, applied_gen;
    u16 desired_idx;
    u64 new_ncr3;
    u64 start_ns, end_ns;
    int swaps_performed = 0;
    
    /* Set real-time priority */
    struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };
    sched_setscheduler(current, SCHED_FIFO, &param);
    
    /* Bind to CPU */
    set_cpus_allowed_ptr(current, cpumask_of(state->cpu));
    
    pr_info("HYPR NPT executor started on CPU %d\n", state->cpu);
    
    while (state->running) {
        swaps_performed = 0;
        
        /* Process each vCPU on this CPU */
        kvm_for_each_vcpu(i, vcpu, kvm) {
            if (vcpu->cpu != state->cpu)
                continue;
                
            if (!vmm_control_page_ptr || i >= MAX_VCPUS)
                continue;
                
            vcpu_ctrl = &vmm_control_page_ptr->vcpus[i];
            swap = &vcpu_ctrl->swap_control;
            
            /* Check for pending swap */
            desired_gen = atomic64_read(&swap->desired_gen);
            applied_gen = atomic64_read(&swap->applied_gen);
            
            if (desired_gen == applied_gen)
                continue;
                
            /* Get desired view */
            desired_idx = atomic_read(&swap->desired_idx);
            
            if (desired_idx >= state->num_views) {
                pr_warn("NPT: Invalid view %u\n", desired_idx);
                continue;
            }
            
            /* Get prepared nCR3 */
            new_ncr3 = state->npt_list[desired_idx];
            if (!new_ncr3)
                continue;
                
            start_ns = ktime_get_ns();
            
            /* Direct VMCB update - ultra fast path */
            svm = to_svm(vcpu);
            if (svm->vmcb) {
                /* Atomic memory view swap */
                svm->vmcb->control.nested_cr3 = new_ncr3;
                vmcb_mark_dirty(svm->vmcb, VMCB_NPT | VMCB_ASID);
                svm->vmcb->control.tlb_ctl = 1;  /* Hardware flush */
                
                /* Update applied state */
                atomic_set(&swap->applied_idx, desired_idx);
                atomic64_set(&swap->applied_gen, desired_gen);
                
                end_ns = ktime_get_ns();
                atomic64_set(&swap->swap_latency_ns, end_ns - start_ns);
                atomic64_inc(&swap->swap_count);
                
                swaps_performed++;
                
                npt_swap_dbg("NPT executor: Swapped vCPU %lu in %lld ns\n",
                            i, end_ns - start_ns);
            }
        }
        
        /* Adaptive polling for optimal latency/CPU balance */
        if (swaps_performed == 0) {
            /* No recent swaps - check every 100 microseconds */
            /* This gives us 10,000 checks/second per CPU */
            usleep_range(100, 100);
        } else {
            /* Just performed swaps - likely more coming (burst) */
            /* Check again in 10 microseconds for fast response */
            usleep_range(10, 10);
            
            /* Could even make this adaptive based on swap frequency:
             * - If >10 swaps/ms: no delay (continuous)
             * - If 1-10 swaps/ms: 10us delay  
             * - If <1 swap/ms: 100us delay
             */
        }
        
        if (kthread_should_stop())
            break;
    }
    
    pr_info("HYPR NPT executor stopped on CPU %d\n", state->cpu);
    return 0;
}

/* Start NPT executors */
static int svm_start_executors(struct kvm *kvm)
{
    struct hypr_npt_executor *executor;
    int cpu;
    
    for_each_online_cpu(cpu) {
        executor = &per_cpu(npt_executors, cpu);
        
        if (executor->thread)
            continue;
            
        executor->cpu = cpu;
        executor->kvm = kvm;
        executor->running = true;
        
        /* Allocate NPT list */
        executor->npt_list = kcalloc(MAX_EPT_VIEWS, sizeof(u64), GFP_KERNEL);
        if (!executor->npt_list) {
            pr_err("NPT: Failed to allocate view list\n");
            return -ENOMEM;
        }
        
        /* Create executor thread */
        executor->thread = kthread_create(npt_executor_thread, executor,
                                         "npt_exec_%d", cpu);
        if (IS_ERR(executor->thread)) {
            kfree(executor->npt_list);
            executor->npt_list = NULL;
            executor->thread = NULL;
            return PTR_ERR(executor->thread);
        }
        
        wake_up_process(executor->thread);
    }
    
    /* Enable fast path in control page */
    if (vmm_control_page_ptr) {
        vmm_control_page_ptr->npt_fast_path = 1;
        smp_wmb();
    }
    
    pr_info("HYPR: Started NPT executors on %d CPUs\n", num_online_cpus());
    return 0;
}

/* Stop NPT executors */
static void svm_stop_executors(void)
{
    struct hypr_npt_executor *executor;
    int cpu;
    
    for_each_online_cpu(cpu) {
        executor = &per_cpu(npt_executors, cpu);
        
        if (!executor->thread)
            continue;
            
        executor->running = false;
        kthread_stop(executor->thread);
        executor->thread = NULL;
        
        if (executor->npt_list) {
            kfree(executor->npt_list);
            executor->npt_list = NULL;
        }
    }
    
    pr_info("HYPR: Stopped NPT executors\n");
}

/* Populate NPT list for fast switching */
int svm_populate_npt_list(struct kvm *kvm, u64 *ncr3_array, int num_views)
{
    struct hypr_npt_executor *executor;
    int cpu, i;
    
    if (num_views > MAX_EPT_VIEWS)
        return -EINVAL;
        
    for_each_online_cpu(cpu) {
        executor = &per_cpu(npt_executors, cpu);
        
        if (!executor->npt_list)
            continue;
            
        for (i = 0; i < num_views; i++) {
            executor->npt_list[i] = ncr3_array[i];
        }
        executor->num_views = num_views;
    }
    
    /* Update control page */
    if (vmm_control_page_ptr) {
        vmm_control_page_ptr->num_views = num_views;
        smp_wmb();
    }
    
    npt_swap_dbg("NPT list populated with %d views\n", num_views);
    return 0;
}

/* Setup fast-path for AMD */
static int svm_setup_fast_path(struct kvm *kvm, struct kvm_fast_path_setup *setup)
{
    int ret;
    
    /* Populate NPT list */
    ret = svm_populate_npt_list(kvm, setup->eptp_list, setup->num_views);
    if (ret)
        return ret;
    
    /* Map control page */
    if (setup->control_page_addr && vmm_control_page_ptr) {
        pr_info("HYPR: Fast-path control page at 0x%llx\n", setup->control_page_addr);
    }
    
    npt_swap_dbg("AMD fast-path setup complete with %u views\n", setup->num_views);
    return 0;
}

/* Include header for registration function */
#include "../ept_swap_ioctl.h"

/* NPT swap initialization - called from svm.c */
int svm_npt_swap_setup(void) {
  if (!npt_enabled) {
    pr_info("NPT swap: NPT not enabled\n");
    return -EOPNOTSUPP;
  }

  /* Register our operations with the ioctl handler */
  hypr_register_ops(kvm_vm_ioctl_npt_swap_all,
                    svm_prepare_npt_swap,
                    svm_cleanup_prepared_npt);

  pr_info("HYPR NPT swap support initialized for AMD\n");
  pr_info("HYPR: AMD micro-batching fast path available\n");
  return 0;
}

void svm_npt_swap_cleanup(void) {
  /* Stop executor threads */
  svm_stop_executors();
  
  /* Unregister operations */
  hypr_register_ops(NULL, NULL, NULL);
  pr_info("HYPR NPT swap support unloaded\n");
}