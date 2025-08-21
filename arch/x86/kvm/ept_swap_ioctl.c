/* HYPR EPT Swap Ioctl Handlers for KVM
 *
 * Implements the ioctl interface for EPT swapping operations.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <asm/kvm_host.h>
#include <asm/vmm_control.h>
#include "../../include/uapi/linux/kvm_hypr.h"
#include "vmx/vmx.h"
#include "x86.h"
#include "ept_swap_ioctl.h"

/* External functions from ept_swap.c */
extern int vmx_get_eptp(struct kvm_vcpu *vcpu, u64 *eptp);
extern int vmx_set_eptp(struct kvm_vcpu *vcpu, u64 new_eptp);
extern int kvm_vm_ioctl_ept_swap_all(struct kvm *kvm, u64 new_eptp);
extern int vmx_prepare_ept_swap(struct kvm *kvm, struct kvm_ept_prepare *prepare);
extern void vmx_cleanup_prepared_ept(struct kvm *kvm, u64 eptp);

/* Cache for prepared EPT roots */
struct ept_cache_entry {
	u64 eptp;
	u64 snapshot_id;
	ktime_t created;
	struct list_head list;
};

static DEFINE_SPINLOCK(ept_cache_lock);
static LIST_HEAD(ept_cache);
static int ept_cache_size = 0;
static const int MAX_EPT_CACHE_SIZE = 16;

/* Statistics tracking */
struct ept_swap_stats {
	atomic64_t swap_count;
	atomic64_t total_time_ns;
	atomic64_t min_time_ns;
	atomic64_t max_time_ns;
	atomic64_t failed_swaps;
};

static struct ept_swap_stats global_stats = {
	.swap_count = ATOMIC64_INIT(0),
	.total_time_ns = ATOMIC64_INIT(0),
	.min_time_ns = ATOMIC64_INIT(LONG_MAX),
	.max_time_ns = ATOMIC64_INIT(0),
	.failed_swaps = ATOMIC64_INIT(0),
};

/* Handle KVM_GET_EPTP ioctl */
int kvm_vcpu_ioctl_get_eptp(struct kvm_vcpu *vcpu, void __user *argp)
{
	u64 eptp;
	int r;
	
	if (!kvm_x86_ops.get_eptp) {
		pr_err("EPT swap: get_eptp not implemented\n");
		return -EOPNOTSUPP;
	}
	
	r = kvm_x86_ops.get_eptp(vcpu, &eptp);
	if (r)
		return r;
	
	if (copy_to_user(argp, &eptp, sizeof(eptp)))
		return -EFAULT;
	
	return 0;
}

/* Handle KVM_SET_EPTP ioctl */
int kvm_vcpu_ioctl_set_eptp(struct kvm_vcpu *vcpu, void __user *argp)
{
	u64 eptp;
	ktime_t start_time, end_time;
	s64 swap_time_ns;
	int r;
	
	if (!kvm_x86_ops.set_eptp) {
		pr_err("EPT swap: set_eptp not implemented\n");
		return -EOPNOTSUPP;
	}
	
	if (copy_from_user(&eptp, argp, sizeof(eptp)))
		return -EFAULT;
	
	/* Verify vCPU is paused */
	if (vmm_control_page_ptr) {
		struct vcpu_control_block *control;
		control = &vmm_control_page_ptr->vcpus[vcpu->vcpu_id];
		if (READ_ONCE(control->state) != VCPU_STATE_PAUSED) {
			pr_err("EPT swap: vCPU %d not paused\n", vcpu->vcpu_id);
			return -EBUSY;
		}
	}
	
	start_time = ktime_get();
	r = kvm_x86_ops.set_eptp(vcpu, eptp);
	end_time = ktime_get();
	
	if (r) {
		atomic64_inc(&global_stats.failed_swaps);
		return r;
	}
	
	/* Update statistics */
	swap_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
	atomic64_inc(&global_stats.swap_count);
	atomic64_add(swap_time_ns, &global_stats.total_time_ns);
	
	/* Update min/max atomically */
	s64 current_min = atomic64_read(&global_stats.min_time_ns);
	while (swap_time_ns < current_min) {
		if (atomic64_cmpxchg(&global_stats.min_time_ns, current_min, swap_time_ns) == current_min)
			break;
		current_min = atomic64_read(&global_stats.min_time_ns);
	}
	
	s64 current_max = atomic64_read(&global_stats.max_time_ns);
	while (swap_time_ns > current_max) {
		if (atomic64_cmpxchg(&global_stats.max_time_ns, current_max, swap_time_ns) == current_max)
			break;
		current_max = atomic64_read(&global_stats.max_time_ns);
	}
	
	return 0;
}

/* Handle KVM_EPT_SWAP_ALL ioctl - swap all vCPUs atomically */
int kvm_vm_ioctl_ept_swap_all_handler(struct kvm *kvm, void __user *argp)
{
	u64 new_eptp;
	ktime_t start_time, end_time;
	s64 swap_time_ns;
	int r;
	
	if (copy_from_user(&new_eptp, argp, sizeof(new_eptp)))
		return -EFAULT;
	
	start_time = ktime_get();
	r = kvm_vm_ioctl_ept_swap_all(kvm, new_eptp);
	end_time = ktime_get();
	
	if (r) {
		atomic64_inc(&global_stats.failed_swaps);
		pr_err("EPT swap all failed: %d\n", r);
		return r;
	}
	
	/* Update statistics */
	swap_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
	atomic64_inc(&global_stats.swap_count);
	atomic64_add(swap_time_ns, &global_stats.total_time_ns);
	
	pr_info("EPT swap all completed in %lld ns\n", swap_time_ns);
	
	return 0;
}

/* Handle KVM_PREPARE_EPT_SWAP ioctl */
int kvm_vm_ioctl_prepare_ept_swap(struct kvm *kvm, void __user *argp)
{
	struct kvm_ept_prepare prepare;
	struct ept_cache_entry *entry;
	void *snapshot_data;
	int r;
	
	if (!kvm_x86_ops.prepare_ept_swap) {
		pr_err("EPT swap: prepare_ept_swap not implemented\n");
		return -EOPNOTSUPP;
	}
	
	if (copy_from_user(&prepare, argp, sizeof(prepare)))
		return -EFAULT;
	
	/* Allocate kernel buffer for snapshot data */
	snapshot_data = vmalloc(prepare.snapshot_size);
	if (!snapshot_data)
		return -ENOMEM;
	
	/* Copy snapshot from userspace */
	if (copy_from_user(snapshot_data, (void __user *)prepare.snapshot_addr, 
			   prepare.snapshot_size)) {
		vfree(snapshot_data);
		return -EFAULT;
	}
	
	/* Create EPT tables from snapshot */
	prepare.snapshot_addr = (__u64)snapshot_data;
	r = kvm_x86_ops.prepare_ept_swap(kvm, &prepare);
	vfree(snapshot_data);
	
	if (r)
		return r;
	
	/* Cache the prepared EPTP */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry) {
		entry->eptp = prepare.prepared_eptp;
		entry->created = ktime_get();
		
		spin_lock(&ept_cache_lock);
		
		/* Evict oldest entry if cache is full */
		if (ept_cache_size >= MAX_EPT_CACHE_SIZE) {
			struct ept_cache_entry *oldest;
			oldest = list_last_entry(&ept_cache, struct ept_cache_entry, list);
			list_del(&oldest->list);
			vmx_cleanup_prepared_ept(kvm, oldest->eptp);
			kfree(oldest);
			ept_cache_size--;
		}
		
		list_add(&entry->list, &ept_cache);
		ept_cache_size++;
		
		spin_unlock(&ept_cache_lock);
	}
	
	/* Return prepared EPTP to userspace */
	if (copy_to_user(argp, &prepare, sizeof(prepare)))
		return -EFAULT;
	
	pr_info("EPT prepared: EPTP=0x%llx\n", prepare.prepared_eptp);
	return 0;
}

/* Handle KVM_COMMIT_EPT_SWAP ioctl */
int kvm_vm_ioctl_commit_ept_swap(struct kvm *kvm, void __user *argp)
{
	struct kvm_ept_swap swap;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	ktime_t start_time, end_time;
	s64 swap_time_ns;
	int r = 0;
	
	if (copy_from_user(&swap, argp, sizeof(swap)))
		return -EFAULT;
	
	/* Validate flags */
	if (swap.flags & ~(KVM_EPT_SWAP_FLAG_ATOMIC | 
			   KVM_EPT_SWAP_FLAG_VALIDATE |
			   KVM_EPT_SWAP_FLAG_NOWAIT))
		return -EINVAL;
	
	mutex_lock(&kvm->lock);
	
	/* Check if all vCPUs are paused if atomic flag is set */
	if (swap.flags & KVM_EPT_SWAP_FLAG_ATOMIC) {
		bool all_paused = true;
		
		if (vmm_control_page_ptr) {
			kvm_for_each_vcpu(i, vcpu, kvm) {
				struct vcpu_control_block *control;
				control = &vmm_control_page_ptr->vcpus[i];
				if (READ_ONCE(control->state) != VCPU_STATE_PAUSED) {
					all_paused = false;
					break;
				}
			}
		}
		
		if (!all_paused && !(swap.flags & KVM_EPT_SWAP_FLAG_NOWAIT)) {
			mutex_unlock(&kvm->lock);
			pr_err("EPT swap: Not all vCPUs paused for atomic swap\n");
			return -EBUSY;
		}
	}
	
	start_time = ktime_get();
	
	/* Perform swap on selected vCPUs */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		u64 current_eptp;
		
		/* Check if this vCPU should be swapped */
		if (swap.vcpu_mask && !(swap.vcpu_mask & (1 << i)))
			continue;
		
		/* Validate old EPTP if requested */
		if (swap.flags & KVM_EPT_SWAP_FLAG_VALIDATE && swap.old_eptp) {
			r = kvm_x86_ops.get_eptp(vcpu, &current_eptp);
			if (r)
				break;
			
			if (current_eptp != swap.old_eptp) {
				pr_err("EPT swap: EPTP mismatch on vCPU %lu\n", i);
				r = -EINVAL;
				break;
			}
		}
		
		/* Perform the swap */
		vcpu_load(vcpu);
		r = kvm_x86_ops.set_eptp(vcpu, swap.new_eptp);
		vcpu_put(vcpu);
		
		if (r) {
			pr_err("EPT swap failed on vCPU %lu: %d\n", i, r);
			break;
		}
	}
	
	end_time = ktime_get();
	
	mutex_unlock(&kvm->lock);
	
	if (r) {
		atomic64_inc(&global_stats.failed_swaps);
		return r;
	}
	
	/* Update statistics */
	swap_time_ns = ktime_to_ns(ktime_sub(end_time, start_time));
	atomic64_inc(&global_stats.swap_count);
	atomic64_add(swap_time_ns, &global_stats.total_time_ns);
	
	pr_info("EPT swap committed in %lld ns\n", swap_time_ns);
	
	return 0;
}

/* Get EPT swap statistics */
int kvm_vm_ioctl_get_ept_swap_stats(struct kvm *kvm, void __user *argp)
{
	struct kvm_ept_swap_stats stats;
	u64 count, total;
	
	memset(&stats, 0, sizeof(stats));
	
	count = atomic64_read(&global_stats.swap_count);
	total = atomic64_read(&global_stats.total_time_ns);
	
	stats.swap_count = count;
	stats.swap_time_ns = total;
	stats.avg_swap_time_ns = count ? total / count : 0;
	stats.min_swap_time_ns = atomic64_read(&global_stats.min_time_ns);
	stats.max_swap_time_ns = atomic64_read(&global_stats.max_time_ns);
	stats.failed_swaps = atomic64_read(&global_stats.failed_swaps);
	
	if (copy_to_user(argp, &stats, sizeof(stats)))
		return -EFAULT;
	
	return 0;
}

/* Cleanup EPT cache on module exit */
void ept_swap_cache_cleanup(void)
{
	struct ept_cache_entry *entry, *tmp;
	
	spin_lock(&ept_cache_lock);
	list_for_each_entry_safe(entry, tmp, &ept_cache, list) {
		list_del(&entry->list);
		/* Note: actual EPT cleanup would need KVM context */
		kfree(entry);
	}
	ept_cache_size = 0;
	spin_unlock(&ept_cache_lock);
}