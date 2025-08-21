/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KVM_HYPR_COMMON_H
#define _KVM_HYPR_COMMON_H

#include <linux/kvm_host.h>
#include <uapi/linux/kvm_hypr.h>

/* CPU-agnostic interface for HYPR temporal scaling */

/* Common operations for both Intel EPT and AMD NPT */
struct hypr_ops {
	/* Get/Set nested page table pointer */
	int (*get_nested_ptr)(struct kvm_vcpu *vcpu, u64 *ptr);
	int (*set_nested_ptr)(struct kvm_vcpu *vcpu, u64 ptr);
	
	/* Prepare and execute swaps */
	int (*prepare_swap)(struct kvm *kvm, struct kvm_ept_prepare *prepare);
	int (*execute_swap_all)(struct kvm *kvm, u64 new_ptr);
	void (*cleanup_prepared)(struct kvm *kvm, u64 ptr);
	
	/* Module init/cleanup */
	int (*setup)(void);
	void (*cleanup)(void);
	
	/* Feature name for logging */
	const char *name;
};

#ifdef CONFIG_KVM_INTEL
#include "vmx/vmx_ept_swap.h"

static inline struct hypr_ops *get_hypr_ops(void)
{
	static struct hypr_ops vmx_hypr_ops = {
		.get_nested_ptr = vmx_get_eptp,
		.set_nested_ptr = vmx_set_eptp,
		.prepare_swap = vmx_prepare_ept_swap,
		.execute_swap_all = kvm_vm_ioctl_ept_swap_all,
		.cleanup_prepared = vmx_cleanup_prepared_ept,
		.setup = vmx_ept_swap_setup,
		.cleanup = vmx_ept_swap_cleanup,
		.name = "Intel EPT"
	};
	return &vmx_hypr_ops;
}

#elif defined(CONFIG_KVM_AMD)
#include "svm/svm_npt_swap.h"

static inline struct hypr_ops *get_hypr_ops(void)
{
	static struct hypr_ops svm_hypr_ops = {
		.get_nested_ptr = svm_get_ncr3,
		.set_nested_ptr = svm_set_ncr3,
		.prepare_swap = svm_prepare_npt_swap,
		.execute_swap_all = kvm_vm_ioctl_npt_swap_all,
		.cleanup_prepared = svm_cleanup_prepared_npt,
		.setup = svm_npt_swap_setup,
		.cleanup = svm_npt_swap_cleanup,
		.name = "AMD NPT"
	};
	return &svm_hypr_ops;
}

#else
static inline struct hypr_ops *get_hypr_ops(void)
{
	return NULL;
}
#endif

/* Common ioctl handler that works for both Intel and AMD */
static inline int kvm_vm_ioctl_hypr_swap(struct kvm *kvm, unsigned int ioctl,
					 unsigned long arg)
{
	struct hypr_ops *ops = get_hypr_ops();
	
	if (!ops) {
		pr_err("HYPR: No CPU support available\n");
		return -EOPNOTSUPP;
	}
	
	switch (ioctl) {
	case KVM_GET_EPTP: {
		u64 ptr;
		struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, 0);
		int ret = ops->get_nested_ptr(vcpu, &ptr);
		if (ret) return ret;
		if (copy_to_user((void __user *)arg, &ptr, sizeof(ptr)))
			return -EFAULT;
		return 0;
	}
	
	case KVM_SET_EPTP: {
		u64 ptr;
		if (copy_from_user(&ptr, (void __user *)arg, sizeof(ptr)))
			return -EFAULT;
		return ops->execute_swap_all(kvm, ptr);
	}
	
	case KVM_PREPARE_EPT_SWAP: {
		struct kvm_ept_prepare prepare;
		if (copy_from_user(&prepare, (void __user *)arg, sizeof(prepare)))
			return -EFAULT;
		return ops->prepare_swap(kvm, &prepare);
	}
	
	default:
		return -ENOTTY;
	}
}

/* Initialize HYPR support */
static inline int hypr_init(void)
{
	struct hypr_ops *ops = get_hypr_ops();
	
	if (!ops) {
		pr_info("HYPR: No CPU support available\n");
		return -EOPNOTSUPP;
	}
	
	pr_info("HYPR: Initializing temporal scaling with %s\n", ops->name);
	return ops->setup();
}

/* Cleanup HYPR support */
static inline void hypr_cleanup(void)
{
	struct hypr_ops *ops = get_hypr_ops();
	
	if (ops) {
		ops->cleanup();
		pr_info("HYPR: %s support unloaded\n", ops->name);
	}
}

#endif /* _KVM_HYPR_COMMON_H */