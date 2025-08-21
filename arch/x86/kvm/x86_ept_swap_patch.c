/* HYPR EPT Swap Integration Patch for KVM x86
 *
 * This file contains the modifications needed to integrate EPT swap
 * functionality into the KVM x86 architecture code.
 *
 * Add these sections to the appropriate places in arch/x86/kvm/x86.c
 */

#include <linux/kvm_host.h>
#include "../../include/uapi/linux/kvm_hypr.h"

/* Add to the includes section of x86.c */
#ifdef CONFIG_KVM_HYPR_EPT_SWAP
#include "ept_swap_ioctl.c"
#endif

/* Add to kvm_arch_vcpu_ioctl() switch statement, before default case */
#ifdef CONFIG_KVM_HYPR_EPT_SWAP
	case KVM_GET_EPTP: {
		r = kvm_vcpu_ioctl_get_eptp(vcpu, argp);
		break;
	}
	case KVM_SET_EPTP: {
		r = kvm_vcpu_ioctl_set_eptp(vcpu, argp);
		break;
	}
#endif

/* Add to kvm_arch_vm_ioctl() switch statement, before default case */
#ifdef CONFIG_KVM_HYPR_EPT_SWAP
	case KVM_EPT_SWAP_ALL: {
		r = kvm_vm_ioctl_ept_swap_all_handler(kvm, argp);
		break;
	}
	case KVM_PREPARE_EPT_SWAP: {
		r = kvm_vm_ioctl_prepare_ept_swap(kvm, argp);
		break;
	}
	case KVM_COMMIT_EPT_SWAP: {
		r = kvm_vm_ioctl_commit_ept_swap(kvm, argp);
		break;
	}
#endif

/* Add to kvm_arch_init() for module initialization */
#ifdef CONFIG_KVM_HYPR_EPT_SWAP
	pr_info("KVM: HYPR EPT swap support enabled\n");
#endif

/* Add to kvm_arch_exit() for cleanup */
#ifdef CONFIG_KVM_HYPR_EPT_SWAP
	ept_swap_cache_cleanup();
#endif