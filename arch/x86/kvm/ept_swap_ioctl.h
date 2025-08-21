/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _EPT_SWAP_IOCTL_H
#define _EPT_SWAP_IOCTL_H

#include <linux/kvm_host.h>

/* Ioctl handler function declarations */
int kvm_vcpu_ioctl_get_eptp(struct kvm_vcpu *vcpu, void __user *argp);
int kvm_vcpu_ioctl_set_eptp(struct kvm_vcpu *vcpu, void __user *argp);
int kvm_vm_ioctl_ept_swap_all_handler(struct kvm *kvm, void __user *argp);
int kvm_vm_ioctl_prepare_ept_swap(struct kvm *kvm, void __user *argp);
int kvm_vm_ioctl_commit_ept_swap(struct kvm *kvm, void __user *argp);
int kvm_vm_ioctl_get_ept_swap_stats(struct kvm *kvm, void __user *argp);
void ept_swap_cache_cleanup(void);

#endif /* _EPT_SWAP_IOCTL_H */