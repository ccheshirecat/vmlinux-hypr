/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _VMX_EPT_SWAP_H
#define _VMX_EPT_SWAP_H

#include <linux/kvm_host.h>

struct kvm_ept_prepare;

#ifdef CONFIG_KVM_HYPR_EPT_SWAP

/* EPT swap function declarations */
int vmx_get_eptp(struct kvm_vcpu *vcpu, u64 *eptp);
int vmx_set_eptp(struct kvm_vcpu *vcpu, u64 new_eptp);
int vmx_prepare_ept_swap(struct kvm *kvm, struct kvm_ept_prepare *prepare);
int vmx_create_ept_from_snapshot(struct kvm *kvm, void *snapshot_data, 
				 size_t snapshot_size, u64 *new_eptp);
void vmx_cleanup_prepared_ept(struct kvm *kvm, u64 eptp);
int kvm_vm_ioctl_ept_swap_all(struct kvm *kvm, u64 new_eptp);

/* MMU helper functions */
struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm *kvm, 
					 struct kvm_mmu_page *parent, int level);
void kvm_mmu_free_page(struct kvm_mmu_page *sp);
int kvm_mmu_populate_ept_from_snapshot(struct kvm *kvm, 
				       struct kvm_mmu_page *root,
				       void *snapshot_data, 
				       size_t snapshot_size);
void ept_sync_context(u64 eptp);
void ept_cleanup_root(struct kvm_mmu_page *root);

#else

/* Stub implementations when EPT swap is disabled */
static inline int vmx_get_eptp(struct kvm_vcpu *vcpu, u64 *eptp)
{
	return -EOPNOTSUPP;
}

static inline int vmx_set_eptp(struct kvm_vcpu *vcpu, u64 new_eptp)
{
	return -EOPNOTSUPP;
}

static inline int vmx_prepare_ept_swap(struct kvm *kvm, 
				       struct kvm_ept_prepare *prepare)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_KVM_HYPR_EPT_SWAP */

#endif /* _VMX_EPT_SWAP_H */