/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SVM_NPT_SWAP_H
#define _SVM_NPT_SWAP_H

#include <linux/kvm_host.h>

struct kvm_ept_prepare;  /* Reuse Intel structure for AMD */

#ifdef CONFIG_KVM_HYPR_EPT_SWAP

/* NPT swap function declarations */
int svm_get_ncr3(struct kvm_vcpu *vcpu, u64 *ncr3);
int svm_set_ncr3(struct kvm_vcpu *vcpu, u64 new_ncr3);
int svm_prepare_npt_swap(struct kvm *kvm, struct kvm_ept_prepare *prepare);
int svm_create_npt_from_snapshot(struct kvm *kvm, void *snapshot_data, 
				 size_t snapshot_size, u64 *new_ncr3);
void svm_cleanup_prepared_npt(struct kvm *kvm, u64 ncr3);
int kvm_vm_ioctl_npt_swap_all(struct kvm *kvm, u64 new_ncr3);

/* MMU helper functions - shared with Intel */
struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm *kvm, 
					 struct kvm_mmu_page *parent, int level);
void kvm_mmu_free_page(struct kvm_mmu_page *sp);

/* AMD-specific MMU functions */
int kvm_mmu_populate_npt_from_snapshot(struct kvm *kvm, 
				       struct kvm_mmu_page *root,
				       void *snapshot_data, 
				       size_t snapshot_size);
void npt_cleanup_root(struct kvm_mmu_page *root);

/* Module init/cleanup functions */
int svm_npt_swap_setup(void);
void svm_npt_swap_cleanup(void);

#else

/* Stub implementations when NPT swap is disabled */
static inline int svm_get_ncr3(struct kvm_vcpu *vcpu, u64 *ncr3)
{
	return -EOPNOTSUPP;
}

static inline int svm_set_ncr3(struct kvm_vcpu *vcpu, u64 new_ncr3)
{
	return -EOPNOTSUPP;
}

static inline int svm_prepare_npt_swap(struct kvm *kvm, 
				       struct kvm_ept_prepare *prepare)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_KVM_HYPR_EPT_SWAP */

#endif /* _SVM_NPT_SWAP_H */