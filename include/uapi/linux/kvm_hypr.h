/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_KVM_HYPR_H
#define _UAPI_LINUX_KVM_HYPR_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* HYPR EPT Swap Extensions for KVM */

/* EPT swap ioctls for HYPR temporal scaling */
#define KVM_GET_EPTP              _IOR(KVMIO,  0xd6, __u64)
#define KVM_SET_EPTP              _IOW(KVMIO,  0xd7, __u64)
#define KVM_PREPARE_EPT_SWAP      _IOW(KVMIO,  0xd8, struct kvm_ept_prepare)
#define KVM_COMMIT_EPT_SWAP       _IOW(KVMIO,  0xd9, struct kvm_ept_swap)
#define KVM_EPT_SWAP_ALL          _IOW(KVMIO,  0xda, __u64)

/* Flags for EPT swap operations */
#define KVM_EPT_SWAP_FLAG_ATOMIC     (1 << 0)  /* Ensure atomic swap across all vCPUs */
#define KVM_EPT_SWAP_FLAG_VALIDATE   (1 << 1)  /* Validate EPT tables before swap */
#define KVM_EPT_SWAP_FLAG_NOWAIT     (1 << 2)  /* Don't wait for vCPU pause */

/* EPT swap structure for coordinated swaps */
struct kvm_ept_swap {
	__u64 new_eptp;      /* New EPT pointer to install */
	__u64 old_eptp;      /* Expected old EPT pointer (for validation) */
	__u32 flags;         /* Flags controlling swap behavior */
	__u32 vcpu_mask;     /* Bitmask of vCPUs to swap (0 = all) */
	__u64 reserved[4];   /* Reserved for future use */
};

/* EPT preparation structure for pre-building tables */
struct kvm_ept_prepare {
	__u64 snapshot_addr;     /* Userspace address of snapshot data */
	__u64 snapshot_size;     /* Size of snapshot in bytes */
	__u64 prepared_eptp;     /* Output: prepared EPT pointer */
	__u32 flags;            /* Preparation flags */
	__u32 reserved;
	__u64 reserved2[3];
};

/* Statistics for EPT swap operations */
struct kvm_ept_swap_stats {
	__u64 swap_count;        /* Total number of swaps performed */
	__u64 swap_time_ns;      /* Total time spent in swaps (ns) */
	__u64 avg_swap_time_ns;  /* Average swap time (ns) */
	__u64 min_swap_time_ns;  /* Minimum swap time (ns) */
	__u64 max_swap_time_ns;  /* Maximum swap time (ns) */
	__u64 failed_swaps;      /* Number of failed swaps */
	__u64 reserved[10];
};

#endif /* _UAPI_LINUX_KVM_HYPR_H */