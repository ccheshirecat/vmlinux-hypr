/* HYPR VMM Control Page Interface
 * 
 * Provides high-performance guest-host communication for EPT/NPT swapping.
 * Enables zero-exit VMFUNC path on Intel and microsecond swaps on AMD.
 */

#ifndef _ASM_X86_VMM_CONTROL_H
#define _ASM_X86_VMM_CONTROL_H

#include <linux/types.h>
#include <linux/atomic.h>

#define VMM_CONTROL_PAGE_MAGIC 0x48595052564D4D21ULL /* "HYPRVMM!" */
#define VMM_CONTROL_PAGE_ADDR  0x00FFE000UL
#define MAX_VCPUS 16  /* Most web VMs use 1-2 vCPUs, 16 is plenty */
#define VMM_PAUSE_IPI_VECTOR 0xF0
#define MAX_EPT_VIEWS 16  /* Maximum number of memory views per VM */

/* VMFUNC leaf numbers */
#define VMFUNC_EPTP_SWITCHING 0

/* State of a single vCPU as seen from host and guest */
enum vcpu_state {
    VCPU_STATE_RUNNING = 0,         /* Normal execution */
    VCPU_STATE_PAUSE_REQUESTED = 1, /* Host has sent IPI, guest should pause */
    VCPU_STATE_PAUSED = 2,          /* Guest has acknowledged and is spinning */
};

/* High-performance swap control for each vCPU */
struct __attribute__((packed)) hypr_swap_control {
    /* Written by guest to signal desired memory view */
    atomic_t desired_idx;      /* 16-bit index of desired EPT/NPT view */
    atomic64_t desired_gen;    /* Generation counter for new requests */
    
    /* Written by host to confirm active view */
    atomic_t applied_idx;      /* Currently active view index */
    atomic64_t applied_gen;    /* Generation of applied view */
    
    /* Statistics for monitoring */
    atomic64_t swap_count;     /* Total swaps performed */
    atomic64_t swap_latency_ns; /* Last swap latency in nanoseconds */
};

/* Represents the state of a single vCPU in the control page */
struct __attribute__((packed)) vcpu_control_block {
    volatile uint32_t state;
    uint32_t padding; /* Align to 8 bytes */
    
    /* High-performance swap control */
    struct hypr_swap_control swap_control;
    /* No extra reserved space - we're tight on space */
};

/* The full 4KB control page layout */
struct __attribute__((packed)) vmm_control_page {
    /* Verification field */
    uint64_t magic;
    
    /* VMFUNC capability flags */
    uint32_t vmfunc_available;    /* 1 if VMFUNC EPTP switching is available */
    uint32_t npt_fast_path;       /* 1 if AMD fast path is enabled */
    
    /* Physical address of EPTP/NPT list page */
    uint64_t eptp_list_phys;      /* Physical address of EPTP list for VMFUNC */
    uint16_t num_views;            /* Number of valid views in list */
    uint16_t padding[3];
    
    /* Per-vCPU control blocks */
    struct vcpu_control_block vcpus[MAX_VCPUS];
    
    /* Reserved space to fill the page */
    uint8_t reserved[4096 - sizeof(uint64_t) - sizeof(uint32_t)*2 - 
                     sizeof(uint64_t) - sizeof(uint16_t)*4 -
                     (MAX_VCPUS * sizeof(struct vcpu_control_block))];
};

/* Global pointer to the mapped control page */
extern struct vmm_control_page *vmm_control_page_ptr;

/* Function prototypes */
void early_vmm_control_init(void);
void vmm_control_init(void);
asmlinkage void handle_vmm_pause_ipi(struct pt_regs *regs);

/* High-performance swap functions */
void hypr_request_swap(uint16_t view_index);
int hypr_check_vmfunc_support(void);
void hypr_enable_fast_path(void);

#endif /* _ASM_X86_VMM_CONTROL_H */
