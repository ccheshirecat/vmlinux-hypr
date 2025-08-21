/* HYPR VMM Control Page Interface
 * 
 * Provides cooperative pause/resume mechanism for atomic EPT swaps.
 * The host VMM can pause all vCPUs atomically to ensure memory coherency
 * during state transitions.
 */

#ifndef _ASM_X86_VMM_CONTROL_H
#define _ASM_X86_VMM_CONTROL_H

#include <linux/types.h>

#define VMM_CONTROL_PAGE_MAGIC 0x48595052564D4D21ULL /* "HYPRVMM!" */
#define VMM_CONTROL_PAGE_ADDR  0x00FFE000UL
#define MAX_VCPUS 64
#define VMM_PAUSE_IPI_VECTOR 0xF0

/* State of a single vCPU as seen from host and guest */
enum vcpu_state {
    VCPU_STATE_RUNNING = 0,         /* Normal execution */
    VCPU_STATE_PAUSE_REQUESTED = 1, /* Host has sent IPI, guest should pause */
    VCPU_STATE_PAUSED = 2,          /* Guest has acknowledged and is spinning */
};

/* Represents the state of a single vCPU in the control page */
struct __attribute__((packed)) vcpu_control_block {
    volatile uint32_t state;
    uint32_t padding; /* Align to 8 bytes */
    uint64_t reserved[6];
};

/* The full 4KB control page layout */
struct __attribute__((packed)) vmm_control_page {
    /* Verification field */
    uint64_t magic;
    
    /* Per-vCPU control blocks */
    struct vcpu_control_block vcpus[MAX_VCPUS];
    
    /* Reserved space to fill the page */
    uint8_t reserved[4096 - sizeof(uint64_t) - 
                     (MAX_VCPUS * sizeof(struct vcpu_control_block))];
};

/* Global pointer to the mapped control page */
extern struct vmm_control_page *vmm_control_page_ptr;

/* Function prototypes */
void early_vmm_control_init(void);
void vmm_control_init(void);
asmlinkage void handle_vmm_pause_ipi(struct pt_regs *regs);

#endif /* _ASM_X86_VMM_CONTROL_H */
