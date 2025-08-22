/* HYPR VMM Control Implementation
 * 
 * Implements cooperative pause/resume mechanism for atomic EPT swaps.
 * This allows the host VMM to pause all vCPUs atomically during state transitions.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>
#include <linux/cpu.h>
#include <asm/vmm_control.h>
#include <asm/fixmap.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>

/* Global pointer to the control page */
struct vmm_control_page *vmm_control_page_ptr;
EXPORT_SYMBOL_GPL(vmm_control_page_ptr);

/* Get the current CPU's control block */
static inline struct vcpu_control_block *get_vcpu_control(void)
{
    if (!vmm_control_page_ptr)
        return NULL;
    
    int cpu = smp_processor_id();
    if (cpu >= MAX_VCPUS)
        return NULL;
        
    return &vmm_control_page_ptr->vcpus[cpu];
}

/* Get the current CPU's swap control */
static inline struct hypr_swap_control *get_swap_control(void)
{
    struct vcpu_control_block *vcpu = get_vcpu_control();
    if (!vcpu)
        return NULL;
    return &vcpu->swap_control;
}

/* Check if VMFUNC EPTP switching is available */
int hypr_check_vmfunc_support(void)
{
    unsigned int eax, ebx, ecx, edx;
    
    /* Check for VMFUNC support in CPUID */
    cpuid_count(0x7, 0, &eax, &ebx, &ecx, &edx);
    
    /* Bit 16 of EBX indicates VMFUNC support */
    if (!(ebx & (1 << 16))) {
        pr_info("HYPR: CPU does not support VMFUNC\n");
        return 0;
    }
    
    /* Check if hypervisor exposes VMFUNC to guest */
    if (!vmm_control_page_ptr || !vmm_control_page_ptr->vmfunc_available) {
        pr_info("HYPR: Hypervisor does not expose VMFUNC\n");
        return 0;
    }
    
    pr_info("HYPR: VMFUNC EPTP switching available\n");
    return 1;
}
EXPORT_SYMBOL_GPL(hypr_check_vmfunc_support);

/* High-performance swap request - guest initiates the swap */
void hypr_request_swap(uint16_t view_index)
{
    struct hypr_swap_control *ctrl;
    uint64_t start_ns, end_ns;
    uint64_t new_gen;
    
    ctrl = get_swap_control();
    if (!ctrl) {
        pr_warn("HYPR: No swap control for CPU %d\n", smp_processor_id());
        return;
    }
    
    /* Validate view index */
    if (view_index >= vmm_control_page_ptr->num_views) {
        pr_warn("HYPR: Invalid view index %u (max %u)\n", 
                view_index, vmm_control_page_ptr->num_views);
        return;
    }
    
    /* Record start time for latency measurement */
    start_ns = ktime_get_ns();
    
    /* Signal the desired state with generation counter */
    atomic_set(&ctrl->desired_idx, view_index);
    new_gen = atomic64_inc_return(&ctrl->desired_gen);
    
    /* Memory barrier to ensure writes are visible */
    smp_wmb();
    
    /* Check for Intel VMFUNC zero-exit fast path */
    if (vmm_control_page_ptr->vmfunc_available) {
        /* Execute VMFUNC directly - no VM-exit, nanosecond latency */
        asm volatile(
            "mov %0, %%ecx\n\t"    /* Leaf 0 for EPTP switching */
            "mov %1, %%eax\n\t"    /* View index in EAX */
            "vmfunc\n\t"
            :
            : "i"(VMFUNC_EPTP_SWITCHING), "r"((uint32_t)view_index)
            : "eax", "ecx", "memory"
        );
        
        /* Update applied state to match (we did it ourselves) */
        atomic_set(&ctrl->applied_idx, view_index);
        atomic64_set(&ctrl->applied_gen, new_gen);
        
        end_ns = ktime_get_ns();
        atomic64_set(&ctrl->swap_latency_ns, end_ns - start_ns);
        atomic64_inc(&ctrl->swap_count);
        
        pr_debug("HYPR: VMFUNC swap to view %u completed in %lld ns\n",
                 view_index, end_ns - start_ns);
    } else if (vmm_control_page_ptr->npt_fast_path) {
        /* AMD fast path - host executor will see generation change */
        /* The micro-batching executor thread will perform the swap */
        
        /* Optionally kick an eventfd or send a lightweight signal */
        /* For now, rely on the host polling at high frequency */
        
        pr_debug("HYPR: AMD fast-path swap requested for view %u\n", view_index);
    } else {
        /* Fallback - should not happen in production */
        pr_warn("HYPR: No fast path available, swap may be slow\n");
    }
}
EXPORT_SYMBOL_GPL(hypr_request_swap);

/* IPI handler for pause requests */
asmlinkage void handle_vmm_pause_ipi(struct pt_regs *regs)
{
    struct vcpu_control_block *vcpu;
    
    /* Acknowledge the interrupt */
#ifdef CONFIG_X86_LOCAL_APIC
    apic_eoi();
#endif
    
    vcpu = get_vcpu_control();
    if (!vcpu)
        return;
    
    /* Transition to PAUSE_REQUESTED state */
    if (READ_ONCE(vcpu->state) == VCPU_STATE_RUNNING) {
        WRITE_ONCE(vcpu->state, VCPU_STATE_PAUSE_REQUESTED);
        
        /* Memory barrier to ensure state change is visible */
        mb();
        
        /* Acknowledge pause and spin */
        WRITE_ONCE(vcpu->state, VCPU_STATE_PAUSED);
        
        /* Spin until resumed */
        while (READ_ONCE(vcpu->state) == VCPU_STATE_PAUSED) {
            cpu_relax();
            barrier();
        }
    }
}

/* Early initialization - map the control page using fixmap */
void early_vmm_control_init(void)
{
    unsigned long control_page_phys = VMM_CONTROL_PAGE_ADDR;
    
    /* Map the control page using fixmap */
    set_fixmap(FIX_VMM_CONTROL, control_page_phys);
    vmm_control_page_ptr = (struct vmm_control_page *)fix_to_virt(FIX_VMM_CONTROL);
    
    /* Verify the magic number */
    if (vmm_control_page_ptr->magic != VMM_CONTROL_PAGE_MAGIC) {
        clear_fixmap(FIX_VMM_CONTROL);
        vmm_control_page_ptr = NULL;
        pr_info("VMM control page not detected\n");
        return;
    }
    
    pr_info("VMM control page initialized at %p\n", vmm_control_page_ptr);
}

/* Helper function to install handler on each CPU */
static void vmm_install_handler_on_cpu(void *info)
{
    struct desc_ptr idt_ptr;
    gate_desc *idt;
    gate_desc desc;
    
    /* Get the IDT base address for this CPU */
    store_idt(&idt_ptr);
    idt = (gate_desc *)idt_ptr.address;
    
    /* Pack the gate descriptor for our IPI handler */
    pack_gate(&desc, GATE_INTERRUPT, (unsigned long)handle_vmm_pause_ipi,
              0, 0, __KERNEL_CS);
    
    /* Write the handler to this CPU's IDT */
    write_idt_entry(idt, VMM_PAUSE_IPI_VECTOR, &desc);
}

/* Setup the IPI handler in the IDT on all CPUs */
static void vmm_control_setup_ipi_handler(void)
{
    /* Install the handler on all CPUs to ensure SMP safety */
    on_each_cpu(vmm_install_handler_on_cpu, NULL, 1);
    
    pr_info("HYPR VMM: Pause IPI handler installed at vector 0x%x on all CPUs\n", 
            VMM_PAUSE_IPI_VECTOR);
}

/* Late initialization - setup IPI handler after SMP is up */
void vmm_control_init(void)
{
    struct vcpu_control_block *vcpu;
    struct hypr_swap_control *swap;
    int cpu;
    
    if (!vmm_control_page_ptr)
        return;
    
    /* Initialize all vCPU states */
    for (cpu = 0; cpu < nr_cpu_ids && cpu < MAX_VCPUS; cpu++) {
        vcpu = &vmm_control_page_ptr->vcpus[cpu];
        WRITE_ONCE(vcpu->state, VCPU_STATE_RUNNING);
        
        /* Initialize swap control */
        swap = &vcpu->swap_control;
        atomic_set(&swap->desired_idx, 0);
        atomic64_set(&swap->desired_gen, 0);
        atomic_set(&swap->applied_idx, 0);
        atomic64_set(&swap->applied_gen, 0);
        atomic64_set(&swap->swap_count, 0);
        atomic64_set(&swap->swap_latency_ns, 0);
    }
    
    /* Install the IPI handler */
    vmm_control_setup_ipi_handler();
    
    /* Check for fast-path capabilities */
    if (hypr_check_vmfunc_support()) {
        pr_info("HYPR: Zero-exit VMFUNC path enabled\n");
    } else if (vmm_control_page_ptr->npt_fast_path) {
        pr_info("HYPR: AMD micro-batching fast path enabled\n");
    } else {
        pr_info("HYPR: Using standard pause/swap mechanism\n");
    }
    
    pr_info("VMM control fully initialized for %d CPUs\n", nr_cpu_ids);
}

/* Call from kernel init after SMP is up */
static int __init vmm_control_late_init(void)
{
    vmm_control_init();
    return 0;
}
late_initcall(vmm_control_late_init);
