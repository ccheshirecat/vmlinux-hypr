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
#include <asm/vmm_control.h>
#include <asm/fixmap.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/processor.h>

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
    int cpu;
    
    if (!vmm_control_page_ptr)
        return;
    
    /* Initialize all vCPU states */
    for (cpu = 0; cpu < nr_cpu_ids && cpu < MAX_VCPUS; cpu++) {
        vcpu = &vmm_control_page_ptr->vcpus[cpu];
        WRITE_ONCE(vcpu->state, VCPU_STATE_RUNNING);
    }
    
    /* Install the IPI handler */
    vmm_control_setup_ipi_handler();
    
    pr_info("VMM control fully initialized for %d CPUs\n", nr_cpu_ids);
}

/* Call from kernel init after SMP is up */
static int __init vmm_control_late_init(void)
{
    vmm_control_init();
    return 0;
}
late_initcall(vmm_control_late_init);
