# HYPR Kernel Modifications for Temporal Scaling

This document details all kernel modifications made to Linux 6.12.43 to support HYPR's temporal scaling architecture with microsecond-level EPT swapping and guest pause coordination.

## Overview

HYPR implements temporal scaling through ultra-fast VM state transitions using EPT (Extended Page Tables) swapping. This requires modifications to both the host kernel (KVM/VMX) and guest kernel for coordinated pause mechanisms.

## Architecture Components

### Host Kernel Components (KVM/VMX)
- **EPT Swap**: Atomic swapping of entire guest physical memory mappings
- **VMO Support**: Virtual Memory Object snapshots for instant VM resurrection
- **Multi-vCPU Coordination**: Safe pause/resume across all vCPUs

### Guest Kernel Components
- **VMM Control Page**: Shared memory page at GPA 0x00FFE000 for host-guest coordination
- **Pause Mechanism**: IPI-based vCPU pause handling for atomic state transitions

## File Modifications

### 1. Guest Kernel Support (VMM Control)

#### New Files Added:
```
arch/x86/kernel/vmm_control.c          # Guest pause mechanism implementation
arch/x86/include/asm/vmm_control.h     # VMM control page definitions
```

#### Modified Files:

**arch/x86/include/asm/fixmap.h** (Line 101)
- Added `FIX_VMM_CONTROL` fixmap entry for VMM control page mapping

**arch/x86/kernel/Makefile** (Line 55)
- Added `vmm_control.o` to kernel build objects

**arch/x86/kernel/setup.c**
- Line 59: Added `#include <asm/vmm_control.h>`
- Line 787: Added `early_vmm_control_init()` call after `early_ioremap_init()`

### 2. Host Kernel Support (KVM EPT Swap)

#### New Files Added:
```
arch/x86/kvm/vmx/ept_swap.c            # Core EPT swap implementation
arch/x86/kvm/vmx/ept_mmu.c             # MMU helper functions for EPT manipulation
arch/x86/kvm/ept_swap_ioctl.c          # Ioctl handlers for EPT operations
arch/x86/kvm/vmx/vmx_ept_swap.h        # EPT swap function declarations
include/uapi/linux/kvm_hypr.h          # HYPR-specific KVM ioctl definitions
```

#### Modified Files:

**arch/x86/kvm/Kconfig** (Lines 216-232)
- Added `CONFIG_KVM_HYPR_EPT_SWAP` configuration option

**arch/x86/kvm/Makefile**
- Line 17: Added `ept_swap_ioctl.o` to kvm module when CONFIG_KVM_HYPR_EPT_SWAP=y
- Line 23: Added `vmx/ept_swap.o vmx/ept_mmu.o` to kvm-intel module

**arch/x86/kvm/x86.c**
- Lines 37-46: Added includes for HYPR EPT swap support
- Lines 6305-6314: Added KVM_GET_EPTP and KVM_SET_EPTP ioctl cases (vCPU ioctls)
- Lines 7387-7400: Added KVM_EPT_SWAP_ALL, KVM_PREPARE_EPT_SWAP, KVM_COMMIT_EPT_SWAP cases (VM ioctls)

**arch/x86/include/asm/kvm_host.h** (Lines 1853-1858)
- Added EPT swap function pointers to `struct kvm_x86_ops`

**arch/x86/kvm/vmx/main.c**
- Lines 9-11: Added include for vmx_ept_swap.h
- Lines 163-167: Added EPT swap ops to vt_x86_ops structure

## Configuration Files

### Host Kernel Config (`host.config`)
- Full KVM/VMX support with Intel VT-x
- CONFIG_KVM_HYPR_EPT_SWAP=y
- EPT, NUMA, NVMe optimizations
- 100Gbps networking, MPTCP support

### Guest Kernel Config (`guest.config`)
- Minimal kernel optimized for cloud workloads
- VMM control page support enabled
- Reduced attack surface
- Fast boot optimizations

## Build Instructions

### Using the Build Script

```bash
cd /data/linux-6.12.43
./build_hypr_kernels.sh
```

This will build both kernels:
- **Guest kernel**: `build-guest/vmlinuz-6.12.43-hypr-guest`
- **Host kernel**: `build-host/vmlinuz-6.12.43-hypr-host`

### Manual Build

#### Guest Kernel:
```bash
cp guest.config .config
make olddefconfig
make -j$(nproc) bzImage modules
```

#### Host Kernel:
```bash
cp host.config .config
make olddefconfig
make -j$(nproc) bzImage modules
```

## Key Features Implemented

### 1. EPT Swap Operations (Host)

**Ioctls Added:**
- `KVM_GET_EPTP`: Get current EPT pointer
- `KVM_SET_EPTP`: Set new EPT pointer (requires paused vCPUs)
- `KVM_EPT_SWAP_ALL`: Swap EPT on all vCPUs atomically
- `KVM_PREPARE_EPT_SWAP`: Pre-build EPT tables from snapshot
- `KVM_COMMIT_EPT_SWAP`: Commit prepared EPT swap

**Safety Mechanisms:**
- All vCPUs must be paused before EPT swap
- EPTP validation according to Intel SDM
- TLB invalidation (INVEPT) after swap
- Memory barriers for coherency

### 2. VMM Control Page (Guest)

**Memory Layout:**
- Located at GPA 0x00FFE000 (16MB - 8KB)
- Magic: 0x48595052564D4D21 ("HYPRVMM!")
- Supports up to 64 vCPUs
- Per-vCPU state tracking (RUNNING/PAUSE_REQUESTED/PAUSED)

**IPI Mechanism:**
- Vector 0xF0 for pause requests
- Guest acknowledges and spins while paused
- Host resumes by clearing pause state

### 3. VMO Snapshot Support

**Snapshot Format:**
- Header with magic, version, memory size
- Page-by-page memory dump with GPA and flags
- Permissions preserved (R/W/X)
- Optimized for 16MB microVMs

## Performance Characteristics

### Expected Metrics:
- EPT swap time: 50-300 microseconds
- vCPU pause coordination: <100 microseconds  
- Snapshot load to EPT: 1-10ms (depending on size)
- TLB flush overhead: ~10 microseconds

### Optimization Points:
- Pre-built EPT tables (built while VM runs)
- EPT cache with LRU eviction
- Atomic multi-vCPU operations
- Hardware-assisted TLB invalidation

## Testing

### Basic Functionality Test:
```bash
# Boot a VM with guest kernel
# From host, trigger EPT swap via HYPR orchestrator
# Verify VM continues execution with new memory state
```

### Stress Testing:
- Rapid EPT swaps under load
- Multi-vCPU coordination verification
- Memory consistency checks
- TLB coherency validation

## Security Considerations

1. **EPT Validation**: All EPTP values validated against Intel SDM
2. **Pause Verification**: Host verifies all vCPUs paused before swap
3. **Snapshot Integrity**: Magic number and version checks
4. **Permission Checks**: Only privileged processes can perform EPT swaps
5. **Memory Barriers**: Proper synchronization for cache coherency

## Debugging

### Enable Debug Output:
```bash
echo 1 > /sys/module/kvm/parameters/ept_swap_debug
dmesg | grep EPT_SWAP
```

### Check VMM Control Page (Guest):
```bash
# The kernel will log if VMM control page is detected
dmesg | grep "VMM control"
```

## Repository Structure

```
/data/linux-6.12.43/
├── arch/x86/
│   ├── kernel/
│   │   ├── vmm_control.c          # [NEW] Guest pause mechanism
│   │   ├── Makefile                # [MODIFIED] Added vmm_control.o
│   │   └── setup.c                 # [MODIFIED] Initialize VMM control
│   ├── include/asm/
│   │   ├── vmm_control.h          # [NEW] VMM control definitions
│   │   ├── fixmap.h                # [MODIFIED] Added FIX_VMM_CONTROL
│   │   └── kvm_host.h              # [MODIFIED] Added EPT swap ops
│   └── kvm/
│       ├── vmx/
│       │   ├── ept_swap.c          # [NEW] EPT swap core
│       │   ├── ept_mmu.c           # [NEW] MMU helpers
│       │   ├── vmx_ept_swap.h      # [NEW] Function declarations
│       │   └── main.c               # [MODIFIED] Wire up ops
│       ├── ept_swap_ioctl.c        # [NEW] Ioctl handlers
│       ├── x86.c                    # [MODIFIED] Ioctl dispatch
│       ├── Makefile                 # [MODIFIED] Build rules
│       └── Kconfig                  # [MODIFIED] Config option
├── include/uapi/linux/
│   └── kvm_hypr.h                  # [NEW] HYPR ioctl definitions
├── guest.config                     # Guest kernel configuration
├── host.config                      # Host kernel configuration
└── build_hypr_kernels.sh           # Build script for both kernels
```

## Notes for Production

1. **Kernel Version**: Based on Linux 6.12.43 (stable)
2. **Testing Required**: Extensive testing needed before production use
3. **Performance Tuning**: May need adjustment based on workload
4. **Compatibility**: Requires Intel VT-x with EPT support
5. **Memory Requirements**: Host needs sufficient RAM for multiple EPT tables

## License

These modifications are provided under the same license as the Linux kernel (GPL v2).

## Contact

For questions about HYPR kernel modifications, please refer to the main HYPR project documentation.