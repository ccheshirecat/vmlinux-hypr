#!/usr/bin/env bash
#
# linux-final-portable-lean-config-v16.sh
#
# PURPOSE:
#   The definitive script to build the Project Raiin kernel. It is lean,
#   portable, and correctly configures the KVM stack as modules that use
#   a runtime registration pattern to avoid all dependency issues.
#
# STRATEGY:
#   This script is the final tool. It assumes the C source code has been
#   modified to use the correct function-pointer registration pattern.

set -euo pipefail

KDIR="$(pwd)"
SCRIPTS_CONFIG="${KDIR}/scripts/config"

if [ ! -f "${SCRIPTS_CONFIG}" ]; then
  echo "ERROR: Kernel scripts/config tool not found. Run from kernel source root." >&2
  exit 2
fi

echo "=== Final Portable Lean Hypervisor Config (v16) ==="

# --- STAGE 1: Start with a minimal, clean-slate configuration ---
echo "[Step 1] Creating a minimal baseline with 'defconfig'..."
make defconfig

# --- STAGE 2: Enforce our critical "must-have" features ---
echo "[Step 2] Forcing critical HYPR features and core subsystems to be enabled..."

# Helper functions
cfg_enable() { "${SCRIPTS_CONFIG}" --enable "$1" || true; }
cfg_module() { "${SCRIPTS_CONFIG}" --module "$1" || true; }
cfg_disable() { "${SCRIPTS_CONFIG}" --disable "$1" || true; }

# Core boot/device support
cfg_enable "DEVTMPFS"
cfg_enable "DEVTMPFS_MOUNT"
cfg_enable "BLK_DEV_INITRD"
cfg_enable "RD_GZIP"
cfg_enable "RD_XZ"
cfg_enable "RD_ZSTD"
cfg_enable "MODULES"

# --- VIRTUALIZATION (Correct Modular Configuration) ---
# This configuration works with the runtime registration pattern.
cfg_enable "VIRTUALIZATION"
cfg_module "KVM"                 # Generic KVM is a module
cfg_module "KVM_INTEL"           # Intel-specific is a module
cfg_module "KVM_AMD"             # AMD-specific is a module
cfg_enable "VFIO"
cfg_enable "VFIO_IOMMU_TYPE1"
cfg_enable "VFIO_PCI"
cfg_enable "IOMMU_SUPPORT"
cfg_enable "INTEL_IOMMU"
cfg_enable "AMD_IOMMU"
cfg_enable "KVM_HYPR_SWAP"        # Our new, portable Kconfig option

# SR-IOV, eBPF, XDP
cfg_enable "PCI_IOV"
cfg_enable "BPF_SYSCALL"
cfg_enable "BPF_JIT"
cfg_enable "DEBUG_INFO_BTF"
cfg_enable "XDP_SOCKETS"

# Core filesystems and networking
cfg_enable "EXT4_FS"
cfg_enable "XFS_FS"
cfg_enable "BRIDGE"

# Device Access for Debugging
cfg_enable "DEVMEM"
cfg_enable "DEVKMEM"

# --- STAGE 3: Intelligently enable ONLY the drivers this machine needs ---
echo "[Step 3] Detecting and enabling drivers for currently used hardware..."
for mod in $(lsmod | tail -n +2 | awk '{print $1}'); do
  # Blacklist KVM modules because we have configured them manually above.
  if [[ "$mod" == "kvm" || "$mod" == "kvm_intel" || "$mod" == "kvm_amd" ]]; then
    continue
  fi

  config_opt="CONFIG_$(echo $mod | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  echo "  -> Enabling module for currently loaded driver: $mod ($config_opt)"
  cfg_module "$config_opt"
done

# --- STAGE 4: Final dependency resolution ---
echo "[Step 4] Finalizing .config and resolving all dependencies..."
make olddefconfig

echo "---"
echo "✅ Final config generated. The vision is ready to be compiled."
echo "---"
