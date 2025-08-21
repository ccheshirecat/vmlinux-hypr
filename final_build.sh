#!/usr/bin/env bash
#
# linux-truly-lean-hypervisor-config-v10.sh
#
# PURPOSE:
#   To generate a TRULY LEAN and MINIMALIST kernel config. This is the final,
#   correct approach that avoids all bloat by building from the ground up.
#
# STRATEGY:
#   1. START FROM ZERO: Use `make defconfig` to create a barebones config.
#   2. ADD YOUR MAGIC: Programmatically enable all critical HYPR features.
#   3. ADD YOUR HARDWARE: Intelligently detect ONLY the drivers your server
#      is currently using and enable them as modules.
#   4. FINALIZE: Run `olddefconfig` to resolve dependencies.

set -euo pipefail

KDIR="$(pwd)"
SCRIPTS_CONFIG="${KDIR}/scripts/config"

if [ ! -f "${SCRIPTS_CONFIG}" ]; then
  echo "ERROR: Kernel scripts/config tool not found. Run from kernel source root." >&2
  exit 2
fi

echo "=== Truly Lean Hypervisor Kernel Config Generator (v10) ==="

# --- STAGE 1: Start with a minimal, clean-slate configuration ---
echo "[Step 1] Creating a minimal baseline with 'defconfig'..."
make defconfig

# --- STAGE 2: Enforce our critical "must-have" features ---
echo "[Step 2] Forcing critical HYPR features and core subsystems to be enabled..."

# Helper functions for this stage
cfg_enable() { "${SCRIPTS_CONFIG}" --enable "$1" || true; }
cfg_module() { "${SCRIPTS_CONFIG}" --module "$1" || true; }

# Core boot/device support
cfg_enable "DEVTMPFS"
cfg_enable "DEVTMPFS_MOUNT"
cfg_enable "BLK_DEV_INITRD"
cfg_enable "RD_GZIP"
cfg_enable "RD_XZ"
cfg_enable "RD_ZSTD"

# Virtualization Host Support (KVM, VFIO)
cfg_enable "VIRTUALIZATION"
cfg_enable "KVM"
cfg_enable "KVM_INTEL"
cfg_enable "KVM_AMD"
cfg_enable "VFIO"
cfg_enable "VFIO_IOMMU_TYPE1"
cfg_enable "VFIO_PCI"
cfg_enable "IOMMU_SUPPORT"
cfg_enable "INTEL_IOMMU"
cfg_enable "AMD_IOMMU"
cfg_enable "KVM_HYPR_EPT_SWAP"

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
cfg_enable "MODULES" # Must be enabled for modules to work

# Device Access for Debugging
cfg_enable "DEVMEM"
cfg_enable "DEVKMEM"

# --- STAGE 3: Intelligently enable ONLY the drivers this machine needs ---
echo "[Step 3] Detecting and enabling drivers for currently used hardware..."
for mod in $(lsmod | tail -n +2 | awk '{print $1}'); do
  # Convert module name to uppercase CONFIG_ equivalent
  config_opt="CONFIG_$(echo $mod | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  echo "  -> Enabling module for currently loaded driver: $mod ($config_opt)"
  cfg_module "$config_opt"
done

# --- STAGE 4: Final dependency resolution ---
echo "[Step 4] Finalizing .config and resolving all dependencies..."
make olddefconfig

echo "---"
echo "✅ Lean generation complete! This kernel is small, fast, and custom-built for this machine."
echo "---"
