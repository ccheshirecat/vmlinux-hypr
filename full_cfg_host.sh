#!/usr/bin/env bash
#
# linux-hypr-guest-config-generator.sh
#
# PURPOSE:
#   Generate a kernel .config specifically tailored for a high-performance
#   "HYPR" virtual machine guest. This configuration ensures that all
#   critical drivers for booting, networking, and performance are built
#   directly into the kernel (`=y`), avoiding reliance on initramfs for
#   essential modules.
#
# STRATEGY:
#   1. Start with a minimal `defconfig` baseline.
#   2. Use `allmodconfig` to discover and enable all possible features as modules.
#   3. Forcibly override critical drivers and features to be BUILT-IN (`=y`).
#      This includes VirtIO, SCSI, SMP, and custom HYPR options.
#   4. Run `make olddefconfig` to resolve dependencies and create the final config.
#
# USAGE:
#   1) Place this script in the root of your kernel source directory.
#   2) Make it executable:
#      chmod +x linux-hypr-guest-config-generator.sh
#   3) Run the script:
#      ./linux-hypr-guest-config-generator.sh
#   4) Build the kernel:
#      make -j$(nproc)
#   5) Install the kernel:
#      sudo make modules_install && sudo make install

set -euo pipefail

KDIR="$(pwd)"
SCRIPTS_CONFIG="${KDIR}/scripts/config"

if [ ! -f "${SCRIPTS_CONFIG}" ]; then
  echo "ERROR: Kernel scripts/config tool not found." >&2
  echo "Please run this script from the root of a kernel source directory." >&2
  exit 2
fi

# --- Helper Functions ---
cfg_enable() {
  "${SCRIPTS_CONFIG}" --enable "$1"
}

cfg_disable() {
  "${SCRIPTS_CONFIG}" --disable "$1"
}

cfg_module() {
  "${SCRIPTS_CONFIG}" --module "$1"
}

# --- STAGE 1: Establish a comprehensive baseline ---
echo "=== HYPR Guest Kernel Config Generator ==="
echo "[Step 1] Creating a sane baseline with 'defconfig'..."
make defconfig

echo "[Step 2] Enabling all possible features as modules with 'allmodconfig'..."
make allmodconfig

# --- STAGE 2: Enforce HYPR-critical features as built-in (=y) ---
echo "[Step 3] Forcing critical HYPR guest features to be built-in..."

# --- Multi-Core and Guest Support (ABSOLUTELY CRITICAL) ---
cfg_enable "SMP"                 # CRITICAL: Symmetric Multi-Processing (multi-vCPU)
cfg_enable "KVM_GUEST"           # CRITICAL: Kernel-based Virtual Machine guest support
cfg_enable "PARAVIRT"            # Paravirtualization support
cfg_enable "HYPERVISOR_GUEST"

# --- VIRTIO Drivers (CRITICAL for Boot & Networking) ---
cfg_enable "VIRTIO"
cfg_enable "VIRTIO_PCI"
cfg_enable "VIRTIO_BLK"          # MUST be =y for boot disks
cfg_enable "VIRTIO_NET"          # MUST be =y for networking
cfg_enable "VIRTIO_CONSOLE"

# --- SCSI/Block Drivers (CRITICAL for Cloud Disks) ---
cfg_enable "SCSI"                # MUST be =y for core SCSI support
cfg_enable "BLK_DEV_SD"          # MUST be =y for SCSI disk support

# --- Filesystems (Built-in for rootfs) ---
cfg_enable "EXT4_FS"
cfg_enable "XFS_FS"
cfg_enable "BTRFS_FS"

# --- Initrd Support (Good practice) ---
cfg_enable "BLK_DEV_INITRD"

# --- Custom HYPR Features ---
# This will only work if your kernel source has this custom option patched in.
# The `|| true` prevents the script from failing if the option doesn't exist.
cfg_enable "CONFIG_KVM_HYPR_EPT_SWAP" || true

# --- Basic Kernel Features ---
cfg_enable "64BIT"
cfg_enable "PROC_FS"
cfg_enable "SYSFS"
cfg_enable "BINFMT_ELF"

# --- Ensure modules can still be loaded if needed ---
cfg_enable "MODULES"
cfg_enable "MODULE_FORCE_LOAD"

# --- STAGE 3: Finalize Configuration ---
echo "[Step 4] Resolving dependencies and finalizing .config with 'olddefconfig'..."
make olddefconfig

echo "---"
echo "✅ HYPR Guest config generation complete!"
echo ""
echo "--- Next Steps ---"
echo "1. Build the kernel: make -j$(nproc)"
echo "2. Install the kernel: sudo make modules_install && sudo make install"
echo "3. Update your bootloader if necessary."
echo ""
echo "--- Post-Boot Verification ---"
echo "After rebooting, verify with:"
echo "zcat /proc/config.gz | grep -E 'CONFIG_SMP|CONFIG_VIRTIO_BLK|CONFIG_VIRTIO_NET|CONFIG_SCSI|CONFIG_BLK_DEV_SD'"
echo "---"
