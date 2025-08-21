#!/usr/bin/env bash
#
# linux-maximal-hypervisor-config-generator-v2.sh
#
# PURPOSE:
#   Generate a "maximal" kernel .config for a bare-metal hypervisor host
#   (e.g., Dell PowerEdge with Intel CPU, NVMe, RAID controllers). This
#   script is designed to fix boot failures related to missing device
#   and filesystem support.
#
# STRATEGY:
#   1. Start with `defconfig` for a sane baseline.
#   2. Use `allmodconfig` to enable every possible feature as a module.
#   3. Forcibly enable CRITICAL host drivers and subsystems as built-ins (`=y`).
#
# USAGE:
#   1) Place this script in the root of your kernel source directory.
#   2) Make it executable:
#      chmod +x linux-maximal-hypervisor-config-generator-v2.sh
#   3) Run the script:
#      ./linux-maximal-hypervisor-config-generator-v2.sh
#   4) Build and install the kernel.

set -euo pipefail

KDIR="$(pwd)"
SCRIPTS_CONFIG="${KDIR}/scripts/config"

if [ ! -f "${SCRIPTS_CONFIG}" ]; then
  echo "ERROR: Kernel scripts/config tool not found. Run from kernel source root." >&2
  exit 2
fi

# --- Helper Functions ---
cfg_enable() {
  # Use || true to prevent script exit if an option doesn't exist in an older kernel
  "${SCRIPTS_CONFIG}" --enable "$1" || true
}

cfg_module() {
  "${SCRIPTS_CONFIG}" --module "$1" || true
}

# --- STAGE 1: Establish a comprehensive baseline ---
echo "=== Maximal Hypervisor Kernel Config Generator (v2) ==="
echo "[Step 1] Creating baseline with 'defconfig'..."
make defconfig

echo "[Step 2] Enabling all possible features as modules with 'allmodconfig'..."
make allmodconfig

# --- STAGE 2: Enforce critical hypervisor features as built-in (=y) ---
echo "[Step 3] Forcing critical HOST features to be built-in..."

# --- Core System & Device Support (FIXES BOOT FAILURE) ---
cfg_enable "DEVTMPFS"           # CRITICAL FIX: Creates /dev dynamically
cfg_enable "DEVTMPFS_MOUNT"     # CRITICAL FIX: Mounts /dev automatically at boot
cfg_enable "TMPFS"              # Required for various temporary filesystems
cfg_enable "PROC_FS"
cfg_enable "SYSFS"
cfg_enable "BINFMT_ELF"

# --- Virtualization Host Support (KVM) ---
cfg_enable "VIRTUALIZATION"
cfg_enable "KVM"
cfg_enable "KVM_INTEL"          # FIX: For your Dell R640's Intel CPU
cfg_enable "KVM_AMD"            # Also enable AMD, it's harmless and makes the kernel portable
cfg_enable "VFIO"
cfg_enable "VFIO_IOMMU_TYPE1"
cfg_enable "VFIO_PCI"
cfg_enable "IOMMU_SUPPORT"
cfg_enable "INTEL_IOMMU"        # For Intel VT-d
cfg_enable "AMD_IOMMU"

# --- Storage Drivers (Dell PERC / LSI) ---
cfg_enable "SCSI"
cfg_enable "BLK_DEV_SD"
cfg_enable "SCSI_MQ_DEFAULT"
cfg_enable "NVME_CORE"
cfg_enable "BLK_DEV_DM"          # Device Mapper (for LVM, etc.)
cfg_module "megaraid_sas"      # Most common Dell PERC / LSI RAID controller driver
cfg_module "ahci"             # SATA controller driver
cfg_module "nvme"

# --- Filesystems ---
cfg_enable "EXT4_FS"
cfg_enable "XFS_FS"
cfg_enable "BTRFS_FS"
cfg_enable "ISO9660_FS"

# --- Networking ---
cfg_enable "NET"
cfg_enable "INET"
cfg_module "e1000e"           # Common Intel 1GbE NIC
cfg_module "igb"              # Common Intel 1GbE NIC
cfg_module "ixgbe"            # Common Intel 10GbE NIC
cfg_module "bnxt_en"          # Common Broadcom NICs

# --- Initramfs Support ---
cfg_enable "BLK_DEV_INITRD"
cfg_enable "RD_GZIP"
cfg_enable "RD_XZ"
cfg_enable "RD_ZSTD"

# --- STAGE 3: Finalize Configuration ---
echo "[Step 4] Resolving dependencies and finalizing .config..."
make olddefconfig

echo "---"
echo "✅ Generation complete! The .config file is now ready for a hypervisor host."
echo ""
echo "--- Next Steps ---"
echo "1. Build the kernel: make -j$(nproc)"
echo "2. Install modules and kernel: sudo make modules_install && sudo make install"
echo "3. Update your bootloader: sudo update-grub (or equivalent)"
echo "4. Reboot."
echo ""
echo "--- Troubleshooting Note ---"
echo "If you still see 'Too many immovable memory regions', try adding 'nokaslr' to"
echo "your kernel boot parameters in GRUB as a temporary workaround."
echo "---"
