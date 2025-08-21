#!/bin/bash
# HYPR Kernel Build Script
# Builds both host and guest kernels with appropriate configurations

set -e

# Allow override via environment or use current directory
KERNEL_DIR="${KERNEL_DIR:-$(pwd)}"
BUILD_THREADS="${BUILD_THREADS:-$(nproc)}"
KERNEL_VERSION="${KERNEL_VERSION:-$(make kernelversion 2>/dev/null || echo "6.12.43")-hypr}"
OUTPUT_BASE="${OUTPUT_BASE:-${KERNEL_DIR}/build}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to build kernel
build_kernel() {
    local config_name=$1
    local output_dir=$2
    local kernel_name=$3
    
    echo_info "Building $kernel_name kernel..."
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Copy config
    cp "${KERNEL_DIR}/${config_name}.config" "${KERNEL_DIR}/.config"
    
    # Build kernel
    echo_info "Compiling kernel (this may take a while)..."
    make -j${BUILD_THREADS} O="${output_dir}" olddefconfig
    make -j${BUILD_THREADS} O="${output_dir}" vmlinux modules
    
    # Install modules to temp directory
    echo_info "Installing modules..."
    make -j${BUILD_THREADS} O="${output_dir}" INSTALL_MOD_PATH="${output_dir}/modules" modules_install
    
    # Copy kernel image (ELF format for fast microVM boot)
    cp "${output_dir}/vmlinux" "${output_dir}/vmlinux-${KERNEL_VERSION}-${kernel_name}"
    cp "${output_dir}/System.map" "${output_dir}/System.map-${KERNEL_VERSION}-${kernel_name}"
    cp "${output_dir}/.config" "${output_dir}/config-${KERNEL_VERSION}-${kernel_name}"
    
    echo_info "$kernel_name kernel built successfully!"
    echo_info "Kernel image: ${output_dir}/vmlinuz-${KERNEL_VERSION}-${kernel_name}"
}

# Main build process
main() {
    cd "$KERNEL_DIR"
    
    echo_info "Starting HYPR kernel build process..."
    echo_info "Using ${BUILD_THREADS} threads for compilation"
    
    # Check if configs exist
    if [ ! -f "guest.config" ]; then
        echo_error "guest.config not found!"
        exit 1
    fi
    
    if [ ! -f "host.config" ]; then
        echo_error "host.config not found!"
        exit 1
    fi
    
    # Check if VMM control files exist
    if [ ! -f "arch/x86/kernel/vmm_control.c" ]; then
        echo_error "vmm_control.c not found!"
        exit 1
    fi
    
    if [ ! -f "arch/x86/include/asm/vmm_control.h" ]; then
        echo_error "vmm_control.h not found!"
        exit 1
    fi
    
    # Check if EPT swap files exist for host
    if [ ! -f "arch/x86/kvm/vmx/ept_swap.c" ]; then
        echo_warn "EPT swap implementation not found, host kernel may not have EPT swap support"
    fi
    
    # Build guest kernel
    echo_info "="
    echo_info "Building GUEST kernel (minimal, with VMM control support)..."
    echo_info "="
    build_kernel "guest" "${KERNEL_DIR}/build-guest" "guest"
    
    # Build host kernel
    echo_info "="
    echo_info "Building HOST kernel (full KVM + EPT swap support)..."
    echo_info "="
    build_kernel "host" "${KERNEL_DIR}/build-host" "host"
    
    echo_info "="
    echo_info "Build complete!"
    echo_info "="
    echo_info "Guest kernel: ${KERNEL_DIR}/build-guest/vmlinuz-${KERNEL_VERSION}-guest"
    echo_info "Host kernel: ${KERNEL_DIR}/build-host/vmlinuz-${KERNEL_VERSION}-host"
    echo_info ""
    echo_info "To use:"
    echo_info "1. For the host system, install: build-host/vmlinuz-${KERNEL_VERSION}-host"
    echo_info "2. For VMs, use: build-guest/vmlinuz-${KERNEL_VERSION}-guest"
    echo_info ""
    echo_info "Features:"
    echo_info "- Guest kernel: VMM control page support for pause coordination"
    echo_info "- Host kernel: KVM with HYPR EPT swap + VMM control (unified kernel)"
}

# Run main function
main "$@"