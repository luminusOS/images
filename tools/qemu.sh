#!/bin/bash

set -x

# Quickly set up a QEMU VM test environment for manual testing.
# This script shouldn't be used in prod and is meant for development only.

# USAGE
# ./qemu.sh [qemu-disk|qemu-iso]
# If no argument is provided, qemu-disk is used by default


# Variables for test environment

# load .env if it exists
if [ -f .env ]; then
    source .env
fi

# default values for QEMU
: ${QEMU_MEM:="4G"}
: ${QEMU_CPU:="4"}
: ${QEMU_BOOT:="uefi"}
: ${QEMU_DISPLAY:="gtk"}
: ${QEMU_DEBUG:="1"}

TEST_HOME=$(pwd)/.test

# Optional install disk for ISO boots (set QEMU_INSTALL_DISK_SIZE like "20G")
# Defaults are set after TEST_HOME is known
: ${QEMU_INSTALL_DISK_SIZE:=""}
QEMU_INSTALL_DISK_PATH=""

# Get testing mode from second argument

if [ -z "$1" ]; then
    SCRIPT_MODE="qemu-disk"
else
    SCRIPT_MODE=$1
fi

function find_iso {
    iso_path=$(find $(pwd) -name "*.iso" | head -n 1)
    if [ -z "$iso_path" ]; then
        echo "No ISO found in $(pwd)"
        exit 1
    fi
    echo $iso_path
}


# Quickly get the absolute path of a file

function abs_path {
    echo $(realpath $1)
}

: ${QEMU_DISK_PATH:="$TEST_HOME/disk.qcow2"}


if [ "$SCRIPT_MODE" = "qemu-disk" ]; then
    # Allow overriding disk path via QEMU_DISK_PATH; assume raw unless it ends with .qcow2
    if [[ "$QEMU_DISK_PATH" == *.qcow2 ]]; then
        QEMU_ARGS="-drive file=$QEMU_DISK_PATH,format=qcow2,if=virtio"
    else
        QEMU_ARGS="-drive file=$QEMU_DISK_PATH,format=raw,if=virtio"
    fi
else
    QEMU_ARGS="-cdrom $(find_iso)"
fi

# if QEMU_BOOT = "uefi" then add UEFI firmware
if [ "$QEMU_BOOT" = "uefi" ]; then
    QEMU_ARGS+=" -bios /usr/share/OVMF/OVMF_CODE.fd"
fi


# Run QEMU


function setup_test_home {
    mkdir -p $TEST_HOME
}

setup_test_home

# Now that TEST_HOME exists, set a default path for the optional install disk
if [ -z "$QEMU_INSTALL_DISK_PATH" ]; then
    QEMU_INSTALL_DISK_PATH="$TEST_HOME/install-disk.qcow2"
fi

# If requested and we are booting an ISO, create/attach an empty install disk
function ensure_install_disk {
    if [ -n "$QEMU_INSTALL_DISK_SIZE" ]; then
        if [ ! -f "$QEMU_INSTALL_DISK_PATH" ]; then
            echo "Creating install disk at $QEMU_INSTALL_DISK_PATH ($QEMU_INSTALL_DISK_SIZE)"
            qemu-img create -f qcow2 "$QEMU_INSTALL_DISK_PATH" "$QEMU_INSTALL_DISK_SIZE"
        fi
        QEMU_ARGS+=" -drive file=$QEMU_INSTALL_DISK_PATH,format=qcow2,if=virtio"
    fi
}

if [ "$SCRIPT_MODE" = "qemu-iso" ]; then
    ensure_install_disk
fi

if [ "$QEMU_DEBUG" != "0" ]; then
    QEMU_LOG_FILE="$TEST_HOME/qemu.log"
    # Capture guest errors, keep the VM from auto-rebooting, and print a serial console for easy debugging.
    QEMU_ARGS+=" -d guest_errors -D $QEMU_LOG_FILE -no-reboot -serial mon:stdio -monitor none"
    echo "Debug logging enabled. Log: $QEMU_LOG_FILE"
fi

qemu-kvm \
    -machine type=q35,accel=kvm \
    -cpu host \
    -m $QEMU_MEM \
    -smp $QEMU_CPU \
    -display $QEMU_DISPLAY \
    $QEMU_ARGS