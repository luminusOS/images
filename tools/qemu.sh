#!/bin/bash

set -x

# Quickly set up a QEMU VM test environment for manual testing.
# This script shouldn't be used in prod and is meant for development only.

# USAGE
# ./qemu.sh [disk|iso]
# If no argument is provided, disk is used by default


# Variables for test environment

# load .env if it exists
if [ -f .env ]; then
    source .env
fi

# default values for QEMU
: ${QEMU_MEM:="4G"}
: ${QEMU_CPU:="4"}
: ${QEMU_BOOT:="uefi"}
: ${QEMU_DISPLAY:="auto"}
: ${QEMU_DEBUG:="1"}
: ${QEMU_NO_REBOOT:="0"}
: ${QEMU_RESET_NVRAM:="0"}
: ${QEMU_RESET_DISK:="0"}
: ${QEMU_DISK_BUS:="ahci"}
: ${QEMU_ISO_PATH:=""}

TEST_HOME=$(pwd)/.test

function setup_test_home {
    mkdir -p $TEST_HOME
}

setup_test_home

if [ "$QEMU_DISPLAY" = "auto" ]; then
    QEMU_DISPLAY="gtk"
fi

# Install disk for ISO boots (set QEMU_INSTALL_DISK_SIZE like "64G")
# Defaults are set after TEST_HOME is known
: ${QEMU_INSTALL_DISK_SIZE:="64G"}
: ${QEMU_INSTALL_DISK_PATH:=""}
: ${QEMU_OVMF_CODE:="/usr/share/OVMF/OVMF_CODE.fd"}
: ${QEMU_OVMF_VARS_TEMPLATE:="/usr/share/OVMF/OVMF_VARS.fd"}
: ${QEMU_OVMF_VARS:="$TEST_HOME/OVMF_VARS.fd"}

# Get testing mode from first argument

if [ -z "${1:-}" ]; then
    SCRIPT_MODE="disk"
else
    SCRIPT_MODE=$1
fi

function find_iso {
    local iso_path
    local latest_iso_path
    local latest_iso_mtime
    local pointer_mtime

    if [ -n "$QEMU_ISO_PATH" ]; then
        if [ ! -f "$QEMU_ISO_PATH" ]; then
            echo "QEMU_ISO_PATH does not exist: $QEMU_ISO_PATH" >&2
            exit 1
        fi
        realpath "$QEMU_ISO_PATH"
        return
    fi

    latest_iso_path=$(
        find "$(pwd)" -maxdepth 1 -type f -name "*.iso" -printf "%T@ %p\n" \
            | sort -nr \
            | awk 'NR == 1 { sub(/^[^ ]+ /, ""); print }'
    )

    if [ -f "$TEST_HOME/last-iso" ]; then
        iso_path=$(cat "$TEST_HOME/last-iso")
        if [ -f "$iso_path" ]; then
            if [ -n "$latest_iso_path" ]; then
                pointer_mtime=$(stat -c "%Y" "$iso_path")
                latest_iso_mtime=$(stat -c "%Y" "$latest_iso_path")
                if [ "$pointer_mtime" -lt "$latest_iso_mtime" ]; then
                    echo "Ignoring older ISO pointer: $iso_path" >&2
                else
                    realpath "$iso_path"
                    return
                fi
            else
                realpath "$iso_path"
                return
            fi
        fi
        echo "Ignoring stale ISO pointer: $iso_path" >&2
    fi

    if [ -z "$latest_iso_path" ]; then
        echo "No ISO found in $(pwd)" >&2
        exit 1
    fi
    realpath "$latest_iso_path"
}


function disk_format {
    if [[ "$1" == *.qcow2 ]]; then
        echo "qcow2"
    else
        echo "raw"
    fi
}

function add_disk {
    local path="$1"
    local id="$2"
    local bootindex="$3"
    local format

    format=$(disk_format "$path")
    QEMU_ARGS+=" -drive file=$path,format=$format,if=none,id=$id"

    case "$QEMU_DISK_BUS" in
      ahci|sata)
        if [[ "$QEMU_ARGS" != *"ich9-ahci,id=ahci"* ]]; then
            QEMU_ARGS+=" -device ich9-ahci,id=ahci"
        fi
        QEMU_ARGS+=" -device ide-hd,drive=$id,bus=ahci.$((bootindex - 1)),bootindex=$bootindex"
        ;;
      virtio)
        QEMU_ARGS+=" -device virtio-blk-pci,drive=$id,bootindex=$bootindex"
        ;;
      *)
        echo "Unknown QEMU_DISK_BUS: $QEMU_DISK_BUS"
        echo "Valid values: ahci, sata, virtio"
        exit 1
        ;;
    esac
}

: ${QEMU_DISK_PATH:="$TEST_HOME/disk.qcow2"}


if [ "$SCRIPT_MODE" = "disk" ]; then
    QEMU_ARGS=""
    add_disk "$QEMU_DISK_PATH" "system_disk" "1"
    QEMU_ARGS+=" -boot order=c,menu=on"
elif [ "$SCRIPT_MODE" = "iso" ]; then
    ISO_PATH=$(find_iso)
    echo "Booting ISO: $ISO_PATH"
    QEMU_ARGS="-cdrom $ISO_PATH"
    QEMU_ARGS+=" -boot once=d,order=c,menu=on"
else
    echo "Unknown QEMU mode: $SCRIPT_MODE"
    echo "Valid modes: disk, iso"
    exit 1
fi

# if QEMU_BOOT = "uefi" then add UEFI firmware
if [ "$QEMU_BOOT" = "uefi" ]; then
    if [ "$QEMU_RESET_NVRAM" != "0" ]; then
        rm -f "$QEMU_OVMF_VARS"
    fi
    if [ ! -f "$QEMU_OVMF_VARS" ]; then
        cp "$QEMU_OVMF_VARS_TEMPLATE" "$QEMU_OVMF_VARS"
    fi
    QEMU_ARGS+=" -drive if=pflash,format=raw,readonly=on,file=$QEMU_OVMF_CODE"
    QEMU_ARGS+=" -drive if=pflash,format=raw,file=$QEMU_OVMF_VARS"
fi

# Run QEMU

# Now that TEST_HOME exists, set a default path for the optional install disk
if [ -z "$QEMU_INSTALL_DISK_PATH" ]; then
    QEMU_INSTALL_DISK_PATH="$TEST_HOME/install-disk.qcow2"
fi

# If requested and we are booting an ISO, create/attach an empty install disk
function ensure_install_disk {
    if [ -n "$QEMU_INSTALL_DISK_SIZE" ]; then
        if [ "$QEMU_RESET_DISK" != "0" ]; then
            rm -f "$QEMU_INSTALL_DISK_PATH"
        fi
        if [ ! -f "$QEMU_INSTALL_DISK_PATH" ]; then
            echo "Creating install disk at $QEMU_INSTALL_DISK_PATH ($QEMU_INSTALL_DISK_SIZE)"
            qemu-img create -f qcow2 "$QEMU_INSTALL_DISK_PATH" "$QEMU_INSTALL_DISK_SIZE"
        fi
        add_disk "$QEMU_INSTALL_DISK_PATH" "install_disk" "2"
    fi
}

if [ "$SCRIPT_MODE" = "iso" ]; then
    ensure_install_disk
fi

if [ "$QEMU_DEBUG" != "0" ]; then
    QEMU_LOG_FILE="$TEST_HOME/qemu.log"
    # Capture guest errors and print a serial console for easy debugging.
    QEMU_ARGS+=" -d guest_errors -D $QEMU_LOG_FILE -serial mon:stdio -monitor none"
    echo "Debug logging enabled. Log: $QEMU_LOG_FILE"
fi

if [ "$QEMU_NO_REBOOT" != "0" ]; then
    QEMU_ARGS+=" -no-reboot"
fi

qemu-kvm \
    -machine type=q35,accel=kvm \
    -cpu host \
    -m $QEMU_MEM \
    -smp $QEMU_CPU \
    -display $QEMU_DISPLAY \
    $QEMU_ARGS
