#!/bin/bash
set -euo pipefail

# Install a bootc container image into a QEMU virtual disk.
#
# Usage: install-qemu.sh <image-ref> [disk-size]
#   image-ref   Container image reference (e.g. localhost/luminusos-gnome:latest)
#   disk-size   Virtual disk size (default: 64G)
#
# This creates a qcow2 disk at .test/disk.qcow2, installs the bootc image
# into it, then boots it in QEMU so you can verify the installation.

IMAGE_REF="${1:?Usage: install-qemu.sh <image-ref> [disk-size]}"
DISK_SIZE="${2:-64G}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$PROJECT_DIR/.test"
DISK_PATH="$TEST_DIR/install-disk.qcow2"
BIB_CONFIG="$PROJECT_DIR/common/bootc-image-builder.toml"

# load .env if it exists
if [ -f "$PROJECT_DIR/.env" ]; then
    # shellcheck disable=SC1091
    source "$PROJECT_DIR/.env"
fi

: "${QEMU_MEM:=4G}"
: "${QEMU_CPU:=4}"
: "${QEMU_DISPLAY:=gtk}"

echo "==> Preparing output directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

# Remove old disk if it exists (may be root-owned from previous run)
if [ -f "$DISK_PATH" ]; then
    echo "    Removing existing disk..."
    rm -f "$DISK_PATH" 2>/dev/null || sudo rm -f "$DISK_PATH"
fi

echo "==> Installing $IMAGE_REF into disk via bootc-image-builder..."

# Use bootc-image-builder (via podman) to write the image to a qcow2 disk.
# This handles partitioning, bootloader setup, and writing the ostree commit.
# --rootfs btrfs: required to specify the filesystem type for partitions.
# The output disk lands at $TEST_DIR/qcow2/disk.qcow2
sudo podman run --rm -it --privileged \
    --pull=newer \
    --security-opt label=type:unconfined_t \
    -v "$TEST_DIR:/output" \
    -v "$BIB_CONFIG:/config.toml:ro" \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest \
    --type qcow2 \
    --rootfs btrfs \
    --config /config.toml \
    "$IMAGE_REF"

# bootc-image-builder outputs to /output/qcow2/disk.qcow2 owned by root
if [ -f "$TEST_DIR/qcow2/disk.qcow2" ]; then
    sudo mv "$TEST_DIR/qcow2/disk.qcow2" "$DISK_PATH"
    sudo chown "$(id -u):$(id -g)" "$DISK_PATH"
    sudo rmdir "$TEST_DIR/qcow2" 2>/dev/null || true
fi

echo "==> Installation complete."
echo ""
echo "To boot the installed system:"
echo "  just qemu run"
echo ""
echo "Or manually:"
echo "  QEMU_DISK_PATH=$DISK_PATH ./tools/qemu.sh disk"
