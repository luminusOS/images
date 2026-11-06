set dotenv-load := true

import 'common.just'

# Boot the latest disk image by default.
default: disk

# Boot the latest workstation ISO.
[no-cd]
iso:
    QEMU_INSTALL_DISK_SIZE="{{ qemu_disk_size }}" python3 ./tools/qemu.py iso

# Boot the latest qcow2 artifact.
[no-cd]
disk:
    python3 ./tools/qemu.py disk

# Build workstation and install it to the QEMU test disk.
[no-cd]
install:
    just build workstation
    python3 ./tools/install-qemu.py "$IMAGES_WORKSTATION"

# Boot the installed QEMU test disk.
[no-cd]
run:
    QEMU_RESET_NVRAM="${QEMU_RESET_NVRAM:-1}" QEMU_DISK_PATH=".test/install-disk.qcow2" python3 ./tools/qemu.py disk
