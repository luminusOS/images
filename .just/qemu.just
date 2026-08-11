set dotenv-load := true

import 'common.just'

# Boot the latest disk image by default.
default: disk

# Boot the latest workstation ISO.
[no-cd]
iso:
    QEMU_INSTALL_DISK_SIZE="{{ qemu_disk_size }}" ./tools/qemu.sh iso

# Boot the latest qcow2 artifact.
[no-cd]
disk:
    ./tools/qemu.sh disk

# Build workstation and install it to the QEMU test disk.
[no-cd]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    keep_sudo_alive
    just build workstation
    ./tools/install-qemu.sh {{ workstation_image }}

# Boot the installed QEMU test disk.
[no-cd]
run:
    QEMU_RESET_NVRAM="${QEMU_RESET_NVRAM:-1}" QEMU_DISK_PATH=".test/install-disk.qcow2" ./tools/qemu.sh disk
