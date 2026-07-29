set dotenv-load := true

registry := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag := env("LOS_TAG", fedora_ver + "." + build_date)
workstation_image := registry + "/luminusos-workstation:" + tag
qemu_disk_size := env("QEMU_INSTALL_DISK_SIZE", "64G")
sudo_keepalive := '''
keep_sudo_alive() {
  sudo -v
  while true; do
    sudo -n true
    sleep 60
  done &
  sudo_keepalive_pid="$!"
  trap 'kill "${sudo_keepalive_pid}" 2>/dev/null || true' EXIT
}
'''

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
