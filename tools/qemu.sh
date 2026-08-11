#!/usr/bin/env bash
# Launch a local workstation ISO or disk under QEMU/KVM.
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_dir="${project_dir}/.test"
mkdir -p "${test_dir}"

if [ -f "${project_dir}/.env" ]; then
  # shellcheck disable=SC1091
  source "${project_dir}/.env"
fi
# shellcheck disable=SC1091
source "${project_dir}/tools/qemu-common.sh"

: "${QEMU_MEM:=4G}"
: "${QEMU_CPU:=4}"
: "${QEMU_BOOT:=uefi}"
: "${QEMU_DISPLAY:=auto}"
: "${QEMU_DEBUG:=1}"
: "${QEMU_NO_REBOOT:=0}"
: "${QEMU_RESET_NVRAM:=0}"
: "${QEMU_RESET_DISK:=0}"
: "${QEMU_DISK_BUS:=ahci}"
: "${QEMU_ISO_PATH:=}"
: "${QEMU_DISK_PATH:=}"
: "${QEMU_INSTALL_DISK_SIZE:=64G}"
: "${QEMU_INSTALL_DISK_PATH:=${test_dir}/install-disk.qcow2}"
: "${QEMU_OVMF_VARS:=${test_dir}/OVMF_VARS.fd}"
: "${QEMU_BINARY:=qemu-kvm}"
: "${QEMU_DRY_RUN:=0}"

mode="${1:-disk}"
case "${mode}" in
  disk | iso) ;;
  *)
    echo "Unknown QEMU mode: ${mode} (expected disk or iso)" >&2
    exit 1
    ;;
esac

if [ "${QEMU_DISPLAY}" = auto ]; then
  QEMU_DISPLAY=gtk
fi

qemu_args=(
  -machine "type=q35,accel=kvm"
  -cpu host
  -m "${QEMU_MEM}"
  -smp "${QEMU_CPU}"
  -display "${QEMU_DISPLAY}"
  -netdev "user,id=net0,hostfwd=tcp::2222-:22"
  -device "virtio-net-pci,netdev=net0"
)
ahci_added=0

add_disk() {
  local path="$1" id="$2" bootindex="$3" format
  format="$(qemu_disk_format "${path}")"
  qemu_args+=(-drive "file=${path},format=${format},if=none,id=${id}")

  case "${QEMU_DISK_BUS}" in
    ahci | sata)
      if [ "${ahci_added}" -eq 0 ]; then
        qemu_args+=(-device "ich9-ahci,id=ahci")
        ahci_added=1
      fi
      qemu_args+=(-device "ide-hd,drive=${id},bus=ahci.$((bootindex - 1)),bootindex=${bootindex}")
      ;;
    virtio)
      qemu_args+=(-device "virtio-blk-pci,drive=${id},bootindex=${bootindex}")
      ;;
    *)
      echo "Unknown QEMU_DISK_BUS: ${QEMU_DISK_BUS} (expected ahci, sata or virtio)" >&2
      exit 1
      ;;
  esac
}

if [ "${mode}" = disk ]; then
  disk_path="$(qemu_resolve_artifact "${project_dir}" \
    "${QEMU_DISK_PATH}" \
    "${test_dir}/last-qcow2" \
    '*.qcow2' \
    "${test_dir}/disk.qcow2")"
  echo "Booting disk: ${disk_path}"
  add_disk "${disk_path}" system_disk 1
  qemu_args+=(-boot "order=c,menu=on")
else
  iso_path="$(qemu_resolve_artifact "${project_dir}" \
    "${QEMU_ISO_PATH}" \
    "${test_dir}/last-iso" \
    '*.iso' \
    '')"
  echo "Booting ISO: ${iso_path}"
  qemu_args+=(-cdrom "${iso_path}" -boot "once=d,order=c,menu=on")

  if [ "${QEMU_RESET_DISK}" != 0 ] && [ "${QEMU_DRY_RUN}" != 1 ]; then
    rm -f "${QEMU_INSTALL_DISK_PATH}"
  fi
  if [ ! -f "${QEMU_INSTALL_DISK_PATH}" ] && [ "${QEMU_DRY_RUN}" != 1 ]; then
    echo "Creating install disk at ${QEMU_INSTALL_DISK_PATH} (${QEMU_INSTALL_DISK_SIZE})"
    qemu-img create -f qcow2 "${QEMU_INSTALL_DISK_PATH}" "${QEMU_INSTALL_DISK_SIZE}"
  fi
  add_disk "${QEMU_INSTALL_DISK_PATH}" install_disk 2
fi

if [ "${QEMU_BOOT}" = uefi ]; then
  qemu_resolve_ovmf
  if [ "${QEMU_RESET_NVRAM}" != 0 ] && [ "${QEMU_DRY_RUN}" != 1 ]; then
    rm -f "${QEMU_OVMF_VARS}"
  fi
  if [ ! -f "${QEMU_OVMF_VARS}" ] && [ "${QEMU_DRY_RUN}" != 1 ]; then
    cp "${QEMU_OVMF_VARS_TEMPLATE_RESOLVED}" "${QEMU_OVMF_VARS}"
  fi
  qemu_args+=(
    -drive "if=pflash,format=raw,readonly=on,file=${QEMU_OVMF_CODE_RESOLVED}"
    -drive "if=pflash,format=raw,file=${QEMU_OVMF_VARS}"
  )
fi

if [ "${QEMU_DEBUG}" != 0 ]; then
  qemu_log="${test_dir}/qemu.log"
  qemu_args+=(-d guest_errors -D "${qemu_log}" -serial mon:stdio -monitor none)
  echo "Debug logging enabled: ${qemu_log}"
fi
if [ "${QEMU_NO_REBOOT}" != 0 ]; then
  qemu_args+=(-no-reboot)
fi

if [ "${QEMU_DRY_RUN}" = 1 ]; then
  printf '%q ' "${QEMU_BINARY}" "${qemu_args[@]}"
  printf '\n'
  exit 0
fi
exec "${QEMU_BINARY}" "${qemu_args[@]}"
