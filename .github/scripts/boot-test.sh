#!/usr/bin/env bash
# openQA-style boot smoke test: boots an artifact headless under QEMU
# (KVM when available), takes periodic screendumps over QMP, and asserts
# the final screen is a real graphical frame — a blank/black console
# fails, a rendered GDM/Sirius/Initial Setup screen passes. Screenshots
# and the serial log are kept as evidence for human review.
#
# Usage: boot-test.sh iso|disk <image-path> [outdir]
set -euxo pipefail

mode="$1"
image="$2"
outdir="${3:-boot-test-out}"
mkdir -p "${outdir}"

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "${project_dir}/tools/qemu-common.sh"

# The final screendump must contain at least this many distinct sampled
# colors. A black screen has 1; a text console under 32; any rendered
# GNOME surface (gradients, antialiased text) has hundreds.
min_colors=64
case "${mode}" in
  iso) boot_wait=420 ;;
  disk) boot_wait=300 ;;
  *)
    echo "Unknown mode: ${mode} (expected iso or disk)" >&2
    exit 1
    ;;
esac

qemu_resolve_ovmf
cp "${QEMU_OVMF_VARS_TEMPLATE_RESOLVED}" "${outdir}/vars.fd"

qmp_sock="${outdir}/qmp.sock"

args=(
  -machine q35 -m 6G -smp 2
  -display none -vga virtio
  -serial "file:${outdir}/serial.log"
  -qmp "unix:${qmp_sock},server,nowait"
  -drive "if=pflash,format=raw,readonly=on,file=${QEMU_OVMF_CODE_RESOLVED}"
  -drive "if=pflash,format=raw,file=${outdir}/vars.fd"
)
if [ -w /dev/kvm ]; then
  args+=(-enable-kvm -cpu host)
else
  echo "WARNING: /dev/kvm unavailable, falling back to TCG (slow)" >&2
  args+=(-cpu max)
fi
case "${mode}" in
  iso) args+=(-cdrom "${image}" -boot d) ;;
  disk) args+=(-snapshot -drive "file=${image},format=qcow2,if=virtio") ;;
esac

qemu-system-x86_64 "${args[@]}" &
qemu_pid=$!
trap 'kill "${qemu_pid}" 2>/dev/null || true' EXIT

qmp() {
  printf '%s\n' '{"execute":"qmp_capabilities"}' "$1" |
    socat -T 10 - "UNIX-CONNECT:${qmp_sock}" >/dev/null
}

count_colors() {
  python3 - "$1" <<'PY'
import sys
p = open(sys.argv[1], "rb")
assert p.readline().strip() == b"P6", "not a P6 PPM"
tokens = []
while len(tokens) < 3:
    line = p.readline()
    if line.startswith(b"#"):
        continue
    tokens += line.split()
w, h, _ = map(int, tokens)
data = p.read(w * h * 3)
colors = set()
for i in range(0, len(data) - 2, 12):  # sample every 4th pixel
    colors.add(data[i:i + 3])
print(len(colors))
PY
}

elapsed=0
interval=30
shot=""
while [ "${elapsed}" -lt "${boot_wait}" ]; do
  sleep "${interval}"
  elapsed=$((elapsed + interval))
  kill -0 "${qemu_pid}" 2>/dev/null || {
    echo "QEMU exited early" >&2
    exit 1
  }
  shot="${outdir}/screen-$(printf '%03d' "${elapsed}").ppm"
  qmp '{"execute":"screendump","arguments":{"filename":"'"$(pwd)/${shot}"'"}}' || true
done

[ -n "${shot}" ] && [ -f "${shot}" ]
colors="$(count_colors "${shot}")"
echo "Final screendump has ${colors} distinct sampled colors (minimum ${min_colors})"

# Advisory OCR: log what is on screen; never fails the test on its own.
if command -v tesseract >/dev/null 2>&1; then
  tesseract "${shot}" "${outdir}/final-screen" 2>/dev/null || true
  if [ -f "${outdir}/final-screen.txt" ]; then
    echo "--- OCR of final screen ---"
    cat "${outdir}/final-screen.txt"
    grep -iEq 'sirius|luminus|install|setup|welcome' "${outdir}/final-screen.txt" &&
      echo "OCR: recognized expected installer/setup wording" ||
      echo "OCR: expected wording not found (advisory only)"
  fi
fi

[ "${colors}" -ge "${min_colors}" ]
