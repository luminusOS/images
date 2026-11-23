#!/usr/bin/env bash
# openQA-style boot smoke test: boots an artifact headless under QEMU
# (KVM when available), takes periodic screendumps over QMP, and checks
# the final screen for a graphical frame and expected text. Screenshots
# and the serial log are kept as evidence for human review.
#
# Usage: boot-test.sh iso|disk <image-path> [outdir]
set -euxo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/boot-feature-config.sh"

feature_ssh() {
  timeout "${BOOT_TEST_SSH_TIMEOUT:-15}" "${BOOT_TEST_SSH:-ssh}" -i "${BOOT_TEST_SSH_KEY}" -p "${BOOT_TEST_SSH_PORT:-2222}" \
    -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null root@127.0.0.1 "$@"
}

feature_check_digest() {
  local expected="$1" actual
  actual="$(feature_ssh sudo bootc status --json | jq -er '.status.booted.image.imageDigest')" || return 1
  if [ "${actual}" != "${expected}" ]; then
    printf 'Unexpected booted digest: expected %s, got %s\n' "${expected}" "${actual}" >&2
    return 1
  fi
}

feature_test() {
  local before after attempt expected="${BOOT_TEST_EXPECTED_DIGEST:-}"
  validate_boot_feature
  [[ "${expected}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "Feature boot tests require BOOT_TEST_EXPECTED_DIGEST" >&2
    return 1
  }
  feature_check_digest "${expected}"
  before="$(feature_ssh cat /proc/sys/kernel/random/boot_id)"
  feature_ssh sudo bash -s -- "${expected}" "${BOOT_TEST_FEATURE}" "${BOOT_TEST_CHANNEL:-testing}" <<'GUEST'
set -euo pipefail
. /usr/lib/os-release
features="$(luminus-features list)"
if [ "$3" = stable ] && grep -Eq '^dummy[[:space:]]' <<<"${features}"; then
    echo "Stable candidate still lists dummy" >&2
    exit 1
fi
if ! grep -Eq "^$2[[:space:]]+disabled([[:space:]]|$)" <<<"${features}"; then
    echo "Expected $2 to be disabled before sync" >&2
    exit 1
fi
build="/var/lib/luminusos/sysext/builds/${IMAGE_VERSION:?}/$1"
if [ -e "${build}" ] || [ -L "${build}" ]; then
    echo "Expected no committed build before sync: ${build}" >&2
    exit 1
fi
GUEST
  echo "Confirmed ${BOOT_TEST_FEATURE} is disabled and the candidate has no prior build"
  feature_ssh sudo luminus-features enable "${BOOT_TEST_FEATURE}"
  BOOT_TEST_SSH_TIMEOUT="${BOOT_TEST_SYNC_TIMEOUT:-1200}" feature_ssh sudo systemctl start luminusos-sysext-sync.service
  feature_ssh sudo bash -s -- "${BOOT_TEST_FEATURE}" <<'GUEST'
set -euo pipefail
set -a
. /usr/lib/os-release
set +a
python3 - "$1" <<'PY'
import hashlib, json, os, subprocess, sys
feature = sys.argv[1]
version = os.environ["IMAGE_VERSION"]
status = json.loads(subprocess.check_output(["bootc", "status", "--json"]))
image = status["status"]["booted"]["image"]
if image["version"] != version:
    raise SystemExit("booted image version does not match IMAGE_VERSION")
digest = image["imageDigest"]
base = f"/var/lib/luminusos/sysext/builds/{version}/{digest}"
with open(f"{base}/release.json") as f:
    desc = json.load(f)
if desc["version"] != version or desc["image_digest"] != digest:
    raise SystemExit("committed descriptor identifies a different image")
with open(f"{base}/luminusos-{feature}_{version}.raw", "rb") as f:
    got = hashlib.file_digest(f, "sha256").hexdigest()
if got != desc["features"][feature]["raw_sha256"]:
    raise SystemExit(f"{feature} payload hash mismatch")
print(f"Verified {feature} raw SHA-256: {got}")
PY
GUEST
  feature_ssh sudo systemctl reboot || true
  for ((attempt = 0; attempt < ${BOOT_TEST_REBOOT_ATTEMPTS:-120}; attempt++)); do
    after="$(feature_ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    if [ -n "${after}" ] && [ "${after}" != "${before}" ]; then
      break
    fi
    sleep "${BOOT_TEST_REBOOT_DELAY:-5}"
  done
  [ -n "${after:-}" ] && [ "${after}" != "${before}" ] || {
    echo "Guest did not reboot" >&2
    return 1
  }
  feature_check_digest "${expected}"
  feature_ssh sudo bash -s -- "${BOOT_TEST_FEATURE}" "${BOOT_TEST_FEATURE_UNIT}" <<'GUEST'
set -euo pipefail
. /usr/lib/os-release
luminus-features list | grep -E "^$1[[:space:]]+merged([[:space:]]|$)" >/dev/null
systemd-sysext status --no-pager | grep -F "luminusos-$1_${IMAGE_VERSION:?}" >/dev/null
systemctl is-active --quiet "$2"
enforcement="$(getenforce)"
if [ "${enforcement}" != Enforcing ]; then
    echo "Expected SELinux Enforcing, got ${enforcement}" >&2
    exit 1
fi
printf '%s merged; %s active; SELinux: %s\n' "$1" "$2" "${enforcement}"
GUEST
}

if [ "${1:-}" = --feature-test ]; then
  feature_test
  exit
fi

mode="$1"
image="$2"
outdir="${3:-boot-test-out}"
mkdir -p "${outdir}"
feature_dir="" qemu_pid=""
cleanup() {
  if [ -n "${qemu_pid}" ]; then
    kill "${qemu_pid}" 2>/dev/null || true
    wait "${qemu_pid}" 2>/dev/null || true
  fi
  [ -z "${feature_dir}" ] || rm -rf "${feature_dir}"
}
trap cleanup EXIT

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck disable=SC1091
source "${project_dir}/tools/qemu-common.sh"

if [ -n "${BOOT_TEST_FEATURE:-}${BOOT_TEST_FEATURE_UNIT:-}" ]; then
  validate_boot_feature
fi
if [ -n "${BOOT_TEST_FEATURE:-}${BOOT_TEST_EXPECTED_DIGEST:-}" ]; then
  [ "${mode}" = disk ] && [[ "${BOOT_TEST_EXPECTED_DIGEST:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "Digest-bound boot requires disk mode and a manifest digest" >&2
    exit 1
  }
  feature_dir="$(mktemp -d "${outdir}/feature.XXXXXX")"
  export BOOT_TEST_SSH_KEY="${feature_dir}/ssh"
  ssh-keygen -q -t ed25519 -N '' -f "${BOOT_TEST_SSH_KEY}"
  qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "${image}")" "${feature_dir}/disk.qcow2"
  python3 "${project_dir}/.github/scripts/prepare-boot-overlay.py" \
    "${feature_dir}/disk.qcow2" "${BOOT_TEST_SSH_KEY}.pub"
  image="${feature_dir}/disk.qcow2"
fi

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
if [ -n "${feature_dir}" ]; then
  args+=(-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${BOOT_TEST_SSH_PORT:-2222}-:22")
fi
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

[ "${colors}" -ge "${min_colors}" ]
tesseract "${shot}" "${outdir}/final-screen" 2>/dev/null
cat "${outdir}/final-screen.txt"
bash "${project_dir}/.github/scripts/check-boot-screen.sh" "${mode}" "${outdir}/final-screen.txt"
if [ -n "${BOOT_TEST_FEATURE:-}" ]; then
  feature_test
elif [ -n "${BOOT_TEST_EXPECTED_DIGEST:-}" ]; then
  feature_check_digest "${BOOT_TEST_EXPECTED_DIGEST}"
fi
