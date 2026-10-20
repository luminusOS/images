#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${T03_ARTIFACT_DIR:-${repo_root}/t03-arm64-proof}"
artifact_dir="$(realpath -m "$artifact_dir")"
image_path="${artifact_dir}/fedora45-arm64.qcow2"
serial_log="${artifact_dir}/serial.log"
qemu_args=()
owned_context=''

cleanup_context() {
  [[ -n "$owned_context" ]] || return 0
  rm -f -- "${owned_context}/proof.env" "${owned_context}/Containerfile" \
    "${owned_context}/proof.service" "${owned_context}/proof.sh" \
    "${owned_context}/diagnostics.service" "${owned_context}/diagnostics.sh" \
    "${owned_context}/90-t03-console.conf" "${owned_context}/hwdb-prepare.sh" \
    "${owned_context}/00-t03-vda3-debug.rules" "${owned_context}/disk.yaml"
  rmdir "$owned_context" 2>/dev/null || true
}

fail() {
  printf 'T03 error: %s\n' "$*" >&2
  exit 1
}

resolve_inputs() {
  local output="$1" workdir repo kind ref
  [[ ! -e "$output" && ! -L "$output" ]] || fail "refusing to overwrite existing resolved-input evidence: ${output}"
  command -v skopeo >/dev/null || fail 'skopeo is required to resolve Fedora 45 inputs'
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/t03-resolve.XXXXXX")"
  for kind in bootc builder; do
    repo="quay.io/fedora/fedora"
    [[ "$kind" == bootc ]] && repo="quay.io/fedora/fedora-bootc"
    if ! skopeo inspect --raw --no-creds "docker://${repo}:45" \
      >"${workdir}/${kind}-manifest.json" 2>"${workdir}/${kind}-inspect.err"; then
      cat "${workdir}/${kind}-inspect.err" >&2
      rm -rf -- "$workdir"
      fail "skopeo could not resolve ${repo}:45"
    fi
  done
  if ! python3 - "$workdir" "$output" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import sys

workdir = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
repositories = {"bootc": "quay.io/fedora/fedora-bootc", "builder": "quay.io/fedora/fedora"}
pattern = re.compile(r"sha256:[a-f0-9]{64}")
inputs = {}
for name, repository in repositories.items():
    raw = (workdir / f"{name}-manifest.json").read_bytes()
    try:
        index = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid {name} Fedora 45 manifest JSON: {error}")
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list):
        raise SystemExit(f"{name} Fedora 45 tag did not resolve to a manifest index")
    matches = [item for item in manifests if isinstance(item, dict)
               and isinstance(item.get("platform"), dict)
               and item["platform"].get("os") == "linux"
               and item["platform"].get("architecture") == "arm64"]
    if len(matches) != 1:
        raise SystemExit(f"{name} Fedora 45 index must contain exactly one linux/arm64 manifest")
    digest = matches[0].get("digest")
    if not isinstance(digest, str) or not pattern.fullmatch(digest):
        raise SystemExit(f"{name} Fedora 45 linux/arm64 child has an invalid digest")
    inputs[name] = {"source": f"{repository}:45", "ref": f"{repository}@{digest}",
                    "raw_manifest_sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}
document = {"resolved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "platform": {"os": "linux", "architecture": "arm64"}, "inputs": inputs}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  then
    rm -f -- "$output"
    rm -rf -- "$workdir"
    fail 'Fedora 45 manifest resolution failed closed'
  fi

  for kind in bootc builder; do
    repo="quay.io/fedora/fedora"
    [[ "$kind" == bootc ]] && repo="quay.io/fedora/fedora-bootc"
    ref="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["inputs"][sys.argv[2]]["ref"])' "$output" "$kind")"
    if ! skopeo inspect --config --no-creds "docker://${ref}" \
      >"${workdir}/${kind}-config.json" 2>"${workdir}/${kind}-config.err"; then
      cat "${workdir}/${kind}-config.err" >&2
      rm -f -- "$output"
      rm -rf -- "$workdir"
      fail "skopeo could not inspect pinned ${kind} config"
    fi
    if ! python3 - "${workdir}/${kind}-config.json" "$output" "$kind" "$repo" "$ref" <<'PY'
import json
import pathlib
import re
import sys

config_path, output_path, name, repository, expected_ref = sys.argv[1:]
try:
    config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
    path = pathlib.Path(output_path)
    evidence = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid {name} pinned config JSON: {error}")
if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "arm64":
    raise SystemExit(f"{name} pinned config platform is not linux/arm64")
if not re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", expected_ref):
    raise SystemExit(f"{name} pinned ref has an invalid allowlisted digest")
if evidence["inputs"][name]["ref"] != expected_ref:
    raise SystemExit(f"{name} pinned ref does not match resolved evidence")
image_config = config.get("config", {})
labels = image_config.get("Labels", {}) if isinstance(image_config, dict) else {}
if not isinstance(labels, dict):
    labels = {}
evidence["inputs"][name]["config"] = {
    "os": config["os"], "architecture": config["architecture"],
    "version_label": labels.get("version") or labels.get("org.opencontainers.image.version")
}
path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    then
      rm -f -- "$output"
      rm -rf -- "$workdir"
      fail "pinned ${kind} config validation failed"
    fi
    printf 'Resolved Fedora 45 %s: %s\n' "$kind" "$ref"
  done
  rm -rf -- "$workdir"
}

validate_pinned_ref() {
  local name="$1" ref="$2" repository="$3"
  [[ "$ref" == "${repository}@"* && "${ref#*@}" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "${name} must be an immutable digest from ${repository}"
}

verify_proof() {
  local log="$1" nonce="$2" expected
  [[ -r "$log" ]] || fail "serial log is missing: ${log}"
  [[ "$nonce" =~ ^[a-zA-Z0-9-]{8,80}$ ]] || fail 'invalid run nonce'
  for expected in \
    "T03_BEGIN=${nonce}" \
    'T03_ARCH=aarch64' \
    'T03_FEDORA_VERSION=45' \
    'T03_UEFI=1' \
    "T03_PASS=${nonce}"; do
    grep -Fqx -- "$expected" <(tr -d '\r' <"$log") || fail "boot proof is incomplete: ${expected}"
  done
}

build_qemu_args() {
  local accelerator="$1" code="$2" vars="$3"
  local cpu=max
  [[ "$accelerator" == kvm ]] && cpu=host
  qemu_args=(qemu-system-aarch64 -machine virt -cpu "$cpu" -smp 4 -m 4096 -accel "$accelerator")
  qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=${code}")
  qemu_args+=(-drive "if=pflash,format=raw,file=${vars}")
  qemu_args+=(-drive "file=${image_path},if=virtio,format=qcow2,snapshot=on")
  qemu_args+=(-display none -serial "file:${serial_log}" -monitor none -no-reboot)
}

print_qemu() {
  local accelerator="${1:-tcg}"
  [[ "$accelerator" == kvm || "$accelerator" == tcg ]] || fail 'QEMU accelerator must be kvm or tcg'
  build_qemu_args "$accelerator" \
    "${QEMU_EFI_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}" \
    "${QEMU_EFI_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
  printf '%q ' "${qemu_args[@]}"
  printf '\n'
}

verify_image() {
  [[ -s "$image_path" ]] || fail "guest disk is missing or empty: ${image_path}"
  command -v qemu-img >/dev/null || fail 'qemu-img is required to inspect the guest disk'
  qemu-img info --output=json "$image_path" | python3 -c 'import json,sys; image=json.load(sys.stdin); sys.exit(0 if image["format"] == "qcow2" else 1)' || fail 'guest disk is not a valid qcow2 image'
}

record_image_metadata() {
  local disk_hash disk_file_bytes disk_allocated_bytes disk_virtual_bytes
  disk_hash="$(sha256sum "$image_path" | cut -d ' ' -f 1)"
  disk_file_bytes="$(stat -c %s "$image_path")"
  disk_allocated_bytes="$(du -B1 "$image_path" | cut -f 1)"
  disk_virtual_bytes="$(qemu-img info --output=json "$image_path" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"
  printf 'Guest disk SHA-256: %s\n' "$disk_hash" >>"${artifact_dir}/metadata.txt"
  printf 'Guest disk file size: %s bytes\n' "$disk_file_bytes" >>"${artifact_dir}/metadata.txt"
  printf 'Guest disk allocated size: %s bytes\n' "$disk_allocated_bytes" >>"${artifact_dir}/metadata.txt"
  printf 'Guest disk virtual size: %s bytes\n' "$disk_virtual_bytes" >>"${artifact_dir}/metadata.txt"
}

builder() {
  local nonce="$1" base_ref="$2" context image_ref architecture
  [[ "$nonce" =~ ^[a-zA-Z0-9-]{8,80}$ ]] || fail 'invalid run nonce'
  validate_pinned_ref bootc "$base_ref" 'quay.io/fedora/fedora-bootc'
  source /etc/os-release
  [[ "${VERSION_ID:-}" == 45 ]] || fail 'Fedora 45 builder container required before installing packages'
  mkdir -p "$artifact_dir"
  [[ ! -e "$image_path" && ! -L "$image_path" ]] || fail "refusing to overwrite an existing guest disk: ${image_path}"
  context="$(mktemp -d "${artifact_dir}/container-context.XXXXXX")"
  owned_context="$context"
  trap cleanup_context EXIT
  image_ref="localhost/t03-fedora45-arm64:${nonce}"

  dnf -y install image-builder podman qemu-img
  mkdir -p "${artifact_dir}/containers-storage" "${artifact_dir}/.osbuild-cache" "${artifact_dir}/build-tmp"
  export TMPDIR="${artifact_dir}/build-tmp"
  cat >"${artifact_dir}/storage.conf" <<EOF
[storage]
driver = "overlay"
graphroot = "/var/lib/containers/storage"
runroot = "/run/containers/storage"
EOF
  export CONTAINERS_STORAGE_CONF="${artifact_dir}/storage.conf"
  if ! podman pull --arch arm64 "$base_ref"; then
    fail 'pinned Fedora 45 ARM64 bootc image could not be pulled; no mutable fallback is allowed'
  fi
  architecture="$(podman image inspect --format '{{.Os}} {{.Architecture}}' "$base_ref")"
  [[ "$architecture" == 'linux arm64' ]] || fail "pinned Fedora bootc image is ${architecture}, expected linux arm64; refusing a mutable fallback"
  if ! podman run --rm "$base_ref" /usr/bin/bash -c 'source /etc/os-release; test "$VERSION_ID" = 45'; then
    fail 'pinned bootc image is not Fedora 45; refusing to continue'
  fi

  printf '%s\n' "T03_NONCE=${nonce}" >"${context}/proof.env"
  cat >"${context}/Containerfile" <<EOF
FROM ${base_ref}
COPY proof.env /etc/t03-arm64-proof.env
COPY proof.service /etc/systemd/system/t03-arm64-proof.service
COPY proof.sh /usr/local/libexec/t03-arm64-proof
COPY diagnostics.service /etc/systemd/system/t03-arm64-diagnostics.service
COPY diagnostics.sh /usr/local/libexec/t03-arm64-diagnostics
COPY 00-t03-vda3-debug.rules /etc/udev/rules.d/00-t03-vda3-debug.rules
COPY hwdb-prepare.sh /usr/local/libexec/t03-hwdb-prepare
COPY 90-t03-console.conf /usr/lib/systemd/journald.conf.d/90-t03-console.conf
COPY disk.yaml /usr/lib/image-builder/bootc/disk.yaml
RUN mkdir -p /usr/lib/systemd/journald.conf.d && \
    chmod 0755 /usr/local/libexec/t03-arm64-proof /usr/local/libexec/t03-arm64-diagnostics /usr/local/libexec/t03-hwdb-prepare && \
    /usr/local/libexec/t03-hwdb-prepare --root / && \
    systemctl enable t03-arm64-proof.service t03-arm64-diagnostics.service
EOF
  cat >"${context}/proof.service" <<'EOF'
[Unit]
Description=T03 ARM64 boot proof

[Service]
Type=oneshot
EnvironmentFile=/etc/t03-arm64-proof.env
ExecStart=/usr/local/libexec/t03-arm64-proof
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  cat >"${context}/diagnostics.service" <<'EOF'
[Unit]
Description=T03 ARM64 emergency diagnostics
DefaultDependencies=no
After=systemd-journald.service
Before=emergency.service

[Service]
Type=oneshot
TimeoutStartSec=60
ExecStart=/usr/local/libexec/t03-arm64-diagnostics

[Install]
WantedBy=emergency.target
EOF
  cat >"${context}/diagnostics.sh" <<'EOF'
#!/usr/bin/bash
set -uo pipefail
exec >/dev/ttyAMA0 2>&1
printf 'T03_DIAGNOSTICS_BEGIN\n'

run_readonly() {
  local label="$1" status
  shift
  printf '\n--- %s ---\n' "$label"
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'T03_DIAGNOSTIC_COMMAND_UNAVAILABLE=%s\n' "$1"
    return 0
  fi
  if "$@"; then
    return 0
  else
    status=$?
    printf 'T03_DIAGNOSTIC_COMMAND_FAILED=%s status=%s\n' "$label" "$status"
  fi
}

run_readonly 'vda3 udev coldplug trace' journalctl --no-pager --boot=0 \
  --output=short-monotonic --unit=systemd-udevd.service \
  --grep='vda3|253:3' --lines=+512
run_readonly 'vda3 device unit history' journalctl --no-pager --boot=0 \
  --output=short-monotonic --lines=+128 --unit=dev-vda3.device

capture_device_snapshot() {
  local device_path="$1" label="$2" device_major_minor
  run_readonly "${label} unit properties" systemctl show --no-pager \
    -p ActiveState -p SubState -p Result -p SysFSPath -p Found -p Names -p Following \
    -p Job -p JobTimeoutUSec -p JobRunningTimeoutUSec \
    -p StateChangeTimestampMonotonic -p ActiveEnterTimestampMonotonic \
    -p InactiveEnterTimestampMonotonic "$device_path"
  run_readonly "${label} udev database properties" udevadm info --query=all --name="$device_path"
  if device_major_minor="$(lsblk --raw --nodeps --noheadings --output MAJ:MIN -- "$device_path" 2>/dev/null)" \
    && [[ "$device_major_minor" =~ ^[0-9]+:[0-9]+$ ]]; then
    run_readonly "${label} udev database entry" cat -- "/run/udev/data/b${device_major_minor}"
  else
    printf 'T03_DIAGNOSTIC_DEVICE_MAJOR_MINOR_UNAVAILABLE=%s\n' "$device_path"
  fi
}

printf '\n--- boot device resolution ---\n'
capture_device_snapshot /dev/vda3 'kernel boot device'
if device_path="$(systemctl show boot.mount --property=What --value 2>/dev/null)" \
  && [[ "$device_path" == /dev/* && "$device_path" != *..* \
    && "$device_path" != *[!A-Za-z0-9_./-]* ]]; then
  if [[ "$device_path" != /dev/vda3 ]]; then
    capture_device_snapshot "$device_path" 'boot UUID alias'
  fi
else
  printf 'T03_DIAGNOSTIC_COMMAND_FAILED=boot device resolution\n'
fi

run_readonly 'failed units' systemctl --failed --no-pager
run_readonly 'filesystem, hwdb, and udev unit status' systemctl status --no-pager --lines=12 \
  boot.mount boot-efi.mount local-fs.target systemd-hwdb-update.service \
  systemd-udev-trigger.service systemd-udevd.service
run_readonly 'filesystem, hwdb, and udev unit results' systemctl show --no-pager \
  -p ActiveState -p SubState -p Result -p ExecMainStatus \
  boot.mount boot-efi.mount local-fs.target systemd-hwdb-update.service \
  systemd-udev-trigger.service systemd-udevd.service
run_readonly 'block devices and filesystems' lsblk --fs
run_readonly 'filesystem identifiers' blkid -c /dev/null
run_readonly 'UUID device links' ls -l /dev/disk/by-uuid
run_readonly 'local hwdb rule directory' ls -la /etc/udev/hwdb.d
for path in /etc/.updated /usr/lib/udev/hwdb.bin /etc/udev/hwdb.bin; do
  if [[ -e "$path" || -L "$path" ]]; then
    run_readonly "hwdb path timestamp ${path}" stat -c '%n size=%s mtime=%y' -- "$path"
    if [[ -f "$path" ]]; then
      run_readonly "hwdb path SHA-256 ${path}" sha256sum -- "$path"
    fi
  else
    printf 'T03_DIAGNOSTIC_PATH_MISSING=%s\n' "$path"
  fi
done
run_readonly 'hwdb and udev unit journal' journalctl --no-pager --boot=0 --lines=40 \
  --unit=systemd-hwdb-update.service --unit=systemd-udev-trigger.service \
  --unit=systemd-udevd.service
run_readonly 'boot warnings' journalctl --no-pager --boot=0 --priority=warning --lines=80
printf 'T03_DIAGNOSTICS_END\n'
EOF
  cat >"${context}/hwdb-prepare.sh" <<'EOF'
#!/usr/bin/bash
set -euo pipefail

fail() {
  printf 'T03_HWDB_ERROR=%s\n' "$*" >&2
  exit 1
}

[[ $# -eq 2 && "$1" == --root ]] || fail 'usage: t03-hwdb-prepare --root IMAGE_ROOT'
root="$(realpath -e -- "$2")" || fail 'image root does not exist'
[[ -d "$root" ]] || fail 'image root is not a directory'
unit_file="${root}/usr/lib/systemd/system/systemd-hwdb-update.service"
local_rules="${root}/etc/udev/hwdb.d"
usr_database="${root}/usr/lib/udev/hwdb.bin"
etc_database="${root}/etc/udev/hwdb.bin"

report_path() {
  local label="$1" path="$2" mtime hash size
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf 'T03_HWDB_%s=missing\n' "$label"
    return 0
  fi
  mtime="$(stat -c '%y' -- "$path" 2>/dev/null || printf unavailable)"
  size="$(stat -c '%s' -- "$path" 2>/dev/null || printf unavailable)"
  hash=unavailable
  if [[ -f "$path" ]]; then
    hash="$(sha256sum -- "$path" 2>/dev/null | cut -d ' ' -f 1 || printf unavailable)"
  fi
  printf 'T03_HWDB_%s=present size=%s mtime=%s sha256=%s\n' "$label" "$size" "$mtime" "$hash"
}

report_state() {
  local phase
  phase="$1"
  printf 'T03_HWDB_PHASE=%s\n' "$phase"
  [[ -r "$unit_file" ]] || fail "missing hwdb update unit: ${unit_file}"
  grep -E '^(ConditionNeedsUpdate|ConditionPathExists|ConditionDirectoryNotEmpty)=' "$unit_file" \
    || fail 'hwdb update unit has no recorded path conditions'
  report_path ETC_UPDATED_STAMP "${root}/etc/.updated"
  report_path USR_DIRECTORY "${root}/usr"
  report_path USR_DATABASE "$usr_database"
  report_path ETC_DATABASE "$etc_database"
  if [[ -d "$local_rules" ]]; then
    shopt -s nullglob dotglob
    local entries=("${local_rules}"/*)
    shopt -u nullglob dotglob
    printf 'T03_HWDB_ETC_RULE_ENTRY_COUNT=%s\n' "${#entries[@]}"
    printf 'T03_HWDB_ETC_RULE_ENTRY=%s\n' "${entries[@]:-}"
  else
    printf 'T03_HWDB_ETC_RULE_ENTRY_COUNT=0\n'
  fi
}

require_no_local_rules() {
  local entries=()
  if [[ -L "$local_rules" || ( -e "$local_rules" && ! -d "$local_rules" ) ]]; then
    fail "local hwdb rules path is not a directory: ${local_rules}"
  fi
  if [[ -d "$local_rules" ]]; then
    shopt -s nullglob dotglob
    entries=("${local_rules}"/*)
    shopt -u nullglob dotglob
  fi
  ((${#entries[@]} == 0)) || fail "local hwdb rules directory is populated; preserving: ${entries[*]}"
}

report_state before
require_no_local_rules
if systemd-hwdb --root "$root" --usr --strict update; then
  :
else
  status=$?
  report_state after
  fail "systemd-hwdb --strict update failed with status ${status}"
fi
report_state after
[[ -s "$usr_database" ]] || fail 'systemd-hwdb produced no non-empty /usr/lib/udev/hwdb.bin'
require_no_local_rules
if [[ -e "$etc_database" || -L "$etc_database" ]]; then
  [[ -f "$etc_database" || -L "$etc_database" ]] || fail 'refusing to remove a non-file /etc/udev/hwdb.bin path'
  rm -f -- "$etc_database"
fi
report_state final
EOF
  cat >"${context}/90-t03-console.conf" <<'EOF'
[Journal]
ForwardToConsole=yes
TTYPath=/dev/ttyAMA0
MaxLevelConsole=info
EOF
  cat >"${context}/00-t03-vda3-debug.rules" <<'EOF'
SUBSYSTEM=="block", KERNEL=="vda3", OPTIONS="log_level=debug"
EOF
  cat >"${context}/disk.yaml" <<'EOF'
mount_configuration: units
partition_table:
  type: gpt
  partitions:
    - size: 1 MiB
      type: 21686148-6449-6e6F-744e-656564454649
      bootable: true
    - size: 200 MiB
      type: c12a7328-f81f-11d2-ba4b-00a0c93ec93b
      payload_type: filesystem
      payload:
        type: vfat
        mountpoint: /boot/efi
        label: ESP
        fstab_options: defaults,uid=0,gid=0,umask=077,shortname=winnt
        fstab_freq: 0
        fstab_passno: 2
    - size: 2 GiB
      type: bc13c2ff-59e6-4262-a352-b275fd6f7172
      payload_type: filesystem
      payload:
        type: ext4
        label: boot
        mountpoint: /boot
        fstab_options: defaults
        fstab_freq: 0
        fstab_passno: 2
    - size: 4 GiB
      type: 0fc63daf-8483-4772-8e79-3d69d8477de4
      payload_type: filesystem
      payload:
        type: ext4
        label: root
        mountpoint: /
        fstab_options: defaults
        fstab_freq: 0
        fstab_passno: 0
EOF
  cat >"${context}/proof.sh" <<'EOF'
#!/usr/bin/bash
set -euo pipefail
source /etc/os-release
printf 'T03_BEGIN=%s\n' "$T03_NONCE" >/dev/ttyAMA0
test "$(uname -m)" = aarch64
printf 'T03_ARCH=aarch64\n' >/dev/ttyAMA0
test "${VERSION_ID}" = 45
printf 'T03_FEDORA_VERSION=%s\n' "$VERSION_ID" >/dev/ttyAMA0
test -d /sys/firmware/efi
printf 'T03_UEFI=1\n' >/dev/ttyAMA0
printf 'T03_PASS=%s\n' "$T03_NONCE" >/dev/ttyAMA0
EOF

  podman build --pull=never --tag "$image_ref" "$context"
  export IMAGE_BUILDER_CACHE="${artifact_dir}/.osbuild-cache"
  (
    cd "$artifact_dir"
    "${repo_root}/tools/package-artifact.sh" qcow2 "$image_ref" "$(basename "$image_path")"
  )
  verify_image
  cleanup_context
  owned_context=''
  trap - EXIT
  printf 'Image builder: %s\n' "$(rpm -q image-builder)" >>"${artifact_dir}/metadata.txt"
  printf 'Guest image: %s\n' "$image_path" >>"${artifact_dir}/metadata.txt"
}

boot_once() {
  local accelerator="$1" qemu_pid
  build_qemu_args "$accelerator" "$local_code" "$uefi_vars"
  : >"$serial_log"
  timeout --foreground 900 "${qemu_args[@]}" \
    >>"${artifact_dir}/qemu.stdout" 2>>"${artifact_dir}/qemu.stderr" &
  qemu_pid=$!
  for _ in $(seq 1 900); do
    if grep -Fqx "T03_PASS=${nonce}" <(tr -d '\r' <"$serial_log") 2>/dev/null; then
      kill "$qemu_pid" 2>/dev/null || true
      wait "$qemu_pid" 2>/dev/null || true
      verify_proof "$serial_log" "$nonce"
      return 0
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      wait "$qemu_pid" 2>/dev/null || true
      return 1
    fi
    sleep 1
  done
  kill "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
  return 1
}

case "${1:-run}" in
  --print-qemu)
    [[ $# -le 2 ]] || fail 'usage: --print-qemu [kvm|tcg]'
    print_qemu "${2:-tcg}"
    ;;
  --verify-proof)
    [[ $# -eq 3 ]] || fail 'usage: --verify-proof SERIAL_LOG NONCE'
    verify_proof "$2" "$3"
    ;;
  --build)
    [[ $# -eq 3 ]] || fail 'usage: --build NONCE BOOTC_REF'
    builder "$2" "$3"
    ;;
  --resolve-inputs)
    [[ $# -eq 2 ]] || fail 'usage: --resolve-inputs OUTPUT_JSON'
    resolve_inputs "$2"
    ;;
  --verify-image)
    verify_image
    ;;
  run)
    [[ -z "${T03_ARTIFACT_DIR:-}" ]] || fail 'T03_ARTIFACT_DIR is only supported by offline builder checks'
    [[ "$(uname -m)" == aarch64 ]] || fail "native ARM64 runner required; got $(uname -m)"
    mkdir -p "$artifact_dir"
    [[ ! -e "$image_path" && ! -L "$image_path" ]] || fail "refusing to overwrite an existing guest disk: ${image_path}"
    command -v skopeo >/dev/null || fail 'skopeo is required to resolve Fedora 45 digests'
    resolve_inputs "${artifact_dir}/resolved-inputs.json"
    base_ref="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["inputs"]["bootc"]["ref"])' "${artifact_dir}/resolved-inputs.json")"
    runner_image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["inputs"]["builder"]["ref"])' "${artifact_dir}/resolved-inputs.json")"
    command -v podman >/dev/null || fail 'podman is required'
    command -v qemu-system-aarch64 >/dev/null || fail 'qemu-system-aarch64 is required'
    command -v qemu-img >/dev/null || fail 'qemu-img is required'
    local_code="${QEMU_EFI_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}"
    local_vars="${QEMU_EFI_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
    [[ -r "$local_code" && -r "$local_vars" ]] || fail 'AArch64 UEFI firmware files are missing'
    owned_image=1
    uefi_vars=""
    cleanup_run() {
      if [[ "${owned_image:-0}" == 1 ]]; then rm -f -- "$image_path"; fi
      if [[ -n "${uefi_vars:-}" ]]; then rm -f -- "$uefi_vars"; fi
    }
    trap cleanup_run EXIT
    uefi_vars="$(mktemp "${artifact_dir}/uefi-vars.XXXXXX.fd")"
    : >"${artifact_dir}/metadata.txt"
    printf 'Fedora 45 ARM64 bootc: %s\n' "$base_ref" >>"${artifact_dir}/metadata.txt"
    printf 'Fedora 45 builder: %s\n' "$runner_image" >>"${artifact_dir}/metadata.txt"
    printf 'Build started: %s\n' "$(date -u +%FT%TZ)" >>"${artifact_dir}/metadata.txt"
    : >"${artifact_dir}/build.log"
    nonce="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    runner_dir="$repo_root"
    build_start="$(date +%s)"
    accelerator=tcg
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then accelerator=kvm; fi
    printf 'Runner architecture: %s\n' "$(uname -m)" >"${artifact_dir}/runner-metadata.txt"
    printf 'Runner CPUs: %s\n' "$(nproc)" >>"${artifact_dir}/runner-metadata.txt"
    printf 'Runner memory: %s kB\n' "$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)" >>"${artifact_dir}/runner-metadata.txt"
    printf 'QEMU: %s\n' "$(qemu-system-aarch64 --version | head -n 1)" >>"${artifact_dir}/runner-metadata.txt"
    printf 'Accelerator: %s\n' "$accelerator" >>"${artifact_dir}/runner-metadata.txt"
    printf 'Firmware code: %s\n' "$local_code" >>"${artifact_dir}/runner-metadata.txt"
    df -h "$artifact_dir" >"${artifact_dir}/disk-space.txt"
    mkdir -p "${artifact_dir}/containers-storage"
    runner=(podman)
    if [[ "$EUID" -ne 0 ]]; then runner=(sudo podman); fi
    if ! "${runner[@]}" run --rm --privileged --security-opt label=type:unconfined_t \
      -v "${runner_dir}:/work" -w /work -e T03_NONCE="$nonce" \
      -v "${artifact_dir}/containers-storage:/var/lib/containers/storage" \
      "$runner_image" bash .github/scripts/t03-arm64-proof.sh --build "$nonce" "$base_ref" \
      2>&1 | LC_ALL=C awk -v log_path="${artifact_dir}/build.log" '
        {
          print
          line = $0 "\n"
          remaining = 1048576 - total
          if (remaining > 0) {
            if (length(line) > remaining) line = substr(line, 1, remaining)
            printf "%s", line >> log_path
            total += length(line)
          }
        }
        END {
          if (total >= 1048576) print "[build log truncated at 1 MiB]" >> log_path
        }
      '; then
      fail "image build failed; see ${artifact_dir}/build.log"
    fi
    printf 'Build duration: %s seconds\n' "$(( $(date +%s) - build_start ))" >>"${artifact_dir}/metadata.txt"
    verify_image
    record_image_metadata

    cp "$local_vars" "$uefi_vars"
    start_time="$(date +%s)"
    : >"${artifact_dir}/qemu.stdout"
    : >"${artifact_dir}/qemu.stderr"
    if [[ "$accelerator" == kvm ]]; then
      if ! boot_once kvm; then
        printf 'KVM did not complete the guest proof; retrying with bounded TCG.\n' \
          | tee -a "${artifact_dir}/qemu.stderr"
        printf 'KVM boot failed; TCG fallback used\n' >>"${artifact_dir}/runner-metadata.txt"
        accelerator=tcg
        boot_once tcg || fail 'guest boot proof failed with both KVM and TCG'
      fi
    else
      boot_once tcg || fail 'guest boot proof failed with bounded TCG'
    fi
    printf 'Successful accelerator: %s\n' "$accelerator" >>"${artifact_dir}/runner-metadata.txt"
    printf 'Boot duration: %s seconds\n' "$(( $(date +%s) - start_time ))" >>"${artifact_dir}/runner-metadata.txt"
    ;;
  *)
    fail 'usage: t03-arm64-proof.sh [--print-qemu [kvm|tcg]|--verify-proof LOG NONCE|--resolve-inputs OUTPUT_JSON|--build NONCE BOOTC_REF|--verify-image]'
    ;;
esac
