#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${T03_ARTIFACT_DIR:-${repo_root}/t03-arm64-proof}"
artifact_dir="$(realpath -m "$artifact_dir")"
image_path="${artifact_dir}/fedora45-arm64.qcow2"
serial_log="${artifact_dir}/serial.log"
base_ref='quay.io/fedora/fedora-bootc@sha256:3c7cf18e9b1eb23d65cdaec7c5d15e8b4d12849ec20f61dba02ac3e3293f66d1'
runner_image='quay.io/fedora/fedora@sha256:54fe92a655ebbcec468dc6fa953c0d1d2b474630a72f953702766c8389dd1a15'
qemu_args=()
owned_context=''

cleanup_context() {
  [[ -n "$owned_context" ]] || return 0
  rm -f -- "${owned_context}/proof.env" "${owned_context}/Containerfile" \
    "${owned_context}/proof.service" "${owned_context}/proof.sh" \
    "${owned_context}/disk.yaml"
  rmdir "$owned_context" 2>/dev/null || true
}

fail() {
  printf 'T03 error: %s\n' "$*" >&2
  exit 1
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
  qemu_args=(qemu-system-aarch64 -machine virt -cpu "$cpu" -smp 2 -m 4096 -accel "$accelerator")
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

builder() {
  local nonce="$1" context image_ref architecture
  [[ "$nonce" =~ ^[a-zA-Z0-9-]{8,80}$ ]] || fail 'invalid run nonce'
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
COPY disk.yaml /usr/lib/image-builder/bootc/disk.yaml
RUN chmod 0755 /usr/local/libexec/t03-arm64-proof && systemctl enable t03-arm64-proof.service
EOF
  cat >"${context}/proof.service" <<'EOF'
[Unit]
Description=T03 ARM64 boot proof

[Service]
Type=oneshot
EnvironmentFile=/etc/t03-arm64-proof.env
ExecStart=/usr/local/libexec/t03-arm64-proof
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
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
    [[ $# -eq 2 ]] || fail 'usage: --build NONCE'
    builder "$2"
    ;;
  --verify-image)
    verify_image
    ;;
  run)
    [[ -z "${T03_ARTIFACT_DIR:-}" ]] || fail 'T03_ARTIFACT_DIR is only supported by offline builder checks'
    [[ "$(uname -m)" == aarch64 ]] || fail "native ARM64 runner required; got $(uname -m)"
    command -v podman >/dev/null || fail 'podman is required'
    command -v qemu-system-aarch64 >/dev/null || fail 'qemu-system-aarch64 is required'
    command -v qemu-img >/dev/null || fail 'qemu-img is required'
    local_code="${QEMU_EFI_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}"
    local_vars="${QEMU_EFI_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
    [[ -r "$local_code" && -r "$local_vars" ]] || fail 'AArch64 UEFI firmware files are missing'
    mkdir -p "$artifact_dir"
    [[ ! -e "$image_path" && ! -L "$image_path" ]] || fail "refusing to overwrite an existing guest disk: ${image_path}"
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
      "$runner_image" bash .github/scripts/t03-arm64-proof.sh --build "$nonce" \
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
    disk_hash="$(sha256sum "$image_path" | cut -d ' ' -f 1)"
    disk_file_bytes="$(stat -c %s "$image_path")"
    disk_allocated_bytes="$(du -B1 "$image_path" | cut -f 1)"
    disk_virtual_bytes="$(qemu-img info --output=json "$image_path" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"
    printf 'Guest disk SHA-256: %s\n' "$disk_hash" >>"${artifact_dir}/metadata.txt"
    printf 'Guest disk file size: %s bytes\n' "$disk_file_bytes" >>"${artifact_dir}/metadata.txt"
    printf 'Guest disk allocated size: %s bytes\n' "$disk_allocated_bytes" >>"${artifact_dir}/metadata.txt"
    printf 'Guest disk virtual size: %s bytes\n' "$disk_virtual_bytes" >>"${artifact_dir}/metadata.txt"
    printf 'Boot duration: %s seconds\n' "$(( $(date +%s) - start_time ))" >>"${artifact_dir}/runner-metadata.txt"
    ;;
  *)
    fail 'usage: t03-arm64-proof.sh [--print-qemu [kvm|tcg]|--verify-proof LOG NONCE|--build NONCE|--verify-image]'
    ;;
esac
