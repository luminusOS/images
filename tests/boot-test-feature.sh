#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "${ROOT}/tests/test-lib.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/boot-feature.XXXXXX")"
trap 'rm -rf "${T}"' EXIT
export FAKE_DIR="${T}" BOOT_TEST_SSH="${T}/ssh" BOOT_TEST_SSH_KEY="${T}/key"
export BOOT_TEST_REBOOT_ATTEMPTS=2 BOOT_TEST_REBOOT_DELAY=0 BOOT_TEST_SYNC_TIMEOUT=2
export BOOT_TEST_EXPECTED_DIGEST="sha256:$(printf '%064d' 1)"
export BOOT_TEST_FEATURE=dummy BOOT_TEST_FEATURE_UNIT=luminusos-dummy-hello.service
mkdir "${T}/bin"
export PATH="${T}/bin:${PATH}"
export GUEST_STORE="${T}/store"
export GUEST_VERSION=45.20261121.103
export GUEST_BUILD="${GUEST_STORE}/builds/${GUEST_VERSION}/${BOOT_TEST_EXPECTED_DIGEST}"
printf 'IMAGE_VERSION=%s\n' "${GUEST_VERSION}" >"${T}/os-release"

cat >"${T}/bin/guest-command" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${0##*/}:$*" in
  "bootc:status --json")
    digest="${BOOT_TEST_EXPECTED_DIGEST}"
    if [[ "${FAKE_FAILURE:-}" == wrong-image ]] ||
      { [[ "${FAKE_FAILURE:-}" == wrong-reboot-image ]] && [ -e "${FAKE_DIR}/rebooted" ]; }; then
      digest="sha256:$(printf '%064d' 2)"
    fi
    printf '{"status":{"booted":{"image":{"imageDigest":"%s","version":"%s"}}}}\n' \
      "${digest}" "${GUEST_VERSION}"
    ;;
  "luminus-features:enable ${BOOT_TEST_FEATURE}")
    echo enable >>"${FAKE_DIR}/trace"
    touch "${FAKE_DIR}/selected"
    ;;
  "luminus-features:list")
    state=disabled
    if [ -e "${FAKE_DIR}/selected" ]; then
      state=pending
      if [ -e "${FAKE_DIR}/rebooted" ] && [[ "${FAKE_FAILURE:-}" != merged ]]; then
        state=merged
      fi
    fi
    printf '%s\t%s\tFixture\n' "${BOOT_TEST_FEATURE}" "${state}"
    if [[ "${FAKE_FAILURE:-}" == visible-dummy ]]; then
      printf 'dummy\tdisabled\tFixture\n'
    fi
    ;;
  "systemctl:start luminusos-sysext-sync.service")
    echo sync >>"${FAKE_DIR}/trace"
    [ "${FAKE_FAILURE:-}" != sync ] || exit 124
    mkdir -p "${GUEST_BUILD}"
    raw="${GUEST_BUILD}/luminusos-${BOOT_TEST_FEATURE}_${GUEST_VERSION}.raw"
    printf 'payload' >"${raw}"
    hash="$(printf 'payload' | sha256sum | cut -d' ' -f1)"
    printf '{"version":"%s","image_digest":"%s","features":{"%s":{"raw_sha256":"%s"}}}\n' \
      "${GUEST_VERSION}" "${BOOT_TEST_EXPECTED_DIGEST}" "${BOOT_TEST_FEATURE}" "${hash}" >"${GUEST_BUILD}/release.json"
    if [[ "${FAKE_FAILURE:-}" == hash ]]; then
      printf 'corrupt' >>"${raw}"
    fi
    ;;
  "systemctl:reboot") touch "${FAKE_DIR}/rebooted" ;;
  "systemctl:is-active --quiet ${BOOT_TEST_FEATURE_UNIT}") [[ "${FAKE_FAILURE:-}" != inactive ]] ;;
  "systemd-sysext:status --no-pager") printf 'luminusos-%s_%s\n' "${BOOT_TEST_FEATURE}" "${GUEST_VERSION}" ;;
  "getenforce:")
    if [[ "${FAKE_FAILURE:-}" == permissive ]]; then echo Permissive; else echo Enforcing; fi
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "${T}/bin/guest-command"
for cmd in bootc luminus-features systemctl systemd-sysext getenforce; do
  ln -s guest-command "${T}/bin/${cmd}"
done
printf '#!/bin/sh\ntouch "$FAKE_DIR/package-attempt"\nexit 71\n' >"${T}/bin/sudo"
chmod +x "${T}/bin/sudo"

cat >"${T}/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" != root@127.0.0.1 ]]; do shift; done
shift
case "$*" in
  "cat /proc/sys/kernel/random/boot_id")
    if [ -e "${FAKE_DIR}/rebooted" ]; then echo after; else echo before; fi
    ;;
  "sudo bash -s"*)
    shift
    sed -e "s|/usr/lib/os-release|${FAKE_DIR}/os-release|g" \
        -e "s|/var/lib/luminusos/sysext|${GUEST_STORE}|g" | "$@"
    ;;
  "sudo "*) shift; "$@" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "${T}/ssh"

run_feature() {
  rm -rf "${GUEST_STORE}"
  rm -f "${T}/rebooted" "${T}/trace" "${T}/selected"
  case "$1" in
    selected) touch "${T}/selected" ;;
    committed) mkdir -p "${GUEST_BUILD}" ;;
  esac
  FAKE_FAILURE="$1" bash "${ROOT}/.github/scripts/boot-test.sh" --feature-test >"${T}/output" 2>&1
}

happy() {
  run_feature "" || {
    cat "${T}/output"
    return 1
  }
  [ "$(tr '\n' ' ' <"${T}/trace")" = "enable sync " ] &&
    grep -Fq "Verified ${BOOT_TEST_FEATURE} raw SHA-256:" "${T}/output" &&
    grep -Fxq "${BOOT_TEST_FEATURE} merged; ${BOOT_TEST_FEATURE_UNIT} active; SELinux: Enforcing" "${T}/output"
}
expect "feature boot test enables syncs verifies reboots and checks merge" happy
BOOT_TEST_FEATURE=sample BOOT_TEST_FEATURE_UNIT=luminusos-sample-probe.service BOOT_TEST_CHANNEL=stable \
  expect "feature boot test exercises a different ID and marker on the stable path" happy
expect_failure "feature boot test rejects sync timeout" run_feature sync
expect_failure "feature boot test rejects payload hash mismatch" run_feature hash
expect_failure "feature boot test rejects missing merge after reboot" run_feature merged
expect_failure "feature boot test rejects an inactive marker after reboot" run_feature inactive
permissive_guest() {
  run_feature permissive && return 1
  [ -e "${T}/rebooted" ] && grep -Fq 'Expected SELinux Enforcing, got Permissive' "${T}/output"
}
expect "feature boot test rejects permissive SELinux after reboot" permissive_guest
dirty_candidate() {
  run_feature "$1" && return 1
  [ ! -e "${T}/trace" ]
}
expect "feature boot test refuses preselected dummy before enabling" dirty_candidate selected
expect "feature boot test refuses a preexisting build directory before enabling" dirty_candidate committed
stable_refuses_visible_dummy() {
  dirty_candidate visible-dummy && grep -Fq 'Stable candidate still lists dummy' "${T}/output"
}
BOOT_TEST_FEATURE=sample BOOT_TEST_FEATURE_UNIT=luminusos-sample-probe.service BOOT_TEST_CHANNEL=stable \
  expect "stable refuses an image that still lists dummy before enabling another feature" stable_refuses_visible_dummy
wrapper_refuses() {
  local feature="$1" unit="$2" channel="$3" message="$4" output
  rm -f "${T}/package-attempt"
  output="$(BOOT_TEST_FEATURE="${feature}" BOOT_TEST_FEATURE_UNIT="${unit}" BOOT_TEST_CHANNEL="${channel}" \
    bash "${ROOT}/.github/scripts/ci-boot-candidate.sh" \
    "candidate@${BOOT_TEST_EXPECTED_DIGEST}" "${BOOT_TEST_EXPECTED_DIGEST}" 2>&1)" && return 1
  [ ! -e "${T}/package-attempt" ] && grep -Fq "${message}" <<<"${output}"
}
expect "candidate wrapper cannot silently fall back to a digest-only check" \
  wrapper_refuses "" "" testing "Invalid BOOT_TEST_FEATURE"
expect "candidate wrapper rejects shell syntax in the feature ID before packaging" \
  wrapper_refuses 'dummy; false' luminusos-dummy-hello.service testing "Invalid BOOT_TEST_FEATURE"
expect "candidate wrapper rejects an unrelated marker before packaging" \
  wrapper_refuses dummy luminusos-sample-probe.service testing "Invalid BOOT_TEST_FEATURE_UNIT"
expect "candidate wrapper blocks the test fixture before stable packaging" \
  wrapper_refuses dummy luminusos-dummy-hello.service stable "Stable candidates cannot use dummy"
wrong_image() {
  run_feature wrong-image && return 1
  [ ! -e "${T}/trace" ]
}
expect "feature boot test refuses a different digest before enabling the feature" wrong_image
expect_failure "feature boot test refuses a different digest after reboot" run_feature wrong-reboot-image
expect "the candidate access helper receives only the disposable overlay and generated public key" \
  grep -Fq -- '"${feature_dir}/disk.qcow2" "${BOOT_TEST_SSH_KEY}.pub"' \
  "${ROOT}/.github/scripts/boot-test.sh"

overlay_layout() {
  PYTHONDONTWRITEBYTECODE=1 python3 - "${ROOT}" "${T}" <<'PY'
import importlib.util
from pathlib import Path
from unittest.mock import patch
import sys
import tarfile

spec = importlib.util.spec_from_file_location(
    "overlay", Path(sys.argv[1]) / ".github/scripts/prepare-boot-overlay.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
key = Path(sys.argv[2]) / "ssh.pub"
key.write_bytes(b"ephemeral key\n")
etc = "/ostree/deploy/default/deploy/" + "a" * 64 + ".0/etc"
zone = f"{etc}/firewalld/zones/public.xml"
replies = iter(["btrfsvol:/dev/sda4/root: btrfs\n", f"{etc}/\n", "<zone><forward/></zone>"])

def fish(image, commands, *, readonly):
    assert image == "disposable.qcow2"
    if readonly:
        return next(replies)
    _, archive, target, option = commands[1].split()
    assert (target, option) == (etc, "xattrs:true")
    with tarfile.open(archive) as tar:
        path = "ssh/boot-test-authorized-keys"
        assert tar.extractfile(path).read() == key.read_bytes()
        assert tar.getmember(path).mode == 0o600
    _, xml, target = commands[2].split()
    assert target == zone
    assert '<service name="ssh"' in Path(xml).read_text()

with patch.object(module, "require_backed_overlay", create=True), \
     patch.object(module, "guestfish", side_effect=fish):
    module.prepare("disposable.qcow2", key)

with patch.object(module, "require_backed_overlay", create=True), \
     patch.object(module, "guestfish", side_effect=[
    "btrfsvol:/dev/sda4/root: btrfs\n", f"{etc}/ {etc}/\n",
]) as guestfish:
    try:
        module.prepare("disposable.qcow2", key)
    except ValueError:
        assert all(call.kwargs["readonly"] for call in guestfish.call_args_list)
    else:
        raise AssertionError("ambiguous deployment was accepted")

with patch.object(module.subprocess, "check_output", return_value='{"format":"qcow2"}'), \
     patch.object(module, "guestfish", side_effect=AssertionError("opened unbacked image")):
    try:
        module.prepare("unbacked.qcow2", key)
    except ValueError:
        pass
    else:
        raise AssertionError("unbacked image was accepted")
PY
}
expect "overlay handles guestfish directory suffix and refuses ambiguous deployment before writing" overlay_layout

[ "${fails}" -eq 0 ] || exit 1
echo "all feature boot tests passed"
