#!/usr/bin/env bash

while IFS= read -r -d '' script; do
  expect "bash -n ${script#"${ROOT}/"}" bash -n "${script}"
done < <(find \
  "${ROOT}/shared/scripts" \
  "${ROOT}/tools" \
  "${ROOT}/tests" \
  "${ROOT}/.github/scripts" \
  "${ROOT}/editions/workstation" \
  -name '*.sh' -print0)

printf 'NAME="Fedora"\nVERSION_ID=44\n' >"${TEST_TMP}/os-release"
OS_RELEASE_FILE="${TEST_TMP}/os-release" \
  bash "${ROOT}/shared/scripts/os-release-set.sh" \
  NAME LuminusOS PRETTY_NAME "Luminus OS 44"
expect "os-release-set replaces existing keys" grep -qx 'NAME="LuminusOS"' "${TEST_TMP}/os-release"
expect "os-release-set appends missing keys" grep -qx 'PRETTY_NAME="Luminus OS 44"' "${TEST_TMP}/os-release"
expect "os-release-set leaves unrelated keys alone" grep -qx 'VERSION_ID=44' "${TEST_TMP}/os-release"

echo '{"uuid":"x","session-modes":["user"]}' >"${TEST_TMP}/metadata.json"
bash "${ROOT}/shared/scripts/aurora-session-modes.sh" \
  "${TEST_TMP}/metadata.json" live-installer initial-setup
expect "aurora-session-modes merges sorted unique modes" \
  jq -e '."session-modes" == ["initial-setup","live-installer","user"]' \
  "${TEST_TMP}/metadata.json"

echo '{"uuid":"x"}' >"${TEST_TMP}/metadata-default.json"
bash "${ROOT}/shared/scripts/aurora-session-modes.sh" \
  "${TEST_TMP}/metadata-default.json" initial-setup
expect "aurora-session-modes supplies the user default" \
  jq -e '."session-modes" == ["initial-setup","user"]' \
  "${TEST_TMP}/metadata-default.json"

# shellcheck disable=SC1091
source "${ROOT}/config/versions.env"
expect_contains "config-value reads the shared Fedora default" "${DEFAULT_FEDORA_VERSION}" \
  "${ROOT}/tools/config-value.sh" DEFAULT_FEDORA_VERSION
expect_failure "config-value rejects unknown keys" \
  "${ROOT}/tools/config-value.sh" NOT_A_SETTING

expect_contains "package adapter maps ISO type" "bootc-generic-iso" \
  env IMAGE_BUILDER_DRY_RUN=1 "${ROOT}/tools/package-artifact.sh" iso image.test out.iso
expect_contains "package adapter maps qcow2 type" "qcow2" \
  env IMAGE_BUILDER_DRY_RUN=1 "${ROOT}/tools/package-artifact.sh" qcow2 image.test out.qcow2
expect_failure "package adapter rejects unknown formats" \
  env IMAGE_BUILDER_DRY_RUN=1 "${ROOT}/tools/package-artifact.sh" raw image.test out.raw

mkdir -p "${TEST_TMP}/kernel-bin"
printf '#!/bin/sh\nexit 1\n' >"${TEST_TMP}/kernel-bin/kernel-install"
printf '#!/bin/sh\nprintf "fallback-kernel\\n"\n' >"${TEST_TMP}/kernel-bin/ls"
printf '#!/bin/sh\nexit 0\n' >"${TEST_TMP}/kernel-bin/plymouth-set-default-theme"
printf '#!/bin/sh\nprintf "%%s\\n" "$@"\n' >"${TEST_TMP}/kernel-bin/dracut"
chmod +x "${TEST_TMP}/kernel-bin/"*
expect_contains "initramfs falls back when kernel-install fails" '/usr/lib/modules/fallback-kernel/initramfs.img' \
  env PATH="${TEST_TMP}/kernel-bin:${PATH}" bash "${ROOT}/shared/scripts/rebuild-initramfs.sh"

printf '%s\n' 'UEFI firmware configuration' >"${TEST_TMP}/boot-screen.txt"
expect_failure "boot evidence rejects a firmware screen" \
  bash "${ROOT}/.github/scripts/check-boot-screen.sh" iso "${TEST_TMP}/boot-screen.txt"
printf '%s\n' 'Sirius Installer' >"${TEST_TMP}/boot-screen.txt"
expect "boot evidence accepts the installer" \
  bash "${ROOT}/.github/scripts/check-boot-screen.sh" iso "${TEST_TMP}/boot-screen.txt"
printf '%s\n' 'Start Installation' >"${TEST_TMP}/boot-screen.txt"
expect "boot evidence accepts the Sirius welcome button" \
  bash "${ROOT}/.github/scripts/check-boot-screen.sh" iso "${TEST_TMP}/boot-screen.txt"
expect_failure "installer evidence does not satisfy the disk check" \
  bash "${ROOT}/.github/scripts/check-boot-screen.sh" disk "${TEST_TMP}/boot-screen.txt"

mkdir -p "${TEST_TMP}/rpm-bin"
printf 'RPM test fixture\n' >"${TEST_TMP}/fixture.rpm"
printf '#!/bin/sh\ncp "$RPM_FIXTURE" "$4"\n' >"${TEST_TMP}/rpm-bin/curl"
printf '#!/bin/sh\ntouch "$RPM_INSTALLED"\n' >"${TEST_TMP}/rpm-bin/dnf"
chmod +x "${TEST_TMP}/rpm-bin/"*
rpm_digest="$(sha256sum "${TEST_TMP}/fixture.rpm" | cut -d ' ' -f1)"
export RPM_FIXTURE="${TEST_TMP}/fixture.rpm" RPM_INSTALLED="${TEST_TMP}/rpm-installed"
expect_failure "RPM installer rejects an incorrect digest" env PATH="${TEST_TMP}/rpm-bin:${PATH}" \
  bash "${ROOT}/editions/workstation/install-rpm.sh" 45 https://example.test/test.rpm "$(printf '%064d' 0)"
expect "RPM installer does not install after a checksum failure" test ! -e "${RPM_INSTALLED}"
expect "RPM installer accepts a matching digest" env PATH="${TEST_TMP}/rpm-bin:${PATH}" \
  bash "${ROOT}/editions/workstation/install-rpm.sh" 45 https://example.test/test.rpm "${rpm_digest}"
expect "RPM installer invokes dnf after verification" test -e "${RPM_INSTALLED}"

# shellcheck disable=SC1091
source "${ROOT}/tools/qemu-common.sh"
expect_contains "QEMU recognizes qcow2 disks" qcow2 qemu_disk_format disk.qcow2
expect_contains "QEMU recognizes raw disks" raw qemu_disk_format disk.img

mkdir -p "${TEST_TMP}/artifacts"
touch -t 202601010000 "${TEST_TMP}/artifacts/older.qcow2"
touch -t 202602010000 "${TEST_TMP}/artifacts/newer.qcow2"
printf '%s\n' "${TEST_TMP}/artifacts/older.qcow2" >"${TEST_TMP}/last-qcow2"
expect_contains "artifact resolver selects the newest valid candidate" \
  "${TEST_TMP}/artifacts/newer.qcow2" \
  qemu_resolve_artifact "${TEST_TMP}/artifacts" "" "${TEST_TMP}/last-qcow2" '*.qcow2' ""
expect_contains "artifact resolver honors an explicit override" \
  "${TEST_TMP}/artifacts/older.qcow2" \
  qemu_resolve_artifact "${TEST_TMP}/artifacts" "${TEST_TMP}/artifacts/older.qcow2" \
  "${TEST_TMP}/last-qcow2" '*.qcow2' ""

expect_contains "QEMU dry-run uses structured qcow2 arguments" "format=qcow2" \
  env QEMU_BOOT=bios QEMU_DEBUG=0 QEMU_DRY_RUN=1 \
  QEMU_DISK_PATH="${TEST_TMP}/artifacts/newer.qcow2" \
  bash "${ROOT}/tools/qemu.sh" disk

printf 'kernel-core 7.2.7-1\nbootc 1.9-1\nzsh 5.9-1\n' >"${TEST_TMP}/rpms-prev"
printf 'kernel-core 7.2.8-1\nbootc 1.9-1\nzsh 5.9-2\nfoo 1-1\n' >"${TEST_TMP}/rpms-new"
printf '#!/bin/sh\ncase "$1" in old) cat "%s";; *) cat "%s";; esac\n' \
  "${TEST_TMP}/rpms-prev" "${TEST_TMP}/rpms-new" >"${TEST_TMP}/rpm-list"
chmod +x "${TEST_TMP}/rpm-list"
# Run outside any git checkout: the script must not depend on repository state.
release_notes="$(cd "${TEST_TMP}" && RPM_LIST_CMD="${TEST_TMP}/rpm-list" bash "${ROOT}/tools/release-notes.sh" new testing-45.20261005.1 old testing-45.20261004.2)"
expect_contains "release notes show a changed major package with its previous version" \
  '| kernel-core | 7.2.8-1 | 7.2.7-1 |' echo "${release_notes}"
expect_contains "release notes keep unchanged major packages without a previous version" \
  '| bootc | 1.9-1 | |' echo "${release_notes}"
expect_contains "release notes count added and updated packages" \
  '3 packages were added or updated' echo "${release_notes}"
expect_contains "release notes end with the rebase command" \
  'sudo bootc switch new' echo "${release_notes}"
