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
release_notes="$(RPM_LIST_CMD="${TEST_TMP}/rpm-list" bash "${ROOT}/tools/release-notes.sh" new testing-45.20261005.1 old testing-45.20261004.2)"
expect_contains "release notes show a changed major package with its previous version" \
  '| kernel-core | 7.2.8-1 | 7.2.7-1 |' echo "${release_notes}"
expect_contains "release notes keep unchanged major packages without a previous version" \
  '| bootc | 1.9-1 | |' echo "${release_notes}"
expect_contains "release notes count added and updated packages" \
  '3 packages were added or updated' echo "${release_notes}"
expect_contains "release notes end with the rebase command" \
  'sudo bootc switch new' echo "${release_notes}"
