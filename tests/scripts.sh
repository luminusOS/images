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

sysext_dir="${ROOT}/editions/workstation/sysext"
manifest_tool="${sysext_dir}/feature-manifest.sh"
expect "the dummy feature manifest validates" bash "${manifest_tool}" json "${ROOT}/editions/workstation/features/dummy"
expect "every shipped feature manifest validates" \
  bash "${manifest_tool}" generate "${ROOT}/editions/workstation/features" "${TEST_TMP}/gen"
expect_contains "generated discovery metadata keeps both firmware matches" \
  'SuggestOnFirmware=smbios-field(product_name $= "MacBookPro11,[45]")' \
  cat "${TEST_TMP}/gen/usr/lib/luminusos/sysupdate-discovery/dummy.feature"
expect_contains "generated transfer template uses the versioned URL" 'Path=@BASE_URL@/@VERSION@/' \
  cat "${TEST_TMP}/gen/usr/lib/luminusos/sysupdate/dummy.transfer.in"

manifest_case() {
  local id="$1" body="$2"
  rm -rf "${TEST_TMP}/mf/${id}"
  mkdir -p "${TEST_TMP}/mf/${id}"
  printf '%s\n' "${body}" >"${TEST_TMP}/mf/${id}/feature.env"
  bash "${manifest_tool}" json "${TEST_TMP}/mf/${id}"
}
good_manifest="FEATURE_ID=demo
FEATURE_DESCRIPTION='Demo'
FEATURE_SIZE_BUDGET_MIB=2"
expect_contains "manifest defaults the expanded budget to 4x" '"expanded_budget_mib":8' \
  manifest_case demo "${good_manifest}"
expect_failure "manifest rejects an ID that differs from its directory" manifest_case other "${good_manifest}"
expect_failure "manifest rejects reserved IDs" manifest_case sysext "${good_manifest/demo/sysext}"
expect_failure "manifest rejects unknown keys" manifest_case demo "${good_manifest}
FEATURE_PACKAGE=(typo)"
expect_failure "manifest rejects scalar arrays" manifest_case demo "${good_manifest}
FEATURE_PACKAGES=mbpfan"
expect_failure "manifest rejects option-like packages" manifest_case demo "${good_manifest}
FEATURE_PACKAGES=(--nogpgcheck)"
expect_failure "manifest rejects unpinned RPMs" manifest_case demo "${good_manifest}
FEATURE_RPMS=('https://rpm.luminusos.org/x.rpm')"
expect_failure "manifest rejects unscoped udev selectors" manifest_case demo "${good_manifest}
FEATURE_UDEV_TRIGGER=(--action=change)"
expect_failure "manifest rejects a multi-line description" manifest_case demo "${good_manifest}
FEATURE_DESCRIPTION=\$'a\\nb'"
expect_failure "manifest rejects an expanded budget below the compressed one" manifest_case demo "${good_manifest}
FEATURE_EXPANDED_BUDGET_MIB=1"
mkdir -p "${TEST_TMP}/mf/demo/files/etc"
expect_failure "manifest rejects /etc content" bash "${manifest_tool}" json "${TEST_TMP}/mf/demo"

guard_root="${TEST_TMP}/guard"
mkdir -p "${TEST_TMP}/stub-bin"
printf '#!/bin/sh\nfor a; do out="$prev"; prev="$a"; done\nhead -c "${STUB_RAW_BYTES:-4096}" /dev/zero >"$out"\n' \
  >"${TEST_TMP}/stub-bin/mkfs.erofs"
printf '#!/bin/sh\nfor a; do f="$a"; done\nhead -c "${STUB_XZ_BYTES:-512}" /dev/zero >"$f.xz"\n' \
  >"${TEST_TMP}/stub-bin/xz"
chmod +x "${TEST_TMP}/stub-bin/"*

guard_setup() {
  rm -rf "${guard_root}"
  mkdir -p "${guard_root}/base/usr/bin" "${guard_root}/base/usr/share/icons/hicolor" \
    "${guard_root}/base/usr/lib/systemd/system" "${guard_root}/base/usr/lib/udev/rules.d" \
    "${guard_root}/base/opt" "${guard_root}/out"
  printf 'rpm-owned\n' >"${guard_root}/base/usr/bin/tool"
  printf 'image-owned\n' >"${guard_root}/base/usr/share/luminusos-marker"
  printf '[Unit]\n' >"${guard_root}/base/usr/lib/systemd/system/base.service"
  ln -s bin "${guard_root}/base/usr/sbin"
  cp -a "${guard_root}/base" "${guard_root}/final"
  mkdir -p "${guard_root}/final/usr/libexec/demo"
  printf '#!/bin/sh\n' >"${guard_root}/final/usr/libexec/demo/run"
  printf '{"id":"demo","udev_trigger":[],"compressed_budget_mib":1,"expanded_budget_mib":4}\n' \
    >"${guard_root}/manifest.json"
}
guard_run() {
  python3 "${ROOT}/tests/sysext-treediff.py" "${guard_root}/base" "${guard_root}/final" >"${guard_root}/diff.json"
  rm -rf "${guard_root}/stage"
  env PATH="${TEST_TMP}/stub-bin:${PATH}" python3 "${sysext_dir}/guard.py" \
    --base "${guard_root}/base" --final "${guard_root}/final" --diff "${guard_root}/diff.json" \
    --manifest "${guard_root}/manifest.json" --stage "${guard_root}/stage" --out "${guard_root}/out" \
    --version 45.1 --image-digest "sha256:$(printf '%064d' 1)" --os-version-id 45 "$@"
}
guard_expect() {
  local description="$1" outcome="$2" mutation="$3"
  shift 3
  guard_setup
  eval "${mutation}"
  if [ "${outcome}" = pass ]; then
    expect "guard accepts ${description}" guard_run "$@"
  else
    expect_failure "guard rejects ${description}" guard_run "$@"
  fi
}
F="${guard_root}/final"
guard_expect "an additive feature" pass ":"
expect "guard stages only feature paths" \
  sh -c 'test -f "$1/usr/libexec/demo/run" && test ! -e "$1/usr/bin/tool"' _ "${guard_root}/stage"
expect "guard writes the extension-release file" grep -qx 'SYSEXT_LEVEL=45.1' \
  "${guard_root}/stage/usr/lib/extension-release.d/extension-release.luminusos-demo_45.1"
expect "guard records the build metadata" \
  jq -e '.raw == "luminusos-demo_45.1.raw" and .nodes["/usr/libexec/demo/run"] == "f" and .nodes["/usr/libexec/demo"] == "d"' \
  "${guard_root}/out/luminusos-demo_45.1.json"
guard_expect "a changed RPM file" fail "printf 'x\n' >>'${F}/usr/bin/tool'"
guard_expect "a changed non-RPM image file" fail "printf 'x\n' >>'${F}/usr/share/luminusos-marker'"
guard_expect "a mode change of a base file" fail "chmod 0700 '${F}/usr/bin/tool'"
guard_expect "a deleted base path" fail "rm '${F}/usr/bin/tool'"
guard_expect "a base file retyped to a symlink" fail "rm '${F}/usr/bin/tool'; ln -s run '${F}/usr/bin/tool'"
guard_expect "a new path under a base symlink" fail "rm '${F}/usr/sbin'; mkdir '${F}/usr/sbin'; touch '${F}/usr/sbin/x'"
guard_expect "a symlink into base content" fail "ln -s ../../bin/tool '${F}/usr/libexec/demo/tool'"
guard_expect "a symlink to its own content" pass "ln -s run '${F}/usr/libexec/demo/alias'"
guard_expect "a merged cache" fail "touch '${F}/usr/share/icons/hicolor/icon-theme.cache'"
guard_expect "a drop-in for a base unit" fail "mkdir '${F}/usr/lib/systemd/system/base.service.d'; touch '${F}/usr/lib/systemd/system/base.service.d/x.conf'"
guard_expect "a unit outside its name prefix" fail "touch '${F}/usr/lib/systemd/system/demo.service'"
guard_expect "its own unit wanted by the features target" pass "printf '[Install]\nWantedBy=luminusos-features.target\n' >'${F}/usr/lib/systemd/system/luminusos-demo-x.service'; mkdir '${F}/usr/lib/systemd/system/luminusos-features.target.wants'; ln -s ../luminusos-demo-x.service '${F}/usr/lib/systemd/system/luminusos-features.target.wants/luminusos-demo-x.service'"
guard_expect "a unit wanted by a base target" fail "printf '[Install]\nWantedBy=multi-user.target\n' >'${F}/usr/lib/systemd/system/luminusos-demo-x.service'"
guard_expect "a unit that names another feature" fail "printf '[Unit]\nAfter=luminusos-other-y.service\n' >'${F}/usr/lib/systemd/system/luminusos-demo-x.service'"
guard_expect "a unit drop-in under /usr/local/lib/systemd" fail "mkdir -p '${F}/usr/local/lib/systemd/system/base.service.d'; touch '${F}/usr/local/lib/systemd/system/base.service.d/x.conf'"
guard_expect "a user unit under /usr/share/systemd" fail "mkdir -p '${F}/usr/share/systemd/user'; touch '${F}/usr/share/systemd/user/x.service'"
guard_expect "a GIO module" fail "mkdir -p '${F}/usr/lib64/gio/modules'; touch '${F}/usr/lib64/gio/modules/libx.so'"
guard_expect "a udev rule outside its name prefix" fail "touch '${F}/usr/lib/udev/rules.d/99-demo.rules'"
guard_expect "a polkit rule" fail "mkdir -p '${F}/usr/share/polkit-1/rules.d'; touch '${F}/usr/share/polkit-1/rules.d/x.rules'"
guard_expect "an out-of-tree kernel module, kept out of ordinary features for NVIDIA" fail \
  "mkdir -p '${F}/usr/lib/modules'; touch '${F}/usr/lib/modules/nvidia.ko'"
guard_expect "a setuid binary" fail "chmod 4755 '${F}/usr/libexec/demo/run'"
STUB_RAW_BYTES=$((5 << 20)) guard_expect "content over the expanded budget" fail ":"
STUB_XZ_BYTES=$((2 << 20)) guard_expect "content over the compressed budget" fail ":"
guard_expect "a udev trigger without a rule" fail "printf '{\"id\":\"demo\",\"udev_trigger\":[\"--subsystem-match=net\"],\"compressed_budget_mib\":1,\"expanded_budget_mib\":4}' >'${guard_root}/manifest.json'"

release_tool="${sysext_dir}/release.py"
release_dir="${TEST_TMP}/release"
release_digest="sha256:$(printf '%064d' 7)"
release_feature() {
  local id="$1" paths="$2" refs="${3:-[]}" raw xz
  printf 'raw-%s\n' "${id}" >"${release_dir}/luminusos-${id}_45.1.raw"
  printf 'xz-%s\n' "${id}" >"${release_dir}/luminusos-${id}_45.1.raw.xz"
  raw="$(sha256sum "${release_dir}/luminusos-${id}_45.1.raw" | cut -d' ' -f1)"
  xz="$(sha256sum "${release_dir}/luminusos-${id}_45.1.raw.xz" | cut -d' ' -f1)"
  jq -n --arg id "${id}" --arg raw "${raw}" --arg xz "${xz}" --arg d "${release_digest}" \
    --argjson nodes "${paths}" --argjson refs "${refs}" \
    '{format:1, id:$id, version:"45.1", architecture:"x86-64", image_digest:$d,
      raw:("luminusos-" + $id + "_45.1.raw"), raw_xz:("luminusos-" + $id + "_45.1.raw.xz"),
      raw_sha256:$raw, raw_xz_sha256:$xz, compressed_budget_mib:1, expanded_budget_mib:4,
      nodes:$nodes, exec_refs:$refs, warnings:[]}' >"${release_dir}/luminusos-${id}_45.1.json"
}
release_reset() {
  rm -rf "${release_dir}"
  mkdir -p "${release_dir}"
  release_feature a '{"/usr":"d","/usr/libexec":"d","/usr/libexec/a":"f"}'
}
release_reset
release_feature b '{"/usr":"d","/usr/libexec":"d","/usr/libexec/b":"f"}'
expect "release assembles independent features" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"
expect "release descriptor binds the image digest and both hashes" jq -e --arg d "${release_digest}" \
  '.image_digest == $d and .version == "45.1" and (.features | keys) == ["a","b"] and .features.a.raw_sha256 and .features.b.raw_xz_sha256' \
  "${release_dir}/release.json"
expect "online checksum list names only compressed payloads" \
  sh -c 'test "$(grep -c "\.raw\.xz$" "$1/SHA256SUMS")" = 2 && ! grep -q "\.raw$" "$1/SHA256SUMS"' _ "${release_dir}"
expect "offline checksum list names only raw payloads" \
  sh -c 'test "$(grep -c "\.raw$" "$1/SHA256SUMS.raw")" = 2' _ "${release_dir}"
release_reset
release_feature b '{"/usr":"d","/usr/libexec":"d","/usr/libexec/a":"f"}'
expect_failure "release rejects a path shipped by two features" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"
release_reset
release_feature b '{"/usr":"d","/usr/libexec":"d","/usr/libexec/a":"d","/usr/libexec/a/x":"f"}'
expect_failure "release rejects a directory where another feature ships a file" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"
release_reset
release_feature b '{"/usr":"d","/usr/libexec":"l"}'
expect_failure "release rejects a symlink where another feature ships a directory" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"
release_reset
release_feature b '{"/usr":"d","/usr/libexec":"d","/usr/libexec/b":"f"}' '["/usr/libexec/a"]'
expect_failure "release rejects a feature that executes another feature's file" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"
release_reset
expect_failure "release rejects metadata for another image digest" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "sha256:$(printf '%064d' 8)"
printf 'tampered\n' >>"${release_dir}/luminusos-a_45.1.raw.xz"
expect_failure "release rejects a payload that differs from its build metadata" \
  python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}"

if command -v gpg >/dev/null 2>&1 && command -v gpgv >/dev/null 2>&1; then
  export GNUPGHOME="${TEST_TMP}/release-gpg"
  mkdir -m 0700 "${GNUPGHOME}"
  gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "Release Test <r@test.invalid>" ed25519 sign never 2>/dev/null
  gpg --batch --export r@test.invalid >"${TEST_TMP}/release-keyring.pgp"
  offline_snapshot() {
    release_reset
    python3 "${release_tool}" assemble "${release_dir}" --version 45.1 --image-digest "${release_digest}" >/dev/null &&
      SYSEXT_SIGNING_PASSPHRASE="" python3 "${release_tool}" sign "${release_dir}" --key r@test.invalid >/dev/null &&
      rm -f "${release_dir}"/*.raw.xz "${release_dir}"/*_45.1.json "${release_dir}/SHA256SUMS" "${release_dir}/SHA256SUMS.gpg"
  }
  offline_verify() {
    python3 "${release_tool}" verify "${release_dir}" --keyring "${TEST_TMP}/release-keyring.pgp" \
      --version 45.1 --image-digest "${1:-${release_digest}}" --offline
  }
  offline_snapshot
  expect "offline verify accepts the ISO subset: raw files, raw list and descriptor" offline_verify
  iso_payload="${TEST_TMP}/iso-payload"
  iso_os_release="${TEST_TMP}/iso-os-release"
  mkdir -p "${iso_payload}/blobs/sha256"
  printf '{}\n' >"${iso_payload}/config"
  iso_config_hash="$(sha256sum "${iso_payload}/config" | cut -d' ' -f1)"
  mv "${iso_payload}/config" "${iso_payload}/blobs/sha256/${iso_config_hash}"
  jq -n --arg digest "sha256:${iso_config_hash}" \
    '{schemaVersion:2,config:{digest:$digest,size:3},layers:[]}' >"${iso_payload}/manifest"
  iso_hash="$(sha256sum "${iso_payload}/manifest" | cut -d' ' -f1)"
  mv "${iso_payload}/manifest" "${iso_payload}/blobs/sha256/${iso_hash}"
  jq -n --arg digest "sha256:${iso_hash}" \
    '{manifests:[{digest:$digest,annotations:{"org.opencontainers.image.ref.name":"latest"}}]}' >"${iso_payload}/index.json"
  printf 'IMAGE_VERSION="45.1"\n' >"${iso_os_release}"
  iso_verify() {
    python3 "${release_tool}" verify-installer "${release_dir}" --keyring "${TEST_TMP}/release-keyring.pgp" \
      --payload "${iso_payload}" --os-release "${iso_os_release}" "$@"
  }
  expect_failure "installer verifier rejects authentic snapshot for a different OCI digest" iso_verify
  release_digest="sha256:${iso_hash}"
  offline_snapshot
  expect "installer verifier binds the signed snapshot to actual manifest bytes and live version" iso_verify
  iso_discovery="${TEST_TMP}/iso-discovery"
  mkdir "${iso_discovery}"
  touch "${iso_discovery}"/{a,luminusos-discovery-probe}.feature
  expect "installer verifier accepts the complete discovery matrix, excluding the probe" \
    iso_verify --discovery-dir "${iso_discovery}"
  touch "${iso_discovery}/missing.feature"
  expect_failure "installer verifier rejects a discoverable feature missing from the ISO snapshot" \
    iso_verify --discovery-dir "${iso_discovery}"
  printf 'x' >>"${iso_payload}/blobs/sha256/${iso_config_hash}"
  expect_failure "installer verifier rejects a changed config blob" iso_verify
  printf '{}\n' >"${iso_payload}/blobs/sha256/${iso_config_hash}"
  touch "${release_dir}/luminusos-unsigned_45.1.raw"
  expect_failure "installer verifier rejects an extra unsigned payload" iso_verify
  unlink "${release_dir}/luminusos-unsigned_45.1.raw"
  printf 'IMAGE_VERSION=45.2\n' >"${iso_os_release}"
  expect_failure "installer verifier rejects a different live version" iso_verify
  printf 'IMAGE_VERSION=45.1\n' >"${iso_os_release}"
  printf ' ' >>"${iso_payload}/blobs/sha256/${iso_hash}"
  expect_failure "installer verifier rejects manifest bytes changed without updating the index" iso_verify
  expect_failure "offline verify rejects another image digest" offline_verify "sha256:$(printf '%064d' 8)"
  offline_snapshot
  printf 'x' >>"${release_dir}/luminusos-a_45.1.raw"
  expect_failure "offline verify rejects a raw payload that differs from the list" offline_verify
  offline_snapshot
  rm -f "${release_dir}/SHA256SUMS.raw.gpg"
  expect_failure "offline verify requires the raw list signature" offline_verify
  offline_snapshot
  printf '\n' >>"${release_dir}/release.json"
  expect_failure "offline verify rejects a descriptor that no longer matches its signature" offline_verify
  unset GNUPGHOME
else
  skip "offline release verification (gpg not installed)"
fi
