#!/usr/bin/env bash

expect "Justfile parses and exposes public groups" env JUST_TEMPDIR=/tmp \
  just --justfile "${ROOT}/Justfile" --list

validate_just_script() {
  local module="$1" recipe="$2"
  JUST_TEMPDIR=/tmp just --justfile "${ROOT}/Justfile" --dry-run "${module}" "${recipe}" 2>/dev/null | bash -n
}
expect "core build recipe renders valid Bash" validate_just_script build core
expect "workstation build recipe renders valid Bash" validate_just_script build workstation
expect "installer build recipe renders valid Bash" validate_just_script build workstation-iso
expect "package recipe renders valid Bash" validate_just_script package workstation
expect "QEMU install recipe renders valid Bash" validate_just_script qemu install

expect_contains "core stamp includes shared build helpers" shared/scripts/rpmdb-repair.sh \
  env JUST_TEMPDIR=/tmp just --justfile "${ROOT}/Justfile" --dry-run build::_core-stamp

expect "publish workflow consumes reusable outputs" \
  sh -c '! grep -q "needs\.version" "$1"' _ "${ROOT}/.github/workflows/publish.yml"
expect "SourceForge SSH host key is checked against the published fingerprint" \
  grep -Fq 'SHA256:209BDmH3jsRyO9UeGPPgLWPSegKmYCBIya0nR/AWWCY' "${ROOT}/.github/workflows/publish.yml"
expect "automatic builds call the reusable workflow" \
  grep -Fq 'uses: ./.github/workflows/containers.yml' \
  "${ROOT}/.github/workflows/build-containers.yml"
expect "auto testing publishes through the reusable workflow with per-day sequence" \
  sh -c 'grep -Fq "uses: ./.github/workflows/containers.yml" "$1" && grep -Fq "build_sequence: true" "$1" && grep -Fq "build_installer: false" "$1"' \
  _ "${ROOT}/.github/workflows/auto-testing.yml"
expect "auto testing rebuilds only when the Fedora base digest changed" \
  sh -c 'grep -Fq "org.opencontainers.image.base.digest" "$1" && grep -Fq "needs.check.outputs.build" "$1"' \
  _ "${ROOT}/.github/workflows/auto-testing.yml"
expect "workstation image records its Fedora base digest" \
  grep -Fq 'org.opencontainers.image.base.digest="${fedora_bootc_digest}"' \
  "${ROOT}/editions/workstation/Containerfile"
expect "release notes script is valid Bash" bash -n "${ROOT}/tools/release-notes.sh"
expect "Fedora bootc digest helper tracks the OCI manifest" \
  grep -Fq 'quay.io/v2/fedora/fedora-bootc/manifests/${version}' \
  "${ROOT}/tools/fedora-bootc-digest.sh"
expect "builds resolve the live Fedora bootc digest" \
  sh -c 'for f in containers.yml auto-testing.yml; do grep -Fq "tools/fedora-bootc-digest.sh" "$1/$f" || exit 1; done' \
  _ "${ROOT}/.github/workflows"
expect "publishing runs only from main, where the signing key may be used" \
  grep -Fq "if: github.ref == 'refs/heads/main'" "${ROOT}/.github/workflows/publish.yml"
expect "publish calls the reusable workflow" \
  grep -Fq 'uses: ./.github/workflows/containers.yml' \
  "${ROOT}/.github/workflows/publish.yml"
expect_contains "publish Fedora input delegates to shared default" \
  'default: ""' \
  grep -A3 'fedora_version:' "${ROOT}/.github/workflows/publish.yml"
expect_contains "publish Sirius input delegates to shared default" \
  'default: ""' \
  grep -A3 'sirius_version:' "${ROOT}/.github/workflows/publish.yml"
expect "custom Sirius release overrides matching RPM version" \
  grep -Fq 'sirius_rpm_version="${INPUT_SIRIUS_VERSION}"' \
  "${ROOT}/.github/workflows/containers.yml"
expect "CI image hash includes shared version defaults" \
  grep -Fq 'config/versions.env' "${ROOT}/tools/ci-image-name.sh"
expect "core installs firewalld" \
  grep -Fq 'install firewalld' "${ROOT}/editions/core/Containerfile"
expect "workstation disables sshd and closes its firewall port" \
  sh -c 'grep -Fq "systemctl disable sshd.service" "$1" && grep -Fq -- "--remove-service-from-zone=ssh" "$1"' \
  _ "${ROOT}/editions/workstation/build.sh"
expect "Sirius RPM is verified against a pinned digest" \
  grep -Fq 'sha256sum -c' "${ROOT}/editions/workstation/Containerfile.installer"
expect "Sirius version override requires a digest" \
  grep -Fq 'sirius_version override requires sirius_sha256' \
  "${ROOT}/.github/workflows/containers.yml"
expect "validation builds never publish" \
  sh -c 'grep -Fq "publish: false" "$1" && ! grep -q "inputs.publish" "$1"' \
  _ "${ROOT}/.github/workflows/build-containers.yml"
expect "only the registry builder publishes" \
  grep -Fq 'publishing requires builder_mode=registry' "${ROOT}/.github/workflows/containers.yml"
expect "stable promotes an existing testing build without rebuilding" \
  sh -c 'grep -Fq "skopeo copy --all --preserve-digests" "$1" && grep -Fq "testing-\${BUILD_VERSION}" "$1"' \
  _ "${ROOT}/.github/workflows/containers.yml"
expect "installed systems follow UPDATE_CHANNEL" \
  grep -Fq 'installer_target=${REGISTRY}/${image_namespace}/luminusos-workstation:${target_tag}' \
  "${ROOT}/.github/workflows/containers.yml"
expect "hosted installer uses the verified snapshot and exact OCI payload after the publication gate" \
  sh -c 'job=$(sed -n "/^  installer:$/,\$p" "$1") &&
    printf "%s\n" "$job" | grep -Fq "needs: [build, gate]" &&
    printf "%s\n" "$job" | grep -Fq -- "--installer-dir .test/installer-inputs/sysext" &&
    printf "%s\n" "$job" | grep -Fq -- "skopeo copy --preserve-digests \"docker://\${BUILD_REF}\"" &&
    printf "%s\n" "$job" | grep -Fq "installer_features=1"' \
  _ "${ROOT}/.github/workflows/containers.yml"
expect_contains "installed systems follow testing until stable is switched on" \
  'UPDATE_CHANNEL=testing' cat "${ROOT}/config/versions.env"
expect "installed systems require signed LuminusOS images" \
  sh -c 'jq -e "$1" "$2" >/dev/null && test -s "$3"' _ \
  '.transports.docker | [.["ghcr.io/luminusos/luminusos"][0], .["ghcr.io/luminusos/luminusos-workstation"][0]]
    | all(.type == "sigstoreSigned" and .keyPath == "/etc/pki/containers/luminusos.pub")' \
  "${ROOT}/editions/workstation/files/system/etc/containers/policy.json" \
  "${ROOT}/editions/workstation/files/system/etc/pki/containers/luminusos.pub"
expect "published images are signed with a containers/image-compatible cosign" \
  sh -c 'grep -Fq "cosign sign --yes --key env://COSIGN_PRIVATE_KEY" "$1" && grep -Fq "cosign-release: v2." "$1"' \
  _ "${ROOT}/.github/workflows/containers.yml"
expect "workflow actions are pinned to immutable digests" \
  sh -c '! grep -rhE "^[[:space:]]*(- )?uses: " "$1" | grep -vE "uses: (\./|[^ ]+@[0-9a-f]{40}( |$)|docker://[^ ]+@sha256:[0-9a-f]{64}( |$))"' \
  _ "${ROOT}/.github/workflows"
expect "workstation stages updates without rebooting" \
  sh -c 'grep -Fq "systemctl enable bootc-fetch-apply-updates.timer" "$1" &&
    grep -qx "ExecStart=" "$2" && grep -qx "ExecStart=/usr/bin/bootc upgrade --quiet" "$2" && ! grep -q -- "--apply" "$2"' \
  _ "${ROOT}/editions/workstation/build.sh" \
  "${ROOT}/editions/workstation/files/system/usr/lib/systemd/system/bootc-fetch-apply-updates.service.d/10-luminusos-stage.conf"
expect "release metadata lists LATEST_RELEASE among SUPPORTED_RELEASES" \
  bash -c 'source "$1" && [[ " ${SUPPORTED_RELEASES} " == *" ${LATEST_RELEASE} "* ]]' \
  _ "${ROOT}/config/releases.env"
expect "builds read release metadata from main" \
  grep -Fq 'git show FETCH_HEAD:config/releases.env' "${ROOT}/.github/workflows/containers.yml"
expect "floating tags only follow LATEST_RELEASE" \
  sh -c '! grep -q channel_policy "$1"/*.yml && grep -Fq "\"\${fedora_version}\" = \"\${LATEST_RELEASE}\"" "$1/containers.yml"' \
  _ "${ROOT}/.github/workflows"
expect "stable is refused before the Fedora release is out" \
  grep -Fq 'docker://quay.io/fedora/fedora-bootc:latest' "${ROOT}/.github/workflows/containers.yml"
expect "public workstation tags move only after the feature gate and signing" \
  sh -c 'w="$1"; r="$2"; grep -Fq "luminusos-workstation-candidate" "$w" &&
    grep -Fq "sysext-release.sh publish" "$w" && grep -Fq "sysext-release.sh promote" "$w" &&
    ! grep -q "docker push.*branch_tag\|docker push.*channel_tag" "$w" &&
    gate=$(grep -n "verify-public" "$r" | head -1 | cut -d: -f1) &&
    sign=$(grep -n "cosign sign" "$r" | head -1 | cut -d: -f1) &&
    verify=$(grep -nF "verify_image_signature \"\${public_repo}@\${digest}\"" "$r" | head -1 | cut -d: -f1) &&
    move=$(grep -n "copy_tag \"\${public_repo}@" "$r" | head -1 | cut -d: -f1) &&
    [ "$sign" -lt "$verify" ] && [ "$gate" -lt "$move" ] && [ "$verify" -lt "$move" ] &&
    ! grep -q "sysext-staging-" "$r"' \
  _ "${ROOT}/.github/workflows/containers.yml" "${ROOT}/.github/scripts/sysext-release.sh"
expect "testing and stable use the same parametrized pre-cutover boot check" \
  sh -c 'step=$(sed -n "/^      - name: Publish the workstation build through the feature gate$/,/^      - name: Upload candidate boot evidence$/p" "$1") &&
    printf "%s\n" "$step" | grep -Eq "^          BOOT_TEST_FEATURE: [a-z][a-z0-9]+$" &&
    printf "%s\n" "$step" | grep -Eq "^          BOOT_TEST_FEATURE_UNIT: luminusos-.*\.service$" &&
    printf "%s\n" "$step" | grep -Fxq "          BOOT_TEST_CHANNEL: \${{ inputs.channel }}" &&
    printf "%s\n" "$step" | grep -Fq -- "--boot-check .github/scripts/ci-boot-candidate.sh" &&
    printf "%s\n" "$step" | grep -F "sysext-release.sh publish" | grep -Fq "\"\${common[@]}\"" &&
    printf "%s\n" "$step" | grep -F -- "--expected-digest" | grep -Fq "\"\${common[@]}\""' \
  _ "${ROOT}/.github/workflows/containers.yml"
