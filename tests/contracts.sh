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
expect "automatic builds call the reusable workflow" \
  grep -Fq 'uses: ./.github/workflows/containers.yml' \
  "${ROOT}/.github/workflows/build-containers.yml"
expect "Fedora bootc updates dispatch the reusable build" \
  grep -Fq 'gh workflow run build-containers.yml --ref main' \
  "${ROOT}/.github/workflows/update-fedora.yml"
expect "Fedora bootc digest helper tracks the OCI manifest" \
  grep -Fq 'quay.io/v2/fedora/fedora-bootc/manifests/${version}' \
  "${ROOT}/tools/fedora-bootc-digest.sh"
expect "builds resolve the live Fedora bootc digest" \
  sh -c 'for f in containers.yml ci.yml update-fedora.yml; do grep -Fq "tools/fedora-bootc-digest.sh" "$1/$f" || exit 1; done' \
  _ "${ROOT}/.github/workflows"
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
expect "container builds publish only from a manual dispatch" \
  grep -Fq "publish: \${{ github.event_name == 'workflow_dispatch' && inputs.publish }}" \
  "${ROOT}/.github/workflows/build-containers.yml"
expect "stable promotes an existing testing build without rebuilding" \
  sh -c 'grep -Fq "skopeo copy --all --preserve-digests" "$1" && grep -Fq "testing-\${BUILD_VERSION}" "$1"' \
  _ "${ROOT}/.github/workflows/containers.yml"
expect "installed systems follow UPDATE_CHANNEL" \
  grep -Fq 'luminusos-workstation:${{ steps.version.outputs.target_tag }}' \
  "${ROOT}/.github/workflows/containers.yml"
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
