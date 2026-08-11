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
expect "publish calls the reusable workflow" \
  grep -Fq 'uses: ./.github/workflows/containers.yml' \
  "${ROOT}/.github/workflows/publish.yml"
expect_contains "publish Fedora input matches shared default" \
  "default: \"${DEFAULT_FEDORA_VERSION}\"" \
  grep -A3 'fedora_version:' "${ROOT}/.github/workflows/publish.yml"
expect_contains "publish Sirius input matches shared default" \
  "default: \"${SIRIUS_VERSION}\"" \
  grep -A3 'sirius_version:' "${ROOT}/.github/workflows/publish.yml"
expect "CI image hash includes shared version defaults" \
  grep -Fq 'config/versions.env' "${ROOT}/tools/ci-image-name.sh"
