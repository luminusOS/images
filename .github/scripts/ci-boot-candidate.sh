#!/usr/bin/env bash
set -euo pipefail

ref=${1:?candidate image by digest}
digest=${2:?candidate digest}
[[ "${ref}" == *@sha256:* && "${ref##*@}" == "${digest}" && "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
source "$(dirname "${BASH_SOURCE[0]}")/boot-feature-config.sh"
validate_boot_feature

sudo podman run --rm --privileged \
  --security-opt label=type:unconfined_t \
  -v "$PWD:/work" -w /work \
  -e WORKSTATION_IMAGE="${ref}" \
  -e OUTPUT_NAME=candidate-boot.qcow2 \
  -e GHCR_USER -e GHCR_TOKEN \
  "quay.io/fedora/fedora:${FEDORA_VERSION:?}" \
  bash .github/scripts/ci-package.sh qcow2

export BOOT_TEST_EXPECTED_DIGEST="${digest}"
bash .github/scripts/boot-test.sh disk candidate-boot.qcow2 candidate-boot
