#!/usr/bin/env bash
# Print the content-addressed CI toolbox image name. The tag hashes every
# input that shapes the image, so CI rebuilds it only when something
# actually changed (same scheme as aurora-shell's ci-image-name.sh).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${PROJECT_DIR}/config/versions.env"
IMAGE_HASH="$({
  cd "${PROJECT_DIR}"
  sha256sum \
    ci/Containerfile \
    config/versions.env \
    tools/ci-image-name.sh
} | sha256sum | cut -c1-12)"

printf 'ghcr.io/luminusos/images-ci:fc%s-%s\n' "${DEFAULT_FEDORA_VERSION}" "${IMAGE_HASH}"
