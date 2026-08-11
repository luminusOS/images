#!/usr/bin/env bash
# Print one allowlisted value from config/versions.env.
set -euo pipefail

key="${1:?Usage: config-value.sh KEY}"
case "${key}" in
  DEFAULT_FEDORA_VERSION | PRIMARY_FEDORA_BRANCH | AURORA_SHELL_VERSION | AURORA_SHELL_SHA256 | SIRIUS_VERSION) ;;
  *)
    echo "Unknown configuration key: ${key}" >&2
    exit 1
    ;;
esac

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${project_dir}/config/versions.env"
printf '%s\n' "${!key}"
