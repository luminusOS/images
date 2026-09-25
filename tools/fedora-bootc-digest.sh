#!/usr/bin/env bash
# Print the live fedora-bootc:<version> digest; quay drops old ones within a day.
set -euo pipefail

version="${1:?Usage: fedora-bootc-digest.sh FEDORA_VERSION}"
digest="$(curl --fail --silent --show-error --head \
  --header 'Accept: application/vnd.oci.image.index.v1+json' \
  "https://quay.io/v2/fedora/fedora-bootc/manifests/${version}" |
  sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *\([^[:space:]]*\).*/\1/p' |
  tr -d '\r')"

if ! [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Could not resolve fedora-bootc:${version} digest (got '${digest}')" >&2
  exit 1
fi
printf '%s\n' "${digest}"
