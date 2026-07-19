#!/usr/bin/env bash
# Set KEY VALUE pairs in /usr/lib/os-release, replacing keys that already
# exist and appending the ones that do not.
set -euo pipefail

while [ "$#" -ge 2 ]; do
  key="$1"
  value="$2"
  shift 2
  if grep -q "^${key}=" /usr/lib/os-release; then
    sed -i "s|^${key}=.*|${key}=\"${value}\"|" /usr/lib/os-release
  else
    printf '%s="%s"\n' "${key}" "${value}" >> /usr/lib/os-release
  fi
done
