#!/usr/bin/env bash
# Set KEY VALUE pairs in os-release, replacing keys that already exist and
# appending the ones that do not. OS_RELEASE_FILE exists for the test suite;
# builds always use the default path.
set -euo pipefail

file="${OS_RELEASE_FILE:-/usr/lib/os-release}"

while [ "$#" -ge 2 ]; do
  key="$1"
  value="$2"
  shift 2
  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=\"${value}\"|" "${file}"
  else
    printf '%s="%s"\n' "${key}" "${value}" >>"${file}"
  fi
done
