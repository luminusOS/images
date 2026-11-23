#!/usr/bin/env bash
# Build one image-builder artifact from an already-built bootc image.
set -euo pipefail

format="${1:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
image="${2:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
output="${3:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
pointer="${4:-}"

case "${format}" in
  iso|qcow2) ;;
  *)
    echo "Unknown artifact format: ${format} (expected iso or qcow2)" >&2
    exit 1
    ;;
esac

privileged=()
if [ "${EUID}" -ne 0 ]; then privileged=(sudo); fi
dry_run="${IMAGE_BUILDER_DRY_RUN:-0}"

path="$(pwd)/${output}"
if [ "${format}" = iso ]; then
  if [[ "${output}" = */* || "${output}" = . || "${output}" = .. ]]; then
    echo "Expected an ISO output filename, got: ${output}" >&2
    exit 1
  fi
  manifest=("${privileged[@]}" image-builder manifest --bootc-ref "${image}" bootc-generic-iso)
  cache="${IMAGE_BUILDER_CACHE:-${PWD}/.osbuild-cache}"
  build=("${privileged[@]}" osbuild --store "${cache}" --export bootiso)
  transformer="$(dirname "${BASH_SOURCE[0]}")/enforce-live-iso.py"
  if [ "${dry_run}" = 1 ]; then
    printf '%q ' "${manifest[@]}"
    printf '| python3 %q > MANIFEST\n' "${transformer}"
    printf '%q ' "${build[@]}"
    printf '%s\n' '--output-directory WORKDIR MANIFEST'
    exit 0
  fi

  work="$(mktemp -d "${PWD}/.iso-package.XXXXXX")"
  trap '"${privileged[@]}" rm -rf -- "${work}"' EXIT
  "${manifest[@]}" | python3 "${transformer}" >"${work}/manifest.json"
  "${build[@]}" --output-directory "${work}" "${work}/manifest.json"
  test -s "${work}/bootiso/install.iso"
  "${privileged[@]}" mv -T -- "${work}/bootiso/install.iso" "${path}"
else
  args=(build --output-dir . --output-name "${output}")
  if [ -n "${IMAGE_BUILDER_CACHE:-}" ]; then
    args+=(--cache "${IMAGE_BUILDER_CACHE}")
  fi
  args+=(--bootc-ref "${image}" qcow2)
  if [ "${dry_run}" = 1 ]; then
    printf '%q ' "${privileged[@]}" image-builder "${args[@]}"
    printf '\n'
    exit 0
  fi
  "${privileged[@]}" image-builder "${args[@]}"
fi

if [ ! -f "${path}" ]; then
  echo "Expected artifact was not created: ${path}" >&2
  exit 1
fi
if [ -n "${pointer}" ]; then
  printf '%s\n' "${path}" >"${pointer}"
  echo "Wrote artifact pointer: ${pointer} -> ${path}"
fi
