#!/usr/bin/env bash
# Build one image-builder artifact from an already-built bootc image.
set -euo pipefail

format="${1:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
image="${2:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
output="${3:?Usage: package-artifact.sh iso|qcow2 IMAGE OUTPUT [POINTER]}"
pointer="${4:-}"

case "${format}" in
  iso) image_builder_type="bootc-generic-iso" ;;
  qcow2) image_builder_type="qcow2" ;;
  *)
    echo "Unknown artifact format: ${format} (expected iso or qcow2)" >&2
    exit 1
    ;;
esac

if [ "${EUID}" -eq 0 ]; then
  command=(image-builder)
else
  command=(sudo image-builder)
fi

args=(
  build
  --output-dir .
  --output-name "${output}"
)
if [ -n "${IMAGE_BUILDER_CACHE:-}" ]; then
  args+=(--cache "${IMAGE_BUILDER_CACHE}")
fi
args+=(--bootc-ref "${image}" "${image_builder_type}")

if [ "${IMAGE_BUILDER_DRY_RUN:-0}" = "1" ]; then
  printf '%q ' "${command[@]}" "${args[@]}"
  printf '\n'
  exit 0
fi

"${command[@]}" "${args[@]}"

path="$(pwd)/${output}"
if [ ! -f "${path}" ]; then
  echo "Expected artifact was not created: ${path}" >&2
  exit 1
fi
if [ -n "${pointer}" ]; then
  printf '%s\n' "${path}" >"${pointer}"
  echo "Wrote artifact pointer: ${pointer} -> ${path}"
fi
