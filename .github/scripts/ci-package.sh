#!/usr/bin/env bash
# Package one workstation artifact from the prebuilt GHCR containers.
# Runs inside a privileged Fedora container; never builds containers itself.
#
# Usage: ci-package.sh iso|qcow2
# Env:   WORKSTATION_IMAGE       payload image ref (ghcr)
#        WORKSTATION_ISO_IMAGE   live-root image ref (ghcr, iso only)
#        OUTPUT_NAME             artifact file name
#        GHCR_USER / GHCR_TOKEN  registry credentials (packages may be private)
set -euxo pipefail

format="$1"

dnf -y install image-builder podman

if [ -n "${GHCR_TOKEN:-}" ]; then
  podman login ghcr.io -u "${GHCR_USER}" -p "${GHCR_TOKEN}"
else
  echo "WARNING: GHCR_TOKEN is empty — pulls from private GHCR packages will fail" >&2
fi

podman pull "${WORKSTATION_IMAGE}"

case "${format}" in
  iso)
    podman pull "${WORKSTATION_ISO_IMAGE}"
    image-builder build \
      --bootc-default-fs btrfs \
      --output-dir . \
      --output-name "${OUTPUT_NAME}" \
      --bootc-ref "${WORKSTATION_ISO_IMAGE}" \
      --bootc-installer-payload-ref "${WORKSTATION_IMAGE}" \
      bootc-generic-iso
    ;;
  qcow2)
    image-builder build \
      --bootc-default-fs btrfs \
      --output-dir . \
      --output-name "${OUTPUT_NAME}" \
      --bootc-ref "${WORKSTATION_IMAGE}" \
      qcow2
    ;;
  *)
    echo "Unknown format: ${format} (expected iso or qcow2)" >&2
    exit 1
    ;;
esac

test -f "${OUTPUT_NAME}"
ls -lh "${OUTPUT_NAME}"
