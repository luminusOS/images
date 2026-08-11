#!/usr/bin/env bash
# Package one workstation artifact from the prebuilt GHCR containers.
# Runs inside a privileged Fedora container; never builds containers itself.
#
# Usage: ci-package.sh iso|qcow2
# Env:   WORKSTATION_IMAGE       payload image ref (ghcr, qcow2 only)
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

# The osbuild cache must NOT live on the container's overlayfs root: the
# ISO build deploys a containers-storage tree inside it, and the overlay
# graph driver refuses to run on top of overlayfs. /work is a bind mount
# of the runner's ext4 disk, which is a supported backing filesystem.
cache_dir="${PWD}/.osbuild-cache"
export IMAGE_BUILDER_CACHE="${cache_dir}"

case "${format}" in
  iso)
    # The installer payload is already embedded in the live root as an OCI
    # layout (see Containerfile.installer), so only the live root is needed.
    podman pull "${WORKSTATION_ISO_IMAGE}"
    ./tools/package-artifact.sh iso "${WORKSTATION_ISO_IMAGE}" "${OUTPUT_NAME}"
    ;;
  qcow2)
    podman pull "${WORKSTATION_IMAGE}"
    ./tools/package-artifact.sh qcow2 "${WORKSTATION_IMAGE}" "${OUTPUT_NAME}"
    ;;
  *)
    echo "Unknown format: ${format} (expected iso or qcow2)" >&2
    exit 1
    ;;
esac

test -f "${OUTPUT_NAME}"
ls -lh "${OUTPUT_NAME}"
