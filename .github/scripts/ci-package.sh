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

dnf -y install image-builder podman jq osbuild

if [ -n "${GHCR_TOKEN:-}" ]; then
  podman login ghcr.io -u "${GHCR_USER}" -p "${GHCR_TOKEN}"
else
  echo "WARNING: GHCR_TOKEN is empty — pulls from private GHCR packages will fail" >&2
fi

podman pull "${WORKSTATION_IMAGE}"

# The osbuild cache must NOT live on the container's overlayfs root: the
# ISO build deploys a containers-storage tree inside it, and the overlay
# graph driver refuses to run on top of overlayfs. /work is a bind mount
# of the runner's ext4 disk, which is a supported backing filesystem.
cache_dir="${PWD}/.osbuild-cache"

case "${format}" in
  iso)
    podman pull "${WORKSTATION_ISO_IMAGE}"
    manifest_json="${OUTPUT_NAME%.iso}.osbuild-manifest.json"
    patched_manifest="${OUTPUT_NAME%.iso}.osbuild-manifest.oci.json"
    image-builder build \
      --cache "${cache_dir}" \
      --bootc-default-fs btrfs \
      --output-dir . \
      --output-name "${OUTPUT_NAME}" \
      --with-manifest \
      --bootc-ref "${WORKSTATION_ISO_IMAGE}" \
      --bootc-installer-payload-ref "${WORKSTATION_IMAGE}" \
      bootc-generic-iso
    test -f "${manifest_json}"
    # Embed the payload as an OCI layout (ready-made layer blobs) instead of
    # a containers-storage blob, so bootc install streams it straight to
    # disk instead of re-tarring each layer into RAM. Same manifest patch
    # the local Justfile flow applies.
    bash tools/patch-iso-payload-to-oci.sh "${manifest_json}" "${patched_manifest}"
    rm -rf bootiso
    osbuild \
      --store "${cache_dir}" \
      --output-directory . \
      --export bootiso \
      "${patched_manifest}"
    mv bootiso/install.iso "${OUTPUT_NAME}"
    rm -rf bootiso
    ;;
  qcow2)
    image-builder build \
      --cache "${cache_dir}" \
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
