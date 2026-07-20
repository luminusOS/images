#!/usr/bin/env bash
# Patch the bootc-generic-iso osbuild manifest so the installer payload is
# embedded as an OCI layout instead of a containers-storage blob.
#
# bootc-generic-iso embeds the payload as a containers-storage blob, which
# forces `bootc install` to re-diff/re-tar each layer into /var/tmp at
# install time (~2.5 GiB). On a live ISO that has nowhere to go but RAM.
# osbuild's skopeo stage also supports an "oci" destination, which stores
# ready-made layer blobs — no re-tar, no large staging area — matching how
# Anaconda embeds ostree-native container payloads.
#
# The destination path carries the ":latest" tag on purpose: the skopeo
# stage passes it straight to `skopeo copy oci:...`, which strips the tag
# from the on-disk directory name and records it as the
# org.opencontainers.image.ref.name annotation in index.json. Without it
# the layout has no ref name and bootc fails with 'no descriptor found for
# reference "latest"' (distro.toml points at the :latest reference).
#
# Usage: patch-iso-payload-to-oci.sh <manifest.json> <patched.json>
set -euo pipefail

manifest_json="$1"
patched_manifest="$2"

skopeo_count="$(jq '[.pipelines[] | select(.name == "os-tree") | .stages[] | select(.type == "org.osbuild.skopeo")] | length' "$manifest_json")"
if [ "$skopeo_count" != "1" ]; then
  echo "Expected exactly 1 org.osbuild.skopeo stage in the 'os-tree' pipeline, found $skopeo_count" >&2
  echo "osbuild/images changed the bootc-generic-iso manifest shape; update tools/patch-iso-payload-to-oci.sh" >&2
  exit 1
fi

jq '
  (.pipelines[] | select(.name == "os-tree") | .stages[] | select(.type == "org.osbuild.skopeo") | .options.destination)
    = {"type": "oci", "path": "/usr/lib/luminusos/payload.oci:latest"}
' "$manifest_json" >"$patched_manifest"
