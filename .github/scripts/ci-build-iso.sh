#!/usr/bin/env bash
# Build the LuminusOS workstation ISO inside a privileged Fedora container.
# Runs the same Justfile recipes used for local builds, so CI and local
# flows cannot drift.
set -euxo pipefail

dnf -y install buildah findutils gawk image-builder jq just podman sudo

just build core
just build workstation

# The core image is baked into the workstation layers by now; drop it to
# reclaim scratch space before the ISO root build + osbuild run.
core_tag="$(cat .test/last-core-tag)"
sudo buildah rmi "localhost/luminusos:${core_tag}" || true

just package workstation iso

ls -lh ./*.iso
