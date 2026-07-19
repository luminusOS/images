#!/usr/bin/env bash
# Squash a local buildah image into a single layer, dropping the ostree
# labels inherited from the pre-squash layer stack:
# squash-image.sh <image-ref>
set -euo pipefail

image="$1"
ctr="$(sudo buildah from --pull=never "${image}")"
cleanup() { sudo buildah rm "${ctr}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
sudo buildah config \
  --unsetlabel ostree.final-diffid \
  --unsetlabel ostree.commit \
  "${ctr}"
sudo buildah commit --squash "${ctr}" "${image}"
