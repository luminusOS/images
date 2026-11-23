#!/usr/bin/env bash
# Build one hardware feature extension against an exact workstation image.
#
#   build-sysext.sh <feature-dir> <image@sha256:digest> <out-dir>
#
# Environment:
#   CONTAINER_ENGINE      podman (default) or another podman-compatible CLI
#   SYSEXT_BUILDER_IMAGE  image with erofs-utils, xz, python3 and gnupg2;
#                         built from sysext/Containerfile.builder when absent
#   SYSEXT_BUILD_NETWORK  network for the package install step (default: host
#                         default; use "none" for features without packages)
set -euo pipefail

usage() {
  echo "usage: $0 <feature-dir> <image@sha256:digest> <out-dir>" >&2
  exit 2
}
die() {
  printf 'build-sysext: %s\n' "$*" >&2
  exit 1
}

[ $# -eq 3 ] || usage
feature_dir="$(cd "$1" && pwd -P)" || die "feature directory $1 not found"
image="$2"
out_dir="$3"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
engine="${CONTAINER_ENGINE:-podman}"

[[ "${image}" =~ ^[^@[:space:]]+@(sha256:[0-9a-f]{64})$ ]] || die "image must be referenced by digest (name@sha256:...)"
image_digest="${BASH_REMATCH[1]}"

manifest="$(bash "${here}/sysext/feature-manifest.sh" json "${feature_dir}")"
feature_id="$(jq -r .id <<<"${manifest}")"

"${engine}" image inspect "${image}" >/dev/null 2>&1 || die "image ${image} is not in local storage"
inspect="$("${engine}" image inspect "${image}" --format json)"
jq -e --arg d "${image_digest}" '.[0] | (.Digest == $d) or ((.RepoDigests // []) | any(endswith("@" + $d)))' \
  <<<"${inspect}" >/dev/null || die "local image does not carry digest ${image_digest}"
label_version="$(jq -r '.[0].Labels["org.opencontainers.image.version"] // ""' <<<"${inspect}")"
case "$(jq -r '.[0].Architecture' <<<"${inspect}")" in
  amd64) architecture=x86-64 ;;
  arm64) architecture=arm64 ;;
  *) die "unsupported image architecture" ;;
esac

os_release="$("${engine}" run --rm --network none --entrypoint cat "${image}" /usr/lib/os-release)"
os_value() {
  local v
  v="$(sed -n "s/^$1=//p" <<<"${os_release}" | tail -n1)"
  v="${v%\"}"
  printf '%s' "${v#\"}"
}
image_version="$(os_value IMAGE_VERSION)"
sysext_level="$(os_value SYSEXT_LEVEL)"
os_id="$(os_value ID)"
os_version_id="$(os_value VERSION_ID)"

[[ "${image_version}" =~ ^[0-9A-Za-z.+~-]+$ ]] || die "image has no usable IMAGE_VERSION"
[ "${image_version}" = "${label_version}" ] ||
  die "IMAGE_VERSION ${image_version} differs from the OCI version label '${label_version}'"
[ "${image_version}" = "${sysext_level}" ] ||
  die "IMAGE_VERSION ${image_version} differs from SYSEXT_LEVEL '${sysext_level}'"
[ -n "${os_id}" ] && [ -n "${os_version_id}" ] || die "image os-release lacks ID or VERSION_ID"

builder="${SYSEXT_BUILDER_IMAGE:-localhost/luminusos-sysext-builder:${os_version_id}}"
if ! "${engine}" image inspect "${builder}" >/dev/null 2>&1; then
  "${engine}" build --tag "${builder}" --build-arg "fedora_version=${os_version_id}" \
    --file "${here}/sysext/Containerfile.builder" "${here}/sysext"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/build-sysext.XXXXXX")"
suffix="$(basename "${work}" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')"
container="luminusos-sysext-${feature_id}-${suffix}"
final_image="localhost/luminusos-sysext-final:${feature_id}-${suffix}"
cleanup() {
  "${engine}" rm -f "${container}" >/dev/null 2>&1 || true
  "${engine}" rmi -f "${final_image}" >/dev/null 2>&1 || true
  rm -rf "${work}"
}
trap cleanup EXIT

printf '%s\n' "${manifest}" >"${work}/manifest.json"
jq -r '.packages[]' <<<"${manifest}" >"${work}/packages.txt"
jq -r '.rpms[]' <<<"${manifest}" >"${work}/rpms.txt"
mkdir -p "${work}/files" "${out_dir}"
[ -d "${feature_dir}/files" ] && cp -a "${feature_dir}/files/." "${work}/files/"
network=()
[ -n "${SYSEXT_BUILD_NETWORK:-}" ] && network=(--network "${SYSEXT_BUILD_NETWORK}")

echo "build-sysext: installing ${feature_id} on ${image}"
"${engine}" run --name "${container}" "${network[@]}" \
  --security-opt label=disable \
  --volume "${here}/sysext/install-feature.sh:/run/sysext/install-feature.sh:ro" \
  --volume "${work}:/run/sysext/work:ro" \
  --entrypoint bash "${image}" \
  /run/sysext/install-feature.sh /run/sysext/work

"${engine}" diff --format json "${container}" >"${work}/diff.json"
"${engine}" commit --quiet "${container}" "${final_image}" >/dev/null

echo "build-sysext: checking ${feature_id} against the base image"
"${engine}" run --rm --network none \
  --security-opt label=disable \
  --mount "type=image,source=${image},destination=/base" \
  --mount "type=image,source=${final_image},destination=/final" \
  --volume "${here}/sysext:/run/sysext/bin:ro" \
  --volume "${work}:/run/sysext/work:ro" \
  --volume "$(cd "${out_dir}" && pwd -P):/run/sysext/out" \
  "${builder}" \
  python3 /run/sysext/bin/guard.py \
  --base /base --final /final \
  --diff /run/sysext/work/diff.json \
  --manifest /run/sysext/work/manifest.json \
  --stage /var/tmp/stage --out /run/sysext/out \
  --version "${image_version}" --image-digest "${image_digest}" \
  --os-id "${os_id}" --os-version-id "${os_version_id}" \
  --architecture "${architecture}" \
  --file-contexts /base/etc/selinux/targeted/contexts/files/file_contexts
