#!/usr/bin/env bash
# Sign hardware feature snapshots and gate the installable workstation tags on
# their public verification.
#
#   sysext-release.sh sign <snapshot> <version> <image-digest> <keyring>
#       SYSEXT_SIGNING_KEY (armored secret key) and SYSEXT_SIGNING_PASSPHRASE
#   sysext-release.sh keyring [--allow-pre-feature] <image@digest> <out-file>
#   sysext-release.sh publish --snapshot DIR --candidate REPO@DIGEST --public-repo REPO
#       --version V --version-tag T [--channel-tag T]... --store URI --public-url URL
#       --keyring FILE [--consumer-keyring FILE]...
#   sysext-release.sh promote --public-repo REPO --source-tag T --version V
#       --version-tag T [--channel-tag T]... --store URI --public-url URL --keyring FILE
#       [--consumer-keyring FILE]...
#
# publish claims and uploads the snapshot, verifies it through the public
# endpoint, signs the private candidate for its public identity, and only
# then copies the signature and image before moving release tags.
# promote re-verifies the snapshot and image signature before moving tags.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
publish_py="${here}/sysext-publish.py"
release_py="${here}/../../editions/workstation/sysext/release.py"

die() {
  printf 'sysext-release: %s\n' "$*" >&2
  exit 1
}
log() { printf 'sysext-release: %s\n' "$*"; }

cmd_sign() {
  [ $# -eq 4 ] || die "usage: sign <snapshot> <version> <image-digest> <keyring>"
  local snapshot="$1" version="$2" digest="$3" keyring="$4" fpr
  [ -n "${SYSEXT_SIGNING_KEY:-}" ] || die "SYSEXT_SIGNING_KEY is not set; refusing to publish unsigned extensions"
  GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/sysext-sign.XXXXXX")"
  export GNUPGHOME
  # shellcheck disable=SC2064
  trap "gpgconf --kill all >/dev/null 2>&1 || true; rm -rf '${GNUPGHOME}'" EXIT
  printf '%s' "${SYSEXT_SIGNING_PASSPHRASE:-}" |
    gpg --batch --pinentry-mode loopback --passphrase-fd 0 --import <(printf '%s\n' "${SYSEXT_SIGNING_KEY}") 2>/dev/null
  fpr="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
  [ -n "${fpr}" ] || die "SYSEXT_SIGNING_KEY holds no secret key"
  python3 "${release_py}" assemble "${snapshot}" --version "${version}" --image-digest "${digest}"
  python3 "${release_py}" sign "${snapshot}" --key "${fpr}"
  python3 "${release_py}" verify "${snapshot}" --keyring "${keyring}" --version "${version}" --image-digest "${digest}"
}

cmd_keyring() {
  local allow_pre_feature=false result=0
  if [ "${1:-}" = --allow-pre-feature ]; then
    allow_pre_feature=true
    shift
  fi
  [ $# -eq 2 ] || die "usage: keyring [--allow-pre-feature] <image@digest> <out-file>"
  local image="$1" out="$2" ctr work
  local engine="${CONTAINER_ENGINE:-podman}"
  "${engine}" image exists "${image}" 2>/dev/null || "${engine}" pull --quiet "${image}" >/dev/null
  ctr="$("${engine}" create "${image}" true)"
  mkdir -p "$(dirname "${out}")"
  work="$(mktemp -d "$(dirname "${out}")/.keyring.XXXXXX")"
  if "${engine}" cp "${ctr}:/usr/share/luminusos/sysupdate/luminusos.pgp" "${work}/ring"; then
    mv -T "${work}/ring" "${out}" || result=1
  elif ${allow_pre_feature} && "${engine}" cp "${ctr}:/usr/lib/os-release" "${work}/os-release" &&
    grep -Eq '^IMAGE_VERSION=.+' "${work}/os-release" &&
    ! grep -Eq '^[[:space:]]*SYSEXT_LEVEL[[:space:]]*=' "${work}/os-release"; then
    log "${image} predates hardware features"
    result=42
  else
    log "${image} ships no readable feature keyring"
    result=1
  fi
  rm -rf "${work}"
  "${engine}" rm -f "${ctr}" >/dev/null
  return "${result}"
}

manifest_digest() {
  local raw
  raw="$(mktemp)"
  skopeo inspect --retry-times 3 --raw "docker://$1" >"${raw}" || {
    rm -f "${raw}"
    return 1
  }
  printf 'sha256:%s\n' "$(sha256sum "${raw}" | cut -d' ' -f1)"
  rm -f "${raw}"
}

registry_write() {
  python3 "${publish_py}" lease-check --store "${store}" --min-remaining-seconds 600
  timeout --kill-after=10s 540s "$@"
}

copy_tag() {
  local src="$1" repo="$2" tag="$3" digest="$4" got
  registry_write skopeo copy --retry-times 3 --all --preserve-digests "docker://${src}" "docker://${repo}:${tag}"
  got="$(manifest_digest "${repo}:${tag}")" || die "cannot read back ${repo}:${tag}"
  [ "${got}" = "${digest}" ] || die "${repo}:${tag} resolves to ${got}, expected ${digest}"
  log "${repo}:${tag} -> ${digest}"
}

verify_image_signature() {
  local ref="$1" digest="${1##*@}" key
  [ -n "${COSIGN_PRIVATE_KEY:-}" ] || die "COSIGN_PRIVATE_KEY is not set; cannot verify image signature"
  key="$(mktemp)"
  if ! cosign public-key --key env://COSIGN_PRIVATE_KEY >"${key}"; then
    rm -f "${key}"
    die "cannot derive cosign public key"
  fi
  if ! cosign verify --key "${key}" "${ref}" |
    python3 -c '
import json, sys

repo, digest = sys.argv[1:]
if not any(
    signature["critical"]["identity"]["docker-reference"] == repo
    and signature["critical"]["image"]["docker-manifest-digest"] == digest
    for signature in json.load(sys.stdin)
):
    sys.exit("no verified signature for the public image identity")
' "${public_repo}" "${digest}"; then
    rm -f "${key}"
    die "image signature verification failed"
  fi
  rm -f "${key}"
}

copy_signed_candidate() {
  local digest="$1" sig_tag="${1/:/-}.sig" candidate_repo="${candidate%@*}"
  local sig_digest got
  registry_write cosign sign --yes --key env://COSIGN_PRIVATE_KEY \
    --sign-container-identity "${public_repo}" "${candidate}"
  verify_image_signature "${candidate}"
  sig_digest="$(manifest_digest "${candidate_repo}:${sig_tag}")"
  copy_tag "${candidate_repo}@${sig_digest}" "${public_repo}" "${sig_tag}" "${sig_digest}"
  registry_write skopeo copy --retry-times 3 --all --preserve-digests \
    "docker://${candidate}" "docker://${public_repo}@${digest}"
  got="$(manifest_digest "${public_repo}@${digest}")"
  [ "${got}" = "${digest}" ] || die "public image digest changed: ${got}"
  verify_image_signature "${public_repo}@${digest}"
}

parse_gate_args() {
  snapshot="" candidate="" public_repo="" source_tag="" expected_digest="" boot_check="" version="" version_tag="" store="" public_url=""
  channel_tags=() candidate_keyring="" consumer_keyrings=()
  while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || die "$1 needs a value"
    case "$1" in
      --snapshot) snapshot="$2" ;;
      --candidate) candidate="$2" ;;
      --public-repo) public_repo="$2" ;;
      --source-tag) source_tag="$2" ;;
      --expected-digest) expected_digest="$2" ;;
      --boot-check) boot_check="$2" ;;
      --version) version="$2" ;;
      --version-tag) version_tag="$2" ;;
      --channel-tag) channel_tags+=("$2") ;;
      --store) store="$2" ;;
      --public-url) public_url="$2" ;;
      --keyring)
        [ -z "${candidate_keyring}" ] && [ -n "$2" ] || die "expected exactly one candidate --keyring"
        candidate_keyring="$2"
        ;;
      --consumer-keyring) consumer_keyrings+=("$2") ;;
      *) die "unknown option $1" ;;
    esac
    shift 2
  done
  [ -n "${public_repo}" ] && [ -n "${version}" ] && [ -n "${version_tag}" ] &&
    [ -n "${store}" ] && [ -n "${public_url}" ] && [ -n "${candidate_keyring}" ] ||
    die "missing required option"
}

verify_public_keyrings() {
  local digest="$1" ring
  local args=(--public-url "${public_url}" --version "${version}" --image-digest "${digest}"
    --attempts "${SYSEXT_VERIFY_ATTEMPTS:-6}" --delay "${SYSEXT_VERIFY_DELAY:-20}")
  [ -z "${snapshot}" ] || args+=(--snapshot "${snapshot}")
  for ring in "${candidate_keyring}" "${consumer_keyrings[@]}"; do
    args+=(--keyring "${ring}")
  done
  python3 "${publish_py}" verify-public "${args[@]}"
}

verify_boot() {
  [ -z "${boot_check}" ] && return 0
  env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u COSIGN_PRIVATE_KEY -u COSIGN_PASSWORD \
    "${boot_check}" "$1" "$2"
  python3 "${publish_py}" lease-check --store "${store}"
}

record_channels() {
  local digest="$1" mode="$2" args=()
  [ ${#channel_tags[@]} -gt 0 ] || return 0
  for tag in "${channel_tags[@]}"; do args+=(--tag "${tag}"); done
  python3 "${publish_py}" record-channel "${mode}" --store "${store}" --version "${version}" \
    --image-digest "${digest}" "${args[@]}"
}

cmd_publish() {
  parse_gate_args "$@"
  if [ -z "${SYSEXT_LEASE_OWNER:-}" ]; then
    python3 "${publish_py}" locked-run --store "${store}" -- bash "$0" publish "$@"
    return
  fi
  [ -n "${snapshot}" ] || die "--snapshot is required"
  [[ "${candidate}" =~ ^[^@[:space:]]+@(sha256:[0-9a-f]{64})$ ]] || die "--candidate must be REPO@sha256:..."
  local digest="${BASH_REMATCH[1]}"
  [ "${candidate%@*}" != "${public_repo}" ] || die "the candidate must come from the private candidate repository"

  python3 "${publish_py}" claim "${snapshot}" --store "${store}" --version "${version}" \
    --image-digest "${digest}" --keyring "${candidate_keyring}"
  python3 "${publish_py}" upload "${snapshot}" --store "${store}" --version "${version}" \
    --image-digest "${digest}"
  verify_public_keyrings "${digest}"
  verify_boot "${candidate}" "${digest}"

  [ -n "${COSIGN_PRIVATE_KEY:-}" ] || die "COSIGN_PRIVATE_KEY is not set; refusing to publish unsigned images"
  local tag
  for tag in "${version_tag}" "${channel_tags[@]}"; do
    [[ "${tag}" != sha256-*.sig ]] || die "release tag conflicts with signature reference"
  done
  copy_signed_candidate "${digest}"
  record_channels "${digest}" --pending
  for tag in "${version_tag}" "${channel_tags[@]}"; do
    copy_tag "${public_repo}@${digest}" "${public_repo}" "${tag}" "${digest}"
  done
  record_channels "${digest}" --confirm
}

cmd_promote() {
  parse_gate_args "$@"
  if [ -z "${SYSEXT_LEASE_OWNER:-}" ]; then
    python3 "${publish_py}" locked-run --store "${store}" -- bash "$0" promote "$@"
    return
  fi
  [ -n "${source_tag}" ] || die "--source-tag is required"
  local digest
  digest="$(manifest_digest "${public_repo}:${source_tag}")" || die "cannot resolve ${public_repo}:${source_tag}"
  [ -z "${expected_digest}" ] || [ "${digest}" = "${expected_digest}" ] ||
    die "stable testing tag changed after digest resolution"
  verify_public_keyrings "${digest}"
  verify_image_signature "${public_repo}@${digest}"
  verify_boot "${public_repo}@${digest}" "${digest}"
  local tag
  for tag in "${version_tag}" "${channel_tags[@]}"; do
    [[ "${tag}" != sha256-*.sig ]] || die "release tag conflicts with signature reference"
  done
  record_channels "${digest}" --pending
  for tag in "${version_tag}" "${channel_tags[@]}"; do
    copy_tag "${public_repo}@${digest}" "${public_repo}" "${tag}" "${digest}"
  done
  record_channels "${digest}" --confirm
}

[ $# -ge 1 ] || die "usage: sysext-release.sh sign|keyring|publish|promote ..."
cmd="$1"
shift
case "${cmd}" in
  sign) cmd_sign "$@" ;;
  keyring) cmd_keyring "$@" ;;
  publish) cmd_publish "$@" ;;
  promote) cmd_promote "$@" ;;
  *) die "unknown command ${cmd}" ;;
esac
