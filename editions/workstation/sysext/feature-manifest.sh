#!/usr/bin/env bash
# Validate hardware feature manifests and generate their image metadata.
#
#   feature-manifest.sh json <feature-dir>
#   feature-manifest.sh generate <features-root> <dest-root>
#
# The selector pattern must stay identical to UDEV_SELECTOR_RE in the
# runtime, which re-validates LUMINUSOS_UDEV_TRIGGER= before replaying it.
set -euo pipefail

readonly ID_RE='^[a-z][a-z0-9]{1,30}$'
readonly RESERVED_IDS=" features sysext discovery probe core workstation "
readonly PACKAGE_RE='^[A-Za-z0-9][A-Za-z0-9._+-]*$'
readonly RPM_RE='^https://[^[:space:]]+[[:space:]]+[0-9a-f]{64}$'
readonly UDEV_SELECTOR_RE='^--(subsystem|sysname|attr|property|tag)-match=[A-Za-z0-9_.:*?=/+-]+$'
readonly MIB_RE='^[1-9][0-9]{0,3}$'
readonly KNOWN_KEYS=" FEATURE_ID FEATURE_DESCRIPTION FEATURE_SUGGEST_ON_FIRMWARE FEATURE_PACKAGES FEATURE_RPMS FEATURE_UDEV_TRIGGER FEATURE_SIZE_BUDGET_MIB FEATURE_EXPANDED_BUDGET_MIB "
readonly MAX_BUDGET_MIB=1024

die() {
  printf 'feature-manifest: %s\n' "$*" >&2
  exit 1
}

json_array() {
  if (($#)); then
    printf '%s\0' "$@" | jq -Rsc 'split("\u0000")[:-1]'
  else
    printf '[]\n'
  fi
}

plain_line() {
  [[ -n "$1" && "$1" != *[[:cntrl:]]* && "$1" != *\\* ]]
}

manifest_json() {
  local dir="${1:?missing feature directory}" file
  dir="${dir%/}"
  file="${dir}/feature.env"
  [ -f "${file}" ] || die "${file}: missing"
  (
    unset "${!FEATURE_@}"
    # shellcheck disable=SC1090
    source "${file}"

    local name
    for name in "${!FEATURE_@}"; do
      [[ "${KNOWN_KEYS}" == *" ${name} "* ]] || die "${file}: unknown key ${name}"
    done
    for name in FEATURE_SUGGEST_ON_FIRMWARE FEATURE_PACKAGES FEATURE_RPMS FEATURE_UDEV_TRIGGER; do
      if declare -p "${name}" >/dev/null 2>&1; then
        [[ "$(declare -p "${name}")" == "declare -a"* ]] || die "${file}: ${name} must be an array"
      else
        declare -ga "${name}=()"
      fi
    done

    local id="${FEATURE_ID:-}"
    [[ "${id}" =~ ${ID_RE} ]] || die "${file}: FEATURE_ID must match ${ID_RE}"
    [[ "${RESERVED_IDS}" != *" ${id} "* ]] || die "${file}: FEATURE_ID ${id} is reserved"
    [ "${id}" = "$(basename "${dir}")" ] || die "${file}: FEATURE_ID ${id} differs from its directory name"

    local description="${FEATURE_DESCRIPTION:-}"
    plain_line "${description}" || die "${file}: FEATURE_DESCRIPTION must be one plain line"
    [ "${#description}" -le 120 ] || die "${file}: FEATURE_DESCRIPTION exceeds 120 characters"

    local entry
    for entry in "${FEATURE_SUGGEST_ON_FIRMWARE[@]}"; do
      plain_line "${entry}" || die "${file}: FEATURE_SUGGEST_ON_FIRMWARE entries must be plain lines"
    done
    for entry in "${FEATURE_PACKAGES[@]}"; do
      [[ "${entry}" =~ ${PACKAGE_RE} ]] || die "${file}: invalid package name '${entry}'"
    done
    for entry in "${FEATURE_RPMS[@]}"; do
      [[ "${entry}" =~ ${RPM_RE} ]] || die "${file}: FEATURE_RPMS entries are 'https-URL SHA256'"
    done
    for entry in "${FEATURE_UDEV_TRIGGER[@]}"; do
      [[ "${entry}" =~ ${UDEV_SELECTOR_RE} ]] || die "${file}: udev selector '${entry}' is not a scoped match"
    done

    local compressed="${FEATURE_SIZE_BUDGET_MIB:-}" expanded
    [[ "${compressed}" =~ ${MIB_RE} ]] || die "${file}: FEATURE_SIZE_BUDGET_MIB must be a positive integer"
    expanded="${FEATURE_EXPANDED_BUDGET_MIB:-$((compressed * 4))}"
    [[ "${expanded}" =~ ${MIB_RE} ]] || die "${file}: FEATURE_EXPANDED_BUDGET_MIB must be a positive integer"
    [ "${expanded}" -le "${MAX_BUDGET_MIB}" ] || die "${file}: expanded budget exceeds ${MAX_BUDGET_MIB} MiB"
    [ "${expanded}" -ge "${compressed}" ] || die "${file}: expanded budget is smaller than the compressed budget"

    if [ -e "${dir}/files" ]; then
      [ -d "${dir}/files" ] && [ ! -L "${dir}/files" ] || die "${dir}/files must be a directory"
      local top
      while IFS= read -r -d '' top; do
        case "${top##*/}" in
          usr | opt) [ -d "${top}" ] && [ ! -L "${top}" ] || die "${top} must be a directory" ;;
          *) die "${top}: features may only ship /usr and /opt content" ;;
        esac
      done < <(find "${dir}/files" -mindepth 1 -maxdepth 1 -print0)
    fi

    jq -nc \
      --arg id "${id}" \
      --arg description "${description}" \
      --argjson suggest "$(json_array "${FEATURE_SUGGEST_ON_FIRMWARE[@]}")" \
      --argjson packages "$(json_array "${FEATURE_PACKAGES[@]}")" \
      --argjson rpms "$(json_array "${FEATURE_RPMS[@]}")" \
      --argjson udev_trigger "$(json_array "${FEATURE_UDEV_TRIGGER[@]}")" \
      --argjson compressed "${compressed}" \
      --argjson expanded "${expanded}" \
      '{id: $id, description: $description, suggest_on_firmware: $suggest,
        packages: $packages, rpms: $rpms, udev_trigger: $udev_trigger,
        compressed_budget_mib: $compressed, expanded_budget_mib: $expanded}'
  )
}

write_feature() {
  local manifest="$1" dest="$2" id
  id="$(jq -r .id <<<"${manifest}")"
  {
    printf '[Feature]\n'
    printf 'Description=%s\n' "$(jq -r .description <<<"${manifest}")"
    jq -r '.suggest_on_firmware[] | "SuggestOnFirmware=" + .' <<<"${manifest}"
  } >"${dest}/usr/lib/luminusos/sysupdate-discovery/${id}.feature"
  # @BASE_URL@, @VERSION@ and @TXDIR@ are filled in by the runtime wrapper;
  # systemd-sysupdate never reads this template directly.
  cat >"${dest}/usr/lib/luminusos/sysupdate/${id}.transfer.in" <<EOF
[Transfer]
Verify=yes

[Source]
Type=url-file
Path=@BASE_URL@/@VERSION@/
MatchPattern=luminusos-${id}_@v.raw.xz

[Target]
Type=regular-file
Path=@TXDIR@
MatchPattern=luminusos-${id}_@v.raw
Mode=0444
EOF
}

generate() {
  local root="${1:?missing features root}" dest="${2:?missing destination root}" dir manifest
  install -d -m 0755 "${dest}/usr/lib/luminusos/sysupdate-discovery" "${dest}/usr/lib/luminusos/sysupdate"
  [ -d "${root}" ] || return 0
  while IFS= read -r -d '' dir; do
    manifest="$(manifest_json "${dir}")"
    write_feature "${manifest}" "${dest}"
  done < <(find "${root}" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
}

case "${1:-}" in
  json) manifest_json "${2:-}" ;;
  generate) generate "${2:-}" "${3:-}" ;;
  *) die "usage: $0 json <feature-dir> | generate <features-root> <dest-root>" ;;
esac
