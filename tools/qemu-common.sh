#!/usr/bin/env bash
# Shared, side-effect-free helpers for local and CI QEMU launchers.

qemu_disk_format() {
  case "$1" in
    *.qcow2) printf '%s\n' qcow2 ;;
    *) printf '%s\n' raw ;;
  esac
}

qemu_resolve_artifact() {
  local root="$1" explicit_path="$2" pointer="$3" pattern="$4" legacy_path="$5"
  local candidate newest="" newest_mtime=-1 candidate_mtime
  local -a candidates=()

  if [ -n "${explicit_path}" ]; then
    if [ ! -f "${explicit_path}" ]; then
      echo "Artifact does not exist: ${explicit_path}" >&2
      return 1
    fi
    realpath "${explicit_path}"
    return
  fi

  if [ -f "${pointer}" ]; then
    candidate="$(<"${pointer}")"
    if [ -f "${candidate}" ]; then
      candidates+=("${candidate}")
    else
      echo "Ignoring stale artifact pointer: ${candidate}" >&2
    fi
  fi
  while IFS= read -r -d '' candidate; do
    candidates+=("${candidate}")
  done < <(find "${root}" -maxdepth 1 -type f -name "${pattern}" -print0)

  for candidate in "${candidates[@]}"; do
    candidate_mtime="$(stat -c '%Y' "${candidate}")"
    if [ "${candidate_mtime}" -gt "${newest_mtime}" ]; then
      newest="${candidate}"
      newest_mtime="${candidate_mtime}"
    fi
  done
  if [ -n "${newest}" ]; then
    realpath "${newest}"
    return
  fi
  if [ -n "${legacy_path}" ] && [ -f "${legacy_path}" ]; then
    realpath "${legacy_path}"
    return
  fi

  echo "No artifact matching ${pattern} found in ${root}" >&2
  return 1
}

qemu_resolve_ovmf() {
  local code_candidate vars_candidate
  local -a code_candidates=()
  local -a vars_candidates=()

  if [ -n "${QEMU_OVMF_CODE:-}" ]; then
    code_candidates+=("${QEMU_OVMF_CODE}")
  fi
  if [ -n "${QEMU_OVMF_VARS_TEMPLATE:-}" ]; then
    vars_candidates+=("${QEMU_OVMF_VARS_TEMPLATE}")
  fi
  code_candidates+=(
    /usr/share/OVMF/OVMF_CODE_4M.fd
    /usr/share/OVMF/OVMF_CODE.fd
    /usr/share/edk2/ovmf/OVMF_CODE.fd
  )
  vars_candidates+=(
    /usr/share/OVMF/OVMF_VARS_4M.fd
    /usr/share/OVMF/OVMF_VARS.fd
    /usr/share/edk2/ovmf/OVMF_VARS.fd
  )

  QEMU_OVMF_CODE_RESOLVED=""
  QEMU_OVMF_VARS_TEMPLATE_RESOLVED=""
  for code_candidate in "${code_candidates[@]}"; do
    if [ -f "${code_candidate}" ]; then
      QEMU_OVMF_CODE_RESOLVED="${code_candidate}"
      break
    fi
  done
  for vars_candidate in "${vars_candidates[@]}"; do
    if [ -f "${vars_candidate}" ]; then
      QEMU_OVMF_VARS_TEMPLATE_RESOLVED="${vars_candidate}"
      break
    fi
  done

  if [ -z "${QEMU_OVMF_CODE_RESOLVED}" ] || [ -z "${QEMU_OVMF_VARS_TEMPLATE_RESOLVED}" ]; then
    echo "Unable to find OVMF code and variables firmware" >&2
    return 1
  fi
}
