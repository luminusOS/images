#!/usr/bin/env bash
# Add GNOME Shell session modes to an extension's metadata.json:
# aurora-session-modes.sh <metadata.json> <mode>...
set -euo pipefail

metadata="$1"
shift
modes="$(printf '%s\n' "$@" | jq -R . | jq -s .)"
tmp="$(mktemp)"
jq --argjson add "${modes}" \
  '.["session-modes"] = (((.["session-modes"] // ["user"]) + $add) | unique)' \
  "${metadata}" >"${tmp}"
install -m 0644 "${tmp}" "${metadata}"
rm -f "${tmp}"
