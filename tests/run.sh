#!/usr/bin/env bash
# Repo test suite: unit tests for the shared build scripts plus static
# validation of every config file that ships in the images. Needs bash,
# jq, and python3 — runs identically on a dev host and in CI.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSTATION_FILES="${ROOT}/editions/workstation/files"
fails=0

pass() { echo "ok   - $1"; }
fail() {
  echo "FAIL - $1"
  fails=$((fails + 1))
}
expect() { # expect <description> <command...>
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

for script in "${ROOT}"/shared/scripts/*.sh "${ROOT}"/tools/*.sh \
  "${ROOT}"/.github/scripts/*.sh "${ROOT}"/editions/workstation/build.sh; do
  expect "bash -n $(basename "${script}")" bash -n "${script}"
done

printf 'NAME="Fedora"\nVERSION_ID=44\n' >"${tmp}/os-release"
OS_RELEASE_FILE="${tmp}/os-release" \
  bash "${ROOT}/shared/scripts/os-release-set.sh" \
  NAME "LuminusOS" PRETTY_NAME "Luminus OS 44"
expect "os-release-set replaces existing keys" \
  grep -qx 'NAME="LuminusOS"' "${tmp}/os-release"
expect "os-release-set appends missing keys" \
  grep -qx 'PRETTY_NAME="Luminus OS 44"' "${tmp}/os-release"
expect "os-release-set leaves other keys alone" \
  grep -qx 'VERSION_ID=44' "${tmp}/os-release"

echo '{"uuid":"x","session-modes":["user"]}' >"${tmp}/metadata.json"
bash "${ROOT}/shared/scripts/aurora-session-modes.sh" \
  "${tmp}/metadata.json" live-installer initial-setup
expect "aurora-session-modes merges modes sorted+unique" \
  jq -e '."session-modes" == ["initial-setup","live-installer","user"]' \
  "${tmp}/metadata.json"

echo '{"uuid":"x"}' >"${tmp}/metadata2.json"
bash "${ROOT}/shared/scripts/aurora-session-modes.sh" \
  "${tmp}/metadata2.json" initial-setup
expect "aurora-session-modes defaults missing list to user" \
  jq -e '."session-modes" == ["initial-setup","user"]' "${tmp}/metadata2.json"

for toml in "${WORKSTATION_FILES}/etc/sirius/distro.toml" \
  "${WORKSTATION_FILES}/etc/sirius/sirius.toml" \
  "${ROOT}/shared/bootc-image-builder.toml.example"; do
  expect "TOML parses: ${toml#"${ROOT}"/}" \
    python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "${toml}"
done

expect "distro.toml has @WORKSTATION_TARGET_IMAGE@ placeholder" \
  grep -q '@WORKSTATION_TARGET_IMAGE@' "${WORKSTATION_FILES}/etc/sirius/distro.toml"
expect "distro.toml points bootc install at the embedded OCI payload" \
  grep -q 'image = "oci:/usr/lib/luminusos/payload.oci:latest"' "${WORKSTATION_FILES}/etc/sirius/distro.toml"
expect "live installer launches Ptyxis" \
  grep -qx 'command = "ptyxis"' "${WORKSTATION_FILES}/etc/sirius/sirius.toml"
expect "live installer exposes the terminal fallback button" \
  grep -qx 'show_button = true' "${WORKSTATION_FILES}/etc/sirius/sirius.toml"
expect "GNOME Initial Setup delegates keyboard choice to the user" \
  python3 -c '
import configparser, sys
p = configparser.ConfigParser(interpolation=None)
p.read(sys.argv[1])
items = lambda key: {v for v in p.get("pages", key, fallback="").split(";") if v}
assert items("skip") == {"software"}
assert items("existing_user_only") == {"language"}
assert "keyboard" not in items("skip") | items("existing_user_only")
' "${WORKSTATION_FILES}/etc/gnome-initial-setup/vendor.conf"
expect "workstation enables GNOME Initial Setup from a static file" \
  grep -qx 'InitialSetupEnable=true' "${WORKSTATION_FILES}/etc/gdm/workstation.conf"
expect "workstation disables GNOME Software search from a static file" \
  grep -qx 'DefaultDisabled=true' \
  "${WORKSTATION_FILES}/usr/share/gnome-shell/search-providers/org.gnome.Software-search-provider.ini"
expect "GDM uses the Luminus logo" \
  grep -Fqx "logo='/usr/share/pixmaps/luminusos-gdm-logo.png'" \
  "${WORKSTATION_FILES}/usr/share/glib-2.0/schemas/99-install-mode.gschema.override"
expect "workstation installs the configured GDM logo" \
  grep -Fqx \
  'COPY editions/workstation/files/usr/share/sirius/logo.png /usr/share/pixmaps/luminusos-gdm-logo.png' \
  "${ROOT}/editions/workstation/Containerfile"
expect "workstation build script does not write static heredoc files" \
  sh -c '! grep -Eq "cat[[:space:]]*>" "$1"' sh \
  "${ROOT}/editions/workstation/build.sh"
expect "Containerfiles copy repository files declaratively" \
  sh -c '! grep -Eq "/wfiles|install[^[:cntrl:]]*/wfiles|cat[^[:cntrl:]]*/wfiles" "$@"' \
  sh \
  "${ROOT}/editions/workstation/Containerfile" \
  "${ROOT}/editions/workstation/Containerfile.installer"

while IFS= read -r json; do
  expect "JSON parses: ${json#"${ROOT}"/}" \
    python3 -c 'import sys, json; json.load(open(sys.argv[1]))' "${json}"
done < <(find "${WORKSTATION_FILES}" -name '*.json')

while IFS= read -r ini; do
  expect "INI parses: ${ini#"${ROOT}"/}" \
    python3 -c '
import sys, configparser
p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
p.optionxform = str
p.read(sys.argv[1])
' "${ini}"
done < <(find "${WORKSTATION_FILES}" \
  \( -path '*/systemd/*' -name '*.service' \) -o \
  \( -path '*/systemd/*' -name '*.mount' \) -o \
  \( -path '*/systemd/*' -name '*.conf' \) -o \
  -path '*/repart.d/*.conf' -o \
  -name '*.desktop' -o \
  -path '*/gdm/custom.conf')

repart_dir="${WORKSTATION_FILES}/usr/share/sirius/repart.d"
expect "repart.d ships exactly 3 definitions" \
  test "$(find "${repart_dir}" -name '*.conf' | wc -l)" = 3
expect "repart root is btrfs" grep -q 'Format=btrfs' "${repart_dir}/10-root.conf"
expect "repart esp exists" test -f "${repart_dir}/30-esp.conf"

if command -v just >/dev/null 2>&1; then
  expect "Justfile parses" just --justfile "${ROOT}/Justfile" --list
else
  echo "skip - just not installed"
fi

echo
if [ "${fails}" -gt 0 ]; then
  echo "${fails} test(s) failed"
  exit 1
fi
echo "all tests passed"
