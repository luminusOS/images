#!/usr/bin/env bash

SYSTEM_FILES="${ROOT}/editions/workstation/files/system"
INSTALLER_FILES="${ROOT}/editions/workstation/files/installer"

for toml in \
  "${INSTALLER_FILES}/etc/sirius/distro.toml" \
  "${INSTALLER_FILES}/etc/sirius/sirius.toml" \
  "${ROOT}/shared/bootc-image-builder.toml.example"; do
  expect "TOML parses: ${toml#"${ROOT}/"}" \
    python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "${toml}"
done

if python3 -c 'import yaml' >/dev/null 2>&1; then
  while IFS= read -r -d '' yaml; do
    expect "YAML parses: ${yaml#"${ROOT}/"}" \
      python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1], encoding="utf-8"))' "${yaml}"
  done < <(find "${ROOT}" -path "${ROOT}/.git" -prune -o \
    \( -name '*.yml' -o -name '*.yaml' \) -type f -print0)
else
  skip "PyYAML unavailable; CI performs YAML parsing"
fi

while IFS= read -r -d '' json; do
  expect "JSON parses: ${json#"${ROOT}/"}" \
    python3 -c 'import sys, json; json.load(open(sys.argv[1], encoding="utf-8"))' "${json}"
done < <(find "${INSTALLER_FILES}" -name '*.json' -print0)

while IFS= read -r -d '' ini; do
  expect "INI parses: ${ini#"${ROOT}/"}" \
    python3 -c '
import configparser, sys
p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
p.optionxform = str
p.read(sys.argv[1])
' "${ini}"
done < <(find "${INSTALLER_FILES}" \( \
  \( -path '*/systemd/*' -name '*.service' \) -o \
  \( -path '*/systemd/*' -name '*.mount' \) -o \
  \( -path '*/systemd/*' -name '*.conf' \) -o \
  -path '*/repart.d/*.conf' -o \
  -name '*.desktop' -o \
  -path '*/gdm/custom.conf' \
  \) -print0)

expect "Sirius distro config retains the target-image placeholder" \
  grep -q '@WORKSTATION_TARGET_IMAGE@' "${INSTALLER_FILES}/etc/sirius/distro.toml"
expect "Sirius installs from the embedded OCI payload" \
  grep -q 'image = "oci:/usr/lib/luminusos/payload.oci:latest"' \
  "${INSTALLER_FILES}/etc/sirius/distro.toml"
expect "live installer launches Ptyxis" \
  grep -qx 'command = "ptyxis"' "${INSTALLER_FILES}/etc/sirius/sirius.toml"
expect "live installer exposes the terminal fallback" \
  grep -qx 'show_button = true' "${INSTALLER_FILES}/etc/sirius/sirius.toml"

expect "GNOME Initial Setup delegates keyboard selection" python3 -c '
import configparser, sys
p = configparser.ConfigParser(interpolation=None)
p.read(sys.argv[1])
items = lambda key: {v for v in p.get("pages", key, fallback="").split(";") if v}
assert items("skip") == {"software"}
assert items("existing_user_only") == {"language"}
assert "keyboard" not in items("skip") | items("existing_user_only")
' "${SYSTEM_FILES}/etc/gnome-initial-setup/vendor.conf"

repart_dir="${INSTALLER_FILES}/usr/share/sirius/repart.d"
expect "repart.d ships exactly three definitions" \
  test "$(find "${repart_dir}" -name '*.conf' | wc -l)" = 3
expect "Sirius root is Btrfs" grep -qx 'Format=btrfs' "${repart_dir}/10-root.conf"
expect "Sirius /boot is ext4" grep -qx 'Format=ext4' "${repart_dir}/20-boot.conf"
expect "Sirius ESP is vfat" grep -qx 'Format=vfat' "${repart_dir}/30-esp.conf"
expect "image-builder /boot is ext4" \
  awk '/type: "ext4"/ { ext4=1 } ext4 && /mountpoint: "\/boot"/ { found=1 } END { exit !found }' \
  "${SYSTEM_FILES}/usr/lib/image-builder/bootc/disk.yaml"
expect "image-builder provides root, home and var Btrfs subvolumes" \
  awk '/mountpoint: "\/"/ { root=1 } /mountpoint: "\/home"/ { home=1 } /mountpoint: "\/var"/ { var=1 } END { exit !(root && home && var) }' \
  "${SYSTEM_FILES}/usr/lib/image-builder/bootc/disk.yaml"

expect "Flatpak list is sorted and unique" bash -c \
  'cmp -s "$1" <(LC_ALL=C sort -u "$1")' _ "${ROOT}/shared/flatpaks"

expect "system overlay excludes Sirius configuration" test ! -e "${SYSTEM_FILES}/etc/sirius"
expect "system overlay excludes liveuser" test ! -e "${SYSTEM_FILES}/var/lib/AccountsService/users/liveuser"
expect "installer overlay contains Sirius configuration" test -f "${INSTALLER_FILES}/etc/sirius/distro.toml"
expect "installer overlay contains liveuser" test -f "${INSTALLER_FILES}/var/lib/AccountsService/users/liveuser"
expect "workstation consumes only the system overlay" \
  grep -Fq 'COPY editions/workstation/files/system/ /' "${ROOT}/editions/workstation/Containerfile"
expect "installer consumes only the live overlay" \
  grep -Fq 'COPY editions/workstation/files/installer/ /' "${ROOT}/editions/workstation/Containerfile.installer"

# shellcheck disable=SC1091
source "${ROOT}/config/versions.env"
expect "core Containerfile default matches shared Fedora version" \
  grep -qx "ARG fedora_version=${DEFAULT_FEDORA_VERSION}" "${ROOT}/editions/core/Containerfile"
expect "workstation Containerfile default matches shared Fedora version" \
  grep -qx "ARG fedora_version=${DEFAULT_FEDORA_VERSION}" "${ROOT}/editions/workstation/Containerfile"
expect "installer default matches shared Sirius version" \
  grep -qx "ARG sirius_version=${SIRIUS_VERSION}" "${ROOT}/editions/workstation/Containerfile.installer"
