#!/usr/bin/env bash

SYSTEM_FILES="${ROOT}/editions/workstation/files/system"
INSTALLER_FILES="${ROOT}/editions/workstation/files/installer"

expect "LuminusOS schema overrides keep final filename precedence" \
  test -f "${SYSTEM_FILES}/usr/share/glib-2.0/schemas/zz-99-luminusos.gschema.override"

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

for files_root in "${SYSTEM_FILES}" "${INSTALLER_FILES}"; do
  while IFS= read -r -d '' json; do
    expect "JSON parses: ${json#"${ROOT}/"}" \
      python3 -c 'import sys, json; json.load(open(sys.argv[1], encoding="utf-8"))' "${json}"
  done < <(find "${files_root}" -name '*.json' -print0)
done

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

expect "GNOME Initial Setup enables Aurora in a user-derived shell mode" python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    mode = json.load(f)
assert mode["parentMode"] == "user"
assert "aurora-shell@luminusos.github.io" in mode["enabledExtensions"]
assert mode["hasOverview"] is False
assert mode["hasRunDialog"] is False
' "${SYSTEM_FILES}/usr/share/gnome-shell/modes/initial-setup.json"

expect "live installer disables the Aurora menu" \
  grep -qx 'module-aurora-menu=false' \
  "${INSTALLER_FILES}/etc/dconf/db/local.d/00-iso-live-mode"
expect "GNOME Initial Setup uses its LuminusOS dconf database" \
  grep -qx 'system-db:luminusos-initial-setup' \
  "${SYSTEM_FILES}/etc/dconf/profile/gnome-initial-setup"
expect "GNOME Initial Setup preserves the upstream dconf defaults" \
  grep -qx 'file-db:/usr/share/gnome-initial-setup/initial-setup-dconf-defaults' \
  "${SYSTEM_FILES}/etc/dconf/profile/gnome-initial-setup"
expect "GNOME Initial Setup disables the Aurora menu" \
  grep -qx 'module-aurora-menu=false' \
  "${SYSTEM_FILES}/etc/dconf/db/luminusos-initial-setup.d/00-aurora-shell"

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

expect "Flatpak list is sorted and unique" env LC_ALL=C sort -cu "${ROOT}/shared/flatpaks"

expect "system overlay excludes Sirius configuration" test ! -e "${SYSTEM_FILES}/etc/sirius"
expect "system overlay excludes liveuser" test ! -e "${SYSTEM_FILES}/var/lib/AccountsService/users/liveuser"
expect "installer overlay contains Sirius configuration" test -f "${INSTALLER_FILES}/etc/sirius/distro.toml"
expect "installer overlay contains liveuser" test -f "${INSTALLER_FILES}/var/lib/AccountsService/users/liveuser"
expect "workstation consumes only the system overlay" \
  grep -Fq 'COPY editions/workstation/files/system/ /' "${ROOT}/editions/workstation/Containerfile"
expect "installer consumes only the live overlay" \
  grep -Fq 'COPY editions/workstation/files/installer/ /' "${ROOT}/editions/workstation/Containerfile.installer"

expect_failure "Containerfiles do not duplicate shared version defaults" \
  grep -EH '^ARG (fedora_version|aurora_shell_version|sirius_version)=' \
  "${ROOT}/ci/Containerfile" \
  "${ROOT}/editions/core/Containerfile" \
  "${ROOT}/editions/workstation/Containerfile" \
  "${ROOT}/editions/workstation/Containerfile.installer"
