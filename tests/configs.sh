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
  disk_yaml="${SYSTEM_FILES}/usr/lib/image-builder/bootc/disk.yaml"
  expect "disk layout associates /boot and subvolumes with their filesystems" \
    python3 "${ROOT}/tests/validate-disk-layout.py" "${disk_yaml}"
  python3 -c 'import sys, yaml; d=yaml.safe_load(open(sys.argv[1])); p=d["partition_table"]["partitions"]; p[1]["payload"]["type"]="ext4"; p[2]["payload"]["type"]="btrfs"; yaml.safe_dump(d, open(sys.argv[2], "w"))' \
    "${disk_yaml}" "${TEST_TMP}/invalid-disk.yaml"
  expect_failure "disk layout rejects btrfs boot even with another ext4 partition" \
    python3 "${ROOT}/tests/validate-disk-layout.py" "${TEST_TMP}/invalid-disk.yaml"
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

expect "Fedora bootc digest is pinned" \
  grep -Eq '^FEDORA_BOOTC_DIGEST=sha256:[0-9a-f]{64}$' "${ROOT}/config/versions.env"
expect "Aurora Shell artifact digest is pinned" \
  grep -Eq '^AURORA_SHELL_SHA256=[0-9a-f]{64}$' "${ROOT}/config/versions.env"
expect "Sirius release and RPM versions are pinned separately" \
  sh -c 'grep -Eq "^SIRIUS_VERSION=[0-9]+\\.[0-9]+\\.[0-9]+$" "$1" && grep -Eq "^SIRIUS_RPM_VERSION=[0-9]+\\.[0-9]+\\.[0-9]+$" "$1"' \
  _ "${ROOT}/config/versions.env"

expect "zswap kargs enable compressed swap" \
  grep -q 'zswap.enabled=1' "${SYSTEM_FILES}/usr/lib/bootc/kargs.d/20-luminusos-zswap.toml"
expect "elastic-swap release digest is pinned" \
  sh -c 'grep -Eq "^ELASTIC_SWAP_VERSION=[0-9]+\\.[0-9]+\\.[0-9]+$" "$1" && grep -Eq "^ELASTIC_SWAP_SHA256=[0-9a-f]{64}$" "$1"' \
  _ "${ROOT}/config/versions.env"
expect "ddcutil-service COPR RPM digest is pinned" \
  grep -Eq '^DDCUTIL_SERVICE_SHA256=[0-9a-f]{64}$' "${ROOT}/config/versions.env"
expect "AppImage thumbnailer RPM digest is pinned" \
  grep -Eq '^APPIMAGE_THUMBNAILER_SHA256=[0-9a-f]{64}$' "${ROOT}/config/versions.env"
expect "elastic-swap daemon is enabled by the build" \
  grep -qx 'systemctl enable elastic-swap.service' "${ROOT}/editions/workstation/build.sh"
expect "interim swap file service and script are gone" \
  sh -c 'test ! -e "$1/usr/lib/systemd/system/luminusos-swapfile.service" && test ! -e "$1/usr/libexec/luminusos-swapfile.sh"' \
  _ "${SYSTEM_FILES}"
expect "the interim fixed swap file is removed on boot" \
  grep -qx 'r! /var/swap/swapfile - - - - -' "${SYSTEM_FILES}/usr/lib/tmpfiles.d/luminusos-swap-migrate.conf"
expect "memory-pressure kill policy ships with systemd-oomd" \
  sh -c 'grep -q "^      systemd-oomd-defaults \\\\$" "$1/editions/workstation/Containerfile" && grep -q "ManagedOOMMemoryPressure=kill" "$1/editions/workstation/Containerfile"' \
  _ "${ROOT}"
expect "oomd kills the biggest swap user among the applications only" \
  sh -c 'f="$1/usr/lib/systemd/user/app.slice.d/20-luminusos-oomd-swap.conf"; grep -qx "ManagedOOMSwap=kill" "$f" && ! ls "$1/usr/lib/systemd/user/session.slice.d" "$1/usr/lib/systemd/user/slice.d" 2>/dev/null | grep -q oomd-swap' \
  _ "${SYSTEM_FILES}"
expect "systemd-oomd is enabled by the build" \
  grep -qx 'systemctl enable systemd-oomd.service' "${ROOT}/editions/workstation/build.sh"
expect "elastic-swap digest reaches every workstation build" \
  sh -c 'grep -q "elastic_swap_sha256=" "$1/.just/build.just" && grep -q "elastic_swap_sha256=" "$1/.github/workflows/containers.yml" && grep -q "elastic_swap_version=" "$1/.just/build.just" && grep -q "elastic_swap_version=" "$1/.github/workflows/containers.yml"' \
  _ "${ROOT}"
expect "the swap daemon and its prepare step stay off inside containers" \
  sh -c 'for u in elastic-swap elastic-swap-prepare; do grep -qx "ConditionVirtualization=!container" "$1/usr/lib/systemd/system/$u.service.d/10-luminusos.conf" || exit 1; done' \
  _ "${SYSTEM_FILES}"
expect "the live ISO runs neither the swap daemon nor its prepare step" \
  sh -c 'for u in elastic-swap elastic-swap-prepare; do grep -qx "ConditionKernelCommandLine=!rd.live.image" "$1/usr/lib/systemd/system/$u.service.d/10-live-iso.conf" || exit 1; done' \
  _ "${INSTALLER_FILES}"

discovery="${SYSTEM_FILES}/usr/lib/luminusos/sysupdate-discovery"
expect "no transfer is installed for stock systemd-sysupdate" test ! -e "${SYSTEM_FILES}/usr/lib/sysupdate.d"
expect "the discovery probe is disabled" grep -qx 'Enabled=no' "${discovery}/luminusos-discovery-probe.feature"
expect "the discovery probe transfer is gated on the probe and stays local" sh -c '
  grep -qx "Features=luminusos-discovery-probe" "$1" && grep -c "^Type=regular-file$" "$1" | grep -qx 2 && ! grep -q "url-" "$1"' \
  _ "${discovery}/00-luminusos-discovery-probe.transfer"
expect "luminus-features is the runtime CLI" \
  test "$(readlink "${SYSTEM_FILES}/usr/bin/luminus-features")" = ../libexec/luminusos/sysext
expect "the feature keyring ships at its dedicated path" test -f "${SYSTEM_FILES}/usr/share/luminusos/sysupdate/luminusos.pgp"
expect "the runtime parses as Python" python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' \
  "${SYSTEM_FILES}/usr/libexec/luminusos/sysext"
expect "download units cannot reach the live sysext refresh socket" sh -c '
  for u in luminusos-sysext-sync.service luminusos-sysext-update.service; do
    grep -qx "InaccessiblePaths=-/run/systemd/sysupdate/notify" "$1/$u" || exit 1
  done' _ "${SYSTEM_FILES}/usr/lib/systemd/system"
expect "activation runs before the merge with a 10 s deadline" sh -c '
  f="$1/luminusos-sysext-activate.service"
  grep -qx "DefaultDependencies=no" "$f" && grep -qx "TimeoutStartSec=10s" "$f" &&
  grep -q "^Before=.*systemd-sysext.service" "$f" &&
  grep -qx "RequiresMountsFor=/var/lib/luminusos/sysext" "$f"' _ "${SYSTEM_FILES}/usr/lib/systemd/system"
while IFS= read -r -d '' ini; do
  expect "INI parses: ${ini#"${ROOT}/"}" python3 -c '
import configparser, sys
p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
p.optionxform = str
p.read(sys.argv[1])
' "${ini}"
done < <(find "${SYSTEM_FILES}/usr/lib/systemd/system" "${discovery}" \
  \( -name 'luminusos-*' -o -name '*luminusos*.conf' -o -name '*.feature' -o -name '*.transfer' \) -type f -print0)

sysupdate=/usr/lib/systemd/systemd-sysupdate
if [ -x "${sysupdate}" ]; then
  sysupdate_defs="${TEST_TMP}/sysupdate"
  mkdir -p "${sysupdate_defs}/transfer" "${sysupdate_defs}/tx"
  bash "${ROOT}/editions/workstation/sysext/feature-manifest.sh" generate \
    "${ROOT}/editions/workstation/features" "${sysupdate_defs}/gen"
  cp -a "${discovery}/." "${sysupdate_defs}/gen/usr/lib/luminusos/sysupdate-discovery/"
  expect "discovery lists every feature and the probe offline" sh -c '
    out="$("$1" --definitions="$2" features --json=short)" &&
    for f in "$3"/*.feature; do
      id="$(basename "$f" .feature)"
      printf "%s" "$out" | jq -e --arg id "$id" ".features | index(\$id)" >/dev/null || exit 1
    done' _ "${sysupdate}" "${sysupdate_defs}/gen/usr/lib/luminusos/sysupdate-discovery" \
    "${sysupdate_defs}/gen/usr/lib/luminusos/sysupdate-discovery"
  for template in "${sysupdate_defs}"/gen/usr/lib/luminusos/sysupdate/*.transfer.in; do
    id="$(basename "${template}" .transfer.in)"
    sed -e 's|@BASE_URL@|https://download.luminusos.org/sysext|' -e 's|@VERSION@|45.1|' \
      -e "s|@TXDIR@|${sysupdate_defs}/tx/|" "${template}" >"${sysupdate_defs}/transfer/50-${id}.transfer"
    expect "rendered transfer template parses cleanly: ${id}" sh -c '
      out="$("$1" --definitions="$2" --offline list 2>&1)" && ! printf "%s" "$out" | grep -q ignoring' \
      _ "${sysupdate}" "${sysupdate_defs}/transfer"
  done
else
  skip "systemd-sysupdate unavailable; tests/sysext-lab.sh parses discovery and templates"
fi
