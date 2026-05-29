#!/usr/bin/env bash
set -uexo pipefail

# Install Flatpaks from common list
releasever="$(cat /etc/dnf/vars/releasever 2>/dev/null || true)"
dnf_args=()
if [ -n "${releasever}" ]; then
  dnf_args+=(--releasever="${releasever}")
fi
dnf_args+=(--disablerepo="terra*")

if [ -x /ctx/common/recover-rpmdb.sh ]; then
  /ctx/common/recover-rpmdb.sh
fi

# Ensure flatpak is installed
if ! command -v flatpak &>/dev/null; then
  dnf -y "${dnf_args[@]}" install flatpak
fi

# Add Flathub remote
curl --retry 3 -Lo /etc/flatpak/remotes.d/flathub.flatpakrepo https://dl.flathub.org/repo/flathub.flatpakrepo

# Install from list
if [ -f "/ctx/common/flatpaks" ]; then
  xargs flatpak install -y --noninteractive < "/ctx/common/flatpaks"
fi
