#!/usr/bin/env bash
set -uexo pipefail

# Common base packages shared across all editions
releasever="$(cat /etc/dnf/vars/releasever 2>/dev/null || true)"
dnf_args=()
if [ -n "${releasever}" ]; then
  dnf_args+=(--releasever="${releasever}")
fi

# Copy static files into the image
if [ -d files ]; then
  find files -mindepth 1 -maxdepth 1 -exec cp -arfT {} / \;
fi

./recover-rpmdb.sh

dnf -y "${dnf_args[@]}" install \
  NetworkManager \
  systemd-udev
