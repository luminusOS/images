#!/usr/bin/env bash
# Recover the RPM database when a previous containerized build step left a
# temporary rebuild database behind. Shared by every edition build stage
# that runs dnf.
set -euo pipefail

rm -f /var/lib/rpm/.rpm.lock /usr/lib/sysimage/rpm/.rpm.lock || true
if ! rpm --rebuilddb; then
  rebuilt_db="$(find /usr/share -maxdepth 1 -type d -name 'rpmrebuilddb.*' | sort -V | tail -n 1)"
  [ -n "${rebuilt_db}" ]
  rm -rf /usr/share/rpm
  mv "${rebuilt_db}" /usr/share/rpm
fi
rpm -qa >/dev/null
