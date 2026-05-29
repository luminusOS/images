#!/usr/bin/env bash
set -uexo pipefail

rm -f /var/lib/rpm/.rpm.lock /usr/lib/sysimage/rpm/.rpm.lock || true

if ! rpm --rebuilddb; then
  rebuilt_db="$(find /usr/share -maxdepth 1 -type d -name 'rpmrebuilddb.*' | sort -V | tail -n 1)"
  if [ -z "${rebuilt_db}" ]; then
    exit 1
  fi

  rm -rf /usr/share/rpm
  mv "${rebuilt_db}" /usr/share/rpm
fi

rpm -qa >/dev/null
