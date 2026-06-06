#!/usr/bin/env bash
set -uexo pipefail

# Final cleanup and commit

if rpm -q rpm-ostree >/dev/null 2>&1; then
  dnf -y remove --no-autoremove rpm-ostree
fi

# OCI whiteout files (.wh.*) from layer deletions are not processed by the
# squashfs generator and appear as real files — dbus-broker fatally rejects them.
find /usr/share/dbus-1/ -name '.wh.*' -delete 2>/dev/null || true

dnf clean all
rm -rf /var/cache/dnf /var/cache/libdnf5 /tmp/*

# Prune /var — bootc mounts a fresh /var at runtime
rm -rf /var/log/* /var/tmp/*
