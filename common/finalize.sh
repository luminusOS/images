#!/usr/bin/env bash
set -uexo pipefail

# Final cleanup and commit

if rpm -q rpm-ostree >/dev/null 2>&1; then
  dnf -y remove --no-autoremove rpm-ostree
fi

dnf clean all
rm -rf /var/cache/dnf /var/cache/libdnf5 /tmp/*

# Prune /var — bootc mounts a fresh /var at runtime
rm -rf /var/log/* /var/tmp/*
