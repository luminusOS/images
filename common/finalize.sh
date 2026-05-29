#!/usr/bin/env bash
set -uexo pipefail

# Final cleanup and commit

dnf clean all
rm -rf /var/cache/dnf /var/cache/libdnf5 /tmp/*

# Prune /var — bootc mounts a fresh /var at runtime
rm -rf /var/log/* /var/tmp/*
