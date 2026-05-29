#!/usr/bin/env bash
set -uexo pipefail

# Clean up after each build layer to keep image size down

dnf clean all
rm -rf /var/cache/dnf/* /var/cache/libdnf5/* /tmp/* || true
