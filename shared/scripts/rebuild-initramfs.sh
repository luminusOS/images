#!/usr/bin/env bash
# Rebuild the newest kernel's initramfs with the lucent Plymouth theme.
# Extra arguments are passed through to dracut — the installer image adds
# the live ISO modules with: rebuild-initramfs.sh --add "plymouth dmsquash-live"
set -euo pipefail

KVER=$(kernel-install list --json pretty 2>/dev/null |
  jq -r '.[] | select(.has_kernel == true) | .version' |
  head -n1)
if [ -z "${KVER}" ]; then
  KVER=$(ls -1 /lib/modules | tail -n1)
fi
plymouth-set-default-theme lucent
DRACUT_NO_XATTR=1 dracut -v -f --zstd --reproducible --no-hostonly "$@" \
  "/usr/lib/modules/${KVER}/initramfs.img" "${KVER}"
