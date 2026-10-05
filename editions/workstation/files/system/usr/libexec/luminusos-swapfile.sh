#!/usr/bin/bash
# Create (once) and enable a Btrfs swap file that zswap evicts cold pages to.
# ponytail: fixed size chosen on first boot; replaced by an on-demand grow/shrink daemon.
set -eu

file=/var/swap/swapfile

if [ ! -e "${file}" ]; then
  if [ "$(stat -f -c %T /var)" != btrfs ]; then
    echo "/var is not Btrfs; skipping swap file" >&2
    exit 0
  fi
  mem_mib=$(($(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024))
  size_mib=$((mem_mib / 2))
  [ "${size_mib}" -ge 2048 ] || size_mib=2048
  [ "${size_mib}" -le 16384 ] || size_mib=16384
  mkdir -p "${file%/*}"
  btrfs filesystem mkswapfile --size "${size_mib}m" "${file}"
fi

swapon --show=NAME --noheadings | grep -qx "${file}" || swapon "${file}"
