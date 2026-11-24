#!/usr/bin/env bash
# Runs inside a container of the base image: install one feature on top of it.
set -euo pipefail

work="${1:?missing work directory}"
files="${work}/files"
# shellcheck disable=SC1091
source /usr/lib/os-release

mapfile -t rpms <"${work}/rpms.txt"
mapfile -t packages <"${work}/packages.txt"
dnf_opts=(-y "--releasever=${VERSION_ID}" --setopt=install_weak_deps=False)

if ((${#rpms[@]})); then
  workdir="$(mktemp -d)"
  rpm_files=()
  for entry in "${rpms[@]}"; do
    read -r url digest <<<"${entry}"
    rpm_file="${workdir}/${#rpm_files[@]}.rpm"
    curl -fsSL "${url}" -o "${rpm_file}"
    printf '%s  %s\n' "${digest}" "${rpm_file}" | sha256sum -c -
    rpm_files+=("${rpm_file}")
  done
  dnf "${dnf_opts[@]}" install "${rpm_files[@]}"
  rm -rf "${workdir}"
fi
if ((${#packages[@]})); then
  dnf "${dnf_opts[@]}" install "${packages[@]}"
fi
if [ -d "${files}" ]; then
  tar -C "${files}" --owner=0 --group=0 --numeric-owner -cf - . |
    tar -C / --no-overwrite-dir -xpf -
fi
