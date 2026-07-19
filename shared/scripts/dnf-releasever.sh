#!/usr/bin/env bash
# Pin the DNF/YUM releasever so package installs resolve against the
# requested Fedora version regardless of the base image's own default.
set -euo pipefail

version="$1"
mkdir -p /etc/dnf/vars /etc/yum/vars
printf '%s\n' "${version}" >/etc/dnf/vars/releasever
printf '%s\n' "${version}" >/etc/yum/vars/releasever
