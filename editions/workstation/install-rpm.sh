#!/usr/bin/env bash
set -euo pipefail

fedora_version="${1:?missing Fedora version}"
url="${2:?missing RPM URL}"
digest="${3:?missing RPM digest}"
rpm_file="$(mktemp --suffix=.rpm)"
trap 'rm -f "${rpm_file}"' EXIT
curl -fsSL "${url}" -o "${rpm_file}"
printf '%s  %s\n' "${digest}" "${rpm_file}" | sha256sum -c -
dnf -y --releasever="${fedora_version}" install "${rpm_file}"
