#!/usr/bin/env bash
# Print GitHub release notes for a testing build, comparing it with the previous one.
#
# Usage: release-notes.sh NEW_IMAGE NEW_TAG [PREV_IMAGE PREV_TAG]
#
# Package versions come from `rpm -qa` inside each image. RPM_LIST_CMD can
# replace the podman call (tests feed it two fixed lists).
set -euo pipefail

new_image="${1:?Usage: release-notes.sh NEW_IMAGE NEW_TAG [PREV_IMAGE PREV_TAG]}"
new_tag="${2:?missing NEW_TAG}"
prev_image="${3:-}"
prev_tag="${4:-}"

# Packages that matter most to a desktop OS; one row each.
major=(
  kernel-core linux-firmware mesa-dri-drivers gnome-shell mutter nautilus
  bootc systemd NetworkManager pipewire flatpak podman
)

rpm_list() {
  if [ -n "${RPM_LIST_CMD:-}" ]; then
    $RPM_LIST_CMD "$1"
  else
    podman run --rm --network none --entrypoint rpm "$1" -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n'
  fi | LC_ALL=C sort
}

new_list="$(mktemp)"
prev_list="$(mktemp)"
trap 'rm -f "${new_list}" "${prev_list}"' EXIT
rpm_list "${new_image}" >"${new_list}"
if [ -n "${prev_image}" ]; then
  rpm_list "${prev_image}" >"${prev_list}"
fi

# Fields arrive separated by \037; keep commit text from breaking the table.
commit_rows() {
  awk -F'\037' '{ gsub(/[`<>]/, "", $2); gsub(/\|/, "\\|", $2); printf "| %s | %s | %s |\n", $1, $2, $3 }'
}

version_in() { awk -v n="$2" '$1 == n { print $2; exit }' "$1"; }

echo "This is an automatically generated changelog for release ${new_tag}."
echo
if [ -n "${prev_tag}" ]; then
  echo "From previous testing version ${prev_tag} there have been the following changes."
else
  echo "This is the first automatic testing release, so there is nothing to compare against."
fi
echo
echo "### Major packages"
echo
echo "| Name | Version | Previous |"
echo "| --- | --- | --- |"
for name in "${major[@]}"; do
  now="$(version_in "${new_list}" "${name}")"
  [ -n "${now}" ] || continue
  before="$(version_in "${prev_list}" "${name}")"
  if [ -n "${before}" ] && [ "${before}" != "${now}" ]; then
    echo "| ${name} | ${now} | ${before} |"
  else
    echo "| ${name} | ${now} | |"
  fi
done

if [ -n "${prev_image}" ]; then
  changed="$(LC_ALL=C comm -13 "${prev_list}" "${new_list}" | awk '{ print $1 }' | sort -u | wc -l)"
  echo
  echo "${changed} packages were added or updated in total."
fi

echo
echo "### Commits"
echo
if [ -n "${prev_tag}" ] && git rev-parse --verify --quiet "refs/tags/${prev_tag}^{commit}" >/dev/null; then
  commits="$(git log --no-merges --format='%h%x1f%s%x1f%an' "refs/tags/${prev_tag}..HEAD" | commit_rows || true)"
else
  commits="$(git log --no-merges -n 10 --format='%h%x1f%s%x1f%an' | commit_rows || true)"
fi
if [ -n "${commits}" ]; then
  echo "| Hash | Subject | Author |"
  echo "| --- | --- | --- |"
  printf '%s\n' "${commits}"
else
  echo "No repository changes since the previous release; the Fedora base was updated."
fi

echo
echo "### How to rebase"
echo
echo '```'
echo "sudo bootc switch ${new_image#docker://}"
echo '```'
echo
# backticks are literal markdown
# shellcheck disable=SC2016
echo 'Already on this branch? `sudo bootc upgrade` is enough.'
