#!/usr/bin/env bash
# Container lab for hardware feature extensions: builds the dummy feature
# against a bootc base, checks the build guards end to end, signs a release
# and fetches it with systemd-sysupdate, and evaluates discovery offline.
#
# Environment:
#   SYSEXT_LAB_FROM   bootc image to derive the lab base from (default: the
#                     current Fedora bootc tag; the lab tests the pipeline,
#                     not a reproducible base)
#   CONTAINER_ENGINE  podman (default)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${ROOT}/tests/test-lib.sh"
# shellcheck disable=SC1091
source "${ROOT}/config/versions.env"

engine="${CONTAINER_ENGINE:-podman}"
command -v "${engine}" >/dev/null || {
  echo "sysext-lab: ${engine} not found" >&2
  exit 1
}
fedora="${DEFAULT_FEDORA_VERSION}"
lab_from="${SYSEXT_LAB_FROM:-quay.io/fedora/fedora-bootc:${fedora}}"
lab_version="${fedora}.19700101.1"
builder="localhost/luminusos-sysext-builder:${fedora}"
sysext="${ROOT}/editions/workstation/sysext"
build="${ROOT}/editions/workstation/build-sysext.sh"
LAB="$(mktemp -d "${TMPDIR:-/tmp}/sysext-lab.XXXXXX")"
images=()
cleanup() {
  for image in "${images[@]}"; do "${engine}" rmi -f "${image}" >/dev/null 2>&1; done
  "${engine}" unshare rm -rf "${LAB}" 2>/dev/null || rm -rf "${LAB}"
}
trap cleanup EXIT

lab_image() {
  local tag="$1" level="$2" label="$3" ctx
  ctx="${LAB}/ctx-${tag}"
  mkdir -p "${ctx}"
  cat >"${ctx}/Containerfile" <<EOF
FROM ${lab_from}
RUN sed -i '/^\(IMAGE_VERSION\|SYSEXT_LEVEL\)=/d' /usr/lib/os-release && \\
    printf 'IMAGE_VERSION="%s"\n' "${lab_version}" >>/usr/lib/os-release && \\
    if [ -n "${level}" ]; then printf 'SYSEXT_LEVEL="%s"\n' "${level}" >>/usr/lib/os-release; fi && \\
    mkdir -p /usr/share/luminusos-lab && echo image-owned >/usr/share/luminusos-lab/marker
LABEL org.opencontainers.image.version="${label}"
EOF
  "${engine}" build -q -t "localhost/luminusos-sysext-lab:${tag}" "${ctx}" >/dev/null || return 1
  images+=("localhost/luminusos-sysext-lab:${tag}")
  printf 'localhost/luminusos-sysext-lab@%s\n' \
    "$("${engine}" image inspect --format '{{.Digest}}' "localhost/luminusos-sysext-lab:${tag}")"
}

expect_failure_with() {
  local description="$1" needle="$2" output
  shift 2
  if output="$("$@" 2>&1)"; then
    fail "${description}"
  elif grep -Fq -- "${needle}" <<<"${output}"; then
    pass "${description}"
  else
    fail "${description}"
    printf '       missing %q in: %s\n' "${needle}" "$(tail -5 <<<"${output}")"
  fi
}

base="$(lab_image base "${lab_version}" "${lab_version}")" || {
  echo "sysext-lab: cannot build the lab base from ${lab_from}" >&2
  exit 1
}
digest="${base#*@}"
nolevel="$(lab_image nolevel "" "${lab_version}")"
mismatch="$(lab_image mismatch "${lab_version}" "${fedora}.19700101.2")"

out="${LAB}/out"
export SYSEXT_BUILD_NETWORK=none
expect "the dummy feature builds from the lab base" \
  bash "${build}" "${ROOT}/editions/workstation/features/dummy" "${base}" "${out}"
expect_failure_with "the build refuses an image without SYSEXT_LEVEL" "differs from SYSEXT_LEVEL" \
  bash "${build}" "${ROOT}/editions/workstation/features/dummy" "${nolevel}" "${LAB}/bad"
expect_failure_with "the build refuses a version label that differs from IMAGE_VERSION" "differs from the OCI version label" \
  bash "${build}" "${ROOT}/editions/workstation/features/dummy" "${mismatch}" "${LAB}/bad"
expect_failure_with "the build refuses an image referenced by tag" "referenced by digest" \
  bash "${build}" "${ROOT}/editions/workstation/features/dummy" localhost/luminusos-sysext-lab:base "${LAB}/bad"

fixture() {
  local name="$1" dir="${LAB}/features/$1"
  rm -rf "${dir}"
  mkdir -p "${LAB}/features"
  cp -a "${ROOT}/editions/workstation/features/dummy" "${dir}"
  sed -i "s/^FEATURE_ID=.*/FEATURE_ID=${name}/" "${dir}/feature.env"
  find "${dir}/files" -depth -name '*dummy*' -execdir sh -c 'mv "$1" "$(echo "$1" | sed "s/dummy/'"${name}"'/g")"' _ {} \;
  find "${dir}/files" -type f -exec sed -i "s/dummy/${name}/g" {} +
  find "${dir}/files" -type l | while read -r l; do
    ln -sfn "$(readlink "${l}" | sed "s/dummy/${name}/g")" "${l}"
  done
  printf '%s\n' "${dir}"
}
dir="$(fixture rpmfile)" && mkdir -p "${dir}/files/usr/bin" && echo replaced >"${dir}/files/usr/bin/bash" && chmod 0755 "${dir}/files/usr/bin/bash"
expect_failure_with "the build rejects a feature that replaces an RPM file" "/usr/bin/bash: base path content changed" bash "${build}" "${dir}" "${base}" "${LAB}/bad"
dir="$(fixture imagefile)" && mkdir -p "${dir}/files/usr/share/luminusos-lab" &&
  echo replaced >"${dir}/files/usr/share/luminusos-lab/marker"
expect_failure_with "the build rejects a feature that replaces an image file" "/usr/share/luminusos-lab/marker: base path content changed" bash "${build}" "${dir}" "${base}" "${LAB}/bad"
dir="$(fixture undersymlink)" && mkdir -p "${dir}/files/usr/sbin" && echo x >"${dir}/files/usr/sbin/luminusos-x"
expect_failure_with "the build rejects a path under a base symlink" "/usr/sbin: base path retyped" bash "${build}" "${dir}" "${base}" "${LAB}/bad"
dir="$(fixture second)"
expect "an independent second feature builds" bash "${build}" "${dir}" "${base}" "${out}"

in_builder() {
  "${engine}" run --rm --security-opt label=disable --network none \
    --volume "${sysext}:/run/sysext/bin:ro" --volume "${LAB}:/lab" "$@"
}
expect "the release step assembles both features" in_builder "${builder}" \
  python3 /run/sysext/bin/release.py assemble /lab/out --version "${lab_version}" --image-digest "${digest}"

keys='set -e
export GNUPGHOME=/lab/gpg-$1
mkdir -p -m 0700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "lab-$1@test.invalid" ed25519 sign never 2>/dev/null
gpg --batch --export "lab-$1@test.invalid" >/lab/keyring-$1.pgp'
expect "lab signing keys are generated" in_builder "${builder}" sh -c "${keys}" _ a
in_builder "${builder}" sh -c "${keys}" _ b >/dev/null 2>&1
expect "the release step signs the snapshot" in_builder --env GNUPGHOME=/lab/gpg-a "${builder}" \
  python3 /run/sysext/bin/release.py sign /lab/out --key lab-a@test.invalid
verify() {
  in_builder "${builder}" python3 /run/sysext/bin/release.py verify "/lab/$1" \
    --keyring "/lab/keyring-$2.pgp" --version "${lab_version}" --image-digest "$3" --raw
}
expect "the signed snapshot verifies online and offline" verify out a "${digest}"
expect_failure_with "verification rejects another image digest" "descriptor names image" verify out a "sha256:$(printf '%064d' 0)"
expect_failure_with "verification rejects an untrusted signer" "signature does not verify" verify out b "${digest}"
cp -a "${out}" "${LAB}/corrupt"
printf 'x' >>"${LAB}/corrupt/luminusos-dummy_${lab_version}.raw"
expect_failure_with "verification rejects a corrupted offline payload" "payload hash does not match" verify corrupt a "${digest}"

expect "the extension-release file matches the lab base os-release" in_builder \
  --mount "type=image,source=${base},destination=/base" "${builder}" sh -c '
    set -e; mkdir /x; fsck.erofs --extract=/x --no-xattrs "/lab/out/luminusos-dummy_$1.raw" >/dev/null
    rel="/x/usr/lib/extension-release.d/extension-release.luminusos-dummy_$1"
    . /base/usr/lib/os-release
    grep -qx "ID=${ID}" "$rel"; grep -qx "VERSION_ID=${VERSION_ID}" "$rel"
    grep -qx "SYSEXT_LEVEL=${SYSEXT_LEVEL}" "$rel"; test "${SYSEXT_LEVEL}" = "$1"
    grep -qx EXTENSION_RELOAD_MANAGER=1 "$rel"; ! grep -q "^EXTENSION_\(RELOAD_OR_\)\?RESTART_UNITS=" "$rel"' _ "${lab_version}"

mkdir -p "${LAB}/disc"
bash "${sysext}/feature-manifest.sh" generate "${ROOT}/editions/workstation/features" "${LAB}/disc" &&
  cp -a "${ROOT}/editions/workstation/files/system/usr/lib/luminusos/sysupdate-discovery/." \
    "${LAB}/disc/usr/lib/luminusos/sysupdate-discovery/"
fetch='set -e
v=$1 sums=${2:-SHA256SUMS.gpg}
cd /lab/out && cp "$sums" /tmp/sig && mkdir -p /tmp/srv/$v && cp ./*.raw.xz SHA256SUMS /tmp/srv/$v/ && cp /tmp/sig /tmp/srv/$v/SHA256SUMS.gpg
(cd /tmp/srv && exec python3 -m http.server 8080 --bind 127.0.0.1 >/tmp/http.log 2>&1) &
for _ in $(seq 50); do python3 -c "import socket; socket.create_connection((\"127.0.0.1\", 8080))" 2>/dev/null && break; sleep 0.1; done
mkdir -p /tmp/defs /tmp/tx
sed -e "s|@BASE_URL@|http://127.0.0.1:8080|" -e "s|@VERSION@|$v|" -e "s|@TXDIR@|/tmp/tx|" \
  /lab/disc/usr/lib/luminusos/sysupdate/dummy.transfer.in >/tmp/defs/50-dummy.transfer
SYSTEMD_OPENPGP_KEYRING=/lab/keyring-a.pgp /usr/lib/systemd/systemd-sysupdate \
  --definitions=/tmp/defs --verify=yes update "${3:-$v}"
want=$(python3 -c "import json,sys; print(json.load(open(\"release.json\"))[\"features\"][\"dummy\"][\"raw_sha256\"])")
echo "$want  /tmp/tx/luminusos-dummy_$v.raw" | sha256sum -c -
! grep -q luminusos-second /tmp/http.log'
lab_fetch() { "${engine}" run --rm --security-opt label=disable --volume "${LAB}:/lab" "${builder}" sh -c "${fetch}" _ "$@"; }
expect "systemd-sysupdate fetches the signed explicit version through the rendered template" lab_fetch "${lab_version}"
in_builder --env GNUPGHOME=/lab/gpg-b "${builder}" sh -c \
  'gpg --batch --yes --detach-sign -o /lab/out/SHA256SUMS.gpg-b /lab/out/SHA256SUMS' >/dev/null 2>&1
expect_failure "systemd-sysupdate refuses a checksum list signed by another key" lab_fetch "${lab_version}" SHA256SUMS.gpg-b
expect_failure "systemd-sysupdate refuses a version that is not published" lab_fetch "${lab_version}" SHA256SUMS.gpg "${fedora}.19700101.9"

dmi() {
  mkdir -p "${LAB}/dmi-$1"
  printf '%s\n' "$2" >"${LAB}/dmi-$1/sys_vendor"
  printf '%s\n' "$3" >"${LAB}/dmi-$1/product_name"
  "${engine}" run --rm --network none --security-opt label=disable \
    --volume "${LAB}/disc/usr/lib/luminusos/sysupdate-discovery:/d:ro" \
    --volume "${LAB}/dmi-$1:/sys/devices/virtual/dmi/id:ro" "${builder}" \
    /usr/lib/systemd/systemd-sysupdate --definitions=/d features "${@:4}" --json=short
}
dmi_check() {
  local filter="$1"
  shift
  dmi "$@" | jq -e "${filter}"
}
expect "offline discovery lists the dummy feature and the probe" dmi_check \
  '.features | index("dummy") and index("luminusos-discovery-probe")' list 'Apple Inc.' 'MacBookPro11,4'
expect "discovery suggests the feature when both firmware lines match" dmi_check \
  '.suggested == true and .enabled == false' both 'Apple Inc.' 'MacBookPro11,5' dummy
expect "discovery does not suggest it when only the vendor matches" dmi_check \
  '.suggested == false' vendor 'Apple Inc.' 'MacBookPro12,1' dummy
expect "discovery does not suggest it when only the product matches" dmi_check \
  '.suggested == false' product 'ASUSTeK COMPUTER INC.' 'MacBookPro11,4' dummy
expect "discovery keeps the probe disabled" dmi_check \
  '.enabled == false' probe 'Apple Inc.' 'MacBookPro11,4' luminusos-discovery-probe

mkdir -p "${LAB}/pubfeatures"
cp -a "${ROOT}/editions/workstation/features/dummy" "${LAB}/features/second" "${LAB}/pubfeatures/"
bash "${sysext}/feature-manifest.sh" generate "${LAB}/pubfeatures" "${LAB}/pubmeta" &&
  cp -a "${ROOT}/editions/workstation/files/system/usr/lib/luminusos/sysupdate-discovery/." \
    "${LAB}/pubmeta/usr/lib/luminusos/sysupdate-discovery/"
mkdir -p "${LAB}/bin"
printf '#!/bin/sh\ncat /lab/bootc.json\n' >"${LAB}/bin/bootc"
chmod +x "${LAB}/bin/bootc"
printf 'ID=fedora\nVERSION_ID=%s\nIMAGE_VERSION="%s"\nSYSEXT_LEVEL="%s"\n' "${fedora}" "${lab_version}" "${lab_version}" \
  >"${LAB}/os-release"
mkdir -p "${LAB}/dmi-wrapper"
printf 'Apple Inc.\n' >"${LAB}/dmi-wrapper/sys_vendor"
printf 'MacBookPro11,4\n' >"${LAB}/dmi-wrapper/product_name"
wrapper='set -e
mkdir -p /tmp/srv/$1 /etc/luminusos
cp /lab/out/*.raw.xz /lab/out/SHA256SUMS /lab/out/SHA256SUMS.gpg /lab/out/release.json /lab/out/release.json.gpg /tmp/srv/$1/
printf "{\"base_url\": \"http://127.0.0.1:8080\"}\n" >/etc/luminusos/sysext.json
(cd /tmp/srv && exec python3 -m http.server 8080 --bind 127.0.0.1 >/tmp/http.log 2>&1) &
for _ in $(seq 50); do python3 -c "import socket; socket.create_connection((\"127.0.0.1\", 8080))" 2>/dev/null && break; sleep 0.1; done
shift
for id in "$@"; do luminus-features enable "$id" >/dev/null 2>&1 || { echo "enable $id failed"; exit 1; }; done
echo "selection: $(tr "\n" " " </var/lib/luminusos/sysext/selection 2>/dev/null)"
rc=0; /usr/libexec/luminusos/sysext update booted 2>/tmp/wrapper.log || rc=$?; echo "wrapper rc=$rc"
echo "requests:"; grep -oE "\"[A-Z]+ [^ ]*" /tmp/http.log | tr -d "\"" | sort | uniq -c || true
echo "committed:"; find /var/lib/luminusos/sysext/builds -type f -name "*.raw" -exec sha256sum {} + || true
echo "status:"; cat /var/lib/luminusos/sysext/status.json 2>/dev/null || true
echo "list:"; luminus-features list
cat /tmp/wrapper.log >&2'
run_wrapper() {
  local digest_for_bootc="$1"
  shift
  jq -n --arg v "${lab_version}" --arg d "${digest_for_bootc}" \
    '{status: {booted: {image: {version: $v, imageDigest: $d}}, staged: null}}' >"${LAB}/bootc.json"
  "${engine}" run --rm --privileged --security-opt label=disable \
    --volume "${LAB}:/lab" \
    --volume "${ROOT}/editions/workstation/files/system/usr/libexec/luminusos/sysext:/usr/libexec/luminusos/sysext:ro" \
    --volume "${ROOT}/editions/workstation/files/system/usr/libexec/luminusos/sysext:/usr/bin/luminus-features:ro" \
    --volume "${LAB}/pubmeta/usr/lib/luminusos/sysupdate:/usr/lib/luminusos/sysupdate:ro" \
    --volume "${LAB}/pubmeta/usr/lib/luminusos/sysupdate-discovery:/usr/lib/luminusos/sysupdate-discovery:ro" \
    --volume "${LAB}/keyring-a.pgp:/usr/share/luminusos/sysupdate/luminusos.pgp:ro" \
    --volume "${LAB}/os-release:/usr/lib/os-release:ro" \
    --volume "${LAB}/bin/bootc:/usr/local/bin/bootc:ro" \
    --volume "${LAB}/dmi-wrapper:/sys/devices/virtual/dmi/id:ro" \
    "${builder}" bash -c "${wrapper}" _ "${lab_version}" "$@"
}
dummy_raw="$(jq -r '.features.dummy.raw_sha256' "${out}/release.json")"
wrapper_none="$(run_wrapper "${digest}" 2>&1)"
expect "the wrapper with nothing selected makes no request" sh -c '
  printf "%s\n" "$1" | grep -qx "wrapper rc=0" &&
  [ "$(printf "%s\n" "$1" | sed -n "/^requests:/,/^committed:/p" | grep -cE "^ *[0-9]+ [A-Z]+ ")" = 0 ]' _ "${wrapper_none}"
expect "the CLI lists real features and hides the discovery probe" sh -c '
  printf "%s\n" "$1" | sed -n "/^list:/,\$p" | grep -q "^dummy	disabled suggested	" &&
  printf "%s\n" "$1" | sed -n "/^list:/,\$p" | grep -q "^second	" &&
  ! printf "%s\n" "$1" | grep -q "^luminusos-discovery-probe"' _ "${wrapper_none}"
wrapper_one="$(run_wrapper "${digest}" dummy 2>&1)"
expect "the wrapper with one selected feature commits only it, with the signed hash" sh -c '
  printf "%s\n" "$1" | grep -qx "wrapper rc=0" &&
  printf "%s\n" "$1" | grep -q "^$2  /var/lib/luminusos/sysext/builds/$3/$4/luminusos-dummy_$3.raw$" &&
  [ "$(printf "%s\n" "$1" | grep -c "/var/lib/luminusos/sysext/builds/.*\.raw$")" = 1 ]' \
  _ "${wrapper_one}" "${dummy_raw}" "${lab_version}" "${digest}"
expect "the wrapper fetches the selected payload and never the unselected one" sh -c '
  r="$(printf "%s\n" "$1" | sed -n "/^requests:/,/^committed:/p")"
  printf "%s\n" "$r" | grep -q "GET /$2/luminusos-dummy_$2.raw.xz" &&
  printf "%s\n" "$r" | grep -q "GET /$2/release.json.gpg" &&
  ! printf "%s\n" "$r" | grep -q "luminusos-second"' _ "${wrapper_one}" "${lab_version}"
wrapper_digest="$(run_wrapper "sha256:$(printf '%064d' 5)" dummy 2>&1)"
expect "the wrapper rejects a descriptor for another image digest before any payload" sh -c '
  r="$(printf "%s\n" "$1" | sed -n "/^requests:/,/^committed:/p")"
  printf "%s\n" "$1" | grep -qx "wrapper rc=2" &&
  printf "%s\n" "$r" | grep -q "GET /$2/release.json" &&
  ! printf "%s\n" "$r" | grep -q "\.raw\.xz" &&
  [ "$(printf "%s\n" "$1" | grep -c "/var/lib/luminusos/sysext/builds/.*\.raw$")" = 0 ] &&
  printf "%s\n" "$1" | grep -q "descriptor names"' _ "${wrapper_digest}" "${lab_version}"
[ -n "${SYSEXT_LAB_LOGDIR:-}" ] && printf "%s\n" "${wrapper_none}" "${wrapper_one}" "${wrapper_digest}" >"${SYSEXT_LAB_LOGDIR}/wrapper-transcripts.txt"

echo
if [ "${fails}" -gt 0 ]; then
  echo "${fails} lab test(s) failed; ${skips} skipped"
  exit 1
fi
echo "all lab tests passed; ${skips} skipped"
