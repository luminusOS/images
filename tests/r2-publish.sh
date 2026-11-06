#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/dist" "$tmp/store/testing/testing-45.20261030" "$tmp/store/stable/keep"
printf old >"$tmp/store/testing/testing-45.20261030/old.iso"
printf keep >"$tmp/store/stable/keep/keep.iso"
printf iso >"$tmp/dist/luminusos-workstation-testing-45.20261031.iso"
printf qcow >"$tmp/dist/luminusos-workstation-testing-45.20261031.qcow2"
cat >"$tmp/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
case "${args[1]}" in
  cp)
    src="${args[2]}"; dst="${args[3]}"
    if [[ "${FAIL_QCOW:-0}" == 1 && "$src" == *.qcow2 ]]; then exit 1; fi
    if [[ "$dst" == s3://* ]]; then
      dst="$STORE/${dst#s3://bucket/}"
      mkdir -p "$(dirname "$dst")"
      cp "$src" "$dst"
    else
      cp "$STORE/${src#s3://bucket/}" "$dst"
    fi
    ;;
  sync)
    src="${args[2]}"; dst="${args[3]}"
    mkdir -p "$STORE/${dst#s3://bucket/}"
    cp "$src"/* "$STORE/${dst#s3://bucket/}"
    ;;
  rm)
    path="$STORE/${args[2]#s3://bucket/}"
    rm -rf "$path"
    ;;
  ls)
    find "$STORE/testing" -mindepth 1 -maxdepth 1 -type d -printf '                           PRE %f/\n'
    ;;
esac
EOF
chmod +x "$tmp/bin/aws"
cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
url="${!#}"
if [[ "${FAIL_DOWNLOAD:-0}" == 1 ]]; then exit 22; fi
if [[ "${CORRUPT_QCOW:-0}" == 1 && "$url" == *.qcow2 ]]; then
  printf corrupt
else
  cat "$STORE/${url#https://download.luminusos.org/}"
fi
EOF
chmod +x "$tmp/bin/curl"
PATH="$tmp/bin:$PATH" STORE="$tmp/store" R2_BUCKET=bucket R2_ENDPOINT=https://example.invalid \
  bash "$root/.github/scripts/publish-r2.sh" testing testing-45.20261031 "$tmp/dist"
test -f "$tmp/store/testing/testing-45.20261031/luminusos-workstation-testing-45.20261031.iso"
test -f "$tmp/store/testing/testing-45.20261031/luminusos-workstation-testing-45.20261031.qcow2"
test ! -e "$tmp/store/testing/testing-45.20261030"
test -f "$tmp/store/stable/keep/keep.iso"
python3 - "$tmp/store/testing/latest.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    release = json.load(f)
assert release['version'] == 'testing-45.20261031'
assert release['assets']['iso'].startswith('https://download.luminusos.org/testing/')
assert release['assets']['qcow2'].endswith('.qcow2')
PY
mkdir -p "$tmp/store/testing/testing-45.20261030"
printf old >"$tmp/store/testing/testing-45.20261030/old.iso"
if PATH="$tmp/bin:$PATH" STORE="$tmp/store" R2_BUCKET=bucket R2_ENDPOINT=https://example.invalid FAIL_QCOW=1 \
  bash "$root/.github/scripts/publish-r2.sh" testing testing-45.20261031 "$tmp/dist"; then
  exit 1
fi
test -f "$tmp/store/testing/testing-45.20261030/old.iso"
if PATH="$tmp/bin:$PATH" STORE="$tmp/store" R2_BUCKET=bucket R2_ENDPOINT=https://example.invalid FAIL_DOWNLOAD=1 \
  bash "$root/.github/scripts/publish-r2.sh" testing testing-45.20261031 "$tmp/dist"; then
  exit 1
fi
test -f "$tmp/store/testing/testing-45.20261030/old.iso"
if PATH="$tmp/bin:$PATH" STORE="$tmp/store" R2_BUCKET=bucket R2_ENDPOINT=https://example.invalid CORRUPT_QCOW=1 \
  bash "$root/.github/scripts/publish-r2.sh" testing testing-45.20261031 "$tmp/dist"; then
  exit 1
fi
test -f "$tmp/store/testing/testing-45.20261030/old.iso"
