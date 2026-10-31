#!/usr/bin/env bash
set -euo pipefail

channel="${1:?channel required}"
version="${2:?version required}"
dist="${3:?artifact directory required}"
: "${R2_BUCKET:?R2_BUCKET required}" "${R2_ENDPOINT:?R2_ENDPOINT required}"

case "$channel:$version" in
  testing:testing-* | stable:[0-9]*) ;;
  *)
    echo "Invalid channel or version" >&2
    exit 1
    ;;
esac
[[ "$version" =~ ^(testing-)?[0-9]+\.[0-9]{8}(\.[0-9]+)?$ ]] || exit 1
base="luminusos-workstation-${version}"
for format in iso qcow2; do
  test -s "$dist/$base.$format"
done

aws_args=(--endpoint-url "$R2_ENDPOINT" --region auto)
destination="s3://${R2_BUCKET}/${channel}/${version}"
for format in iso qcow2; do
  aws s3 cp "$dist/$base.$format" "$destination/$base.$format" "${aws_args[@]}" --no-progress --content-type application/octet-stream
  curl --fail --silent --show-error --head "https://download.luminusos.org/${channel}/${version}/${base}.${format}" >/dev/null
done

manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT
python3 - "$manifest" "$channel" "$version" "$base" <<'PY'
import json, sys
path, channel, version, base = sys.argv[1:]
prefix = f'https://download.luminusos.org/{channel}/{version}/{base}'
with open(path, 'w') as output:
    json.dump({'version': version, 'assets': {fmt: f'{prefix}.{fmt}' for fmt in ('iso', 'qcow2')}}, output)
PY
aws s3 cp "$manifest" "s3://${R2_BUCKET}/${channel}/latest.json" "${aws_args[@]}" --content-type application/json --cache-control 'no-cache' --no-progress

listing="$(aws s3 ls "s3://${R2_BUCKET}/${channel}/" "${aws_args[@]}")"
while read -r marker directory; do
  [[ "$marker" == PRE && "$directory" == */ ]] || continue
  old="${directory%/}"
  [[ "$old" == "$version" ]] && continue
  if [[ "$channel" == testing && "$old" =~ ^testing-[0-9]+\.[0-9]{8}(\.[0-9]+)?$ ]] ||
    [[ "$channel" == stable && "$old" =~ ^[0-9]+\.[0-9]{8}(\.[0-9]+)?$ ]]; then
    aws s3 rm "s3://${R2_BUCKET}/${channel}/${old}/" --recursive "${aws_args[@]}" --no-progress
  fi
done <<<"$listing"
