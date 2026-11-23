#!/usr/bin/env bash
# Release gate for hardware feature snapshots: create-only claims and
# payloads against a directory store and a local S3-compatible server, public
# verification before any tag, stable promotion, retention, and a key
# rotation dry run through the shipped runtime's verifier.
#
# Needs gpg, gpgv and python3 only. skopeo and cosign are fakes that record
# every tag and signature operation against a local registry directory.
#
# Environment:
#   SYSEXT_PUBLISH_S3_ENDPOINT  also run the store scenarios against this real
#                               S3-compatible endpoint (bucket
#                               SYSEXT_PUBLISH_S3_BUCKET, credentials from
#                               AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, public
#                               reads from SYSEXT_PUBLISH_S3_PUBLIC_URL)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "${ROOT}/tests/test-lib.sh"

for tool in gpg gpgv python3; do
  command -v "${tool}" >/dev/null || {
    echo "sysext-publish: ${tool} not found" >&2
    exit 1
  }
done

T="$(mktemp -d "${TMPDIR:-/tmp}/sysext-publish.XXXXXX")"
PUB="${ROOT}/.github/scripts/sysext-publish.py"
REL="${ROOT}/.github/scripts/sysext-release.sh"
RUNTIME="${ROOT}/editions/workstation/files/system/usr/libexec/luminusos/sysext"
CAND=ghcr.io/test/luminusos-workstation-candidate
PUBLIC=ghcr.io/test/luminusos-workstation
cleanup() {
  [ -f "${T}/pids" ] && while read -r pid; do kill "${pid}" 2>/dev/null; done <"${T}/pids"
  GNUPGHOME="${T}/gpg" gpgconf --kill all >/dev/null 2>&1
  rm -rf "${T}"
}
trap cleanup EXIT

export FAKE_REGISTRY="${T}/registry" TAGLOG="${T}/tags.log" PYTHONDONTWRITEBYTECODE=1
export COSIGN_PRIVATE_KEY=test-cosign-key SYSEXT_VERIFY_ATTEMPTS=2 SYSEXT_VERIFY_DELAY=0
real_s3_id="${AWS_ACCESS_KEY_ID:-}" real_s3_secret="${AWS_SECRET_ACCESS_KEY:-}"
export AWS_ACCESS_KEY_ID=test-access AWS_SECRET_ACCESS_KEY=test-secret
mkdir -p "${T}/bin" "${FAKE_REGISTRY}"
: >"${TAGLOG}"

cat >"${T}/bin/skopeo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
pos=()
while [ $# -gt 0 ]; do
  case "$1" in
    --retry-times) shift 2 ;;
    --*) shift ;;
    *) pos+=("$1"); shift ;;
  esac
done
resolve() {
  local ref="${1#docker://}" repo digest
  if [[ "${ref}" == *@* ]]; then
    repo="${ref%@*}" digest="${ref#*@}"
  else
    repo="${ref%:*}"
    digest="$(cat "${FAKE_REGISTRY}/${repo}/tags/${ref##*:}" 2>/dev/null)" || { echo "manifest unknown" >&2; exit 1; }
  fi
  [ -f "${FAKE_REGISTRY}/${repo}/manifests/${digest}" ] || { echo "manifest unknown" >&2; exit 1; }
  printf '%s\n' "${FAKE_REGISTRY}/${repo}/manifests/${digest}"
}
case "${pos[0]}" in
  inspect) cat "$(resolve "${pos[1]}")" ;;
  copy)
    src="$(resolve "${pos[1]}")"
    dst="${pos[2]#docker://}"
    if [[ "${dst}" == *@* ]]; then
      repo="${dst%@*}" tag=""
      [ "${dst#*@}" = "$(basename "${src}")" ] || exit 1
    else
      repo="${dst%:*}" tag="${dst##*:}"
    fi
    [ -z "${tag}" ] || [ "${FAKE_FAIL_TAG:-}" != "${tag}" ] || { echo "injected copy failure" >&2; exit 1; }
    if [ -n "${tag}" ] && [ "${FAKE_PAUSE_TAG:-}" = "${tag}" ]; then
      touch "${FAKE_PAUSE_READY}"
      while [ ! -e "${FAKE_PAUSE_STOP}" ]; do sleep 0.1; done
    fi
    mkdir -p "${FAKE_REGISTRY}/${repo}/manifests" "${FAKE_REGISTRY}/${repo}/tags"
    [ -f "${FAKE_REGISTRY}/${repo}/manifests/$(basename "${src}")" ] || cp "${src}" "${FAKE_REGISTRY}/${repo}/manifests/"
    if [ -n "${tag}" ]; then
      basename "${src}" >"${FAKE_REGISTRY}/${repo}/tags/${tag}"
    fi
    echo "copy ${pos[1]#docker://} ${dst}" >>"${TAGLOG}"
    ;;
  *) exit 2 ;;
esac
EOF
cat >"${T}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ref="${!#}"
if [[ "${ref}" == *@* ]]; then
  repo="${FAKE_REGISTRY}/${ref%@*}" digest="${ref#*@}"
  tag="${digest/:/-}.sig"
fi
case "$1" in
  public-key) printf 'fake public key\n' ;;
  sign)
    [[ "${ref}" == *@sha256:* ]] && [ -f "${FAKE_REGISTRY}/${ref%@*}/manifests/${ref#*@}" ] || exit 1
    echo "sign ${ref}" >>"${TAGLOG}"
    [ "${FAIL_COSIGN_SIGN:-0}" = 0 ] || exit 1
    identity="${ref%@*}"
    while [ $# -gt 1 ]; do
      if [ "$1" = "--sign-container-identity" ]; then
        identity="$2"
        break
      fi
      shift
    done
    identity="${FAKE_SIGN_IDENTITY:-${identity}}"
    mkdir -p "${repo}/tags"
    signature="$(printf '[{"critical":{"identity":{"docker-reference":"%s"},"image":{"docker-manifest-digest":"%s"}}}]' "${identity}" "${digest}")"
    signature_digest="sha256:$(printf '%s' "${signature}" | sha256sum | cut -d' ' -f1)"
    printf '%s' "${signature}" >"${repo}/manifests/${signature_digest}"
    printf '%s\n' "${signature_digest}" >"${repo}/tags/${tag}"
    ;;
  verify)
    echo "verify ${ref}" >>"${TAGLOG}"
    [ -f "${repo}/manifests/${digest}" ]
    cat "${repo}/manifests/$(cat "${repo}/tags/${tag}")"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "${T}/bin/skopeo" "${T}/bin/cosign"
export PATH="${T}/bin:${PATH}"

cat >"${T}/helper.py" <<'EOF'
import hashlib, http.server, json, os, sys, threading, urllib.parse
from xml.sax.saxutils import escape
sys.dont_write_bytecode = True


def serve(mode, root, portfile, logfile=None):
    lock = threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def target(self):
            u = urllib.parse.urlsplit(self.path)
            return urllib.parse.unquote(u.path.lstrip("/")), urllib.parse.parse_qs(u.query)

        def reply(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authed(self):
            return self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 Credential=test-access/")

        def note(self, what):
            if logfile:
                with lock, open(logfile, "a") as f:
                    f.write(what + "\n")

        def do_GET(self):
            key, q = self.target()
            if mode == "s3" and "list-type" in q:
                if not self.authed():
                    return self.reply(403)
                bucket = key.rstrip("/")
                prefix = q.get("prefix", [""])[0]
                start = q.get("continuation-token", [""])[0]
                base = os.path.join(root, bucket)
                keys = sorted(os.path.relpath(os.path.join(d, n), base)
                              for d, _, ns in os.walk(base) for n in ns)
                keys = [k for k in keys if k.startswith(prefix) and k > start]
                page, more = keys[:2], len(keys) > 2
                body = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                body += "".join(f"<Contents><Key>{escape(k)}</Key></Contents>" for k in page)
                body += f"<IsTruncated>{'true' if more else 'false'}</IsTruncated>"
                if more:
                    body += f"<NextContinuationToken>{escape(page[-1])}</NextContinuationToken>"
                return self.reply(200, (body + "</ListBucketResult>").encode())
            path = os.path.join(root, key)
            if not os.path.isfile(path):
                return self.reply(404, b"NoSuchKey")
            with open(path, "rb") as f:
                data = f.read()
            self.reply(200, data, {"ETag": '"%s"' % hashlib.md5(data).hexdigest()})

        def do_PUT(self):
            key, _ = self.target()
            data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if mode != "s3" or not self.authed() or \
                    self.headers.get("x-amz-content-sha256") != hashlib.sha256(data).hexdigest():
                return self.reply(403)
            if key == "fault-history/sysext/channels.json" and os.path.exists(os.path.join(root, "fail-history")):
                return self.reply(500, b"injected history write failure")
            path = os.path.join(root, key)
            with lock:
                exists = os.path.isfile(path)
                etag = None
                if exists:
                    with open(path, "rb") as f:
                        etag = '"%s"' % hashlib.md5(f.read()).hexdigest()
                if self.headers.get("If-None-Match") == "*" and exists:
                    return self.reply(412, b"PreconditionFailed")
                im = self.headers.get("If-Match")
                if im is not None and im != etag:
                    return self.reply(412, b"PreconditionFailed")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path + ".part", "wb") as f:
                    f.write(data)
                os.replace(path + ".part", path)
            self.note(f"PUT {key}")
            self.reply(200, headers={"ETag": '"%s"' % hashlib.md5(data).hexdigest()})

        def do_DELETE(self):
            key, _ = self.target()
            if mode != "s3" or not self.authed():
                return self.reply(403)
            path = os.path.join(root, key)
            with lock:
                if self.headers.get("If-Match"):
                    if not os.path.isfile(path):
                        return self.reply(412)
                    with open(path, "rb") as f:
                        etag = '"%s"' % hashlib.md5(f.read()).hexdigest()
                    if self.headers["If-Match"] != etag:
                        return self.reply(412)
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            self.note(f"DELETE {key}")
            self.reply(204)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(portfile + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(portfile + ".tmp", portfile)
    srv.serve_forever()


def runtime(path, mode, keyring, run, builds, base, version, digest):
    import importlib.machinery, importlib.util, lzma, subprocess, tempfile, urllib.request
    loader = importlib.machinery.SourceFileLoader("luminusos_sysext", path)
    spec = importlib.util.spec_from_loader("luminusos_sysext", loader)
    rt = importlib.util.module_from_spec(spec)
    loader.exec_module(rt)
    rt.RUN, rt.BUILDS = run, builds
    rt.gpg_verify.__defaults__ = (keyring,)
    ident = {"version": version, "digest": digest}
    if mode == "fetch":
        os.makedirs(f"{run}/fetch", exist_ok=True)
        desc = rt.fetch_descriptor({"base_url": base}, ident, f"{run}/fetch")
    elif mode == "update":
        rt.STORE = os.path.dirname(builds)
        rt.INCOMING = f"{rt.STORE}/incoming"
        rt.WORKER_LOCK, rt.STATE_LOCK = f"{run}/worker.lock", f"{run}/state.lock"
        rt.TEMPLATES = f"{run}/templates"
        os.makedirs(builds, exist_ok=True)
        os.makedirs(rt.INCOMING, exist_ok=True)
        os.makedirs(rt.TEMPLATES, exist_ok=True)
        with open(f"{rt.TEMPLATES}/dummy.transfer.in", "w") as f:
            f.write("@BASE_URL@ @VERSION@ @TXDIR@ @ID@")
        rt.read_selection = lambda: ["dummy"]
        rt.reap_incoming = lambda: None
        rt.admission_ok = lambda cfg, size: None
        rt.cgroup_populated = lambda cg: False
        rt.write_status = lambda **kw: None
        cg = tempfile.mkdtemp(dir=run)
        real_run = subprocess.run

        def simulate_sysupdate(cmd, **kwargs):
            if cmd[0] != rt.SYSUPDATE:
                return real_run(cmd, **kwargs)
            tx = next(os.scandir(rt.INCOMING)).path
            name = rt.feature_file("dummy", version)
            with urllib.request.urlopen(f"{base}/{version}/{name}.xz") as response:
                data = lzma.decompress(response.read())
            with open(f"{tx}/payload/{name}", "wb") as f:
                f.write(data)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        subprocess.run = simulate_sysupdate
        rc = rt.reconcile({"base_url": base, "max_builds": 10, "pull_timeout_s": 30},
                          cg, ident, ["dummy"], "booted")
        if rc:
            sys.exit(rc)
        committed = f"{builds}/{version}/{digest}/{rt.feature_file('dummy', version)}"
        if not os.path.isfile(committed):
            sys.exit("payload not committed")
        desc, err = rt.stored_descriptor(ident)
        if err or rt.sha256_file(committed) != desc["features"]["dummy"]["raw_sha256"]:
            sys.exit("committed payload invalid")
        print(f"committed {committed}")
    else:
        desc, err = rt.stored_descriptor(ident)
        if desc is None:
            sys.exit(f"stored descriptor rejected: {err}")
    print(f"verified {desc['version']} {desc['image_digest']}")


def store(uri, op, key, endpoint=""):
    sys.path.insert(0, os.path.dirname(os.environ["PUB"]))
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("pub", os.environ["PUB"])
    pub = importlib.util.module_from_spec(importlib.util.spec_from_loader("pub", loader))
    loader.exec_module(pub)
    class A: pass
    a = A(); a.store, a.endpoint, a.region = uri, endpoint, "auto"
    s = pub.open_store(a)
    if op == "rm":
        s.delete(key)
    elif op == "ls":
        print("\n".join(s.list(key)))


if __name__ == "__main__":
    {"serve": serve, "runtime": runtime, "store": store}[sys.argv[1]](*sys.argv[2:])
EOF
export PUB

# Starts a server in the background; port_of prints its port.
start_server() {
  local mode="$1" root="$2" portfile="${T}/port-$3" log="${4:-}"
  mkdir -p "${root}"
  python3 "${T}/helper.py" serve "${mode}" "${root}" "${portfile}" ${log:+"${log}"} >/dev/null 2>&1 &
  echo $! >>"${T}/pids"
  for _ in $(seq 100); do
    [ -s "${portfile}" ] && return 0
    sleep 0.1
  done
  return 1
}
port_of() { cat "${T}/port-$1"; }

# Signing keys: A (passphrase-protected, current) and B (next).
export GNUPGHOME="${T}/gpg"
mkdir -m 0700 "${GNUPGHOME}"
gpg --batch --pinentry-mode loopback --passphrase pw-a --quick-gen-key "Test A <a@test.invalid>" ed25519 sign never 2>/dev/null
gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "Test B <b@test.invalid>" ed25519 sign never 2>/dev/null
gpg --batch --pinentry-mode loopback --passphrase pw-a --armor --export-secret-keys a@test.invalid >"${T}/sec-A.asc"
gpg --batch --pinentry-mode loopback --passphrase "" --armor --export-secret-keys b@test.invalid >"${T}/sec-B.asc"
gpg --batch --export a@test.invalid >"${T}/ring-A.pgp"
gpg --batch --export b@test.invalid >"${T}/ring-B.pgp"
gpg --batch --export a@test.invalid b@test.invalid >"${T}/ring-AB.pgp"
unset GNUPGHOME

# A candidate image in the private repository; prints its digest.
candidate() {
  local name="$1" digest
  mkdir -p "${FAKE_REGISTRY}/${CAND}/manifests" "${FAKE_REGISTRY}/${CAND}/tags"
  printf '{"schemaVersion":2,"build":"%s"}' "${name}" >"${T}/manifest"
  digest="sha256:$(sha256sum "${T}/manifest" | cut -d' ' -f1)"
  mv "${T}/manifest" "${FAKE_REGISTRY}/${CAND}/manifests/${digest}"
  printf '%s\n' "${digest}"
}

# Build metadata for two features as guard.py writes it, then sign the
# snapshot through the CI signing path.
snapshot() {
  local dir="$1" version="$2" digest="$3" variant="$4" signer="${5:-A}" fid
  mkdir -p "${dir}"
  for fid in dummy second; do
    printf 'raw %s %s %s\n' "${fid}" "${version}" "${variant}" >"${dir}/luminusos-${fid}_${version}.raw"
    xz -c "${dir}/luminusos-${fid}_${version}.raw" >"${dir}/luminusos-${fid}_${version}.raw.xz"
    python3 - "${dir}" "${fid}" "${version}" "${digest}" <<'PY'
import hashlib, json, sys
d, fid, v, digest = sys.argv[1:]
h = lambda p: hashlib.sha256(open(f"{d}/{p}", "rb").read()).hexdigest()
raw, xz = f"luminusos-{fid}_{v}.raw", f"luminusos-{fid}_{v}.raw.xz"
json.dump({"id": fid, "version": v, "image_digest": digest, "architecture": "x86-64",
           "raw": raw, "raw_xz": xz, "raw_sha256": h(raw), "raw_xz_sha256": h(xz),
           "compressed_budget_mib": 1, "expanded_budget_mib": 4,
           "nodes": {f"/usr/share/luminusos-{fid}": "d", f"/usr/share/luminusos-{fid}/data": "f"},
           "exec_refs": []}, open(f"{d}/luminusos-{fid}_{v}.json", "w"))
PY
  done
  local pass=pw-a
  [ "${signer}" = A ] || pass=""
  SYSEXT_SIGNING_KEY="$(cat "${T}/sec-${signer}.asc")" SYSEXT_SIGNING_PASSPHRASE="${pass}" \
    bash "${REL}" sign "${dir}" "${version}" "${digest}" "${T}/ring-AB.pgp" >/dev/null
}

publish() {
  local snap="$1" version="$2" digest="$3" store="$4" url="$5"
  bash "${REL}" publish --snapshot "${snap}" --candidate "${CAND}@${digest}" --public-repo "${PUBLIC}" \
    --version "${version}" --version-tag "testing-${version}" --channel-tag testing-45 --channel-tag testing \
    --store "${store}" --public-url "${url}" --keyring "${T}/ring-AB.pgp"
}

no_tag_ops() {
  if grep -q "${PUBLIC}" "${TAGLOG}"; then
    echo "unexpected public tag operations:"
    cat "${TAGLOG}"
    return 1
  fi
}

tag_digest() { cat "${FAKE_REGISTRY}/${PUBLIC}/tags/$1" 2>/dev/null; }

store_ls() { python3 "${T}/helper.py" store "$1" ls "sysext/$2" "${S3_ENDPOINT:-}"; }
store_rm() { python3 "${T}/helper.py" store "$1" rm "$2" "${S3_ENDPOINT:-}"; }
same_bytes() {
  local url="$1" v="$2" snap="$3" name
  for name in CLAIM luminusos-dummy_"${v}".raw.xz luminusos-second_"${v}".raw.xz \
    SHA256SUMS SHA256SUMS.gpg SHA256SUMS.raw SHA256SUMS.raw.gpg release.json release.json.gpg; do
    python3 -c 'import sys, urllib.request; sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())' \
      "${url}/sysext/${v}/${name}" >"${T}/got" || return 1
    [ "${name}" = CLAIM ] && continue
    [ "$(sha256sum <"${T}/got")" = "$(sha256sum <"${snap}/${name}")" ] || {
      echo "${name} differs from ${snap}"
      return 1
    }
  done
}

# Store scenarios, run once per backend. $1 label, $2 store URI, $3 public URL.
scenarios() {
  local label="$1" store="$2" url="$3" p="$4"
  local d1 d2 v

  # Racing publishers: same version, different builds and bytes.
  v="45.20261101.${p}1"
  d1="$(candidate "race-a-${label}")" d2="$(candidate "race-b-${label}")"
  snapshot "${T}/${label}/race-a" "${v}" "${d1}" a
  snapshot "${T}/${label}/race-b" "${v}" "${d2}" b
  race() {
    : >"${TAGLOG}"
    publish "${T}/${label}/race-a" "${v}" "${d1}" "${store}" "${url}" >"${T}/race-a.log" 2>&1 &
    local pa=$!
    publish "${T}/${label}/race-b" "${v}" "${d2}" "${store}" "${url}" >"${T}/race-b.log" 2>&1 &
    local pb=$! ra=0 rb=0
    wait "${pa}" || ra=$?
    wait "${pb}" || rb=$?
    local win lose wd ld
    if [ "${ra}" = 0 ] && [ "${rb}" != 0 ]; then
      win=a lose=b wd="${d1}" ld="${d2}"
    elif [ "${rb}" = 0 ] && [ "${ra}" != 0 ]; then
      win=b lose=a wd="${d2}" ld="${d1}"
    else
      echo "expected exactly one winner (a=${ra} b=${rb})"
      cat "${T}/race-a.log" "${T}/race-b.log"
      return 1
    fi
    grep -Eq "claimed by a different bundle; nothing was written|publication lease is held" "${T}/race-${lose}.log" || {
      cat "${T}/race-${lose}.log"
      return 1
    }
    same_bytes "${url}" "${v}" "${T}/${label}/race-${win}" || return 1
    grep -q "${ld}" "${TAGLOG}" && {
      echo "loser digest reached the public repository"
      return 1
    }
    [ "$(tag_digest "testing-${v}")" = "${wd}" ] && [ "$(tag_digest testing-45)" = "${wd}" ] || return 1
    # A later retry of the losing bundle still changes nothing.
    : >"${TAGLOG}"
    publish "${T}/${label}/race-${lose}" "${v}" "${ld}" "${store}" "${url}" >/dev/null 2>&1 && return 1
    no_tag_ops && same_bytes "${url}" "${v}" "${T}/${label}/race-${win}"
  }
  expect "${label}: two racing publishers with different bytes leave one snapshot and no loser tags" race

  # Interruption after the claim, then an identical retry.
  v="45.20261102.${p}1"
  d1="$(candidate "resume-${label}")"
  snapshot "${T}/${label}/resume" "${v}" "${d1}" r
  interrupted() {
    : >"${TAGLOG}"
    python3 "${PUB}" claim "${T}/${label}/resume" --store "${store}" --version "${v}" \
      --image-digest "${d1}" --keyring "${T}/ring-AB.pgp" >/dev/null || return 1
    python3 "${PUB}" verify-public --public-url "${url}" --version "${v}" --image-digest "${d1}" \
      --keyring "${T}/ring-AB.pgp" --attempts 1 --delay 0 >/dev/null 2>&1 && return 1
    no_tag_ops || return 1
    # Upload, then lose the descriptor as an upload cut short before its last objects.
    python3 "${PUB}" upload "${T}/${label}/resume" --store "${store}" --version "${v}" \
      --image-digest "${d1}" >/dev/null || return 1
    store_rm "${store}" "sysext/${v}/release.json.gpg"
    store_rm "${store}" "sysext/${v}/release.json"
    python3 "${PUB}" verify-public --public-url "${url}" --version "${v}" --image-digest "${d1}" \
      --keyring "${T}/ring-AB.pgp" --attempts 1 --delay 0 >/dev/null 2>&1 && return 1
    no_tag_ops || return 1
    publish "${T}/${label}/resume" "${v}" "${d1}" "${store}" "${url}" >"${T}/resume.log" 2>&1 || {
      cat "${T}/resume.log"
      return 1
    }
    grep -q "resuming the claim" "${T}/resume.log" && grep -q "already present luminusos-dummy" "${T}/resume.log" &&
      [ "$(tag_digest "testing-${v}")" = "${d1}" ] && same_bytes "${url}" "${v}" "${T}/${label}/resume"
  }
  expect "${label}: a job interrupted after the claim resumes with the identical bundle" interrupted
  rebuilt() {
    snapshot "${T}/${label}/rebuilt" "${v}" "${d1}" rebuilt
    : >"${TAGLOG}"
    local rc=0
    publish "${T}/${label}/rebuilt" "${v}" "${d1}" "${store}" "${url}" >/dev/null 2>&1 || rc=$?
    [ "${rc}" = 3 ] && no_tag_ops && same_bytes "${url}" "${v}" "${T}/${label}/resume"
  }
  expect "${label}: a rebuilt bundle with different bytes cannot reuse the claimed version" rebuilt

  # Snapshots that must never reach a tag.
  v="45.20261103.${p}1"
  d1="$(candidate "incomplete-${label}")"
  snapshot "${T}/${label}/incomplete" "${v}" "${d1}" i
  rm "${T}/${label}/incomplete/release.json.gpg"
  incomplete() {
    : >"${TAGLOG}"
    publish "${T}/${label}/incomplete" "${v}" "${d1}" "${store}" "${url}" >/dev/null 2>&1 && return 1
    no_tag_ops && [ -z "$(store_ls "${store}" "${v}")" ]
  }
  expect "${label}: an incomplete snapshot is refused before any write or tag" incomplete

  v="45.20261104.${p}1"
  d1="$(candidate "wrong-a-${label}")" d2="$(candidate "wrong-b-${label}")"
  snapshot "${T}/${label}/wrong" "${v}" "${d1}" w
  wrong_digest() {
    : >"${TAGLOG}"
    publish "${T}/${label}/wrong" "${v}" "${d2}" "${store}" "${url}" >"${T}/wrong.log" 2>&1 && return 1
    grep -q "snapshot is for" "${T}/wrong.log" && no_tag_ops && [ -z "$(store_ls "${store}" "${v}")" ]
  }
  expect "${label}: a snapshot for another image digest is refused and creates no tag" wrong_digest

  v="45.20261105.${p}1"
  d1="$(candidate "stale-${label}")"
  snapshot "${T}/${label}/stale" "${v}" "${d1}" s
  snapshot "${T}/${label}/stale-old" "${v}" "${d1}" old
  stale() {
    # The public endpoint still serves an older copy of the version.
    local mirror="${T}/${label}/mirror" port
    mkdir -p "${mirror}/sysext/${v}"
    cp "${T}/${label}/stale-old/"{SHA256SUMS,SHA256SUMS.gpg,SHA256SUMS.raw,SHA256SUMS.raw.gpg,release.json,release.json.gpg,*.raw.xz} "${mirror}/sysext/${v}/"
    python3 "${PUB}" claim "${T}/${label}/stale-old" --store "dir:${mirror}" --version "${v}" \
      --image-digest "${d1}" --keyring "${T}/ring-AB.pgp" >/dev/null || return 1
    start_server static "${mirror}" "mirror-${label}" || return 1
    port="$(port_of "mirror-${label}")"
    : >"${TAGLOG}"
    publish "${T}/${label}/stale" "${v}" "${d1}" "${store}" "http://127.0.0.1:${port}" >"${T}/stale.log" 2>&1 && return 1
    grep -q "public CLAIM differs from the local snapshot" "${T}/stale.log" &&
      grep -q "refusing to create tags" "${T}/stale.log" && no_tag_ops
  }
  expect "${label}: a stale public endpoint fails closed and delays every tag" stale
}

DIRSTORE="${T}/dirstore"
start_server static "${DIRSTORE}" dir
dir_port="$(port_of dir)"
scenarios dir "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" 1

S3ROOT="${T}/s3"
mkdir -p "${S3ROOT}/bucket"
start_server s3 "${S3ROOT}" s3 "${T}/s3.log"
s3_port="$(port_of s3)"
export S3_ENDPOINT="http://127.0.0.1:${s3_port}" R2_ENDPOINT="http://127.0.0.1:${s3_port}"
scenarios s3 "s3://bucket" "http://127.0.0.1:${s3_port}/bucket" 2
if [ -n "${SYSEXT_PUBLISH_S3_ENDPOINT:-}" ]; then
  export S3_ENDPOINT="${SYSEXT_PUBLISH_S3_ENDPOINT}" R2_ENDPOINT="${SYSEXT_PUBLISH_S3_ENDPOINT}"
  export AWS_ACCESS_KEY_ID="${real_s3_id}" AWS_SECRET_ACCESS_KEY="${real_s3_secret}"
  scenarios real-s3 "s3://${SYSEXT_PUBLISH_S3_BUCKET:?}" "${SYSEXT_PUBLISH_S3_PUBLIC_URL:?}" 3
  export S3_ENDPOINT="http://127.0.0.1:${s3_port}" R2_ENDPOINT="http://127.0.0.1:${s3_port}"
  export AWS_ACCESS_KEY_ID=test-access AWS_SECRET_ACCESS_KEY=test-secret
else
  skip "real S3 endpoint scenarios (set SYSEXT_PUBLISH_S3_ENDPOINT)"
fi

# Stable promotion of the published resume build (directory store).
v=45.20261102.11
d1="$(tag_digest "testing-${v}")"
promote() {
  bash "${REL}" promote --public-repo "${PUBLIC}" --source-tag "testing-$1" --version "$1" \
    --version-tag "$1" --channel-tag 45 --channel-tag latest \
    --store "dir:${DIRSTORE}" --public-url "http://127.0.0.1:${dir_port}" --keyring "${T}/ring-AB.pgp"
}
promotion() {
  local before
  before="$(find "${DIRSTORE}/sysext/${v}" -type f -exec sha256sum {} + | sort)"
  : >"${TAGLOG}"
  promote "${v}" >"${T}/promote.log" 2>&1 || {
    cat "${T}/promote.log"
    return 1
  }
  grep -q "public snapshot ${v} verified" "${T}/promote.log" || return 1
  for tag in "${v}" 45 latest; do [ "$(tag_digest "${tag}")" = "${d1}" ] || return 1; done
  grep -q "^sign" "${TAGLOG}" && return 1
  [ "${before}" = "$(find "${DIRSTORE}/sysext/${v}" -type f -exec sha256sum {} + | sort)" ] &&
    python3 - "${DIRSTORE}/sysext/channels.json" "${v}" "${d1}" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))["channels"]
assert c["latest"]["version"] == sys.argv[2] and c["latest"]["digest"] == sys.argv[3], c
assert c["45"]["version"] == sys.argv[2]
PY
}
expect "stable promotion re-verifies and copies the same digest without new snapshot objects" promotion
promotion_tampered() {
  local victim="${DIRSTORE}/sysext/45.20261101.11/luminusos-dummy_45.20261101.11.raw.xz"
  cp "${victim}" "${T}/victim"
  printf corrupt >"${victim}"
  : >"${TAGLOG}"
  local rc=0
  promote 45.20261101.11 >/dev/null 2>&1 && rc=1
  cp "${T}/victim" "${victim}"
  [ "${rc}" = 0 ] && no_tag_ops
}
expect "stable promotion refuses a snapshot that no longer verifies and moves no tag" promotion_tampered

promotion_requires_resolved_digest() {
  local digest
  digest="$(candidate different-stable-build)" || return 1
  : >"${TAGLOG}"
  bash "${REL}" promote --source-tag testing-45.20261101.11 --expected-digest "${digest}" \
    --public-repo "${PUBLIC}" --version 45.20261101.11 --version-tag stable-mismatch \
    --store "dir:${DIRSTORE}" --public-url "http://127.0.0.1:${dir_port}" \
    --keyring "${T}/ring-AB.pgp" >"${T}/changed-stable.log" 2>&1 && return 1
  grep -Fq 'stable testing tag changed after digest resolution' "${T}/changed-stable.log" &&
    ! grep -q '^copy ' "${TAGLOG}"
}
expect "stable does not publish a digest different from the one it resolved for packaging" promotion_requires_resolved_digest

sign_failure_preserves_tags() {
  local version=45.20261112.1 digest before
  digest="$(candidate sign-failure)"
  snapshot "${T}/sign-failure" "${version}" "${digest}" s
  before="$(tag_digest testing)"
  : >"${TAGLOG}"
  FAIL_COSIGN_SIGN=1 publish "${T}/sign-failure" "${version}" "${digest}" \
    "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" >/dev/null 2>&1 && return 1
  [ "$(tag_digest testing)" = "${before}" ] &&
    [ ! -e "${FAKE_REGISTRY}/${PUBLIC}/tags/testing-${version}" ] &&
    [ ! -e "${FAKE_REGISTRY}/${PUBLIC}/manifests/${digest}" ] &&
    ! grep -q " ${PUBLIC}[:@]" "${TAGLOG}"
}
expect "sign failure leaves no public reference to the candidate image" sign_failure_preserves_tags

bad_signature_stays_private() {
  local version=45.20261112.2 digest
  digest="$(candidate wrong-signature-identity)"
  snapshot "${T}/wrong-signature-identity" "${version}" "${digest}" s
  : >"${TAGLOG}"
  FAKE_SIGN_IDENTITY="${CAND}" publish "${T}/wrong-signature-identity" "${version}" "${digest}" \
    "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" >"${T}/bad-identity.log" 2>&1 && return 1
  grep -q "no verified signature for the public image identity" "${T}/bad-identity.log" &&
    ! grep -q " ${PUBLIC}[:@]" "${TAGLOG}" &&
    [ ! -e "${FAKE_REGISTRY}/${PUBLIC}/manifests/${digest}" ]
}
expect "a valid signature for the wrong repository cannot expose the candidate" bad_signature_stays_private

signature_copy_failure_stays_private() {
  local version=45.20261112.3 digest
  digest="$(candidate signature-copy-failure)"
  snapshot "${T}/signature-copy-failure" "${version}" "${digest}" s
  : >"${TAGLOG}"
  FAKE_FAIL_TAG="${digest/:/-}.sig" publish "${T}/signature-copy-failure" "${version}" "${digest}" \
    "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" >"${T}/sig-copy-failure.log" 2>&1 && return 1
  grep -q "injected copy failure" "${T}/sig-copy-failure.log" &&
    ! grep -q " ${PUBLIC}[:@]" "${TAGLOG}" &&
    [ ! -e "${FAKE_REGISTRY}/${PUBLIC}/manifests/${digest}" ]
}
expect "failure to mirror the signature leaves the candidate private" signature_copy_failure_stays_private

signature_before_release_tags() {
  local version=45.20261113.1 digest sign private_verify signature_copy image_copy public_verify release
  digest="$(candidate signing-order)"
  snapshot "${T}/signing-order" "${version}" "${digest}" s
  : >"${TAGLOG}"
  publish "${T}/signing-order" "${version}" "${digest}" \
    "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" >"${T}/signing-order.log" 2>&1 || return 1
  grep -q "public snapshot ${version} verified" "${T}/signing-order.log" || return 1
  sign="$(grep -nFx "sign ${CAND}@${digest}" "${TAGLOG}" | cut -d: -f1)"
  private_verify="$(grep -nFx "verify ${CAND}@${digest}" "${TAGLOG}" | cut -d: -f1)"
  signature_copy="$(grep -nF " ${PUBLIC}:${digest/:/-}.sig" "${TAGLOG}" | cut -d: -f1)"
  image_copy="$(awk -v destination="${PUBLIC}@${digest}" '$1 == "copy" && $3 == destination { print NR }' "${TAGLOG}")"
  public_verify="$(grep -nFx "verify ${PUBLIC}@${digest}" "${TAGLOG}" | cut -d: -f1)"
  release="$(grep -n " ${PUBLIC}:testing-${version}$" "${TAGLOG}" | cut -d: -f1)"
  ! grep -Fq " ${PUBLIC}:sysext-staging-" "${TAGLOG}" &&
    [ "${sign}" -lt "${private_verify}" ] && [ "${private_verify}" -lt "${signature_copy}" ] &&
    [ "${signature_copy}" -lt "${image_copy}" ] && [ "${image_copy}" -lt "${public_verify}" ] &&
    [ "${public_verify}" -lt "${release}" ]
}
expect "image signing and verification precede the first release tag" signature_before_release_tags

boot_failure_stays_private() {
  local v=45.20261112.5 digest snapshot_dir="${T}/boot-failure"
  digest="$(candidate failed-boot)" || return 1
  snapshot "${snapshot_dir}" "${v}" "${digest}" b || return 1
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$@" >%q\nexit 19\n' "${T}/boot-failure.args" >"${T}/boot-check"
  chmod +x "${T}/boot-check"
  : >"${TAGLOG}"
  bash "${REL}" publish --snapshot "${snapshot_dir}" --candidate "${CAND}@${digest}" \
    --public-repo "${PUBLIC}" --version "${v}" --version-tag "testing-${v}" \
    --store "dir:${DIRSTORE}" --public-url "http://127.0.0.1:${dir_port}" \
    --keyring "${T}/ring-AB.pgp" --boot-check "${T}/boot-check" >/dev/null 2>&1 && return 1
  grep -Fxq "${CAND}@${digest}" "${T}/boot-failure.args" &&
    grep -Fxq "${digest}" "${T}/boot-failure.args" &&
    [ ! -e "${FAKE_REGISTRY}/${PUBLIC}/manifests/${digest}" ] &&
    no_tag_ops
}
expect "a real boot-check callback must pass before the candidate reaches the public repository" boot_failure_stays_private

unsigned_promotion() {
  local sig="${FAKE_REGISTRY}/${PUBLIC}/tags/${d1/:/-}.sig"
  mv "${sig}" "${sig}.saved" || return 1
  : >"${TAGLOG}"
  local rc=0
  promote "${v}" >/dev/null 2>&1 && rc=1
  mv "${sig}.saved" "${sig}"
  [ "${rc}" = 0 ] && ! grep -q '^copy ' "${TAGLOG}"
}
expect "promotion rejects an unsigned image before moving tags" unsigned_promotion

published_order() {
  local v=45.20261101.21 order
  order="$(grep "PUT bucket/sysext/${v}/" "${T}/s3.log" | sed "s|PUT bucket/sysext/${v}/||" | tr '\n' ' ')"
  [ "${order}" = "CLAIM luminusos-dummy_${v}.raw.xz luminusos-second_${v}.raw.xz SHA256SUMS SHA256SUMS.gpg SHA256SUMS.raw SHA256SUMS.raw.gpg release.json release.json.gpg " ] || {
    echo "upload order: ${order}"
    return 1
  }
  grep -q "PUT bucket/sysext/45.20261102.21/CLAIM" "${T}/s3.log" &&
    ! grep -q "PUT bucket/sysext/45.20261103.21\|PUT bucket/sysext/45.20261104.21" "${T}/s3.log"
}
expect "s3: the claim comes first, payloads before checksums, the descriptor last" published_order

restore_installer_snapshot() {
  local v=45.20261101.11 digest out="${T}/installer-snapshot"
  digest="$(tag_digest "testing-${v}")" || return 1
  python3 "${PUB}" verify-public --public-url "http://127.0.0.1:${dir_port}" \
    --version "${v}" --image-digest "${digest}" --keyring "${T}/ring-AB.pgp" \
    --installer-dir "${out}" --attempts 1 || return 1
  [ "$(find "${out}" -maxdepth 1 -type f | wc -l)" = 6 ] &&
    python3 "${ROOT}/editions/workstation/sysext/release.py" verify "${out}" --offline \
      --version "${v}" --image-digest "${digest}" --keyring "${T}/ring-AB.pgp"
}
expect "restore the exact offline snapshot from a published testing bundle" restore_installer_snapshot

# Retention against a synthetic channel history (days since 2026-01-01).
RSTORE="${T}/retention"
RETAIN_REPO=ghcr.io/test/retention
mkdir -p "${FAKE_REGISTRY}/${RETAIN_REPO}/manifests" "${FAKE_REGISTRY}/${RETAIN_REPO}/tags"
printf '{"schemaVersion":2,"build":"retention"}' >"${T}/retention-manifest"
RETAIN_DIGEST="sha256:$(sha256sum "${T}/retention-manifest" | cut -d' ' -f1)"
cp "${T}/retention-manifest" "${FAKE_REGISTRY}/${RETAIN_REPO}/manifests/${RETAIN_DIGEST}"
day() { date -u -d "2026-01-01 +$1 days" +%Y-%m-%dT%H:%M:%SZ; }
claim_only() {
  mkdir -p "${RSTORE}/sysext/$1"
  printf '{"format":1,"image_digest":"%s","objects":{},"version":"%s"}\n' "${RETAIN_DIGEST}" "$1" >"${RSTORE}/sysext/$1/CLAIM"
  printf x >"${RSTORE}/sysext/$1/luminusos-dummy_$1.raw.xz"
  printf x >"${RSTORE}/sysext/$1/release.json"
}
record() {
  python3 "${PUB}" locked-run --store "dir:${RSTORE}" -- \
    python3 "${PUB}" record-channel --store "dir:${RSTORE}" --version "$1" \
    --image-digest "${RETAIN_DIGEST}" --now "$(day "$2")" "${@:3}" >/dev/null
  local args=("${@:3}") i
  for ((i = 1; i < ${#args[@]}; i += 2)); do
    printf '%s\n' "${RETAIN_DIGEST}" >"${FAKE_REGISTRY}/${RETAIN_REPO}/tags/${args[i]}"
  done
}
expect_failure "retention refuses to run without channel history" \
  python3 "${PUB}" retention --store "dir:${RSTORE}" --public-repo "${RETAIN_REPO}"
for i in 1 2 3 4 5 6 7 8; do
  claim_only "t${i}"
  record "t${i}" "${i}" --tag testing-45 --tag testing
done
record t2 3 --tag 45 --tag latest
record t4 5 --tag 45 --tag latest
claim_only untracked
plan() { python3 "${PUB}" retention --store "dir:${RSTORE}" --public-repo "${RETAIN_REPO}" --now "$(day "$1")" | jq -r 'select(.action == "delete") | .version' | sort | tr '\n' ' '; }
expect "retention keeps channel targets, previous targets and the last five testing builds" \
  test "$(plan 40)" = "t1 t3 "
expect "retention keeps versions inside the 30-day recovery window" \
  test "$(plan 20)" = ""
expect "retention deletes a version only after its recovery window expires" \
  test "$(plan 3)$(plan 33)" = "t1 "
consumer_window() {
  local store="${T}/consumer-window" old recent pending got
  old="$(candidate consumer-old)"
  recent="$(candidate consumer-recent)"
  pending="$(candidate consumer-pending)"
  mkdir -p "${store}/sysext"
  jq -n --arg old "${old}" --arg recent "${recent}" --arg pending "${pending}" \
    --arg now "$(day 10)" '
      {format:1, channels:{"45":{version:"v2",digest:$recent,previous:"v1",previous_digest:$old}},
       pending:{testing:{version:"v3",digest:$pending,at:$now}},
       history:[{tag:"45",version:"v1",digest:$old,at:"2026-01-01T00:00:00Z"},
                {tag:"45",version:"v2",digest:$recent,at:$now}]}
    ' >"${store}/sysext/channels.json"
  got="$(python3 "${PUB}" locked-run --store "dir:${store}" -- \
    python3 "${PUB}" consumer-digests --store "dir:${store}" --now "$(day 80)")" || return 1
  [ "${got}" = "$(printf '%s\n' "${old}" "${recent}" "${pending}" | sort)" ]
}
expect "old rollback and pending deployment digests remain covered by the signing gate" consumer_window

retention_unknown_live() {
  local bad
  printf '{"schemaVersion":2,"build":"unknown"}' >"${T}/unknown-manifest"
  bad="sha256:$(sha256sum "${T}/unknown-manifest" | cut -d' ' -f1)"
  cp "${T}/unknown-manifest" "${FAKE_REGISTRY}/${RETAIN_REPO}/manifests/${bad}"
  printf '%s\n' "${bad}" >"${FAKE_REGISTRY}/${RETAIN_REPO}/tags/testing"
  local rc=0
  python3 "${PUB}" retention --store "dir:${RSTORE}" --public-repo "${RETAIN_REPO}" \
    --now "$(day 40)" --apply >"${T}/unknown.log" 2>&1 && rc=1
  printf '%s\n' "${RETAIN_DIGEST}" >"${FAKE_REGISTRY}/${RETAIN_REPO}/tags/testing"
  [ "${rc}" = 0 ] && [ -f "${RSTORE}/sysext/t1/CLAIM" ] && grep -q "unrecorded target" "${T}/unknown.log"
}
expect "retention refuses an unrecorded live registry target without deleting" retention_unknown_live
retention_apply() {
  python3 "${PUB}" retention --store "dir:${RSTORE}" --public-repo "${RETAIN_REPO}" --now "$(day 40)" >/dev/null || return 1
  [ -f "${RSTORE}/sysext/t1/CLAIM" ] || return 1
  python3 "${PUB}" retention --store "dir:${RSTORE}" --public-repo "${RETAIN_REPO}" --now "$(day 40)" --apply >/dev/null || return 1
  [ ! -e "${RSTORE}/sysext/t1/CLAIM" ] && [ ! -e "${RSTORE}/sysext/t3/release.json" ] &&
    [ -f "${RSTORE}/sysext/retired/t1" ] && [ -f "${RSTORE}/sysext/t2/CLAIM" ] &&
    [ -f "${RSTORE}/sysext/untracked/CLAIM" ] && [ -f "${RSTORE}/sysext/t4/CLAIM" ]
}
expect "retention is a dry run by default and --apply deletes only expired versions" retention_apply
retired_reuse() {
  local rc=0 d
  d="$(candidate retired)"
  snapshot "${T}/retired" t1 "${d}" x
  python3 "${PUB}" claim "${T}/retired" --store "dir:${RSTORE}" --version t1 --image-digest "${d}" \
    --keyring "${T}/ring-AB.pgp" >/dev/null 2>&1 || rc=$?
  [ "${rc}" = 3 ] && [ ! -e "${RSTORE}/sysext/t1/CLAIM" ]
}
expect "a retired version can never be claimed again" retired_reuse
s3_retention() {
  local zero i name order
  zero="${RETAIN_DIGEST}"
  # Three successive targets of one channel, so r1 is neither current nor previous.
  for i in 1 2 3; do
    mkdir -p "${S3ROOT}/retain/sysext/r${i}"
    for name in CLAIM release.json release.json.gpg SHA256SUMS SHA256SUMS.gpg "luminusos-dummy_r${i}.raw.xz"; do
      printf '{"image_digest":"%s"}\n' "${zero}" >"${S3ROOT}/retain/sysext/r${i}/${name}"
    done
    python3 "${PUB}" locked-run --store s3://retain -- \
      python3 "${PUB}" record-channel --store s3://retain --version "r${i}" --tag s3-only \
      --image-digest "${zero}" --now "$(day "${i}")" >/dev/null || return 1
  done
  printf '%s\n' "${zero}" >"${FAKE_REGISTRY}/${RETAIN_REPO}/tags/s3-only"
  : >"${T}/s3.log"
  python3 "${PUB}" retention --store s3://retain --public-repo "${RETAIN_REPO}" --now "$(day 9)" --window-days 5 --apply >"${T}/s3-retention.log" || return 1
  order="$(grep "DELETE retain/sysext/r1/" "${T}/s3.log" | sed "s|DELETE retain/sysext/r1/||" | tr '\n' ' ')"
  [ "${order}" = "release.json release.json.gpg SHA256SUMS SHA256SUMS.gpg luminusos-dummy_r1.raw.xz CLAIM " ] || {
    echo "delete order: ${order}"
    cat "${T}/s3-retention.log"
    return 1
  }
  grep -q "PUT retain/sysext/retired/r1" "${T}/s3.log" && ! grep -q "DELETE retain/sysext/r[23]/" "${T}/s3.log"
}
expect "s3: retention deletes the descriptor first and the claim last" s3_retention

FSTORE="${T}/fault-store"
start_server static "${FSTORE}" fault
furl="http://127.0.0.1:$(port_of fault)"
fault_publish() {
  bash "${REL}" publish --snapshot "$1" --candidate "${CAND}@$3" --public-repo "${PUBLIC}" \
    --version "$2" --version-tag "fault-$2" --channel-tag fault-a --channel-tag fault-b \
    --store "dir:${FSTORE}" --public-url "${furl}" --keyring "${T}/ring-AB.pgp"
}
fv1=45.20261114.1 fv2=45.20261115.1
fd1="$(candidate fault-one)" fd2="$(candidate fault-two)"
snapshot "${T}/fault-one" "${fv1}" "${fd1}" one
snapshot "${T}/fault-two" "${fv2}" "${fd2}" two
fault_publish "${T}/fault-one" "${fv1}" "${fd1}" >/dev/null
partial_move() {
  FAKE_FAIL_TAG=fault-b fault_publish "${T}/fault-two" "${fv2}" "${fd2}" >"${T}/partial.log" 2>&1 && return 1
  [ "$(tag_digest fault-a)" = "${fd2}" ] && [ "$(tag_digest fault-b)" = "${fd1}" ] || return 1
  python3 "${PUB}" retention --store "dir:${FSTORE}" --public-repo "${PUBLIC}" --window-days 0 --apply \
    >"${T}/partial-retention.log" 2>&1 || return 1
  [ -f "${FSTORE}/sysext/${fv1}/CLAIM" ] && [ -f "${FSTORE}/sysext/${fv2}/CLAIM" ]
}
expect "partial channel move keeps both live and pending snapshots" partial_move

history_failure() {
  mv "${FSTORE}/sysext/channels.json" "${T}/saved-channels" || return 1
  mkdir "${FSTORE}/sysext/channels.json"
  : >"${TAGLOG}"
  local rc=0 rr=0
  fault_publish "${T}/fault-one" "${fv1}" "${fd1}" >"${T}/history-failure.log" 2>&1 && rc=1
  python3 "${PUB}" retention --store "dir:${FSTORE}" --public-repo "${PUBLIC}" --apply \
    >"${T}/history-retention.log" 2>&1 && rr=1
  rmdir "${FSTORE}/sysext/channels.json"
  mv "${T}/saved-channels" "${FSTORE}/sysext/channels.json"
  [ "${rc}" = 0 ] && [ "${rr}" = 0 ] && ! grep -q " ${PUBLIC}:fault-" "${TAGLOG}" &&
    [ -f "${FSTORE}/sysext/${fv1}/CLAIM" ] && [ -f "${FSTORE}/sysext/${fv2}/CLAIM" ]
}
expect "failed history access prevents tag moves and retention deletion" history_failure

history_write_failure() {
  local hs="s3://fault-history" hu="http://127.0.0.1:${s3_port}/fault-history"
  local av=45.20261116.1 bv=45.20261117.1 ad bd rc=0
  ad="$(candidate history-a)" bd="$(candidate history-b)"
  snapshot "${T}/history-a" "${av}" "${ad}" a
  snapshot "${T}/history-b" "${bv}" "${bd}" b
  mkdir -p "${S3ROOT}/fault-history"
  bash "${REL}" publish --snapshot "${T}/history-a" --candidate "${CAND}@${ad}" --public-repo "${PUBLIC}" \
    --version "${av}" --version-tag "history-${av}" --channel-tag history-channel \
    --store "${hs}" --public-url "${hu}" --keyring "${T}/ring-AB.pgp" >/dev/null || return 1
  touch "${S3ROOT}/fail-history"
  : >"${TAGLOG}"
  bash "${REL}" publish --snapshot "${T}/history-b" --candidate "${CAND}@${bd}" --public-repo "${PUBLIC}" \
    --version "${bv}" --version-tag "history-${bv}" --channel-tag history-channel \
    --store "${hs}" --public-url "${hu}" --keyring "${T}/ring-AB.pgp" >"${T}/failed-write.log" 2>&1 && rc=1
  rm -f "${S3ROOT}/fail-history"
  [ "${rc}" = 0 ] && ! grep -q " ${PUBLIC}:history-" "${TAGLOG}" &&
    grep -q "PUT sysext/channels.json: HTTP 500" "${T}/failed-write.log" || return 1
  python3 "${PUB}" retention --store "${hs}" --public-repo "${PUBLIC}" --window-days 0 --apply \
    >"${T}/write-retention.log" 2>&1 || return 1
  [ -f "${S3ROOT}/fault-history/sysext/${av}/CLAIM" ] &&
    [ -f "${S3ROOT}/fault-history/sysext/${bv}/CLAIM" ]
}
expect "failed pending history write moves no release tag and retains snapshots" history_write_failure

lease_race() {
  FAKE_PAUSE_TAG=fault-a FAKE_PAUSE_READY="${T}/lease-ready" FAKE_PAUSE_STOP="${T}/lease-stop" \
    bash "${REL}" promote --public-repo "${PUBLIC}" --source-tag "fault-${fv2}" \
    --version "${fv2}" --version-tag "fault-${fv2}" --channel-tag fault-a --channel-tag fault-b \
    --store "dir:${FSTORE}" --public-url "${furl}" --keyring "${T}/ring-AB.pgp" >"${T}/race-promotion.log" 2>&1 &
  local pid=$! rc=0
  for _ in $(seq 100); do
    [ -f "${T}/lease-ready" ] && break
    sleep 0.1
  done
  [ -f "${T}/lease-ready" ] || rc=1
  python3 "${PUB}" retention --store "dir:${FSTORE}" --public-repo "${PUBLIC}" --apply \
    >"${T}/lease-retention.log" 2>&1 && rc=1
  touch "${T}/lease-stop"
  wait "${pid}" || rc=1
  [ "${rc}" = 0 ] && grep -q "lease is held" "${T}/lease-retention.log" &&
    [ -f "${FSTORE}/sysext/${fv2}/CLAIM" ]
}
expect "retention refuses while promotion holds the shared lease" lease_race

stale_lease() {
  local store="${T}/stale-lease" old='{"expiry":"2020-01-01T00:00:00Z","owner":"old"}'
  mkdir -p "${store}/sysext"
  printf '%s' "${old}" >"${store}/sysext/LOCK"
  python3 "${PUB}" locked-run --store "dir:${store}" -- touch "${store}/entered" >"${T}/stale-lease.log" 2>&1 && return 1
  [ ! -e "${store}/entered" ] && [ "$(cat "${store}/sysext/LOCK")" = "${old}" ] &&
    grep -q "confirm the previous writer and its operations have stopped" "${T}/stale-lease.log"
}
expect "stale lease never admits a competing writer automatically" stale_lease

near_expiry() {
  local store="${T}/near-expiry"
  mkdir -p "${store}/sysext"
  printf '{"expiry":"%s","owner":"test"}\n' "$(date -u -d '+1 minute' +%FT%TZ)" >"${store}/sysext/LOCK"
  SYSEXT_LEASE_OWNER=test python3 "${PUB}" lease-check --store "dir:${store}" || return 1
  SYSEXT_LEASE_OWNER=test python3 "${PUB}" lease-check --store "dir:${store}" \
    --min-remaining-seconds 600 >"${T}/near-expiry.log" 2>&1 && return 1
  grep -Fq 'insufficient time left on publication lease' "${T}/near-expiry.log"
}
expect "a lease near expiry cannot start a registry write" near_expiry

consumer_keyring_compatibility() {
  local fake="${T}/consumer-engine" ring="${T}/consumer.pgp" rc=0
  cat >"${fake}" <<'EOF'
#!/usr/bin/env bash
case "$1:$2" in
  image:exists) exit 0 ;;
  create:*) echo container ;;
  rm:-f) exit 0 ;;
  cp:container:/usr/lib/os-release)
    printf 'IMAGE_VERSION=45.20261121.111\n%s' "${FAKE_SYSEXT_LEVEL}" >"$3" ;;
  cp:container:/usr/share/luminusos/sysupdate/luminusos.pgp) exit 1 ;;
  *) exit 99 ;;
esac
EOF
  chmod +x "${fake}"
  FAKE_SYSEXT_LEVEL='' CONTAINER_ENGINE="${fake}" \
    bash "${REL}" keyring --allow-pre-feature "${PUBLIC}@${fd1}" "${ring}" || rc=$?
  [ "${rc}" = 42 ] && [ ! -e "${ring}" ] || return 1
  rc=0
  FAKE_SYSEXT_LEVEL=SYSEXT_LEVEL=45.20261121.111 CONTAINER_ENGINE="${fake}" \
    bash "${REL}" keyring --allow-pre-feature "${PUBLIC}@${fd1}" "${ring}" || rc=$?
  [ "${rc}" = 1 ] && [ ! -e "${ring}" ]
}
expect "a pre-feature consumer may lack a ring but a feature-capable consumer may not" consumer_keyring_compatibility

# Key rotation dry run. Build N ships keyring {A,B} and is signed by A; build
# N+1 is signed by B. N's updater (the shipped runtime with N's keyring)
# verifies N+1 before reboot, and N as a rollback deployment still verifies its
# retained descriptor. A keyring with only A shows why the overlap is needed.
vn=45.20261110.1 vn1=45.20261111.1
dn="$(candidate rotation-n)" dn1="$(candidate rotation-n1)"
snapshot "${T}/rot-n" "${vn}" "${dn}" n A
snapshot "${T}/rot-n1" "${vn1}" "${dn1}" n1 B
rot_publish() {
  publish "${T}/rot-n" "${vn}" "${dn}" "dir:${DIRSTORE}" "http://127.0.0.1:${dir_port}" >/dev/null &&
    bash "${REL}" publish --snapshot "${T}/rot-n1" --candidate "${CAND}@${dn1}" --public-repo "${PUBLIC}" \
      --version "${vn1}" --version-tag "testing-${vn1}" --channel-tag testing-45 --channel-tag testing \
      --store "dir:${DIRSTORE}" --public-url "http://127.0.0.1:${dir_port}" \
      --keyring "${T}/ring-AB.pgp" --consumer-keyring "${T}/ring-AB.pgp" >/dev/null &&
    python3 "${PUB}" verify-public --public-url "http://127.0.0.1:${dir_port}" --version "${vn1}" \
      --image-digest "${dn1}" --keyring "${T}/ring-AB.pgp" --keyring "${T}/ring-B.pgp" --delay 0 >/dev/null
}
rotation_consumer_reject() {
  : >"${TAGLOG}"
  bash "${REL}" publish --snapshot "${T}/rot-n1" --candidate "${CAND}@${dn1}" --public-repo "${PUBLIC}" \
    --version "${vn1}" --version-tag "testing-${vn1}" --channel-tag testing \
    --store "dir:${DIRSTORE}" --public-url "http://127.0.0.1:${dir_port}" \
    --keyring "${T}/ring-AB.pgp" --consumer-keyring "${T}/ring-A.pgp" >/dev/null 2>&1 && return 1
  no_tag_ops
}
expect "rotation: consumer without B rejects publication before any tag operation" rotation_consumer_reject
expect "rotation: N (signed A) and N+1 (signed B) pass the gate with the overlapping keyring" rot_publish
expect_failure "rotation: the gate rejects N+1 for a deployment whose keyring lacks B" \
  python3 "${PUB}" verify-public --public-url "http://127.0.0.1:${dir_port}" --version "${vn1}" \
  --image-digest "${dn1}" --keyring "${T}/ring-A.pgp" --attempts 1 --delay 0
runtime() {
  mkdir -p "${T}/rt-run"
  python3 "${T}/helper.py" runtime "${RUNTIME}" "$1" "$2" "${T}/rt-run" "${T}/rt-builds" \
    "http://127.0.0.1:${dir_port}/sysext" "$3" "$4"
}
expect_contains "rotation: N's runtime updater verifies the N+1 descriptor before reboot" \
  "verified ${vn1} ${dn1}" runtime fetch "${T}/ring-AB.pgp" "${vn1}" "${dn1}"
expect_contains "rotation: oldest updater fetches verifies and commits B-signed payload" \
  "committed ${T}/rt-builds/${vn1}/${dn1}/luminusos-dummy_${vn1}.raw" \
  runtime update "${T}/ring-AB.pgp" "${vn1}" "${dn1}"
expect_failure "rotation: a runtime keyring with only A rejects the N+1 descriptor" \
  runtime fetch "${T}/ring-A.pgp" "${vn1}" "${dn1}"
mkdir -p "${T}/rt-builds/${vn}/${dn}"
cp "${T}/rot-n/release.json" "${T}/rot-n/release.json.gpg" "${T}/rt-builds/${vn}/${dn}/"
expect_contains "rotation: rollback deployment N still verifies its retained descriptor" \
  "verified ${vn} ${dn}" runtime stored "${T}/ring-A.pgp" "${vn}" "${dn}"
expect_failure "rotation: the retained N descriptor does not verify under a keyring with only B" \
  runtime stored "${T}/ring-B.pgp" "${vn}" "${dn}"

echo
if [ "${fails}" -gt 0 ]; then
  echo "${fails} publication test(s) failed; ${skips} skipped"
  exit 1
fi
echo "all publication tests passed; ${skips} skipped"
