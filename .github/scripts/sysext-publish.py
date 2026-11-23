#!/usr/bin/env python3
"""Publish immutable hardware feature snapshots and gate tags on them.

  sysext-publish.py claim <snapshot> --store URI --version V --image-digest D --keyring K
  sysext-publish.py upload <snapshot> --store URI --version V --image-digest D
  sysext-publish.py verify-public --public-url URL --version V --image-digest D --keyring K...
                                  [--snapshot DIR] [--installer-dir DIR] [--attempts N] [--delay S]
  sysext-publish.py locked-run --store URI -- COMMAND...
  sysext-publish.py record-channel --store URI --version V --image-digest D --tag T... [--pending|--confirm]
  sysext-publish.py retention --store URI --public-repo REPO [--apply] [--keep-testing 5] [--window-days 30] [--now ISO]

URI is dir:<path> (tests, local mirrors) or s3://<bucket> (R2; endpoint from
--endpoint or R2_ENDPOINT, credentials from AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY). Snapshot objects live under sysext/<version>/ and are
only ever written create-only; an existing object is accepted only when its
bytes are identical.

The CLAIM object binds the candidate image digest and the SHA-256 of every
bundle object. It is canonical JSON without a timestamp, so a retry of the
same bundle reproduces it byte for byte and resumes, while a different bundle
loses (exit 3) before writing anything.

Retention keeps a version while any channel points to it, while it is the
previous target of a channel, while it is among the last five testing builds,
and for a recovery window after it stopped being a channel target. The
30-day default window is a project decision: long enough for a machine that
was offline for a month to roll back and refetch, short enough to bound R2
storage. Versions without channel history are never deleted.
"""

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import hmac
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE_PY = os.path.join(HERE, "..", "..", "editions", "workstation", "sysext", "release.py")
PREFIX = "sysext"
CHANNELS = f"{PREFIX}/channels.json"
RETIRED = f"{PREFIX}/retired"
LOCK = f"{PREFIX}/LOCK"
EXIT_CONFLICT = 3
# Payloads first, then the list sysupdate verifies, the descriptor last.
OFFLINE_SUMS = ("SHA256SUMS.raw", "SHA256SUMS.raw.gpg")
SIGNED_ORDER = ("SHA256SUMS", "SHA256SUMS.gpg", *OFFLINE_SUMS, "release.json", "release.json.gpg")
# Retention deletes the descriptor first so a partial deletion fails closed.
DELETE_FIRST = ("release.json", "release.json.gpg", "SHA256SUMS", "SHA256SUMS.gpg", *OFFLINE_SUMS)


class Conflict(Exception):
    pass


def die(msg, code=1):
    print(f"sysext-publish: {msg}", file=sys.stderr)
    sys.exit(code)


def log(msg):
    print(f"sysext-publish: {msg}", flush=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


def now_utc(arg):
    if arg:
        return datetime.datetime.fromisoformat(arg.replace("Z", "+00:00"))
    return datetime.datetime.now(datetime.timezone.utc)


def iso(ts):
    return ts.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DirStore:
    """Filesystem store. Create-only writes link a complete temporary file into
    place, so a name either does not exist or holds the full object."""

    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _path(self, key):
        return os.path.join(self.root, key)

    def get(self, key):
        try:
            with open(self._path(key), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _temp(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        return tmp

    def put_create(self, key, data, content_type=None):
        """True if written, False if an identical object exists; Conflict otherwise."""
        path = self._path(key)
        tmp = self._temp(path, data)
        try:
            os.link(tmp, path)
            return True
        except FileExistsError:
            if self.get(key) != data:
                raise Conflict(f"{key} exists with different bytes") from None
            return False
        finally:
            os.unlink(tmp)

    def get_versioned(self, key):
        data = self.get(key)
        return data, (sha256(data) if data is not None else None)

    def put_replace(self, key, data, expected_tag, content_type=None):
        """Compare-and-swap on the content hash, under an exclusive lock."""
        path = self._path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(os.path.join(self.root, ".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            _, tag = self.get_versioned(key)
            if tag != expected_tag:
                raise Conflict(f"{key} changed concurrently")
            tmp = self._temp(path, data)
            os.replace(tmp, path)

    def delete(self, key):
        try:
            os.unlink(self._path(key))
        except FileNotFoundError:
            pass

    def delete_if(self, key, expected_tag):
        with open(os.path.join(self.root, ".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            _, tag = self.get_versioned(key)
            if tag != expected_tag:
                raise Conflict(f"{key} changed concurrently")
            self.delete(key)

    def list(self, prefix):
        base = self._path(prefix)
        out = []
        for d, _, files in os.walk(base):
            for name in files:
                if name.startswith(".tmp-") or name == ".lock":
                    continue
                out.append(os.path.relpath(os.path.join(d, name), self.root))
        return sorted(out)


class S3Store:
    """S3-compatible store (Cloudflare R2) using path-style SigV4 requests.
    Create-only writes use If-None-Match: *; R2 and S3 answer 412 when the key
    exists and S3 may answer 409 while a concurrent conditional write is in
    flight."""

    def __init__(self, bucket, endpoint, region):
        if not endpoint:
            die("s3:// store needs --endpoint or R2_ENDPOINT")
        self.bucket = bucket
        self.endpoint = endpoint.rstrip("/")
        self.region = region
        self.access = os.environ.get("AWS_ACCESS_KEY_ID", "")
        self.secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        if not self.access or not self.secret:
            die("s3:// store needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")

    def _request(self, method, key="", query=None, data=b"", headers=None):
        query = query or {}
        path = f"/{self.bucket}" + (f"/{urllib.parse.quote(key, safe='/~')}" if key else "")
        host = urllib.parse.urlsplit(self.endpoint).netloc
        stamp = datetime.datetime.now(datetime.timezone.utc)
        amz_date = stamp.strftime("%Y%m%dT%H%M%SZ")
        day = stamp.strftime("%Y%m%d")
        payload_hash = sha256(data)
        hdrs = {k.lower(): v for k, v in (headers or {}).items()}
        hdrs.update({"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash})
        qs = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                      for k, v in sorted(query.items()))
        signed = ";".join(sorted(hdrs))
        canon = "\n".join([method, path, qs,
                           "".join(f"{k}:{hdrs[k].strip()}\n" for k in sorted(hdrs)),
                           signed, payload_hash])
        scope = f"{day}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, sha256(canon.encode())])
        k = f"AWS4{self.secret}".encode()
        for part in (day, self.region, "s3", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        hdrs["authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
                                 f"SignedHeaders={signed}, Signature={sig}")
        del hdrs["host"]
        url = self.endpoint + path + (f"?{qs}" if qs else "")
        req = urllib.request.Request(url, data=data if method == "PUT" else None,
                                     method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def get_versioned(self, key):
        status, body, headers = self._request("GET", key)
        if status == 404:
            return None, None
        if status != 200:
            raise RuntimeError(f"GET {key}: HTTP {status} {body[:200]!r}")
        etag = {k.lower(): v for k, v in headers.items()}.get("etag")
        return body, etag

    def get(self, key):
        return self.get_versioned(key)[0]

    def put_create(self, key, data, content_type="application/octet-stream"):
        headers = {"if-none-match": "*", "content-type": content_type,
                   "cache-control": "public, max-age=31536000, immutable"}
        for attempt in range(6):
            status, body, _ = self._request("PUT", key, data=data, headers=headers)
            if status == 200:
                return True
            if status == 412:
                break
            if status == 409 and attempt < 5:
                time.sleep(1 + attempt)
                continue
            raise RuntimeError(f"PUT {key}: HTTP {status} {body[:200]!r}")
        existing = self.get(key)
        if existing is None:
            raise RuntimeError(f"PUT {key}: precondition failed but the object is absent")
        if existing != data:
            raise Conflict(f"{key} exists with different bytes")
        return False

    def put_replace(self, key, data, expected_tag, content_type="application/json"):
        headers = {"content-type": content_type, "cache-control": "no-cache"}
        if expected_tag is None:
            headers["if-none-match"] = "*"
        else:
            headers["if-match"] = expected_tag
        status, body, _ = self._request("PUT", key, data=data, headers=headers)
        if status in (409, 412):
            raise Conflict(f"{key} changed concurrently")
        if status != 200:
            raise RuntimeError(f"PUT {key}: HTTP {status} {body[:200]!r}")

    def delete(self, key):
        status, body, _ = self._request("DELETE", key)
        if status not in (200, 204, 404):
            raise RuntimeError(f"DELETE {key}: HTTP {status} {body[:200]!r}")

    def delete_if(self, key, expected_tag):
        status, body, _ = self._request("DELETE", key, headers={"if-match": expected_tag})
        if status in (409, 412, 404):
            raise Conflict(f"{key} changed concurrently")
        if status not in (200, 204):
            raise RuntimeError(f"DELETE {key}: HTTP {status} {body[:200]!r}")

    def list(self, prefix):
        keys, token = [], None
        while True:
            query = {"list-type": "2", "prefix": prefix.rstrip("/") + "/"}
            if token:
                query["continuation-token"] = token
            status, body, _ = self._request("GET", query=query)
            if status != 200:
                raise RuntimeError(f"LIST {prefix}: HTTP {status} {body[:200]!r}")
            root = ET.fromstring(body)
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            keys += [c.findtext(f"{ns}Key") for c in root.findall(f"{ns}Contents")]
            if root.findtext(f"{ns}IsTruncated") != "true":
                return sorted(keys)
            token = root.findtext(f"{ns}NextContinuationToken")


def open_store(args):
    uri = args.store
    if uri.startswith("dir:"):
        return DirStore(uri[4:])
    if uri.startswith("s3://"):
        bucket = uri[5:].strip("/")
        if not bucket or "/" in bucket:
            die(f"invalid store {uri}")
        return S3Store(bucket, args.endpoint or os.environ.get("R2_ENDPOINT", ""), args.region)
    die(f"unsupported store {uri}")


@contextlib.contextmanager
def lease(store):
    owner = uuid.uuid4().hex
    expires = now_utc(None) + datetime.timedelta(hours=3)
    data = canonical({"owner": owner, "expiry": iso(expires)})
    try:
        store.put_create(LOCK, data, "application/json")
    except Conflict:
        old, tag = store.get_versioned(LOCK)
        if old is None or not tag:
            raise RuntimeError("lease changed while acquiring; retry") from None
        try:
            expiry = now_utc(json.loads(old)["expiry"])
        except (KeyError, ValueError, TypeError):
            raise RuntimeError("invalid lease; refusing to break it") from None
        if expiry >= now_utc(None):
            raise RuntimeError("publication lease is held") from None
        raise RuntimeError(
            "publication lease expired; confirm the previous writer and its operations have stopped "
            "before removing the stale lock"
        ) from None
    try:
        yield owner
    finally:
        current, tag = store.get_versioned(LOCK)
        if current == data and tag:
            store.delete_if(LOCK, tag)


def cmd_locked_run(args):
    store = open_store(args)
    with lease(store) as owner:
        env = dict(os.environ, SYSEXT_LEASE_OWNER=owner)
        command = args.command
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            die("locked-run needs a command")
        result = subprocess.run(command, env=env)
        if result.returncode:
            sys.exit(result.returncode)


def require_lease(store, min_remaining_seconds=0):
    data = store.get(LOCK)
    if not data:
        raise RuntimeError("publication lease is absent")
    obj = json.loads(data)
    remaining = now_utc(obj["expiry"]) - now_utc(None)
    if obj.get("owner") != os.environ.get("SYSEXT_LEASE_OWNER") or remaining.total_seconds() <= 0:
        raise RuntimeError("publication lease is not held or expired")
    if remaining.total_seconds() < min_remaining_seconds:
        raise RuntimeError("insufficient time left on publication lease")


def cmd_lease_check(args):
    require_lease(open_store(args), args.min_remaining_seconds)


def require_caller_lease(store):
    if os.environ.get("SYSEXT_LEASE_OWNER"):
        require_lease(store)


def release_verify(directory, keyring, version, digest, *mode):
    r = subprocess.run([sys.executable, RELEASE_PY, "verify", directory, "--keyring", keyring,
                        "--version", version, "--image-digest", digest, *mode],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def bundle_names(descriptor, version):
    payloads = sorted(f"luminusos-{fid}_{version}.raw.xz" for fid in descriptor.get("features") or {})
    return payloads + list(SIGNED_ORDER)


def local_bundle(snapshot, version, digest):
    """Read the bundle of a local snapshot and build its CLAIM bytes."""
    try:
        with open(os.path.join(snapshot, "release.json"), encoding="utf-8") as f:
            descriptor = json.load(f)
    except (OSError, ValueError) as e:
        die(f"snapshot has no readable release.json: {e}")
    if descriptor.get("version") != version or descriptor.get("image_digest") != digest:
        die(f"snapshot is for {descriptor.get('version')} {descriptor.get('image_digest')}, "
            f"not {version} {digest}")
    objects = {}
    for name in bundle_names(descriptor, version):
        try:
            with open(os.path.join(snapshot, name), "rb") as f:
                objects[name] = f.read()
        except OSError:
            die(f"snapshot is incomplete: {name} missing")
    claim = canonical({"format": 1, "version": version, "image_digest": digest,
                       "objects": {n: sha256(b) for n, b in objects.items()}})
    return objects, claim


def check_version(version):
    if not re.fullmatch(r"[0-9A-Za-z+~-][0-9A-Za-z.+~-]*", version) or version == "retired":
        die(f"invalid version {version!r}")


def cmd_claim(args):
    check_version(args.version)
    objects, claim = local_bundle(args.snapshot, args.version, args.image_digest)
    for keyring in args.keyring:
        ok, out = release_verify(args.snapshot, keyring, args.version, args.image_digest, "--raw")
        if not ok:
            die(f"local snapshot does not verify with {keyring}: {out}")
    store = open_store(args)
    if store.get(f"{RETIRED}/{args.version}") is not None:
        die(f"version {args.version} was retired; allocate a new version", EXIT_CONFLICT)
    try:
        require_caller_lease(store)
        created = store.put_create(f"{PREFIX}/{args.version}/CLAIM", claim, "application/json")
    except Conflict:
        die(f"version {args.version} is claimed by a different bundle; nothing was written",
            EXIT_CONFLICT)
    log(f"{'claimed' if created else 'resuming the claim of'} {args.version} for {args.image_digest} "
        f"({len(objects)} objects)")


def cmd_upload(args):
    check_version(args.version)
    objects, claim = local_bundle(args.snapshot, args.version, args.image_digest)
    store = open_store(args)
    if store.get(f"{PREFIX}/{args.version}/CLAIM") != claim:
        die(f"the stored claim for {args.version} is absent or names another bundle", EXIT_CONFLICT)
    for name, data in objects.items():
        ctype = "application/json" if name == "release.json" else "application/octet-stream"
        try:
            require_caller_lease(store)
            created = store.put_create(f"{PREFIX}/{args.version}/{name}", data, ctype)
        except Conflict as e:
            die(str(e), EXIT_CONFLICT)
        log(f"{'uploaded' if created else 'already present'} {name}")


def fetch_url(url, timeout=60):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"{url}: {e}") from None


def restore_installer(source, descriptor, args):
    source = Path(source)
    destination = Path(args.installer_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(destination):
        raise RuntimeError(f"installer directory already exists: {destination}")
    with tempfile.TemporaryDirectory(prefix=".sysext-iso-", dir=destination.parent) as tmp:
        output = Path(tmp) / "snapshot"
        output.mkdir()
        for name in (*OFFLINE_SUMS, "release.json", "release.json.gpg"):
            shutil.copyfile(source / name, output / name)
        for fid, entry in descriptor["features"].items():
            if not re.fullmatch(r"[a-z][a-z0-9]{1,30}", fid):
                raise RuntimeError(f"invalid installer feature ID {fid!r}")
            budget = entry.get("expanded_budget_mib")
            if type(budget) is not int or budget <= 0:
                raise RuntimeError(f"invalid expanded budget for {fid}")
            remaining = budget * (1 << 20)
            name = f"luminusos-{fid}_{args.version}.raw"
            with lzma.open(source / f"{name}.xz", "rb") as payload, (output / name).open("xb") as raw:
                while chunk := payload.read(min(1 << 20, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise RuntimeError(f"{name} exceeds its signed expanded budget")
                    raw.write(chunk)
        for keyring in args.keyring:
            ok, out = release_verify(output, keyring, args.version, args.image_digest, "--offline")
            if not ok:
                raise RuntimeError(f"offline snapshot does not verify with {keyring}: {out}")
        output.rename(destination)


def verify_public_once(args, expected_claim):
    base = f"{args.public_url.rstrip('/')}/{PREFIX}/{args.version}"
    claim_bytes = fetch_url(f"{base}/CLAIM")
    if expected_claim is not None and claim_bytes != expected_claim:
        raise RuntimeError("public CLAIM differs from the local snapshot")
    claim = json.loads(claim_bytes)
    if claim.get("version") != args.version or claim.get("image_digest") != args.image_digest:
        raise RuntimeError(f"public CLAIM names {claim.get('version')} {claim.get('image_digest')}")
    objects = claim.get("objects") or {}
    with tempfile.TemporaryDirectory(prefix="sysext-public-") as tmp:
        for name, digest in sorted(objects.items()):
            if "/" in name or name.startswith("."):
                raise RuntimeError(f"CLAIM lists an invalid name {name!r}")
            data = fetch_url(f"{base}/{name}")
            if sha256(data) != digest:
                raise RuntimeError(f"public {name} does not match the claim")
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
        with open(os.path.join(tmp, "release.json"), encoding="utf-8") as f:
            descriptor = json.load(f)
        if sorted(objects) != sorted(bundle_names(descriptor, args.version)):
            raise RuntimeError("CLAIM does not list exactly the descriptor's bundle")
        for keyring in args.keyring:
            ok, out = release_verify(tmp, keyring, args.version, args.image_digest)
            if not ok:
                raise RuntimeError(f"public snapshot does not verify with {keyring}: {out}")
        if args.installer_dir:
            restore_installer(tmp, descriptor, args)
    return len(objects)


def cmd_verify_public(args):
    check_version(args.version)
    expected = None
    if args.snapshot:
        _, expected = local_bundle(args.snapshot, args.version, args.image_digest)
    for attempt in range(1, args.attempts + 1):
        try:
            n = verify_public_once(args, expected)
            log(f"public snapshot {args.version} verified: {n} objects, image {args.image_digest}")
            return
        except (RuntimeError, ValueError, OSError, EOFError, lzma.LZMAError) as e:
            print(f"sysext-publish: attempt {attempt}/{args.attempts}: {e}", file=sys.stderr)
            if attempt < args.attempts:
                time.sleep(args.delay)
    die("public snapshot did not verify; refusing to create tags")


def load_channels(store):
    data, tag = store.get_versioned(CHANNELS)
    if data is None:
        return {"format": 1, "channels": {}, "history": [], "pending": {}}, None
    state = json.loads(data)
    if state.get("format") != 1:
        die("unsupported channels.json format")
    state.setdefault("pending", {})
    return state, tag


def cmd_record_channel(args):
    check_version(args.version)
    store = open_store(args)
    require_lease(store)
    claim = store.get(f"{PREFIX}/{args.version}/CLAIM")
    if claim is None or json.loads(claim).get("image_digest") != args.image_digest:
        die(f"{args.version} is not claimed for {args.image_digest}")
    at = iso(now_utc(args.now))
    for attempt in range(5):
        state, tag = load_channels(store)
        for t in args.tag:
            cur = state["channels"].get(t)
            intended = {"version": args.version, "digest": args.image_digest, "at": at}
            pending = state["pending"].get(t)
            if args.pending:
                if pending and (pending["version"], pending["digest"]) != (args.version, args.image_digest):
                    die(f"{t} has an unresolved pending target")
                state["pending"][t] = intended
                continue
            if args.confirm:
                if not pending or (pending["version"], pending["digest"]) != (args.version, args.image_digest):
                    die(f"{t} has no matching pending target")
                del state["pending"][t]
            if cur and cur["version"] == args.version and cur["digest"] == args.image_digest:
                continue
            state["channels"][t] = {
                "version": args.version, "digest": args.image_digest,
                "previous": cur["version"] if cur else None,
                "previous_digest": cur["digest"] if cur else None,
            }
            state["history"].append({"tag": t, "version": args.version,
                                     "digest": args.image_digest, "at": at})
        try:
            require_lease(store)
            store.put_replace(CHANNELS, json.dumps(state, indent=2, sort_keys=True).encode() + b"\n", tag)
            log(f"recorded {args.version} on {', '.join(args.tag)}")
            return
        except Conflict:
            time.sleep(1 + attempt)
    die("channels.json kept changing; giving up")


def retention_plan(state, versions, now, keep_testing, window):
    channels, history = state["channels"], state["history"]
    protected = {}
    for tag, pending in state.get("pending", {}).items():
        protected.setdefault(pending["version"], f"pending target of {tag}")
    for t, c in channels.items():
        protected.setdefault(c["version"], f"current target of {t}")
        if c.get("previous"):
            protected.setdefault(c["previous"], f"previous target of {t}")
    testing = []
    for h in history:
        if h["tag"].startswith("testing") and h["version"] not in testing:
            testing.append(h["version"])
    for v in testing[len(testing) - keep_testing:] if keep_testing > 0 else []:
        protected.setdefault(v, f"among the last {keep_testing} testing builds")
    retired_at = {}
    for t in {h["tag"] for h in history}:
        entries = [h for h in history if h["tag"] == t]
        for prev, nxt in zip(entries, entries[1:]):
            if prev["version"] != nxt["version"]:
                at = now_utc(nxt["at"])
                retired_at[prev["version"]] = max(retired_at.get(prev["version"], at), at)
    known = {h["version"] for h in history}
    plan = []
    for v in sorted(versions):
        if v in protected:
            plan.append((v, False, protected[v]))
        elif v not in known:
            plan.append((v, False, "no channel history"))
        elif v not in retired_at:
            plan.append((v, False, "never superseded"))
        elif now - retired_at[v] < window:
            plan.append((v, False, f"inside the recovery window (retired {iso(retired_at[v])})"))
        else:
            plan.append((v, True, f"retired {iso(retired_at[v])}"))
    return plan


def cmd_consumer_digests(args):
    store = open_store(args)
    require_lease(store)
    state, _ = load_channels(store)
    by_version = {}

    def add(version, digest):
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise RuntimeError(f"invalid deployment digest for {version}")
        if by_version.setdefault(version, digest) != digest:
            raise RuntimeError(f"conflicting deployment digests for {version}")

    for entry in [*state["history"], *state["pending"].values(), *state["channels"].values()]:
        add(entry["version"], entry["digest"])
        if entry.get("previous"):
            add(entry["previous"], entry.get("previous_digest"))
    kept = retention_plan(state, by_version, now_utc(args.now), 5, datetime.timedelta(days=30))
    for digest in sorted({by_version[version] for version, delete, _ in kept if not delete}):
        print(digest)


def reconcile_channels(state, repo):
    if not repo:
        raise RuntimeError("retention requires --public-repo for live channel reconciliation")
    tags = set(state["channels"]) | set(state.get("pending", {}))
    for tag in sorted(tags):
        proc = subprocess.run(["skopeo", "inspect", "--retry-times", "3", "--raw",
                               f"docker://{repo}:{tag}"], capture_output=True)
        if proc.returncode:
            raise RuntimeError(f"cannot resolve live channel {tag}")
        digest = "sha256:" + sha256(proc.stdout)
        candidates = [c for c in (state["channels"].get(tag), state.get("pending", {}).get(tag)) if c]
        if not any(c["digest"] == digest for c in candidates):
            raise RuntimeError(f"live channel {tag} has unrecorded target {digest}")


def retention_locked(args, store):
    state, _ = load_channels(store)
    if not state["history"]:
        die("no channel history; refusing to evaluate retention")
    reconcile_channels(state, args.public_repo)
    versions = {}
    for key in store.list(PREFIX):
        parts = key.split("/")
        if len(parts) == 3 and parts[1] != "retired":
            versions.setdefault(parts[1], []).append(key)
    plan = retention_plan(state, versions, now_utc(args.now), args.keep_testing,
                          datetime.timedelta(days=args.window_days))
    for v, delete, reason in plan:
        print(json.dumps({"version": v, "action": "delete" if delete else "keep", "reason": reason}))
    if not args.apply:
        return
    for v, delete, _ in plan:
        if not delete:
            continue
        require_lease(store)
        prefix = f"{PREFIX}/{v}/"
        claim = store.get(f"{prefix}CLAIM")
        if claim is not None:
            store.put_create(f"{RETIRED}/{v}", claim, "application/json")
        keys = versions[v]
        first = [prefix + n for n in DELETE_FIRST if prefix + n in keys]
        rest = [k for k in keys if k not in first and k != f"{prefix}CLAIM"]
        for key in first + rest:
            require_lease(store)
            store.delete(key)
        require_lease(store)
        store.delete(f"{prefix}CLAIM")
        log(f"deleted {v}")


def cmd_retention(args):
    store = open_store(args)
    with lease(store) as owner:
        os.environ["SYSEXT_LEASE_OWNER"] = owner
        retention_locked(args, store)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, store=True, identity=True):
        if store:
            p.add_argument("--store", required=True)
            p.add_argument("--endpoint", default="")
            p.add_argument("--region", default="auto")
        if identity:
            p.add_argument("--version", required=True)
            p.add_argument("--image-digest", required=True)
        return p

    p = common(sub.add_parser("claim"))
    p.add_argument("snapshot")
    p.add_argument("--keyring", action="append", required=True)
    p = common(sub.add_parser("upload"))
    p.add_argument("snapshot")
    p = common(sub.add_parser("verify-public"), store=False)
    p.add_argument("--public-url", required=True)
    p.add_argument("--keyring", action="append", required=True)
    p.add_argument("--snapshot")
    p.add_argument("--installer-dir")
    p.add_argument("--attempts", type=int, default=6)
    p.add_argument("--delay", type=float, default=20)
    p = common(sub.add_parser("record-channel"))
    p.add_argument("--tag", action="append", required=True)
    p.add_argument("--now")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--pending", action="store_true")
    mode.add_argument("--confirm", action="store_true")
    p = common(sub.add_parser("retention"), identity=False)
    p.add_argument("--public-repo", required=True)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--keep-testing", type=int, default=5)
    p.add_argument("--window-days", type=int, default=30)
    p.add_argument("--now")
    p = common(sub.add_parser("locked-run"), identity=False)
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = common(sub.add_parser("lease-check"), identity=False)
    p.add_argument("--min-remaining-seconds", type=int, default=0)
    p = common(sub.add_parser("consumer-digests"), identity=False)
    p.add_argument("--now")
    args = ap.parse_args()
    try:
        {"claim": cmd_claim, "upload": cmd_upload, "verify-public": cmd_verify_public,
         "record-channel": cmd_record_channel, "retention": cmd_retention,
         "locked-run": cmd_locked_run, "lease-check": cmd_lease_check,
         "consumer-digests": cmd_consumer_digests}[args.cmd](args)
    except (RuntimeError, OSError, Conflict) as e:
        die(str(e))


if __name__ == "__main__":
    main()
