#!/usr/bin/env python3
"""Assemble, sign and verify one hardware feature release snapshot.

  release.py assemble <dir> --version V --image-digest sha256:...
  release.py sign <dir> --key <fingerprint>      (uses GNUPGHOME)
  release.py verify <dir> --keyring <file> --version V --image-digest sha256:... [--raw|--offline]
  release.py verify-installer <dir> --keyring <file> --payload <OCI layout> --os-release <file>

assemble reads the per-feature metadata written by guard.py, checks the
whole feature matrix, and writes SHA256SUMS (.raw.xz, verified online by
systemd-sysupdate), SHA256SUMS.raw (.raw, for the offline ISO import) and the
release.json descriptor that binds both to one workstation image digest.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SIGNED = ("SHA256SUMS", "SHA256SUMS.raw", "release.json")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+~-]+$")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    sys.exit(f"release: {msg}")


def check_identity(version, digest):
    if not VERSION_RE.match(version):
        fail(f"invalid version {version!r}")
    if not DIGEST_RE.match(digest):
        fail(f"invalid image digest {digest!r}")


def load_features(d, version, digest):
    metas = []
    for path in sorted(glob.glob(f"{d}/luminusos-*_{version}.json")):
        with open(path, encoding="utf-8") as fh:
            meta = json.load(fh)
        name = f"luminusos-{meta['id']}_{version}"
        if os.path.basename(path) != f"{name}.json":
            fail(f"{path}: metadata names feature {meta['id']}")
        if meta["version"] != version or meta["image_digest"] != digest:
            fail(f"{name}: built for {meta['version']} {meta['image_digest']}, not {version} {digest}")
        for key, file in (("raw_sha256", meta["raw"]), ("raw_xz_sha256", meta["raw_xz"])):
            if sha256(f"{d}/{file}") != meta[key]:
                fail(f"{file}: hash differs from its build metadata")
        metas.append(meta)
    if not metas:
        fail(f"no feature metadata for version {version} in {d}")
    return metas


def check_matrix(metas):
    """Shared directories are fine; any other path owned by two features, or
    owned as a directory by one and as a file or symlink by another, is not."""
    owners, errors = {}, []
    for meta in metas:
        for path, kind in meta["nodes"].items():
            owners.setdefault(path, {})[meta["id"]] = kind
    for path, by_id in sorted(owners.items()):
        if len(by_id) > 1 and set(by_id.values()) != {"d"}:
            desc = ", ".join(f"{fid} ({kind})" for fid, kind in sorted(by_id.items()))
            errors.append(f"{path} is shipped by {desc}")
    for meta in metas:
        for ref in meta["exec_refs"]:
            others = set(owners.get(ref, {})) - {meta["id"]}
            if others:
                errors.append(f"{meta['id']} executes {ref} owned by {', '.join(sorted(others))}")
    if errors:
        for e in errors:
            print(f"release: {e}", file=sys.stderr)
        fail("feature matrix check failed")


def atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def assemble(args):
    check_identity(args.version, args.image_digest)
    metas = load_features(args.dir, args.version, args.image_digest)
    check_matrix(metas)
    architectures = {m["architecture"] for m in metas}
    if len(architectures) != 1:
        fail(f"mixed architectures {sorted(architectures)}")
    for name in SIGNED:
        for p in (f"{args.dir}/{name}", f"{args.dir}/{name}.gpg"):
            if os.path.lexists(p):
                os.unlink(p)
    sums = "".join(f"{m['raw_xz_sha256']}  {m['raw_xz']}\n" for m in metas)
    sums_raw = "".join(f"{m['raw_sha256']}  {m['raw']}\n" for m in metas)
    descriptor = {
        "format": 1,
        "version": args.version,
        "architecture": architectures.pop(),
        "image_digest": args.image_digest,
        "features": {
            m["id"]: {
                "raw_xz_sha256": m["raw_xz_sha256"],
                "raw_sha256": m["raw_sha256"],
                "compressed_budget_mib": m["compressed_budget_mib"],
                "expanded_budget_mib": m["expanded_budget_mib"],
            }
            for m in metas
        },
    }
    atomic_write(f"{args.dir}/SHA256SUMS", sums)
    atomic_write(f"{args.dir}/SHA256SUMS.raw", sums_raw)
    atomic_write(f"{args.dir}/release.json", json.dumps(descriptor, indent=2, sort_keys=True) + "\n")
    print(f"release: assembled {len(metas)} feature(s) for {args.version} {args.image_digest}")


def sign(args):
    for name in SIGNED:
        path = f"{args.dir}/{name}"
        if not os.path.isfile(path):
            fail(f"{path} missing; run assemble first")
        subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
             "--local-user", args.key, "--detach-sign", "--output", f"{path}.gpg", path],
            input=os.environ.get("SYSEXT_SIGNING_PASSPHRASE", "").encode(), check=True,
        )
    print(f"release: signed {', '.join(SIGNED)} with {args.key}")


def gpgv(keyring, path):
    r = subprocess.run(["gpgv", "--keyring", os.path.abspath(keyring), f"{path}.gpg", path],
                       capture_output=True, text=True)
    if r.returncode:
        fail(f"{os.path.basename(path)}: signature does not verify\n{r.stderr.strip()}")


def parse_sums(path):
    entries = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            digest, name = line.rstrip("\n").split("  ", 1)
            if name in entries:
                fail(f"{path}: duplicate entry {name}")
            entries[name] = digest
    return entries


def verify(args, *, installer=False, discovery_dir=None):
    check_identity(args.version, args.image_digest)
    if args.offline:
        signed = ("SHA256SUMS.raw", "release.json")
    elif args.raw:
        signed = SIGNED
    else:
        signed = ("SHA256SUMS", "release.json")
    for name in signed:
        gpgv(args.keyring, f"{args.dir}/{name}")
    with open(f"{args.dir}/release.json", encoding="utf-8") as fh:
        descriptor = json.load(fh)
    if descriptor.get("format") != 1:
        fail("unsupported descriptor format")
    if descriptor.get("version") != args.version:
        fail(f"descriptor names version {descriptor.get('version')}, expected {args.version}")
    if descriptor.get("image_digest") != args.image_digest:
        fail(f"descriptor names image {descriptor.get('image_digest')}, expected {args.image_digest}")
    features = descriptor.get("features") or {}
    if not features:
        fail("descriptor lists no features")
    if discovery_dir is not None:
        discovered = {p.stem for p in discovery_dir.glob("*.feature")} - {"luminusos-discovery-probe"}
        if set(features) != discovered:
            fail(f"installer feature matrix mismatch: missing={sorted(discovered - features.keys())}; "
                 f"not discoverable={sorted(features.keys() - discovered)}")
    lists = [] if args.offline else [("SHA256SUMS", ".raw.xz", "raw_xz_sha256")]
    if args.raw or args.offline:
        lists.append(("SHA256SUMS.raw", ".raw", "raw_sha256"))
    for list_name, suffix, key in lists:
        sums = parse_sums(f"{args.dir}/{list_name}")
        want = {f"luminusos-{fid}_{args.version}{suffix}": e[key] for fid, e in features.items()}
        if sums != want:
            fail(f"{list_name} does not match the descriptor")
        for name, digest in want.items():
            if sha256(f"{args.dir}/{name}") != digest:
                fail(f"{name}: payload hash does not match")
    if installer:
        expected = set(want) | {name + suffix for name in signed for suffix in ("", ".gpg")}
        if {path.name for path in Path(args.dir).iterdir()} != expected:
            fail("installer feature directory contains unexpected files")
    print(f"release: verified {len(features)} feature(s) for {args.version} {args.image_digest}")


def verify_installer(args):
    versions = re.findall(r"^IMAGE_VERSION=(.*)$", args.os_release.read_text(), re.MULTILINE)
    if len(versions) != 1:
        fail("expected exactly one live IMAGE_VERSION")
    version = versions[0]
    if len(version) >= 2 and version[0] in "\"'" and version[-1] == version[0]:
        version = version[1:-1]
    if not VERSION_RE.fullmatch(version) or version in {".", ".."}:
        fail("invalid live IMAGE_VERSION")
    index = json.loads((args.payload / "index.json").read_bytes())
    latest = [
        entry for entry in index["manifests"]
        if entry.get("annotations", {}).get("org.opencontainers.image.ref.name") == "latest"
    ]
    if len(latest) != 1:
        fail("expected exactly one latest OCI manifest")
    digest = latest[0]["digest"]
    if not DIGEST_RE.fullmatch(digest):
        fail("invalid installer OCI manifest digest")
    manifest = (args.payload / "blobs" / "sha256" / digest.removeprefix("sha256:")).read_bytes()
    if f"sha256:{hashlib.sha256(manifest).hexdigest()}" != digest:
        fail("installer OCI manifest bytes do not match index digest")
    document = json.loads(manifest)
    if document.get("schemaVersion") != 2:
        fail("unsupported installer OCI manifest schema")
    for descriptor in [document["config"], *document["layers"]]:
        blob_digest = descriptor["digest"]
        size = descriptor["size"]
        if not DIGEST_RE.fullmatch(blob_digest) or type(size) is not int or size < 0:
            fail("invalid installer OCI blob descriptor")
        blob = args.payload / "blobs" / "sha256" / blob_digest.removeprefix("sha256:")
        if not blob.is_file() or blob.stat().st_size != size or f"sha256:{sha256(blob)}" != blob_digest:
            fail(f"installer OCI blob does not match manifest: {blob_digest}")
    verify(argparse.Namespace(
        dir=args.dir, keyring=args.keyring, version=version, image_digest=digest,
        offline=True, raw=False,
    ), installer=True, discovery_dir=args.discovery_dir)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("dir")
    a.add_argument("--version", required=True)
    a.add_argument("--image-digest", required=True)
    s = sub.add_parser("sign")
    s.add_argument("dir")
    s.add_argument("--key", required=True)
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--keyring", required=True)
    v.add_argument("--version", required=True)
    v.add_argument("--image-digest", required=True)
    mode = v.add_mutually_exclusive_group()
    mode.add_argument("--raw", action="store_true", help="also verify the offline .raw list and files")
    mode.add_argument("--offline", action="store_true",
                      help="verify only the ISO subset: release.json, SHA256SUMS.raw and the .raw files")
    i = sub.add_parser("verify-installer")
    i.add_argument("dir")
    i.add_argument("--keyring", required=True)
    i.add_argument("--payload", required=True, type=Path)
    i.add_argument("--os-release", required=True, type=Path)
    i.add_argument("--discovery-dir", type=Path)
    args = ap.parse_args()
    {"assemble": assemble, "sign": sign, "verify": verify, "verify-installer": verify_installer}[args.cmd](args)


if __name__ == "__main__":
    main()
