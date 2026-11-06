#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

VERSION = r"[0-9]+\.[0-9]{8}(?:\.[0-9]+)?"
EVIDENCE_NAMES = {
    "sbom.spdx.json",
    "provenance.json",
    "vulnerabilities.json",
    "scan-evidence.json",
    "release-evidence.json",
    "candidate.json",
    "validation.json",
}
PUBLIC_KEY = (
    Path(__file__).resolve().parents[2]
    / "shared/trust/etc/pki/containers/luminusos.pub"
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_digest(url):
    command = ["curl", "--fail", "--silent", "--show-error", url]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, start_new_session=True)
    digest = hashlib.sha256()
    try:
        with process.stdout:
            for block in iter(lambda: process.stdout.read(1024 * 1024), b""):
                digest.update(block)
        code = process.wait()
        if code:
            raise subprocess.CalledProcessError(code, command)
        return digest.hexdigest()
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except ProcessLookupError:
                process.wait()
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def _evidence_files(dist):
    root = dist.resolve(strict=True)
    images = {
        path.name for path in dist.iterdir() if path.name.endswith((".iso", ".qcow2"))
    }
    selected = {}
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ValueError("Evidence directory must not contain symlinks")
        if not path.is_file():
            continue
        relative = path.relative_to(dist).as_posix()
        if (
            any(c in relative for c in "\r\n\\")
            or relative.startswith("/")
            or ".." in relative.split("/")
        ):
            raise ValueError("Unsafe evidence path")
        resolved = path.resolve(strict=True)
        if resolved != root and root not in resolved.parents:
            raise ValueError("Evidence path escapes distribution directory")
        if (
            path.name in EVIDENCE_NAMES
            and (path.suffix == ".json" or path.name.endswith(".json"))
            or path.name.endswith(".sig")
            and path.name[:-4] in EVIDENCE_NAMES
            or path.name in images
        ):
            selected[relative] = path
    return selected


def _required_evidence(dist, artifacts):
    files = _evidence_files(dist)
    manifest = dist / "SHA256SUMS"
    signature = dist / "SHA256SUMS.sig"
    if (
        not manifest.is_file()
        or manifest.is_symlink()
        or not signature.is_file()
        or signature.is_symlink()
    ):
        raise ValueError("--require-evidence requires SHA256SUMS and SHA256SUMS.sig")
    subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(PUBLIC_KEY),
            "--signature",
            str(signature),
            str(manifest),
        ],
        check=True,
        capture_output=True,
    )
    expected = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line, re.ASCII)
        if not match:
            raise ValueError("Malformed SHA256SUMS entry")
        name, digest = match.group(2), match.group(1)
        if (
            name.startswith("/")
            or ".." in name.split("/")
            or "\\" in name
            or name in expected
        ):
            raise ValueError("Unsafe or duplicate SHA256SUMS entry")
        expected[name] = digest
    required = {
        path.relative_to(dist).as_posix(): sha256(path)
        for path in files.values()
        if not path.name.endswith(".sig")
    }
    image_paths = {
        path.relative_to(dist).as_posix(): sha256(path) for path in artifacts.values()
    }
    required.update(image_paths)
    if expected != required:
        raise ValueError(
            "SHA256SUMS does not exactly match published artifacts and evidence"
        )
    files.update({path.name: path for path in artifacts.values()})
    files["SHA256SUMS"] = manifest
    files["SHA256SUMS.sig"] = signature
    return files


def publish(channel, version, dist, bucket, endpoint, require_evidence=False):
    version_pattern = ("testing-" if channel == "testing" else "") + VERSION
    if channel not in ("testing", "stable") or not re.fullmatch(
        version_pattern, version, re.ASCII
    ):
        raise ValueError("Invalid channel or version")
    if (
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])?", bucket, re.ASCII)
        or ".." in bucket
    ):
        raise ValueError("Invalid bucket")
    url = urlsplit(endpoint)
    if (
        url.scheme not in ("http", "https")
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        raise ValueError("Invalid R2 endpoint")
    base = f"luminusos-workstation-{version}"
    artifacts = {fmt: dist / f"{base}.{fmt}" for fmt in ("iso", "qcow2")}
    for path in artifacts.values():
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Missing or empty artifact: {path}")
    evidence_files = (
        _required_evidence(dist, artifacts)
        if require_evidence
        else {path.name: path for path in artifacts.values()}
    )
    aws_args = ["--endpoint-url", endpoint, "--region", "auto"]
    destination = f"s3://{bucket}/{channel}/{version}"
    public_root = f"https://download.luminusos.org/{quote(channel)}/{quote(version)}"
    public = f"{public_root}/{base}"
    uploaded_links = {}
    for relative, path in evidence_files.items():
        remote_path = "/".join(
            quote(segment, safe="") for segment in relative.split("/")
        )
        public_url = f"{public_root}/{remote_path}"
        subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                str(path),
                f"{destination}/{remote_path}",
                *aws_args,
                "--no-progress",
                "--content-type",
                "application/octet-stream",
            ],
            check=True,
        )
        actual = download_digest(public_url)
        if actual != sha256(path):
            raise ValueError(f"Public download checksum mismatch: {relative}")
        uploaded_links[relative] = public_url
    manifest = {
        "version": version,
        "assets": {fmt: f"{public}.{fmt}" for fmt in artifacts},
    }
    if require_evidence:
        manifest["evidence"] = {
            name: url
            for name, url in uploaded_links.items()
            if name
            not in {path.relative_to(dist).as_posix() for path in artifacts.values()}
        }
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "latest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                str(path),
                f"s3://{bucket}/{channel}/latest.json",
                *aws_args,
                "--content-type",
                "application/json",
                "--cache-control",
                "no-cache",
                "--no-progress",
            ],
            check=True,
        )
    result = subprocess.run(
        ["aws", "s3", "ls", f"s3://{bucket}/{channel}/", *aws_args],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"\s*PRE\s+([^/\s]+)/\s*", line)
        if not match:
            continue
        old = match.group(1)
        if old != version and re.fullmatch(version_pattern, old, re.ASCII):
            subprocess.run(
                [
                    "aws",
                    "s3",
                    "rm",
                    f"s3://{bucket}/{channel}/{old}/",
                    "--recursive",
                    *aws_args,
                    "--no-progress",
                ],
                check=True,
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("channel", choices=("testing", "stable"))
    parser.add_argument("version")
    parser.add_argument("dist", type=Path)
    parser.add_argument("--require-evidence", action="store_true")
    args = parser.parse_args()
    try:
        publish(
            args.channel,
            args.version,
            args.dist,
            os.environ["R2_BUCKET"],
            os.environ["R2_ENDPOINT"],
            args.require_evidence,
        )
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"publish-r2: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    previous = signal.signal(
        signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    finally:
        signal.signal(signal.SIGTERM, previous)
