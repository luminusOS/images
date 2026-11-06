import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
KEY = ROOT / "shared/trust/etc/pki/containers/luminusos.pub"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def inputs_hash(root, fedora, base):
    if not re.fullmatch(r"[0-9]+", fedora) or not DIGEST.fullmatch(base):
        raise ValueError("invalid Fedora or base digest")
    paths = [root / "editions/core", root / "shared/trust"]
    paths += [
        root / "shared/scripts" / name
        for name in ("dnf-releasever.py", "os-release-set.py", "rpmdb-repair.py")
    ]
    digest = hashlib.sha256(f"fedora={fedora}\nbase={base}\n".encode())
    for source in paths:
        if not source.exists() or source.is_symlink():
            raise ValueError(f"missing or symlinked core input: {source}")
        for path in sorted(source.rglob("*") if source.is_dir() else [source]):
            if path.is_symlink():
                raise ValueError(f"symlinked core input: {path}")
            if path.is_file():
                digest.update(str(path.relative_to(root)).encode() + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def command(args, capture=False):
    return subprocess.run(args, check=True, capture_output=capture, text=True)


def select(ref, fedora, fingerprint, target, force=False):
    if force or not ref:
        return ""
    if not re.fullmatch(
        r"ghcr\.io/[a-z0-9_.-]+/luminusos(?::[A-Za-z0-9_.-]+|@sha256:[0-9a-f]{64})", ref
    ):
        return ""
    try:
        digest = command(
            ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{ref}"], True
        ).stdout.strip()
        if not DIGEST.fullmatch(digest) or (
            "@" in ref and ref.split("@", 1)[1] != digest
        ):
            return ""
        immutable = f"{ref.split('@', 1)[0].rsplit(':', 1)[0]}@{digest}"
        command(["cosign", "verify", "--key", str(KEY), immutable], True)
        image = json.loads(
            command(["skopeo", "inspect", f"docker://{immutable}"], True).stdout
        )
        if not isinstance(image, dict):
            return ""
        labels = image.get("Labels") or {}
        if not isinstance(labels, dict):
            return ""
        if (
            labels.get("org.luminusos.core.fedora") != fedora
            or labels.get("org.luminusos.core.inputs-sha256") != fingerprint
        ):
            return ""
        command(["docker", "pull", immutable])
        command(["docker", "tag", immutable, target])
        return digest
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError):
        return ""


def image_id(ref):
    value = command(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref], True
    ).stdout.strip()
    if not DIGEST.fullmatch(value):
        raise ValueError("invalid local image id")
    return value


def save(ref, archive):
    identity = image_id(ref)
    command(["docker", "save", "-o", str(archive), ref])
    with archive.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    return identity, checksum


def load(ref, archive, checksum, identity):
    if not re.fullmatch(r"[0-9a-f]{64}", checksum) or not DIGEST.fullmatch(identity):
        raise ValueError("invalid archive metadata")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            raise ValueError("archive checksum mismatch")
    command(["docker", "load", "-i", str(archive)])
    if image_id(ref) != identity:
        raise ValueError("loaded image id mismatch")


def export_payload(image, channel, digest):
    Path(".test").mkdir(exist_ok=True)
    if channel == "stable":
        if not DIGEST.fullmatch(digest):
            raise ValueError("stable installer requires workstation manifest digest")
        immutable = f"{image.rsplit(':', 1)[0]}@{digest}"
        command(["docker", "pull", immutable])
        command(["docker", "tag", immutable, image])
        source = f"docker://{immutable}"
    elif channel == "testing":
        source = f"docker-daemon:{image}"
    else:
        raise ValueError("invalid channel")
    command(["skopeo", "copy", source, "oci:.test/payload.oci:latest"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("hash", "select", "save", "load", "export"))
    args = parser.parse_args()
    env = os.environ
    outputs = {}
    if args.action == "hash":
        outputs["fingerprint"] = inputs_hash(
            ROOT, env["FEDORA_VERSION"], env["BASE_DIGEST"]
        )
    elif args.action == "select":
        digest = select(
            env.get("CORE_REF", ""),
            env["FEDORA_VERSION"],
            env["FINGERPRINT"],
            env["IMAGE"],
            env.get("FORCE_REBUILD") == "true",
        )
        outputs.update(reused=str(bool(digest)).lower(), digest=digest)
    elif args.action == "save":
        identity, checksum = save(env["IMAGE"], Path(env["ARCHIVE"]))
        outputs.update(image_id=identity, archive_sha256=checksum)
    elif args.action == "load":
        load(env["IMAGE"], Path(env["ARCHIVE"]), env["ARCHIVE_SHA256"], env["IMAGE_ID"])
    else:
        export_payload(env["IMAGE"], env["CHANNEL"], env.get("WORKSTATION_DIGEST", ""))
    if outputs:
        with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            for key, value in outputs.items():
                print(f"{key}={value}", file=out)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"build helper: {exc}", file=sys.stderr)
        sys.exit(1)
