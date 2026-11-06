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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("hash", "select"))
    args = parser.parse_args()
    env = os.environ
    outputs = {}
    if args.action == "hash":
        outputs["fingerprint"] = inputs_hash(
            ROOT, env["FEDORA_VERSION"], env["BASE_DIGEST"]
        )
    else:
        digest = select(
            env.get("CORE_REF", ""),
            env["FEDORA_VERSION"],
            env["FINGERPRINT"],
            env["IMAGE"],
            env.get("FORCE_REBUILD") == "true",
        )
        outputs.update(reused=str(bool(digest)).lower(), digest=digest)
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
