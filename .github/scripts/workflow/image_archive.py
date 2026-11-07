import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def command(args, capture=False):
    return subprocess.run(args, check=True, capture_output=capture, text=True)


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
    actual = image_id(ref)
    if actual != identity:
        raise ValueError(f"loaded image id mismatch: expected {identity}, got {actual}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("save", "load"))
    args = parser.parse_args()
    env = os.environ
    if args.action == "save":
        identity, checksum = save(env["IMAGE"], Path(env["ARCHIVE"]))
        with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
            print(f"image_id={identity}", file=out)
            print(f"archive_sha256={checksum}", file=out)
    else:
        load(env["IMAGE"], Path(env["ARCHIVE"]), env["ARCHIVE_SHA256"], env["IMAGE_ID"])


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"build helper: {exc}", file=sys.stderr)
        sys.exit(1)
