#!/usr/bin/env python3
import hashlib
import sys

from config_values import ROOT, read_config


def image_name():
    version = read_config()["DEFAULT_FEDORA_VERSION"]
    digest = hashlib.sha256()
    for relative in (
        "ci/Containerfile",
        "tools/ci-image-name.py",
        "tools/config_values.py",
    ):
        file_digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        digest.update(f"{file_digest}  {relative}\n".encode())
    digest.update(f"DEFAULT_FEDORA_VERSION={version}\n".encode())
    return f"ghcr.io/luminusos/images-ci:fc{version}-{digest.hexdigest()[:12]}"


if __name__ == "__main__":
    try:
        print(image_name())
    except (OSError, KeyError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
