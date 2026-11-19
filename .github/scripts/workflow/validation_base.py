"""Confirm an image candidate's pinned published base before a disk is built.

The disposable validation disk must be built from the release the candidate
was prepared against. When release history or the line tag has moved since,
the candidate is stale and the run fails before anything is built.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import published_base
import release_pipeline

DISK_NAME = "published-base.qcow2"


def check(candidate: dict) -> dict:
    release_pipeline.require(
        release_pipeline.release_kind(candidate) == "image",
        "only image candidates are validated from a published base",
    )
    pinned = candidate["published_base"]
    current = published_base.resolve(
        candidate["repository"], candidate["channel"], candidate["fedora_version"]
    )
    for edition in published_base.EDITIONS:
        release_pipeline.require(
            current.get(edition) == pinned[edition],
            f"stale candidate: the published {edition} base is now "
            f"{(current.get(edition) or {}).get('version')} "
            f"{(current.get(edition) or {}).get('index_digest')}, the candidate pins "
            f"{pinned[edition]['version']} {pinned[edition]['index_digest']}",
        )
    release_pipeline.require(current == pinned, "stale candidate: published base moved")
    workstation = pinned["workstation"]
    repository = published_base.image_repository(candidate["repository"], "workstation")
    return {
        "workstation_image": f"{repository}@{workstation['index_digest']}",
        "base_manifest": workstation["manifest_digest"],
        "fedora_version": candidate["fedora_version"],
        "disk_name": DISK_NAME,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        candidate = release_pipeline.candidate(
            args.candidate, args.public_key, legacy_only=True
        )
        outputs = check(candidate)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.writelines(f"{k}={v}\n" for k, v in outputs.items())
    except (
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"published base check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(outputs, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
