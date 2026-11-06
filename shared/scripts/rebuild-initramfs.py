#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    result = subprocess.run(
        ["kernel-install", "list", "--json", "pretty"],
        capture_output=True,
        text=True,
        check=True,
    )
    version = next(
        (
            item["version"]
            for item in json.loads(result.stdout)
            if item.get("has_kernel") is True
        ),
        None,
    )
    if not version:
        versions = sorted(path.name for path in Path("/lib/modules").iterdir())
        if not versions:
            raise ValueError("No installed kernel found")
        version = versions[-1]
    if "/" in version or version in (".", ".."):
        raise ValueError("invalid kernel version")
    subprocess.run(["plymouth-set-default-theme", "lucent"], check=True)
    subprocess.run(
        [
            "dracut",
            "-v",
            "-f",
            "--zstd",
            "--reproducible",
            "--no-hostonly",
            *sys.argv[1:],
            f"/usr/lib/modules/{version}/initramfs.img",
            version,
        ],
        env={**os.environ, "DRACUT_NO_XATTR": "1"},
        check=True,
    )


if __name__ == "__main__":
    main()
