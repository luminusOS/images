#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=("iso", "qcow2"))
    parser.add_argument("image")
    parser.add_argument("output")
    parser.add_argument("pointer", nargs="?")
    args = parser.parse_args()
    if not args.image or not args.output:
        parser.error("image and output must not be empty")
    command = ([] if os.geteuid() == 0 else ["sudo"]) + [
        "image-builder",
        "build",
        "--output-dir",
        ".",
        "--output-name",
        args.output,
    ]
    if cache := os.environ.get("IMAGE_BUILDER_CACHE"):
        command.extend(["--cache", cache])
    command.extend(
        [
            "--bootc-ref",
            args.image,
            "bootc-generic-iso" if args.format == "iso" else "qcow2",
        ]
    )
    if os.environ.get("IMAGE_BUILDER_DRY_RUN", "0") == "1":
        print(shlex.join(command))
        return 0
    try:
        subprocess.run(command, check=True)
        path = Path.cwd() / args.output
        if not path.is_file():
            raise ValueError(f"Expected artifact was not created: {path}")
        if args.pointer:
            Path(args.pointer).write_text(f"{path}\n")
            print(f"Wrote artifact pointer: {args.pointer} -> {path}")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"package-artifact: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
