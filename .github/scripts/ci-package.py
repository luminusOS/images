#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=("iso", "qcow2"))
    args = parser.parse_args()
    image_key = "WORKSTATION_ISO_IMAGE" if args.format == "iso" else "WORKSTATION_IMAGE"
    try:
        image = os.environ[image_key]
        output = os.environ["OUTPUT_NAME"]
        if not image or not output:
            raise ValueError("image reference and output name must not be empty")
        token = os.environ.get("GHCR_TOKEN", "")
        user = os.environ.get("GHCR_USER", "")
        if token and not user:
            raise ValueError("GHCR_USER is required when GHCR_TOKEN is set")
        subprocess.run(["dnf", "-y", "install", "image-builder", "podman"], check=True)
        if token:
            subprocess.run(
                ["podman", "login", "ghcr.io", "-u", user, "--password-stdin"],
                input=token,
                text=True,
                check=True,
            )
        else:
            print(
                "WARNING: GHCR_TOKEN is empty — private pulls may fail", file=sys.stderr
            )
        env = os.environ.copy()
        env["IMAGE_BUILDER_CACHE"] = str(Path.cwd() / ".osbuild-cache")
        subprocess.run(["podman", "pull", image], check=True, env=env)
        subprocess.run(
            ["python3", "./tools/package-artifact.py", args.format, image, output],
            check=True,
            env=env,
        )
        if not Path(output).is_file():
            raise ValueError(f"artifact not found: {output}")
        subprocess.run(["ls", "-lh", output], check=True)
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ci-package: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
