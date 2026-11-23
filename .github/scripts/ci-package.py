#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def resolve_packaging_image(image: str) -> str:
    reference = re.fullmatch(r"([^@\s]+)@(sha256:[0-9a-f]{64})", image)
    if reference is None:
        raise ValueError("packaging requires an immutable repository@sha256 reference")
    result = subprocess.run(
        ["skopeo", "inspect", "--raw", f"docker://{image}"],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = json.loads(result.stdout)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ValueError("invalid image manifest schema")
    manifest_types = (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
    media_type = manifest.get("mediaType")
    if media_type in manifest_types:
        if (
            not isinstance(manifest.get("config"), dict)
            or not isinstance(manifest.get("layers"), list)
            or "manifests" in manifest
        ):
            raise ValueError("invalid image manifest shape")
        return image
    if media_type not in (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ) or not isinstance(manifest.get("manifests"), list):
        raise ValueError("invalid image index shape or media type")
    candidates: list[str] = []
    for descriptor in manifest["manifests"]:
        if not isinstance(descriptor, dict) or "platform" not in descriptor:
            raise ValueError("invalid image index descriptor")
        platform = descriptor.get("platform")
        digest = descriptor.get("digest")
        if (
            not isinstance(platform, dict)
            or not isinstance(platform.get("os"), str)
            or not isinstance(platform.get("architecture"), str)
            or descriptor.get("mediaType") not in manifest_types
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise ValueError("invalid image index platform, media type or digest")
        if platform["os"] == "linux" and platform["architecture"] == "amd64":
            candidates.append(digest)
    if len(candidates) != 1:
        raise ValueError("image index must contain exactly one linux/amd64 manifest")
    return f"{reference[1]}@{candidates[0]}"


def main() -> int:
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
        subprocess.run(
            ["dnf", "-y", "install", "image-builder", "podman", "skopeo"], check=True
        )
        subprocess.run(
            ["python3", str(Path(__file__).with_name("ci-mount-probe.py"))],
            check=True,
        )
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
        packaging_image = resolve_packaging_image(image)
        print(f"Packaging source: {image}; platform manifest: {packaging_image}")
        subprocess.run(["podman", "pull", packaging_image], check=True, env=env)
        subprocess.run(
            [
                "python3",
                "./tools/package-artifact.py",
                args.format,
                packaging_image,
                output,
            ],
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
