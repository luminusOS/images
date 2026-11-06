import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

DIGEST = re.compile(r"\bdigest:\s*(sha256:[0-9a-f]{64})\b")
KEY = Path("shared/trust/etc/pki/containers/luminusos.pub")


def push_and_sign(image: str) -> str:
    if "@" in image or not re.fullmatch(
        r"ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
        image,
    ):
        raise ValueError("invalid candidate image reference")
    result = subprocess.run(
        ["docker", "push", image], check=True, capture_output=True, text=True
    )
    matches = DIGEST.findall(result.stdout + "\n" + result.stderr)
    if len(matches) != 1:
        raise ValueError(f"push did not return one manifest digest for {image}")
    immutable = f"{image.rsplit(':', 1)[0]}@{matches[0]}"
    subprocess.run(
        ["cosign", "sign", "--yes", "--key", "env://COSIGN_PRIVATE_KEY", immutable],
        check=True,
    )
    subprocess.run(
        ["cosign", "verify", "--key", str(KEY), immutable],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return immutable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installer-only", action="store_true")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("images", nargs="+")
    args = parser.parse_args()
    try:
        if args.metadata:
            if args.installer_only or len(args.images) != 3:
                raise ValueError("metadata requires core, workstation and installer")
            metadata = {
                "version": 1,
                "repository": os.environ["GITHUB_REPOSITORY"],
                "source_sha": os.environ["GITHUB_SHA"],
                "run_id": int(os.environ["GITHUB_RUN_ID"]),
                "channel": os.environ["CHANNEL"],
                "version_tag": os.environ["VERSION_TAG"],
                "build_version": os.environ["BUILD_VERSION"],
                "fedora_version": os.environ["FEDORA_VERSION"],
                "fedora_bootc_digest": os.environ["FEDORA_BOOTC_DIGEST"],
                "images": dict(
                    zip(("core", "workstation", "installer"), args.images, strict=True)
                ),
            }
            args.metadata.write_text(
                json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
            )
            return 0
        if args.installer_only and len(args.images) != 1:
            raise ValueError("expected one installer image")
        if not args.installer_only and len(args.images) not in (2, 3):
            raise ValueError("expected core and workstation, optionally installer")
        if not os.environ.get("COSIGN_PRIVATE_KEY"):
            raise ValueError("COSIGN_PRIVATE_KEY is required")
        if not KEY.is_file():
            raise ValueError("trusted signing key is unavailable")
        references = [push_and_sign(image) for image in args.images]
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            names = (
                ("installer",)
                if args.installer_only
                else ("core", "workstation", "installer")[: len(references)]
            )
            for name, reference in zip(names, references, strict=True):
                print(f"{name}={reference}", file=output)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"candidate publication failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
