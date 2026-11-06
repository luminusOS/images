#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fedora_version")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.fedora_version, flags=re.ASCII):
        parser.error("FEDORA_VERSION must contain only digits")
    try:
        response = subprocess.run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--head",
                "--header",
                "Accept: application/vnd.oci.image.index.v1+json",
                f"https://quay.io/v2/fedora/fedora-bootc/manifests/{args.fedora_version}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            f"Could not resolve fedora-bootc:{args.fedora_version} digest: {exc}",
            file=sys.stderr,
        )
        return 1
    values = [
        line.split(":", 1)[1].strip()
        for line in response.stdout.splitlines()
        if line.lower().startswith("docker-content-digest:")
    ]
    if len(values) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", values[0]):
        print(
            f"Could not resolve fedora-bootc:{args.fedora_version} digest",
            file=sys.stderr,
        )
        return 1
    print(values[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
