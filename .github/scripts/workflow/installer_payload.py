import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def command(args, capture=False):
    return subprocess.run(args, check=True, capture_output=capture, text=True)


def export_payload(image, channel, digest):
    Path(".test").mkdir(exist_ok=True)
    if channel == "stable":
        if not DIGEST.fullmatch(digest):
            raise ValueError("stable installer requires workstation manifest digest")
        immutable = f"{image.rsplit(':', 1)[0]}@{digest}"
        command(["docker", "pull", immutable])
        command(["docker", "tag", immutable, image])
        source = f"docker://{immutable}"
    elif channel == "testing":
        source = f"docker-daemon:{image}"
    else:
        raise ValueError("invalid channel")
    command(["skopeo", "copy", source, "oci:.test/payload.oci:latest"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("export",))
    parser.parse_args()
    env = os.environ
    export_payload(env["IMAGE"], env["CHANNEL"], env.get("WORKSTATION_DIGEST", ""))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"build helper: {exc}", file=sys.stderr)
        sys.exit(1)
