#!/usr/bin/env python3
import argparse
import json
import os
import re
import signal
import subprocess
import sys


def run(command, *, capture=False):
    isolated = not sys.stdin.isatty()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE if capture else None,
        text=True,
        start_new_session=isolated,
    )
    try:
        output, _ = process.communicate()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM) if isolated else process.terminate()
            process.wait(timeout=10)
        except ProcessLookupError:
            process.wait()
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL) if isolated else process.kill()
            process.wait()
        raise
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    args = parser.parse_args()
    if not args.image or args.image.startswith("-"):
        parser.error("invalid image reference")
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    container = ""
    try:
        raw = run(
            ["sudo", "buildah", "inspect", "--type", "image", args.image],
            capture=True,
        )
        try:
            image = json.loads(raw)["OCIv1"]
            rootfs = image["rootfs"]
            layers = rootfs["diff_ids"]
            labels = image["config"]["Labels"]
            valid = (
                rootfs["type"] == "layers"
                and isinstance(layers, list)
                and bool(layers)
                and all(
                    isinstance(layer, str)
                    and re.fullmatch(
                        r"[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-f0-9]{32,}", layer
                    )
                    for layer in layers
                )
                and isinstance(labels, dict)
                and all(
                    isinstance(k, str) and isinstance(v, str) for k, v in labels.items()
                )
            )
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("invalid buildah image metadata") from error
        if not valid:
            raise ValueError("invalid buildah image metadata")
        if (
            len(layers) == 1
            and not {"ostree.final-diffid", "ostree.commit"} & labels.keys()
        ):
            return
        container = run(
            ["sudo", "buildah", "from", "--pull=never", args.image], capture=True
        ).strip()
        if not container:
            raise ValueError("buildah did not return a container")
        run(
            [
                "sudo",
                "buildah",
                "config",
                "--unsetlabel",
                "ostree.final-diffid",
                "--unsetlabel",
                "ostree.commit",
                container,
            ]
        )
        run(["sudo", "buildah", "commit", "--squash", container, args.image])
    finally:
        if container:
            subprocess.run(
                ["sudo", "buildah", "rm", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"squash-image: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
