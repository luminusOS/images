#!/usr/bin/env python3
import argparse
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, *, capture=False, **kwargs):
    isolated = not sys.stdin.isatty()
    process = subprocess.Popen(
        command,
        start_new_session=isolated,
        stdout=subprocess.PIPE if capture else kwargs.pop("stdout", None),
        text=capture,
        **kwargs,
    )
    try:
        output, _ = process.communicate()
    except BaseException:
        try:
            if isolated:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=10)
        except ProcessLookupError:
            process.wait()
        except subprocess.TimeoutExpired:
            if isolated:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
        raise
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command)
    return output


def verify_disk_layout(image):
    if not image.startswith("localhost/"):
        return
    container = run(
        ["sudo", "buildah", "from", "--pull=never", image], capture=True
    ).strip()
    if not container:
        raise ValueError("buildah did not return a container")
    mounted = False
    try:
        root = run(["sudo", "buildah", "mount", container], capture=True).strip()
        if not root or not Path(root).is_absolute():
            raise ValueError("buildah did not return an absolute mount path")
        mounted = True
        content = run(
            ["sudo", "cat", str(Path(root) / "usr/lib/image-builder/bootc/disk.yaml")],
            capture=True,
        )
        block = re.search(
            r'type:\s*"(ext4|btrfs)"(?:(?!\btype:).)*?mountpoint:\s*"/boot"',
            content,
            flags=re.DOTALL,
        )
        if not block or block.group(1) != "ext4":
            raise ValueError(
                f"{image} does not have /boot as ext4; rebuild workstation before packaging"
            )
    finally:
        if mounted:
            subprocess.run(
                ["sudo", "buildah", "umount", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        subprocess.run(
            ["sudo", "buildah", "rm", container],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "format",
        nargs="?",
        default="all",
        choices=("all", "iso", "sirius-iso", "qcow2"),
    )
    args = parser.parse_args()
    test_dir = ROOT / ".test"
    if test_dir.is_symlink():
        raise ValueError("refusing symlinked .test directory")
    test_dir.mkdir(exist_ok=True)
    tag = os.environ.get("LOS_TAG")
    pointer = test_dir / "last-workstation-tag"
    if not tag and pointer.is_file():
        tag = pointer.read_text().strip()
    tag = tag or os.environ["IMAGES_TAG"]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag, re.ASCII):
        raise ValueError("invalid image tag")
    registry = os.environ["IMAGES_WORKSTATION"].rsplit("/luminusos-workstation:", 1)[0]
    image = f"{registry}/luminusos-workstation:{tag}"
    iso_image = f"{image}-iso"
    run(["sudo", "-v"])
    stop = threading.Event()

    def keepalive():
        while not stop.wait(60):
            if subprocess.run(
                ["sudo", "-n", "true"], check=False, timeout=10
            ).returncode:
                return

    thread = threading.Thread(target=keepalive, daemon=True)
    thread.start()
    try:
        if image.startswith("localhost/"):
            run(["sudo", "buildah", "inspect", image], stdout=subprocess.DEVNULL)
        if args.format in ("all", "qcow2"):
            verify_disk_layout(image)
        if image.startswith("localhost/"):
            run([sys.executable, "tools/squash-image.py", image])
        if args.format in ("all", "iso", "sirius-iso"):
            if iso_image.startswith("localhost/"):
                env = {**os.environ, "LOS_TAG": tag}
                run(["just", "build", "workstation-iso"], env=env)
            run(
                [
                    sys.executable,
                    "tools/package-artifact.py",
                    "iso",
                    iso_image,
                    f"luminusos-workstation-{tag}.iso",
                    str(test_dir / "last-iso"),
                ]
            )
        if args.format in ("all", "qcow2"):
            run(
                [
                    sys.executable,
                    "tools/package-artifact.py",
                    "qcow2",
                    image,
                    f"luminusos-workstation-{tag}.qcow2",
                    str(test_dir / "last-qcow2"),
                ]
            )
    finally:
        stop.set()
        thread.join()


if __name__ == "__main__":
    old_term = signal.signal(
        signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"package-workstation: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    finally:
        signal.signal(signal.SIGTERM, old_term)
