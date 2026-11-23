#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path

from qemu_common import is_owned_file, record_owned_file

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    isolated = not sys.stdin.isatty()
    process = subprocess.Popen(command, start_new_session=isolated)
    try:
        code = process.wait()
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
    if code:
        raise subprocess.CalledProcessError(code, command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    args = parser.parse_args()
    config = ROOT / "shared/bootc-image-builder.toml"
    if not config.is_file():
        raise ValueError(
            f"Missing {config}; copy the example and set a test-user password or SSH key"
        )
    test_dir = ROOT / ".test"
    if test_dir.is_symlink():
        raise ValueError("refusing to use symlinked .test directory")
    test_dir.mkdir(exist_ok=True)
    disk = test_dir / "install-disk.qcow2"
    marker = test_dir / ".install-disk-owned"
    result = test_dir / "qcow2/disk.qcow2"
    if result.parent.is_symlink() or result.exists() or result.is_symlink():
        raise ValueError(f"Refusing pre-existing image-builder output: {result}")
    if disk.is_symlink():
        raise ValueError(f"Refusing to remove symlink: {disk}")
    if marker.is_symlink():
        raise ValueError(f"Refusing symlinked ownership marker: {marker}")
    if disk.exists():
        if not is_owned_file(disk, marker, "luminusos-install-disk"):
            raise ValueError(f"Refusing to remove unowned disk: {disk}")
        try:
            disk.unlink()
        except PermissionError:
            run(["sudo", "rm", "-f", str(disk)])
    run(
        [
            "sudo",
            "podman",
            "run",
            "--rm",
            "-it",
            "--privileged",
            "--pull=newer",
            "--security-opt",
            "label=type:unconfined_t",
            "-v",
            f"{test_dir}:/output",
            "-v",
            f"{config}:/config.toml:ro",
            "-v",
            "/var/lib/containers/storage:/var/lib/containers/storage",
            "quay.io/centos-bootc/bootc-image-builder:latest",
            "--type",
            "qcow2",
            "--rootfs",
            "btrfs",
            "--config",
            "/config.toml",
            args.image,
        ]
    )
    if result.parent.is_symlink() or not result.is_file() or result.is_symlink():
        raise ValueError(f"Expected output disk not found: {result}")
    run(["sudo", "mv", str(result), str(disk)])
    run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(disk)])
    record_owned_file(disk, marker, "luminusos-install-disk")
    subprocess.run(
        ["sudo", "rmdir", str(result.parent)], check=False, stderr=subprocess.DEVNULL
    )
    print("Installation complete. Boot with: just qemu run")


if __name__ == "__main__":
    previous = signal.signal(
        signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"install-qemu: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    finally:
        signal.signal(signal.SIGTERM, previous)
