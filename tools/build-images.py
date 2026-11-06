#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    isolated = not sys.stdin.isatty()
    process = subprocess.Popen(command, start_new_session=isolated, **kwargs)
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


@contextmanager
def sudo_session():
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
        yield
    finally:
        stop.set()
        thread.join()


def stamp(args):
    return subprocess.check_output(
        [
            sys.executable,
            str(ROOT / "tools/core-stamp.py"),
            args.base,
            args.fedora,
            args.tag,
            args.version,
            args.name,
            args.pretty,
        ],
        text=True,
    ).strip()


def test_directory():
    path = ROOT / ".test"
    if path.is_symlink():
        raise ValueError("refusing symlinked .test directory")
    path.mkdir(exist_ok=True)
    return path


def core(args):
    run(
        [
            "sudo",
            "buildah",
            "bud",
            "--layers",
            "--tag",
            args.core,
            "--file",
            "editions/core/Containerfile",
            "--build-arg",
            f"base={args.base}",
            "--build-arg",
            f"fedora_version={args.fedora}",
            "--build-arg",
            f"distro_version={args.version}",
            "--build-arg",
            f"distro_name={args.name}",
            "--build-arg",
            f"distro_pretty_name={args.pretty}",
            ".",
        ]
    )
    run([sys.executable, "tools/squash-image.py", args.core])
    (test_directory() / "last-core-stamp").write_text(stamp(args) + "\n")


def workstation(args):
    directory = test_directory()
    previous = directory / "last-core-stamp"
    inspect = subprocess.run(
        ["sudo", "buildah", "inspect", args.core],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if (
        args.force_core == "1"
        or not previous.is_file()
        or previous.read_text().strip() != stamp(args)
        or inspect.returncode
    ):
        core(args)
    else:
        print(f"Using existing core image: {args.core}", flush=True)
    params = {
        "core_image": args.core,
        "fedora_bootc_base": args.base,
        "fedora_version": args.fedora,
        "image_version": args.version,
        "edition_name": "Workstation",
        "edition_id": "workstation",
        "aurora_shell_version": args.aurora_version,
        "aurora_shell_sha256": args.aurora_sha256,
        "elastic_swap_version": args.elastic_version,
        "elastic_swap_sha256": args.elastic_sha256,
        "skip_flatpaks": args.skip_flatpaks,
    }
    command = [
        "sudo",
        "buildah",
        "bud",
        "--layers",
        "--cap-add",
        "sys_admin",
        "--security-opt",
        "label=disable",
        "--tag",
        args.workstation,
        "--file",
        "editions/workstation/Containerfile",
    ]
    for key, value in params.items():
        command.extend(["--build-arg", f"{key}={value}"])
    run([*command, "."])
    run([sys.executable, "tools/squash-image.py", args.workstation])
    (directory / "last-workstation-tag").write_text(args.tag + "\n")


def installer(args):
    inspect = subprocess.run(
        ["sudo", "buildah", "inspect", args.workstation],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if inspect.returncode:
        raise ValueError(
            f"Workstation image not found: {args.workstation}; run just build workstation first"
        )
    directory = test_directory()
    payload = directory / "payload.oci"
    marker = directory / ".payload-oci-owned"
    if payload.is_symlink() or marker.is_symlink():
        raise ValueError("refusing symlinked payload or ownership marker")
    if payload.exists():
        if not marker.is_file() or marker.read_text() != "luminusos-payload-oci\n":
            raise ValueError(f"refusing to remove unowned payload directory: {payload}")
        run(["sudo", "rm", "-rf", "--", str(payload)])
    marker.write_text("luminusos-payload-oci\n")
    run(
        [
            "sudo",
            "skopeo",
            "copy",
            f"containers-storage:{args.workstation}",
            f"oci:{payload}:latest",
        ]
    )
    run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(payload)])
    params = {
        "fedora_version": args.fedora,
        "sirius_version": args.sirius_version,
        "sirius_rpm_version": args.sirius_rpm_version,
        "sirius_sha256": args.sirius_sha256,
        "workstation_image": args.workstation,
        "workstation_target_image": args.target,
        "image_version": args.version,
    }
    command = [
        "sudo",
        "buildah",
        "bud",
        "--layers",
        "--tag",
        args.installer,
        "--file",
        "editions/workstation/Containerfile.installer",
    ]
    for key, value in params.items():
        command.extend(["--build-arg", f"{key}={value}"])
    run([*command, "."])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("core", "workstation", "workstation-iso"))
    for name in (
        "base",
        "fedora",
        "tag",
        "version",
        "name",
        "pretty",
        "core",
        "workstation",
        "installer",
        "target",
        "aurora-version",
        "aurora-sha256",
        "elastic-version",
        "elastic-sha256",
        "sirius-version",
        "sirius-rpm-version",
        "sirius-sha256",
        "force-core",
        "skip-flatpaks",
    ):
        default = os.environ.get("IMAGES_" + name.upper().replace("-", "_"))
        parser.add_argument(f"--{name}", default=default, required=default is None)
    args = parser.parse_args()
    old_term = signal.signal(
        signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    try:
        with sudo_session():
            {"core": core, "workstation": workstation, "workstation-iso": installer}[
                args.mode
            ](args)
    finally:
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"build-images: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
