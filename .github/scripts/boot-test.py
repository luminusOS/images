#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
import install_feasibility as vmlib
from qemu_common import resolve_ovmf

HEALTH = "systemctl is-system-running --wait"
HOME_MOUNT = "findmnt -J --mountpoint /var/home -o TARGET,SOURCE,FSTYPE,OPTIONS"
HOME_LINK = "readlink -f /home"


def count_colors(path):
    with Path(path).open("rb") as image:
        if image.readline().strip() != b"P6":
            raise ValueError("not a P6 PPM")
        tokens = []
        while len(tokens) < 3:
            line = image.readline()
            if not line:
                raise ValueError("incomplete PPM header")
            if not line.startswith(b"#"):
                tokens.extend(line.split())
        width, height, maximum = map(int, tokens)
        if width <= 0 or height <= 0 or maximum != 255:
            raise ValueError("invalid PPM dimensions or color depth")
        data = image.read(width * height * 3)
        if len(data) != width * height * 3:
            raise ValueError("incomplete PPM data")
        return len({data[i : i + 3] for i in range(0, len(data) - 2, 12)})


def screendump(socket_path, image_path):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(10)
        conn.connect(str(socket_path))
        stream = conn.makefile("rwb", buffering=0)
        greeting = json.loads(stream.readline())
        if "QMP" not in greeting:
            raise ValueError("invalid QMP greeting")
        for command in (
            {"execute": "qmp_capabilities"},
            {
                "execute": "screendump",
                "arguments": {"filename": str(image_path.resolve())},
            },
        ):
            stream.write(json.dumps(command).encode() + b"\n")
            while True:
                response = json.loads(stream.readline())
                if "error" in response:
                    raise ValueError(f"QMP error: {response['error']}")
                if "return" in response:
                    break


def home_problems(findmnt_json: str) -> list[str]:
    try:
        mounts = json.loads(findmnt_json).get("filesystems") or []
    except (json.JSONDecodeError, AttributeError):
        return ["findmnt did not return JSON"]
    if len(mounts) != 1:
        return [f"/var/home has {len(mounts)} mounts, want 1"]
    mount = mounts[0]
    options = str(mount.get("options", "")).split(",")
    problems = []
    if mount.get("target") != "/var/home":
        problems.append(f"mount target is {mount.get('target')!r}")
    if mount.get("fstype") != "btrfs":
        problems.append(f"/var/home is {mount.get('fstype')!r}, want btrfs")
    # The kernel reports subvol=/home; image-builder's units write subvol=home.
    if not ({"subvol=/home", "subvol=home"} & set(options)):
        problems.append(f"/var/home is not the home subvolume: {options}")
    return problems


def guest_checks(remote) -> list[str]:
    """Return why the booted disk is unhealthy; an empty list means it passed.

    remote(name, command, timeout) runs a command in the guest and returns a
    CompletedProcess.
    """
    problems = []
    state = remote("is-system-running", HEALTH, 900)
    if state.returncode != 0 or state.stdout.strip() != "running":
        problems.append(f"system is {state.stdout.strip()!r} ({state.returncode})")
    failed = remote("failed-units", vmlib.FAILED_UNITS, 120)
    if failed.returncode != 0 or failed.stdout.strip():
        problems.append(f"failed units: {failed.stdout.strip() or failed.returncode}")
    if problems:
        excerpt = vmlib.failed_unit_diagnostics(
            lambda name, command: remote(name, command, 300),
            "diagnostics",
            failed.stdout,
        )
        if excerpt:
            problems.append(f"failed unit journals:\n{excerpt}")
    home = remote("var-home-mount", HOME_MOUNT, 120)
    problems += (
        home_problems(home.stdout)
        if home.returncode == 0
        else ["/var/home is not a mount point"]
    )
    link = remote("home-link", HOME_LINK, 120)
    if link.returncode != 0 or link.stdout.strip() != "/var/home":
        problems.append(f"/home resolves to {link.stdout.strip()!r}")
    return problems


def check_guest(vm) -> None:
    vmlib.wait_for_ssh(vm, timeout=900)

    def remote(name, command, timeout):
        return vmlib.remote(vm, name, command, timeout=timeout)

    problems = guest_checks(remote)
    (vm.output / "guest-checks.json").write_text(
        json.dumps({"passed": not problems, "problems": problems}, indent=1) + "\n"
    )
    if problems:
        raise RuntimeError("installed disk is unhealthy: " + "; ".join(problems))
    print("Installed disk: running, no failed units, /var/home is the home subvolume")


def disk_vm(outdir: Path, keys: Path, image: Path, code: Path, variables: Path):
    if not os.access("/dev/vhost-vsock", os.R_OK | os.W_OK):
        raise RuntimeError("vhost-vsock is not usable by the runner user")
    key = keys / "ssh-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    return vmlib.VM(
        cid=3 + os.getpid() % 10000,
        disk=image,
        key=key,
        public_key=key.with_suffix(".pub").read_text().strip(),
        output=outdir,
        code=code,
        variables=variables,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("iso", "disk"))
    parser.add_argument("image", type=Path)
    parser.add_argument("outdir", type=Path, nargs="?", default=Path("boot-test-out"))
    args = parser.parse_args()
    if not args.image.is_file():
        parser.error(f"image does not exist: {args.image}")
    args.outdir.mkdir(parents=True, exist_ok=True)
    proc = None
    keys = None
    old_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        code, template = resolve_ovmf(os.environ)
        variables = args.outdir / "vars.fd"
        shutil.copyfile(template, variables)
        qmp = args.outdir / "qmp.sock"
        command = [
            "qemu-system-x86_64",
            "-machine",
            "q35",
            "-m",
            "6G",
            "-smp",
            "2",
            "-display",
            "none",
            "-vga",
            "virtio",
            "-serial",
            f"file:{args.outdir / 'serial.log'}",
            "-qmp",
            f"unix:{qmp},server,nowait",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive",
            f"if=pflash,format=raw,file={variables}",
        ]
        command += (
            ["-enable-kvm", "-cpu", "host"]
            if os.access("/dev/kvm", os.W_OK)
            else ["-cpu", "max"]
        )
        vm = None
        if args.mode == "iso":
            command += ["-cdrom", str(args.image), "-boot", "d"]
        else:
            # The key lives outside the uploaded evidence directory.
            keys = Path(tempfile.mkdtemp(prefix="boot-test-key-"))
            vm = disk_vm(args.outdir, keys, args.image, code, variables)
            command += [
                "-snapshot",
                "-drive",
                f"file={args.image},format=qcow2,if=virtio",
            ]
            command += vmlib.vsock_ssh_argv(vm)
        proc = subprocess.Popen(command, start_new_session=True)
        shot = None
        final_screenshot_ok = False
        for elapsed in range(30, (420 if args.mode == "iso" else 300) + 1, 30):
            time.sleep(30)
            if proc.poll() is not None:
                raise RuntimeError("QEMU exited early")
            shot = args.outdir / f"screen-{elapsed:03}.ppm"
            final_screenshot_ok = False
            try:
                screendump(qmp, shot)
                final_screenshot_ok = True
            except (OSError, ValueError, json.JSONDecodeError) as error:
                print(f"QMP screenshot failed: {error}", file=sys.stderr)
        if not final_screenshot_ok or shot is None or not shot.is_file():
            raise RuntimeError("final screenshot missing")
        colors = count_colors(shot)
        print(f"Final screendump has {colors} distinct sampled colors (minimum 64)")
        if shutil.which("tesseract"):
            subprocess.run(
                ["tesseract", str(shot), str(args.outdir / "final-screen")],
                stderr=subprocess.DEVNULL,
                check=False,
            )
            ocr_output = args.outdir / "final-screen.txt"
            if ocr_output.is_file():
                text = ocr_output.read_text(errors="replace")
                print(f"--- OCR of final screen ---\n{text}")
                print(
                    "OCR: recognized expected installer/setup wording"
                    if re.search(
                        r"sirius|luminus|install|setup|welcome", text, re.IGNORECASE
                    )
                    else "OCR: expected wording not found (advisory only)"
                )
        if vm is not None:
            check_guest(vm)
        return int(colors < 64)
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        print(f"boot-test: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except ProcessLookupError:
                proc.wait()
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        if keys is not None:
            shutil.rmtree(keys, ignore_errors=True)
        signal.signal(signal.SIGTERM, old_term)


if __name__ == "__main__":
    sys.exit(main())
