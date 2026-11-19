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
FINDMNT = "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS --target"
STORAGE = (("sysroot", "/sysroot"), ("var", "/var"), ("var-home", "/var/home"))
HOME_LINK = "readlink -f /home"
RANDOM_SEED = "systemctl show -p Result -p ActiveState systemd-random-seed.service"
LABELS = "ls -ldZ /var /var/home /var/lib/systemd"
RELABEL = "restorecon -n -v /var /var/home /var/lib/systemd"
# findmnt shows a bind mount from a Btrfs subvolume as device[path]. /var is
# the ostree stateroot directory inside the root subvolume; the stateroot name
# and the root subvolume path are not pinned. The pre-fix layouts mounted
# separate var or home subvolumes, which show as device[/var] or device[/home].
SOURCE = re.compile(r"(?P<device>/dev/[^\[\]\s]+)(?:\[(?P<path>/[^\[\]]*)\])?\Z")
STATEROOT_VAR = re.compile(r"(?:/[^\[\]]*)?/ostree/deploy/[^/\[\]]+/var\Z")
OLD_SUBVOLUMES = ("/var", "/home")


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


def mount_of(result) -> tuple[dict | None, str | None]:
    if result.returncode != 0:
        return None, f"findmnt exited {result.returncode}"
    try:
        mounts = json.loads(result.stdout).get("filesystems") or []
    except (json.JSONDecodeError, AttributeError):
        return None, "findmnt did not return JSON"
    if len(mounts) != 1:
        return None, f"findmnt returned {len(mounts)} filesystems"
    return mounts[0], None


def storage_problems(results: dict) -> list[str]:
    """Check /var and /var/home come from the root filesystem, not old subvolumes.

    results maps "sysroot", "var" and "var-home" to findmnt --target results.
    """
    problems = []
    mounts = {}
    for name, path in STORAGE:
        mount, error = mount_of(results[name])
        if error:
            problems.append(f"{path}: {error}")
            continue
        source = SOURCE.fullmatch(str(mount.get("source", "")))
        if mount.get("fstype") != "btrfs" or source is None:
            problems.append(
                f"{path} is on {mount.get('source')!r} ({mount.get('fstype')!r}),"
                " want the root Btrfs filesystem"
            )
            continue
        mounts[name] = (mount, source)
    if problems:
        return problems
    sysroot, sysroot_source = mounts["sysroot"]
    var, var_source = mounts["var"]
    home, home_source = mounts["var-home"]
    for path, source in (("/var", var_source), ("/var/home", home_source)):
        if source["path"] in OLD_SUBVOLUMES:
            problems.append(
                f"{path} is the separate {source['path'][1:]} subvolume"
                f" {source.group(0)!r}"
            )
    if problems:
        return problems
    if sysroot.get("target") != "/sysroot":
        problems.append(f"/sysroot is not mounted: {sysroot.get('target')!r}")
    if var.get("target") != "/var":
        problems.append(f"/var is not a mount point: {var.get('target')!r}")
    if var_source["device"] != sysroot_source["device"]:
        problems.append(
            f"/var is on {var_source['device']}, the root filesystem is"
            f" {sysroot_source['device']}"
        )
    prefix = sysroot_source["path"] or ""
    path = var_source["path"] or ""
    if not (
        path.startswith(prefix + "/")
        and STATEROOT_VAR.fullmatch(path.removeprefix(prefix))
    ):
        problems.append(f"/var is {var_source.group(0)!r}, not the ostree stateroot")
    if (home.get("target"), home_source.group(0)) != ("/var", var_source.group(0)):
        problems.append(
            f"/var/home is a separate mount {home.get('target')!r}"
            f" from {home_source.group(0)!r}"
        )
    return problems


def unit_problems(result) -> list[str]:
    properties = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if result.returncode != 0 or (
        properties.get("Result"),
        properties.get("ActiveState"),
    ) != ("success", "active"):
        return [
            (
                "systemd-random-seed.service did not succeed in this boot:"
                f" {result.stdout.strip() or result.returncode!r}"
            )
        ]
    return []


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
    problems += storage_problems(
        {
            name: remote(f"{name}-mount", f"{FINDMNT} {path}", 120)
            for name, path in STORAGE
        }
    )
    link = remote("home-link", HOME_LINK, 120)
    if link.returncode != 0 or link.stdout.strip() != "/var/home":
        problems.append(f"/home resolves to {link.stdout.strip()!r}")
    problems += unit_problems(remote("random-seed", RANDOM_SEED, 120))
    labels = remote("labels", LABELS, 120)
    if (
        labels.returncode != 0
        or labels.stderr.strip()
        or len(labels.stdout.splitlines()) != 3
        or "unlabeled_t" in labels.stdout
    ):
        problems.append(
            "cannot confirm SELinux labels:"
            f" {(labels.stdout + labels.stderr).strip() or labels.returncode!r}"
        )
    relabel = remote("restorecon", RELABEL, 300)
    if relabel.returncode != 0 or relabel.stdout.strip() or relabel.stderr.strip():
        problems.append(
            "SELinux labels differ from policy:"
            f" {(relabel.stdout + relabel.stderr).strip() or relabel.returncode!r}"
        )
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
    print(
        "Installed disk: running, no failed units, random seed saved,"
        " /var from the root subvolume, labels match policy"
    )


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
