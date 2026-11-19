"""Diagnostic: install the exact candidate ISO with Sirius on a hosted KVM runner.

Produces evidence for feasibility only. It writes no release receipts and signs
nothing, so its output can never stand in for installation validation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from qemu_common import resolve_ovmf

GIB = 1024**3
TARGET_DISK = "/dev/vda"
FAILED_UNITS = "systemctl --failed --no-legend --plain --no-pager"
# Unit names reach a guest shell, so anything outside this set is skipped.
UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:-]*\Z")
MAX_DIAGNOSED_UNITS = 10
JOURNAL_EXCERPT_LINES = 10
BOOT_DIAGNOSTICS = (
    (
        "avc",
        (
            "journalctl -b --no-pager -o short-monotonic _TRANSPORT=audit"
            " | grep -E 'avc|denied' | tail -200"
        ),
    ),
    ("systemd-state", "ls -laZ /var/lib/systemd"),
    ("mounts", "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS /var /sysroot /"),
)


class ProbeError(RuntimeError):
    pass


@dataclass
class VM:
    cid: int
    disk: Path
    key: Path
    public_key: str
    output: Path
    code: Path
    variables: Path


def failed_unit_names(listing: str) -> list[str]:
    names = (line.split()[0] for line in listing.splitlines() if line.split())
    return [name for name in names if UNIT_NAME.fullmatch(name)]


def failed_unit_diagnostics(run, prefix: str, listing: str) -> str:
    """Record why failed units failed; return a short journal excerpt.

    run(name, command) runs a guest command, records its output and returns a
    CompletedProcess. Diagnostics only explain a failure that is already
    certain, so their own errors are reported in the excerpt, never raised.
    """

    def attempt(name: str, command: str):
        try:
            return run(name, command), None
        except (subprocess.SubprocessError, OSError, RuntimeError) as error:
            return None, f"{type(error).__name__}: {error}"

    excerpts = []
    units = failed_unit_names(listing)[:MAX_DIAGNOSED_UNITS]
    for number, unit in enumerate(units, 1):
        attempt(
            f"{prefix}-unit-{number}-status",
            f"systemctl status --no-pager -l -- {unit}",
        )
        journal, error = attempt(
            f"{prefix}-unit-{number}-journal",
            f"journalctl -b --no-pager -o short-monotonic -u {unit}",
        )
        lines = (
            journal.stdout.splitlines()[-JOURNAL_EXCERPT_LINES:]
            if journal is not None
            else [f"journal unavailable: {error}"]
        )
        excerpts.append("\n".join([f"--- {unit}", *lines]))
    for name, command in BOOT_DIAGNOSTICS:
        attempt(f"{prefix}-{name}", command)
    return "\n".join(excerpts)


def install_request(target_disk: str) -> str:
    return json.dumps(
        {
            "target_disk": target_disk,
            "encrypt": False,
            "tpm": False,
            "encryption_key": "",
            "locale": "en_US.UTF-8",
            "keyboard": "us",
            "timezone": "UTC",
            "hostname": "luminus-validation",
            "username": "validation",
            "full_name": "Validation",
            "partition_plan": None,
        }
    )


def vsock_ssh_argv(vm: VM) -> list[str]:
    return [
        "-device",
        f"vhost-vsock-pci,guest-cid={vm.cid}",
        # systemd imports SMBIOS type 11 credentials; tmpfiles provisions this one
        # as root's authorized_keys, so neither image has to change.
        "-smbios",
        f"type=11,value=io.systemd.credential:ssh.authorized_keys.root={vm.public_key}",
    ]


def qemu_argv(vm: VM, *, iso: Path | None) -> list[str]:
    argv = [
        "qemu-system-x86_64",
        "-machine",
        "q35",
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        "8G",
        "-smp",
        "4",
        "-display",
        "none",
        "-serial",
        f"file:{vm.output / ('serial-live.log' if iso else 'serial-installed.log')}",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={vm.code}",
        "-drive",
        f"if=pflash,format=raw,file={vm.variables}",
        "-drive",
        f"file={vm.disk},format=qcow2,if=virtio",
        *vsock_ssh_argv(vm),
        "-no-reboot",
    ]
    if iso is not None:
        argv += [
            "-drive",
            f"id=live,if=none,media=cdrom,readonly=on,format=raw,file={iso}",
            "-device",
            "ide-cd,bus=ide.0,drive=live,bootindex=0",
        ]
    return argv


def ssh_argv(vm: VM, command: str) -> list[str]:
    return [
        "ssh",
        "-o",
        f"ProxyCommand=socat - VSOCK-CONNECT:{vm.cid}:22",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "LogLevel=ERROR",
        "-i",
        str(vm.key),
        "root@vsock",
        command,
    ]


def playbook_finished(stdout: str, returncode: int) -> bool:
    if returncode != 0:
        return False
    finished = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict) and "Error" in message:
            return False
        if message == "Finished":
            finished = True
    return finished


def preflight(work: Path, *, required_bytes: int) -> dict:
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise ProbeError("KVM is not usable by the runner user")
    if not os.access("/dev/vhost-vsock", os.R_OK | os.W_OK):
        raise ProbeError("vhost-vsock is not usable by the runner user")
    free = shutil.disk_usage(work).free
    if free < required_bytes:
        raise ProbeError(f"insufficient disk: {free} free, {required_bytes} required")
    return {"free_bytes": free, "required_bytes": required_bytes}


def wait_for_ssh(vm: VM, *, timeout: int) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            result = subprocess.run(
                ssh_argv(vm, "true"),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = None
        if result is not None and result.returncode == 0:
            return time.monotonic() - started
        time.sleep(10)
    raise ProbeError(f"ssh over vsock not ready after {timeout} s")


def remote(vm: VM, name: str, command: str, *, timeout: int = 600, stdin=None):
    result = subprocess.run(
        ssh_argv(vm, command),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    (vm.output / f"{name}.stdout").write_text(result.stdout)
    (vm.output / f"{name}.stderr").write_text(result.stderr)
    return result


def installed_facts(vm: VM) -> dict:
    state = remote(
        vm, "is-system-running", "systemctl is-system-running --wait", timeout=900
    )
    system_state = state.stdout.strip()
    if system_state not in ("running", "degraded"):
        raise ProbeError(f"installed system did not finish booting: {system_state!r}")
    failed = remote(vm, "failed-units", "systemctl --failed --no-legend --plain")
    if failed.returncode != 0:
        raise ProbeError("cannot list failed units")
    facts = {
        "system_state": system_state,
        "failed_units": [
            line.split()[0] for line in failed.stdout.splitlines() if line.strip()
        ],
    }
    for name, command, key in (
        ("bootc-status", "bootc status --json", "bootc_status"),
        ("findmnt", "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS", "mounts"),
    ):
        result = remote(vm, name, command)
        if result.returncode != 0:
            raise ProbeError(f"{command} failed with {result.returncode}")
        try:
            facts[key] = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ProbeError(f"{command} did not return JSON") from error
    selinux = remote(vm, "getenforce", "getenforce")
    if selinux.returncode != 0:
        raise ProbeError("getenforce failed")
    facts["selinux"] = selinux.stdout.strip()
    return facts


def stop(process: subprocess.Popen, vm: VM, *, timeout: int = 300) -> None:
    remote(vm, "poweroff", "systemctl poweroff", timeout=60)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise ProbeError("guest did not power off") from None


def run(iso: Path, output: Path, *, cid: int) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    work = Path(os.environ.get("RUNNER_TEMP", output))
    key = work / "feasibility-key"
    variables = work / "feasibility-vars.fd"
    disk = work / "feasibility-target.qcow2"
    phases: dict[str, float] = {}
    record: dict = {"iso": str(iso), "phases": phases, "status": "failed"}
    try:
        record["iso_bytes"] = iso.stat().st_size
        record["preflight"] = preflight(
            work, required_bytes=record["iso_bytes"] + 40 * GIB
        )
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        code, template = resolve_ovmf(os.environ)
        shutil.copyfile(template, variables)
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), "64G"],
            check=True,
            capture_output=True,
        )
        vm = VM(
            cid=cid,
            disk=disk,
            key=key,
            public_key=key.with_suffix(".pub").read_text().strip(),
            output=output,
            code=code,
            variables=variables,
        )
        for phase, image in (("live", iso), ("installed", None)):
            argv = qemu_argv(vm, iso=image)
            (output / f"qemu-{phase}.json").write_text(json.dumps(argv, indent=1))
            started = time.monotonic()
            process = subprocess.Popen(argv, start_new_session=True)
            try:
                phases[f"{phase}_ssh_ready_s"] = wait_for_ssh(vm, timeout=1200)
                if phase == "live":
                    remote(
                        vm,
                        "live-facts",
                        "rpm -q sirius; lsblk -J; systemctl is-system-running",
                    )
                    begun = time.monotonic()
                    result = remote(
                        vm,
                        "sirius-run-playbook",
                        "sirius run-playbook",
                        timeout=5400,
                        stdin=install_request(TARGET_DISK),
                    )
                    phases["install_s"] = time.monotonic() - begun
                    record["install_exit_code"] = result.returncode
                    if not playbook_finished(result.stdout, result.returncode):
                        raise ProbeError("Sirius did not report Finished")
                else:
                    record["installed"] = installed_facts(vm)
                stop(process, vm)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                phases[f"{phase}_total_s"] = time.monotonic() - started
        record["disk_after"] = {"free_bytes": shutil.disk_usage(work).free}
        record["status"] = "installed-and-booted"
    except BaseException as error:
        record["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        for path in (key, key.with_suffix(".pub"), variables, disk):
            path.unlink(missing_ok=True)
        (output / "manifest.json").write_text(json.dumps(record, indent=1) + "\n")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("iso", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cid", type=int, default=3 + os.getpid() % 10000)
    args = parser.parse_args(argv)
    try:
        record = run(args.iso, args.output, cid=args.cid)
    except (ProbeError, OSError, subprocess.SubprocessError) as error:
        print(f"installation feasibility failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record["phases"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
