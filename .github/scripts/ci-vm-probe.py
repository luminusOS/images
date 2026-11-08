#!/usr/bin/env python3
import argparse
import fcntl
import grp
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from qemu_security import secure_firmware

COMMANDS = ("qmp_capabilities", "query-kvm", "cont", "query-status", "stop", "quit")


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def capture(output, name, command, *, stdin=None, timeout=10):
    started = time.monotonic()
    record = {"command": command, "started_unix_seconds": time.time()}
    process = None
    try:
        if stdin is not None:
            (output / f"{name}.stdin").write_bytes(stdin)
        with (
            (output / f"{name}.stdout").open("wb") as stdout,
            (output / f"{name}.stderr").open("wb") as stderr,
        ):
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            )
            record["pid"] = process.pid
            process.communicate(input=stdin, timeout=timeout)
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
    except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        record["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        try:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        finally:
            record["exit_code"] = process.poll() if process is not None else None
            record["elapsed_seconds"] = time.monotonic() - started
            write_json(output / f"{name}.json", record)


def check_kvm(path=Path("/dev/kvm")):
    descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    try:
        version = fcntl.ioctl(descriptor, 0xAE00)
        if version != 12:
            raise ValueError(f"unsupported KVM API: {version}")
        return version
    finally:
        os.close(descriptor)


def qmp_probe(output, timeout=10):
    command = [
        "qemu-system-x86_64",
        "-no-user-config",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        "128M",
        "-smp",
        "1",
        "-nodefaults",
        "-nic",
        "none",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-qmp",
        "stdio",
        "-S",
    ]
    requests = b"".join(
        json.dumps({"execute": name, "id": index}).encode() + b"\n"
        for index, name in enumerate(COMMANDS)
    )
    capture(output, "qemu", command, stdin=requests, timeout=timeout)
    messages = [
        json.loads(line)
        for line in (output / "qemu.stdout").read_bytes().splitlines()
        if line.strip()
    ]
    if not messages or any(not isinstance(item, dict) for item in messages):
        raise ValueError("invalid QMP messages")
    greeting = messages[0].get("QMP")
    if not isinstance(greeting, dict) or not isinstance(greeting.get("version"), dict):
        raise TypeError("invalid QMP greeting")
    replies = [item for item in messages[1:] if "event" not in item]
    if [item.get("id") for item in replies] != list(range(len(COMMANDS))):
        raise ValueError("missing, duplicate or unexpected QMP responses")
    if any(
        "error" in item or not isinstance(item.get("return"), dict) for item in replies
    ):
        raise ValueError("QMP command failed")
    kvm, state = replies[1]["return"], replies[3]["return"]
    if kvm.get("enabled") is not True or kvm.get("present") is not True:
        raise ValueError("QMP did not confirm active KVM")
    if state.get("running") is not True or state.get("status") != "running":
        raise ValueError("QMP did not confirm running state")
    return {"kvm": kvm, "state": state}


def run_probe(output, expected_uid=None):
    output.mkdir(parents=True, exist_ok=True)
    result = {
        "status": "failed",
        "errors": {},
        "started_unix_seconds": time.time(),
        "required": ["resources", "firmware", "kvm", "qemu", "qmp"],
        "guest_security_validated": False,
        "limitations": (
            "No OS installation, guest security, TPM runtime or full-install capacity "
            "validated. UEFI/Secure Boot firmware is discovered, not executed. "
            "QMP running state is not OS boot evidence. T1 remains incomplete."
        ),
        "context": {
            name: os.environ.get(name)
            for name in ("GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID", "ImageVersion")
        },
    }
    write_json(output / "manifest.json", result)
    stage = "identity"
    try:
        identity = result["identity"] = {
            "euid": os.geteuid(),
            "egid": os.getegid(),
            "groups": os.getgroups(),
            "expected_uid": expected_uid,
        }
        if expected_uid is not None:
            identity["expected_gid"] = grp.getgrnam("kvm").gr_gid
            if (
                expected_uid <= 0
                or identity["euid"] != expected_uid
                or identity["egid"] != identity["expected_gid"]
            ):
                raise ValueError("expected non-root runner UID and primary kvm GID")
        stage = "resources"
        meminfo = Path("/proc/meminfo").read_text()
        (output / "meminfo.txt").write_text(meminfo)
        memory = {
            line.split(":")[0]: int(line.split()[1]) * 1024
            for line in meminfo.splitlines()
            if line.startswith(("MemTotal:", "MemAvailable:"))
        }
        result["resources"] = {
            "cpu_count": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "memory_bytes": memory,
            "disk_bytes": shutil.disk_usage(output)._asdict(),
            "uname": tuple(platform.uname()),
            "euid": os.geteuid(),
            "egid": os.getegid(),
            "groups": os.getgroups(),
        }
        if set(memory) != {"MemTotal", "MemAvailable"}:
            raise ValueError("missing memory counters")
        swtpm = shutil.which("swtpm")
        result["tpm_tool"] = {"available": bool(swtpm), "required": False}
        if swtpm:
            try:
                capture(output, "swtpm-version", [swtpm, "--version"])
            except (OSError, subprocess.SubprocessError) as error:
                result["tpm_tool"]["error"] = str(error)
        stage = "firmware"
        result["firmware_descriptors"] = {}
        try:
            inventory = output / "firmware-descriptors"
            inventory.mkdir(exist_ok=True)
            for index, directory in enumerate(
                ("/etc/qemu/firmware", "/usr/share/qemu/firmware")
            ):
                for descriptor in sorted(Path(directory).glob("*.json")):
                    destination = inventory / f"{index}-{descriptor.name}"
                    destination.write_bytes(descriptor.read_bytes())
                    result["firmware_descriptors"][str(descriptor)] = str(
                        destination.relative_to(output)
                    )
            result["firmware_sha256"] = {
                str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in secure_firmware({})
            }
        except (OSError, ValueError, TypeError) as error:
            result["errors"]["firmware"] = f"{type(error).__name__}: {error}"
        stage = "kvm"
        device = result["kvm_device"] = {}
        try:
            metadata = os.stat("/dev/kvm")
            device.update(
                file_type=stat.S_IFMT(metadata.st_mode),
                mode=oct(stat.S_IMODE(metadata.st_mode)),
                uid=metadata.st_uid,
                gid=metadata.st_gid,
            )
            try:
                device["group"] = grp.getgrgid(metadata.st_gid).gr_name
            except KeyError as error:
                device["group_error"] = f"{type(error).__name__}: {error}"
        except OSError as error:
            device["stat_error"] = f"{type(error).__name__}: {error}"
        getfacl = shutil.which("getfacl")
        device["acl"] = {"available": bool(getfacl), "required": False}
        if getfacl:
            try:
                capture(output, "kvm-getfacl", [getfacl, "--", "/dev/kvm"])
            except (OSError, subprocess.SubprocessError) as error:
                device["acl"]["error"] = f"{type(error).__name__}: {error}"
        result["kvm_api"] = check_kvm()
        stage = "qemu"
        capture(output, "qemu-version", ["qemu-system-x86_64", "--version"])
        stage = "qmp"
        result["qmp"] = qmp_probe(output)
        result["status"] = "failed" if result["errors"] else "passed"
    except (
        OSError,
        KeyError,
        ValueError,
        TypeError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ) as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["errors"][stage] = result["error"]
    finally:
        result["finished_unix_seconds"] = time.time()
        write_json(output / "manifest.json", result)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--expected-uid", type=int, required=True)

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        arguments = parser.parse_args()
        sys.exit(run_probe(arguments.output, arguments.expected_uid))
    finally:
        signal.signal(signal.SIGTERM, previous)
