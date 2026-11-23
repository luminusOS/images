#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Match osbuild v193's default stage capabilities rather than the full container set.
CAPABILITIES = (
    "CAP_AUDIT_WRITE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_CHROOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
)
STATUS_FIELDS = {
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "Seccomp_filters",
}
STORAGE = Path("/run/osbuild/containers/storage")
SOURCE = "/run/ci-mount-source"
SCRIPT = "/run/ci-mount-probe.py"


def security_context(label: str, proc: Path = Path("/proc/self")) -> None:
    print(f"mount-probe: {label} pid={os.getpid()}", flush=True)
    try:
        current = (proc / "attr/current").read_text().strip()
        print(f"mount-probe: attr/current={current}", flush=True)
    except OSError as exc:
        print(f"mount-probe: attr/current unavailable (errno={exc.errno})", flush=True)
    try:
        for line in (proc / "status").read_text().splitlines():
            if line.partition(":")[0] in STATUS_FIELDS:
                print(f"mount-probe: {line}", flush=True)
    except OSError as exc:
        print(f"mount-probe: status unavailable (errno={exc.errno})", flush=True)


def probe_child() -> None:
    security_context("bwrap child")
    STORAGE.mkdir(parents=True)
    subprocess.run(
        ["mount", "--make-private", "-o", "rbind,rw,0755", SOURCE, str(STORAGE)],
        check=True,
    )
    print("mount-probe: recursive bind/private mount succeeded", flush=True)


def run_probe() -> None:
    for tool in ("bwrap", "mount", "python3"):
        if shutil.which(tool) is None:
            raise ValueError(
                f"required tool not found after dependency install: {tool}"
            )
    security_context("packaging container")
    with tempfile.TemporaryDirectory(prefix="ci-mount-probe-") as source:
        command = [
            "bwrap",
            "--chdir",
            "/",
            "--die-with-parent",
            "--new-session",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--cap-drop",
            "ALL",
        ]
        for capability in CAPABILITIES:
            command.extend(["--cap-add", capability])
        command.extend(
            [
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/sbin",
                "/sbin",
                "--dev",
                "/dev",
                "--dir",
                "/etc",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/tmp",
                "--proc",
                "/proc",
                "--bind",
                source,
                SOURCE,
                "--ro-bind",
                str(Path(__file__).resolve()),
                SCRIPT,
                "--",
                "/usr/bin/python3",
                SCRIPT,
                "--child",
            ]
        )
        # Namespace teardown removes probe mounts before temporary source cleanup.
        subprocess.run(
            command,
            check=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin", "PYTHONUNBUFFERED": "1"},
        )


def main() -> int:
    try:
        if sys.argv[1:] == ["--child"]:
            probe_child()
        elif not sys.argv[1:]:
            run_probe()
        else:
            raise ValueError("unexpected probe arguments")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"mount-probe: failed; packaging cannot continue: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
