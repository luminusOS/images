import fcntl
import fnmatch
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


def enabled(env, name):
    value = env.get(name, "0")
    if value not in ("0", "1"):
        raise ValueError(f"{name} must be 0 or 1")
    return value == "1"


def secure_firmware(env):
    code = env.get("QEMU_OVMF_CODE")
    variables = env.get("QEMU_OVMF_VARS_TEMPLATE")
    if bool(code) != bool(variables):
        raise ValueError(
            "Secure Boot requires both QEMU_OVMF_CODE and QEMU_OVMF_VARS_TEMPLATE"
        )
    descriptors = []
    for directory in (Path("/etc/qemu/firmware"), Path("/usr/share/qemu/firmware")):
        descriptors.extend(sorted(directory.glob("*.json")))
    for descriptor in descriptors:
        try:
            data = json.loads(descriptor.read_text())
            mapping = data["mapping"]
            executable = mapping["executable"]
            template = mapping["nvram-template"]
            features = set(data["features"])
            compatible = any(
                target["architecture"] == "x86_64"
                and any(
                    fnmatch.fnmatchcase("pc-q35-0", pattern)
                    for pattern in target["machines"]
                )
                for target in data["targets"]
            )
            pair = (Path(executable["filename"]), Path(template["filename"]))
            if (
                "uefi" in data["interface-types"]
                and mapping["device"] == "flash"
                and mapping["mode"] == "split"
                and executable["format"] == template["format"] == "raw"
                and {"secure-boot", "enrolled-keys", "requires-smm"} <= features
                and compatible
                and all(path.is_absolute() and path.is_file() for path in pair)
                and (not code or pair == (Path(code), Path(variables)))
            ):
                return pair
        except (OSError, ValueError, TypeError, KeyError):
            continue
    raise ValueError(
        "Secure Boot requires a QEMU firmware descriptor for a raw q35 UEFI pair "
        "with secure-boot, enrolled-keys and requires-smm (install edk2-ovmf or ovmf)"
    )


def state_path(test_dir, disk):
    identity = hashlib.sha256(os.fsencode(str(Path(disk).resolve()))).hexdigest()
    return test_dir / "qemu-vms" / identity


def tpm_arguments(socket_path):
    return [
        "-chardev",
        f"socket,id=chrtpm,path={socket_path}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-tis,tpmdev=tpm0",
    ]


@contextmanager
def locked_state(path):
    for directory in (path.parent, path):
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"refusing unsafe VM state directory: {directory}")
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise ValueError(f"VM state directory must be private: {directory}")
    fd = os.open(path / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError(f"VM state is already in use: {path}") from None
        yield
    finally:
        os.close(fd)


def require_swtpm(env):
    binary = shutil.which("swtpm", path=env.get("PATH"))
    if not binary:
        raise ValueError(
            "TPM requested but swtpm is missing; install swtpm with TPM 2.0 support"
        )
    return binary


def copy_vars(template, destination):
    fd, temporary = tempfile.mkstemp(prefix=".vars-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as target, template.open("rb") as source:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


def run(command, env, state, tpm):
    with tempfile.TemporaryDirectory(prefix="luminus-tpm-") as runtime:
        tpm_process = None
        qemu_process = None
        signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        previous = {sig: signal.getsignal(sig) for sig in signals}

        def interrupted(signum, frame):
            for sig in signals:
                signal.signal(sig, signal.SIG_IGN)
            raise InterruptedError(f"received signal {signum}")

        try:
            for sig in signals:
                signal.signal(sig, interrupted)
            if tpm:
                tpm_dir = state / "tpm"
                tpm_dir.mkdir(mode=0o700, exist_ok=True)
                if (
                    tpm_dir.is_symlink()
                    or tpm_dir.stat().st_uid != os.getuid()
                    or tpm_dir.stat().st_mode & 0o077
                ):
                    raise ValueError(f"TPM state directory must be private: {tpm_dir}")
                socket_path = Path(runtime) / "swtpm.sock"
                tpm_process = subprocess.Popen(
                    [
                        require_swtpm(env),
                        "socket",
                        "--tpm2",
                        "--tpmstate",
                        f"dir={tpm_dir}",
                        "--ctrl",
                        f"type=unixio,path={socket_path}",
                    ],
                    env=env,
                )
                deadline = time.monotonic() + 5
                while not socket_path.is_socket():
                    if tpm_process.poll() is not None:
                        raise ValueError(
                            "swtpm exited before its control socket became ready"
                        )
                    if time.monotonic() >= deadline:
                        raise ValueError("timed out waiting for swtpm control socket")
                    time.sleep(0.05)
                command.extend(tpm_arguments(socket_path))
            qemu_process = subprocess.Popen(command, env=env)
            return qemu_process.wait()
        finally:
            for sig in signals:
                signal.signal(sig, signal.SIG_IGN)
            try:
                for process in (qemu_process, tpm_process):
                    if process is not None and process.poll() is None:
                        try:
                            process.terminate()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
                            process.wait()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
