import re
import shlex
import stat
import sys
from pathlib import Path


def owned_file_identity(path, label):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"refusing non-regular owned file: {path}")
    return f"{label} {info.st_dev} {info.st_ino}\n"


def record_owned_file(path, marker, label):
    if marker.is_symlink():
        raise ValueError(f"refusing symlinked ownership marker: {marker}")
    marker.write_text(owned_file_identity(path, label))


def is_owned_file(path, marker, label):
    return (
        not marker.is_symlink()
        and marker.is_file()
        and marker.read_text() == owned_file_identity(path, label)
    )


def load_environment(root, environment):
    values = dict(environment)
    dotenv = Path(root) / ".env"
    if not dotenv.is_file():
        return values
    for number, line in enumerate(dotenv.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, raw = line.partition("=")
        if (
            not separator
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            or "$" in raw
            or "`" in raw
        ):
            raise ValueError(f"Unsupported .env assignment on line {number}")
        parts = shlex.split(raw, comments=True)
        if len(parts) > 1:
            raise ValueError(f"Unsupported .env value on line {number}")
        values[key] = parts[0] if parts else ""
    return values


def disk_format(path):
    return "qcow2" if str(path).endswith(".qcow2") else "raw"


def resolve_artifact(root, explicit, pointer, pattern, legacy=None):
    root = Path(root)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ValueError(f"Artifact does not exist: {path}")
        return path.resolve()
    candidates = []
    pointer = Path(pointer)
    if pointer.is_file():
        path = Path(pointer.read_text().strip())
        if path.is_file():
            candidates.append(path)
        else:
            print(f"Ignoring stale artifact pointer: {path}", file=sys.stderr)
    candidates.extend(
        path for path in root.glob(pattern) if not path.is_symlink() and path.is_file()
    )
    if candidates:
        return max(candidates, key=lambda path: int(path.stat().st_mtime)).resolve()
    if legacy and Path(legacy).is_file():
        return Path(legacy).resolve()
    raise ValueError(f"No artifact matching {pattern} found in {root}")


def resolve_ovmf(env):
    code = [
        env.get("QEMU_OVMF_CODE"),
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    ]
    variables = [
        env.get("QEMU_OVMF_VARS_TEMPLATE"),
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    ]
    selected = [
        next((Path(path) for path in options if path and Path(path).is_file()), None)
        for options in (code, variables)
    ]
    if any(path is None for path in selected):
        raise ValueError("Unable to find OVMF code and variables firmware")
    return selected
