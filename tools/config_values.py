import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSIGNMENT = re.compile(r"([A-Z][A-Z0-9_]*)=([A-Za-z0-9_.:+@/~-]*)", re.ASCII)


def read_config(path=ROOT / "config/versions.env"):
    result = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if not match:
            raise ValueError(f"Unsupported configuration at {path}:{number}")
        key, value = match.groups()
        if key in result:
            raise ValueError(f"Duplicate configuration key {key}")
        result[key] = value
    return result
