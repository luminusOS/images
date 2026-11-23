#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("values", nargs=6)
    args = parser.parse_args()
    inputs = [
        ROOT / "editions/core",
        ROOT / "shared/trust",
        *(
            ROOT / "shared/scripts" / name
            for name in ("dnf-releasever.py", "os-release-set.py", "rpmdb-repair.py")
        ),
    ]
    paths = sorted(
        path
        for item in inputs
        for path in (item.rglob("*") if item.is_dir() else [item])
        if path.is_file()
    )
    digest = hashlib.sha256()
    for value in args.values:
        digest.update(f"{value}\n".encode())
    for path in paths:
        digest.update(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}\n".encode()
        )
    print(digest.hexdigest())


if __name__ == "__main__":
    main()
