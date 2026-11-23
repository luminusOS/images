#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path


def main(arguments):
    if not arguments or len(arguments) % 2:
        raise ValueError("expected KEY VALUE pairs")
    updates = {}
    for key, value in zip(arguments[::2], arguments[1::2]):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key, re.ASCII):
            raise ValueError(f"invalid key: {key}")
        if "\n" in value or "\r" in value:
            raise ValueError("values must not contain newlines")
        updates[key] = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("$", "\\$")
            .replace("`", "\\`")
        )
    path = Path(os.environ.get("OS_RELEASE_FILE", "/usr/lib/os-release"))
    lines = path.read_text().splitlines()
    seen = set()
    for index, line in enumerate(lines):
        key = line.partition("=")[0]
        if key in updates:
            lines[index] = f'{key}="{updates[key]}"'
            seen.add(key)
    lines.extend(
        f'{key}="{value}"' for key, value in updates.items() if key not in seen
    )
    path.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
