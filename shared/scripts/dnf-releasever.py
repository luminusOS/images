#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("version")
args = parser.parse_args()
if not args.version.isascii() or not args.version.isdecimal():
    parser.error("version must contain only digits")
for directory in (Path("/etc/dnf/vars"), Path("/etc/yum/vars")):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "releasever").write_text(args.version + "\n")
