#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("metadata", type=Path)
parser.add_argument("modes", nargs="*")
args = parser.parse_args()
metadata = json.loads(args.metadata.read_text())
metadata["session-modes"] = sorted(
    set(metadata.get("session-modes", ["user"]) + args.modes)
)
args.metadata.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
args.metadata.chmod(0o644)
