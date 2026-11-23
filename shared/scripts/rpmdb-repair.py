#!/usr/bin/env python3
import re
import shutil
import subprocess
from pathlib import Path


def natural_key(path):
    return [
        (1, int(part)) if part.isdecimal() else (0, part)
        for part in re.split(r"(\d+)", path.name)
    ]


for lock in (Path("/var/lib/rpm/.rpm.lock"), Path("/usr/lib/sysimage/rpm/.rpm.lock")):
    try:
        lock.unlink(missing_ok=True)
    except OSError:
        pass
if subprocess.run(["rpm", "--rebuilddb"], check=False).returncode:
    candidates = [
        path
        for path in Path("/usr/share").glob("rpmrebuilddb.*")
        if path.is_dir() and not path.is_symlink()
    ]
    if not candidates:
        raise RuntimeError("rpm rebuild failed without a recovery database")
    target = Path("/usr/share/rpm")
    if target.is_symlink():
        raise RuntimeError("refusing to replace symlinked RPM database")
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(max(candidates, key=natural_key)), str(target))
subprocess.run(["rpm", "-qa"], stdout=subprocess.DEVNULL, check=True)
