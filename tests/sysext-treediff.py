#!/usr/bin/env python3
"""Write a podman-diff-style JSON for two trees: tests/sysext-treediff.py <base> <final>."""

import hashlib
import json
import os
import stat
import sys


def walk(root):
    nodes = {}
    for top, dirs, files in os.walk(root):
        for name in dirs + files:
            full = os.path.join(top, name)
            st = os.lstat(full)
            key = full[len(root):]
            sig = (stat.S_IFMT(st.st_mode), st.st_mode, st.st_uid, st.st_gid)
            if stat.S_ISLNK(st.st_mode):
                sig += (os.readlink(full),)
            elif stat.S_ISREG(st.st_mode):
                sig += (hashlib.sha256(open(full, "rb").read()).hexdigest(),)
            elif stat.S_ISDIR(st.st_mode):
                sig += (tuple(sorted(os.listdir(full))),)
            nodes[key] = sig
    return nodes


base, final = walk(sys.argv[1].rstrip("/")), walk(sys.argv[2].rstrip("/"))
print(json.dumps({
    "added": sorted(set(final) - set(base)),
    "deleted": sorted(set(base) - set(final)),
    "changed": sorted(p for p in set(base) & set(final) if base[p] != final[p]),
}))
