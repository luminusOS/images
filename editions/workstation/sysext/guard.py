#!/usr/bin/env python3
"""Check one feature build against its base image and pack it as a sysext.

Inputs are the base tree, the final tree of the build container and the
container's diff (podman diff --format json). Every guard failure is
collected and reported together; any failure means no artifact is written.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

KEPT_ROOTS = ("/usr", "/opt")
STRIPPED = ("/usr/lib/sysimage",)
RESERVED_UNIT_IDS = {"features", "sysext", "discovery"}

MERGED_CACHES = (
    "*/gschemas.compiled",
    "*/icon-theme.cache",
    "/usr/share/mime/*",
    "*/gdk-pixbuf-2.0/*/loaders.cache",
    "*/gio/modules/giomodule.cache",
    "/usr/lib/fontconfig/cache/*",
    "*/fonts.cache-*",
    "/usr/share/fonts/*/.uuid",
    "/usr/share/applications/mimeinfo.cache",
    "/usr/share/info/dir",
    "/usr/lib/locale/locale-archive*",
    "/usr/lib/udev/hwdb.bin",
)
MERGED_CACHE_EXCEPTIONS = ("/usr/share/mime/packages", "/usr/share/mime/packages/*.xml")

DENIED_PREFIXES = (
    "/usr/local",
    "/usr/share/systemd",
    "/usr/lib/gio/modules",
    "/usr/lib64/gio/modules",
    "/usr/lib/modules",
    "/usr/lib/extension-release.d",
    "/usr/lib/os-release",
    "/usr/lib/pam.d",
    "/usr/lib/security",
    "/usr/lib64/security",
    "/usr/lib/polkit-1",
    "/usr/share/polkit-1",
    "/usr/lib/dbus-1.0",
    "/usr/share/dbus-1",
    "/usr/lib/tmpfiles.d",
    "/usr/lib/sysctl.d",
    "/usr/lib/binfmt.d",
    "/usr/lib/modules-load.d",
    "/usr/lib/environment.d",
    "/usr/lib/kernel",
    "/usr/lib/dracut",
    "/usr/lib/bootc",
    "/usr/lib/ostree",
    "/usr/lib/selinux",
    "/usr/share/selinux",
    "/usr/lib/firewalld",
    "/usr/lib/NetworkManager/dispatcher.d",
    "/usr/share/factory",
    "/usr/etc",
    "/usr/lib/udev/hwdb.d",
)
NSS_PATTERNS = ("/usr/lib*/libnss_*",)

UNIT_DEPENDENCY_KEYS = {
    "Requires",
    "Requisite",
    "Wants",
    "BindsTo",
    "PartOf",
    "Upholds",
    "After",
    "Before",
    "Conflicts",
    "OnFailure",
    "OnSuccess",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "JoinsNamespaceOf",
}
UNIT_FORBIDDEN_INSTALL_KEYS = {
    "RequiredBy",
    "UpheldBy",
    "Alias",
    "Also",
    "DefaultInstance",
}
EXEC_KEY_RE = re.compile(r"^Exec[A-Za-z]*$")
UDEV_EXEC_RE = re.compile(r'(?:RUN|PROGRAM|IMPORT\{program\})\+?=+"([^"]*)"')
LUMINUS_NAME_RE = re.compile(r"luminusos-([a-z][a-z0-9]*)-")


class Guard:
    def __init__(self, args):
        self.base = args.base.rstrip("/")
        self.final = args.final.rstrip("/")
        self.id = args.manifest["id"]
        self.manifest = args.manifest
        self.errors = []
        self.warnings = []
        self.exec_refs = set()
        self.unit_prefix = f"luminusos-{self.id}-"

    def error(self, path, why):
        self.errors.append(f"{path}: {why}")

    def b(self, path):
        return self.base + path

    def f(self, path):
        return self.final + path

    @staticmethod
    def lstat(path):
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None

    @staticmethod
    def kept(path):
        if any(path == p or path.startswith(p + "/") for p in STRIPPED):
            return False
        return any(path == r or path.startswith(r + "/") for r in KEPT_ROOTS)

    def resolve(self, root, path, hops=40):
        """Resolve path inside root the way the merged system would see it."""
        parts = [p for p in path.split("/") if p]
        done = []
        while parts:
            part = parts.pop(0)
            if part == ".":
                continue
            if part == "..":
                if done:
                    done.pop()
                continue
            candidate = "/" + "/".join(done + [part])
            st = self.lstat(root + candidate)
            if st is not None and stat.S_ISLNK(st.st_mode):
                hops -= 1
                if hops < 0:
                    return None
                target = os.readlink(root + candidate)
                if target.startswith("/"):
                    done = []
                parts = [p for p in target.split("/") if p] + parts
                continue
            done.append(part)
        return "/" + "/".join(done)

    @staticmethod
    def digest(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def same(self, path, bst, fst):
        if stat.S_IFMT(bst.st_mode) != stat.S_IFMT(fst.st_mode):
            return "retyped"
        if (bst.st_mode, bst.st_uid, bst.st_gid) != (
            fst.st_mode,
            fst.st_uid,
            fst.st_gid,
        ):
            return "mode or owner changed"
        if stat.S_ISLNK(fst.st_mode) and os.readlink(self.b(path)) != os.readlink(
            self.f(path)
        ):
            return "link target changed"
        if stat.S_ISREG(fst.st_mode) and (
            bst.st_size != fst.st_size
            or self.digest(self.b(path)) != self.digest(self.f(path))
        ):
            return "content changed"
        return None

    def check_base_paths(self, diff):
        for path in diff.get("deleted") or []:
            if not self.kept(path):
                continue
            bst, fst = self.lstat(self.b(path)), self.lstat(self.f(path))
            if fst is None:
                self.error(path, "base path deleted")
            elif bst is not None:
                self.error(path, f"base path {self.same(path, bst, fst) or 'replaced'}")
        for path in diff.get("changed") or []:
            if not self.kept(path):
                continue
            bst, fst = self.lstat(self.b(path)), self.lstat(self.f(path))
            if bst is None:
                continue
            if fst is None:
                self.error(path, "base path deleted")
                continue
            why = self.same(path, bst, fst)
            if why:
                self.error(path, f"base path {why}")

    def privileged(self, path, st):
        uid = self.id
        systemd = "/usr/lib/systemd"
        wants = "/usr/lib/systemd/system/luminusos-features.target.wants"
        if path == systemd or path.startswith(systemd + "/"):
            if stat.S_ISDIR(st.st_mode):
                if path in (systemd, systemd + "/system", wants):
                    return None
                return "directory outside the unit allowlist"
            name = os.path.basename(path)
            own_unit = name.startswith(self.unit_prefix) and name.endswith(".service")
            if (
                os.path.dirname(path) == systemd + "/system"
                and own_unit
                and stat.S_ISREG(st.st_mode)
            ):
                return None
            if os.path.dirname(path) == wants and own_unit and stat.S_ISLNK(st.st_mode):
                target = self.resolve(self.final, path)
                if target == f"{systemd}/system/{name}":
                    return None
                return (
                    "wants link must point to the feature's own unit of the same name"
                )
            return f"only {systemd}/system/{self.unit_prefix}*.service and their luminusos-features.target.wants links are allowed"
        if path == "/usr/lib/udev" or path.startswith("/usr/lib/udev/"):
            if path in ("/usr/lib/udev", "/usr/lib/udev/rules.d") and stat.S_ISDIR(
                st.st_mode
            ):
                return None
            if fnmatch.fnmatchcase(
                path, f"/usr/lib/udev/rules.d/70-luminusos-{uid}-*.rules"
            ) and stat.S_ISREG(st.st_mode):
                return None
            return f"only /usr/lib/udev/rules.d/70-luminusos-{uid}-*.rules is allowed"
        if path == "/usr/lib/modprobe.d" or path.startswith("/usr/lib/modprobe.d/"):
            if path == "/usr/lib/modprobe.d" and stat.S_ISDIR(st.st_mode):
                return None
            if path == f"/usr/lib/modprobe.d/luminusos-{uid}.conf" and stat.S_ISREG(
                st.st_mode
            ):
                return None
            return f"only /usr/lib/modprobe.d/luminusos-{uid}.conf is allowed"
        if path == "/usr/lib/sysusers.d" or path.startswith("/usr/lib/sysusers.d/"):
            if path == "/usr/lib/sysusers.d" and stat.S_ISDIR(st.st_mode):
                return None
            if path == f"/usr/lib/sysusers.d/luminusos-{uid}.conf" and stat.S_ISREG(
                st.st_mode
            ):
                return None
            return f"only /usr/lib/sysusers.d/luminusos-{uid}.conf is allowed"
        for prefix in DENIED_PREFIXES:
            if path == prefix or path.startswith(prefix + "/"):
                return f"privileged path {prefix} is not allowed"
        if any(fnmatch.fnmatchcase(path, p) for p in NSS_PATTERNS):
            return "NSS modules are not allowed"
        return None

    def check_names(self, path, text):
        for other in sorted(set(LUMINUS_NAME_RE.findall(text))):
            if other != self.id and other not in RESERVED_UNIT_IDS:
                self.error(path, f"names another feature (luminusos-{other}-*)")

    def check_unit(self, path):
        text = Path(self.f(path)).read_text(encoding="utf-8", errors="replace")
        self.check_names(path, text)
        section = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if "=" not in line:
                continue
            key, value = (s.strip() for s in line.split("=", 1))
            if key in UNIT_DEPENDENCY_KEYS:
                for token in value.split():
                    if token.startswith("luminusos-") and not (
                        token.startswith(self.unit_prefix)
                        or token == "luminusos-features.target"
                    ):
                        self.error(path, f"{key}= names {token}")
            if EXEC_KEY_RE.match(key):
                for token in value.split():
                    token = token.lstrip("-@:+!|")
                    if token.startswith("/"):
                        self.exec_refs.add(token)
            if section == "Install":
                if key in UNIT_FORBIDDEN_INSTALL_KEYS:
                    self.error(path, f"[Install] {key}= is not allowed")
                if key == "WantedBy" and any(
                    t != "luminusos-features.target" for t in value.split()
                ):
                    self.error(
                        path, "WantedBy= may only name luminusos-features.target"
                    )

    def check_rule(self, path):
        text = Path(self.f(path)).read_text(encoding="utf-8", errors="replace")
        self.check_names(path, text)
        for command in UDEV_EXEC_RE.findall(text):
            for token in command.split():
                if token.startswith("/"):
                    self.exec_refs.add(token)

    def check_added(self, diff):
        added = sorted({p for p in diff.get("added") or [] if self.kept(p)})
        own = set(added)
        kept = []
        has_rule = False
        for path in added:
            st = self.lstat(self.f(path))
            if st is None:
                continue
            mode = st.st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                self.error(
                    path, "only regular files, directories and symlinks are allowed"
                )
                continue
            if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
                self.error(path, "setuid or setgid file")
            if stat.S_ISREG(mode):
                try:
                    os.getxattr(
                        self.f(path), "security.capability", follow_symlinks=False
                    )
                    self.error(path, "file capabilities are not allowed")
                except OSError:
                    pass
            parent = os.path.dirname(path)
            while parent not in ("/", ""):
                pst = self.lstat(self.b(parent))
                if pst is not None and not stat.S_ISDIR(pst.st_mode):
                    self.error(path, f"parent {parent} is not a directory in the base")
                    break
                parent = os.path.dirname(parent)
            if stat.S_ISLNK(mode):
                target = self.resolve(self.final, path)
                if target is None:
                    self.error(path, "symlink loop")
                elif (
                    target not in own
                    and self.kept(target)
                    and self.lstat(self.b(target)) is not None
                ):
                    self.error(path, f"symlink points into base content ({target})")
            if any(fnmatch.fnmatchcase(path, p) for p in MERGED_CACHES) and not any(
                fnmatch.fnmatchcase(path, p) for p in MERGED_CACHE_EXCEPTIONS
            ):
                self.error(path, "merged cache")
            why = self.privileged(path, st)
            if why:
                self.error(path, why)
            elif stat.S_ISREG(mode) and path.startswith("/usr/lib/systemd/system/"):
                self.check_unit(path)
            elif stat.S_ISREG(mode) and path.startswith("/usr/lib/udev/rules.d/"):
                has_rule = True
                self.check_rule(path)
            kept.append(path)
        if self.manifest["udev_trigger"] and not has_rule:
            self.errors.append(
                "FEATURE_UDEV_TRIGGER is set but the feature ships no udev rule"
            )
        if not any(
            not stat.S_ISDIR(os.lstat(self.f(p)).st_mode)
            for p in kept
            if self.lstat(self.f(p))
        ):
            self.errors.append("the feature adds no files")
        dropped = sorted(p for p in diff.get("added") or [] if p.startswith("/etc/"))
        if dropped:
            self.warnings.append(
                f"dropped {len(dropped)} /etc path(s), first: {dropped[0]}"
            )
        return kept

    def stage(self, kept, dest):
        links = {}
        for path in kept:
            ancestors = []
            parent = os.path.dirname(path)
            while parent not in ("/", ""):
                ancestors.append(parent)
                parent = os.path.dirname(parent)
            for anc in reversed(ancestors):
                self.copy_node(anc, dest, links)
            self.copy_node(path, dest, links)
        root = os.lstat(self.final + "/")
        os.chmod(dest, stat.S_IMODE(root.st_mode))

    def copy_node(self, path, dest, links):
        src, dst = self.f(path), dest + path
        if os.path.lexists(dst):
            return
        st = os.lstat(src)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(dst)
        elif stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(src), dst)
        elif st.st_nlink > 1 and (st.st_dev, st.st_ino) in links:
            os.link(links[(st.st_dev, st.st_ino)], dst)
            return
        else:
            shutil.copyfile(src, dst, follow_symlinks=False)
            links[(st.st_dev, st.st_ino)] = dst
        os.lchown(dst, st.st_uid, st.st_gid)
        if not stat.S_ISLNK(st.st_mode):
            os.chmod(dst, stat.S_IMODE(st.st_mode))
        os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)


def write_release(dest, args):
    fid, version = args.manifest["id"], args.version
    rel_dir = dest + "/usr/lib/extension-release.d"
    os.makedirs(rel_dir, mode=0o755, exist_ok=True)
    lines = [
        f"ID={args.os_id}",
        f"VERSION_ID={args.os_version_id}",
        f"SYSEXT_LEVEL={version}",
        f"ARCHITECTURE={args.architecture}",
        "EXTENSION_RELOAD_MANAGER=1",
    ]
    if args.manifest["udev_trigger"]:
        lines.append(
            'LUMINUSOS_UDEV_TRIGGER="' + " ".join(args.manifest["udev_trigger"]) + '"'
        )
    path = f"{rel_dir}/extension-release.luminusos-{fid}_{version}"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o644)


def pack(dest, args, guard):
    fid, version = args.manifest["id"], args.version
    name = f"luminusos-{fid}_{version}"
    raw, xz = f"{args.out}/{name}.raw", f"{args.out}/{name}.raw.xz"
    for p in (raw, xz):
        if os.path.lexists(p):
            os.unlink(p)
    cmd = [args.mkfs, "--quiet", "-zlz4hc"]
    if args.file_contexts:
        cmd.append(f"--file-contexts={args.file_contexts}")
    subprocess.run(cmd + [raw, dest], check=True)
    os.chmod(raw, 0o644)
    expanded_limit = args.manifest["expanded_budget_mib"] << 20
    compressed_limit = args.manifest["compressed_budget_mib"] << 20
    raw_size = os.path.getsize(raw)
    if raw_size > expanded_limit:
        os.unlink(raw)
        sys.exit(
            f"guard: {name}.raw is {raw_size} bytes, over the expanded budget of {expanded_limit}"
        )
    subprocess.run([args.xz, "-T0", "-k", "-f", raw], check=True)
    xz_size = os.path.getsize(xz)
    if xz_size > compressed_limit:
        os.unlink(raw)
        os.unlink(xz)
        sys.exit(
            f"guard: {name}.raw.xz is {xz_size} bytes, over the compressed budget of {compressed_limit}"
        )
    nodes = {}
    for top, dirs, files in os.walk(dest):
        for n in dirs + files:
            full = os.path.join(top, n)
            mode = os.lstat(full).st_mode
            kind = "d" if stat.S_ISDIR(mode) else "l" if stat.S_ISLNK(mode) else "f"
            nodes[full[len(dest) :]] = kind
    meta = {
        "format": 1,
        "id": fid,
        "version": version,
        "architecture": args.architecture,
        "image_digest": args.image_digest,
        "raw": os.path.basename(raw),
        "raw_xz": os.path.basename(xz),
        "raw_sha256": Guard.digest(raw),
        "raw_xz_sha256": Guard.digest(xz),
        "raw_bytes": raw_size,
        "raw_xz_bytes": xz_size,
        "compressed_budget_mib": args.manifest["compressed_budget_mib"],
        "expanded_budget_mib": args.manifest["expanded_budget_mib"],
        "nodes": dict(sorted(nodes.items())),
        "exec_refs": sorted(guard.exec_refs),
        "warnings": guard.warnings,
    }
    with open(f"{args.out}/{name}.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(
        json.dumps(
            {k: meta[k] for k in ("raw", "raw_bytes", "raw_xz_bytes", "raw_sha256")}
        )
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--final", required=True)
    ap.add_argument("--diff", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--out")
    ap.add_argument("--version", required=True)
    ap.add_argument("--image-digest", default="")
    ap.add_argument("--os-id", default="fedora")
    ap.add_argument("--os-version-id", required=True)
    ap.add_argument("--architecture", default="x86-64")
    ap.add_argument("--file-contexts")
    ap.add_argument("--mkfs", default="mkfs.erofs")
    ap.add_argument("--xz", default="xz")
    ap.add_argument("--check-only", action="store_true")
    args = ap.parse_args()
    with open(args.manifest, encoding="utf-8") as fh:
        args.manifest = json.load(fh)
    with open(args.diff, encoding="utf-8") as fh:
        diff = json.load(fh)

    guard = Guard(args)
    guard.check_base_paths(diff)
    kept = guard.check_added(diff)
    for w in guard.warnings:
        print(f"guard: warning: {w}", file=sys.stderr)
    if guard.errors:
        for e in guard.errors:
            print(f"guard: {e}", file=sys.stderr)
        sys.exit(f"guard: {len(guard.errors)} violation(s) in feature {guard.id}")
    os.makedirs(args.stage, exist_ok=True)
    if os.listdir(args.stage):
        sys.exit(f"guard: stage directory {args.stage} is not empty")
    guard.stage(kept, args.stage)
    write_release(args.stage, args)
    if args.check_only:
        print(f"guard: feature {guard.id} passed ({len(kept)} paths)")
        return
    os.makedirs(args.out, exist_ok=True)
    pack(args.stage, args, guard)


if __name__ == "__main__":
    main()
