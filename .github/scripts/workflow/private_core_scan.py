"""Trusted supervisor for an independent, non-promoting private vulnerability gate.

Bootstrap must launch reviewed immutable tooling with a trusted system Python -I.
Invocation and bundle hashes come from independent reviewed configuration, not
their documents. Protected inputs exclude concurrent same-UID/privileged writers.
Polling bounds are admission/detection, not filesystem quotas or crash recovery.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
# A regular-file prefix cannot contain cached bytecode; -B alone still reads it.
sys.pycache_prefix = str(Path(__file__).resolve())
PYTHON = "/usr/bin/python3"
POLICY_SHA256 = "c9d47908efd8b2738b9f71b2bcd67cbf7c1372f64d7259d857ad3c5ba0e96f40"
SCOPE = {
    "edition": "core",
    "component_scope": "core_payload",
    "channel": "testing",
    "fedora": "45",
}
TOTAL_LIMIT = 4 * 1024**3
JSON_LIMIT = 64 * 1024
TOOL_ARCHIVES = {
    "syft": (
        "1.34.2",
        "b62a3d4167f9a04bc190a5e654b05711737527ed47b616dc398e541f903c2d72",
    ),
    "grype": (
        "0.101.1",
        "3a1aba2db34d034e2443336e5fc78154651ee2820c74ff8c5602a2b6eec84a89",
    ),
}
VERIFICATION = {
    **dict.fromkeys(
        (
            "archive",
            "oci",
            "diff_ids",
            "base_prefix",
            "attempt",
            "private_handoff_attestation",
        ),
        "completed",
    ),
    "upstream_signature": "not_evaluated",
    "vulnerability_policy": "not_evaluated",
    "vulnerability_scan": "not_run",
    "vm": "not_run",
}
FLAGS = {
    "production_ready": False,
    "runtime_verified": False,
    "release_authorized": False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


@lru_cache(maxsize=1)
def _libraries():
    modules = []
    for name in ("core_build_acquisition", "supply_chain"):
        spec = importlib.util.spec_from_file_location(
            name, Path(__file__).with_name(name + ".py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return tuple(modules)


def _absolute(value):
    require(isinstance(value, (str, Path)), "absolute path required")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "unsafe absolute path")
    return path


def _fields(value, names):
    require(
        isinstance(value, dict) and set(value) == set(names.split()),
        "unknown or missing fields",
    )


def _hash(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
        "expected SHA256 required",
    )
    return value


def _read(path, limit=JSON_LIMIT, *, readonly=False, allow_empty=False):
    path = _absolute(path)
    oci = _libraries()[0].oci
    with oci.directory(path.parent) as parent:
        info = os.fstat(parent)
        require(
            info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
            "protected input parent required",
        )
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid in (0, os.geteuid())
            and not info.st_mode & (0o222 if readonly else 0o022),
            "protected regular input required",
        )
        if allow_empty and info.st_size == 0:
            return b""
        return oci.contents(parent, path.name, limit)


def _document(raw):
    return _libraries()[0].oci.document(raw)


def _checked_document(descriptor):
    _fields(descriptor, "path sha256")
    raw = _read(descriptor["path"])
    require(
        hashlib.sha256(raw).hexdigest() == _hash(descriptor["sha256"]),
        "document hash mismatch",
    )
    return _document(raw)


def _relative(root, name):
    require(
        isinstance(name, str) and len(name) <= 256, "bounded relative path required"
    )
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and path.parts
        and path.as_posix() == name
        and all(
            re.fullmatch(r"[A-Za-z0-9_+.-]+", p) and p not in (".", "..")
            for p in path.parts
        ),
        "unsafe bundle path",
    )
    return root / name


def _separate(left, right):
    require(
        left != right and left not in right.parents and right not in left.parents,
        "overlapping inputs or output",
    )


def _tree_bytes(root):
    oci = _libraries()[0].oci
    with oci.directory(root):
        total = 0
        deadline = time.monotonic() + 30
        for count, path in enumerate(root.rglob("*")):
            require(count < 4096, "file count budget exceeded")
            require(time.monotonic() <= deadline, "accounting deadline exceeded")
            info = path.lstat()
            require(
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "unsafe accounted entry",
            )
            if stat.S_ISREG(info.st_mode):
                total += max(info.st_size, info.st_blocks * 512)
                require(total <= TOTAL_LIMIT, "accounted tree exceeds budget")
        return total


def _bundle(descriptor):
    path = _absolute(descriptor["path"])
    require(path.name == "bundle.json", "fixed bundle manifest name required")
    raw = _read(path, readonly=True)
    require(
        hashlib.sha256(raw).hexdigest() == _hash(descriptor["sha256"]),
        "bundle hash mismatch",
    )
    bundle = _document(raw)
    _fields(bundle, "kind schema_version tools runtime_files database")
    require(
        bundle["kind"] == "private-core-scan-bundle"
        and type(bundle["schema_version"]) is int
        and bundle["schema_version"] == 1,
        "unsupported bundle",
    )
    root = path.parent
    local = _libraries()[1].local_oci_scan
    inventory = {"bundle.json"}

    def file(entry, extras=""):
        _fields(entry, "path sha256 size_bytes " + extras)
        target = _relative(root, entry["path"])
        require(entry["path"] not in inventory, "duplicate bundle input")
        inventory.add(entry["path"])
        _hash(entry["sha256"])
        require(
            type(entry["size_bytes"]) is int and 0 < entry["size_bytes"] <= TOTAL_LIMIT,
            "invalid bundle size",
        )
        # Hash large prepared databases in streaming bounded reads, never copy them.
        with local.oci.directory(target.parent) as parent:
            info = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid in (0, os.geteuid())
                and not info.st_mode & 0o6222
                and info.st_size == entry["size_bytes"],
                "bundle file must be protected and read-only",
            )
        require(local.sha256(target) == entry["sha256"], "bundle file hash mismatch")
        return local.TrustedFile(target, entry["sha256"])

    _fields(bundle["tools"], "syft grype bwrap prlimit")
    tools = {}
    for name, entry in bundle["tools"].items():
        if name in TOOL_ARCHIVES:
            tools[name] = file(entry, "version archive_sha256")
            require(
                (entry["version"], entry["archive_sha256"]) == TOOL_ARCHIVES[name],
                "unsupported scanner archive/version",
            )
        else:
            tools[name] = file(entry)
        require(os.access(tools[name].path, os.X_OK), "bundle executable required")
    require(
        isinstance(bundle["runtime_files"], list)
        and len(bundle["runtime_files"]) <= 32,
        "finite runtime inventory required",
    )
    runtime, destinations = [], set()
    for entry in bundle["runtime_files"]:
        trusted = file(entry, "destination")
        destination = entry["destination"]
        require(
            isinstance(destination, str)
            and re.fullmatch(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_+./-]+", destination)
            and ".." not in Path(destination).parts
            and Path(destination).as_posix() == destination
            and destination not in destinations,
            "unsafe runtime destination",
        )
        destinations.add(destination)
        runtime.append(local.RuntimeFile(trusted, destination))
    db = bundle["database"]
    _fields(
        db,
        "cache_path installed import_metadata archive schemaVersion built preparation_receipt",
    )
    require(
        db["cache_path"] == "db"
        and db["installed"]["path"] == "db/6/vulnerability.db"
        and db["import_metadata"]["path"] == "db/6/import.json",
        "fixed model-6 DB paths required",
    )
    installed, imported, prepared = (
        file(db["installed"]),
        file(db["import_metadata"]),
        file(db["preparation_receipt"]),
    )
    _fields(db["archive"], "url sha256 size_bytes")
    archive = db["archive"]
    _hash(archive["sha256"])
    require(
        type(archive["size_bytes"]) is int and 0 < archive["size_bytes"] <= TOTAL_LIMIT,
        "invalid distribution archive size",
    )
    url = urlsplit(archive["url"])
    require(
        url.scheme == "https"
        and url.netloc in ("toolbox-data.anchore.io", "grype.anchore.io")
        and url.path.startswith(("/grype/databases/v6/", "/databases/v6/"))
        and not url.query
        and not url.fragment,
        "official DB distribution identity required",
    )
    preparation = _document(_read(prepared.path, readonly=True))
    require(
        preparation
        == {
            "kind": "prepared-grype-database",
            "schema_version": 1,
            **{
                k: v
                for k, v in db.items()
                if k not in ("cache_path", "preparation_receipt")
            },
        }
        and type(preparation["schema_version"]) is int,
        "DB preparation identity mismatch",
    )
    local.check_db_status(
        {
            "valid": True,
            "built": db["built"],
            "schemaVersion": db["schemaVersion"],
            "path": "/db/6/vulnerability.db",
        },
        datetime.now(UTC),
    )
    actual = set()
    for count, item in enumerate(root.rglob("*")):
        require(count < 4096, "bundle file count exceeded")
        info = item.lstat()
        require(
            info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
            "protected bundle tree required",
        )
        require(
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
            "unsafe bundle tree",
        )
        if stat.S_ISREG(info.st_mode):
            actual.add(item.relative_to(root).as_posix())
    require(actual == inventory, "unlisted or missing bundle files")
    return {
        "root": root,
        "bytes": _tree_bytes(root),
        "tools": tools,
        "runtime": tuple(runtime),
        "db": db,
        "installed": installed,
        "imported": imported,
        "prepared": prepared,
    }


def _preflight(invocation, work):
    require(
        os.environ.get("SECURITY_FINDINGS_BYPASS", "false") == "false",
        "bypass forbidden",
    )
    _fields(
        invocation,
        "kind schema_version trusted_root source_checkout scope policy bundle acquisition logical_image layout_max_bytes",
    )
    require(
        invocation["kind"] == "private-core-scan-invocation"
        and type(invocation["schema_version"]) is int
        and invocation["schema_version"] == 1
        and invocation["scope"] == SCOPE,
        "fixed caller scope required",
    )
    trusted = _absolute(invocation["trusted_root"])
    require(
        trusted == Path(__file__).resolve().parents[3],
        "unexpected trusted tooling path",
    )
    source = _absolute(invocation["source_checkout"])
    for path in (source, trusted):
        ancestor = path
        while not ancestor.exists() and not ancestor.is_symlink():
            ancestor = ancestor.parent
        with _libraries()[0].oci.directory(ancestor):
            pass
    _fields(invocation["policy"], "path sha256")
    require(
        invocation["policy"]["sha256"] == POLICY_SHA256,
        "unapproved vulnerability policy hash",
    )
    policy = _absolute(invocation["policy"]["path"])
    raw = _read(policy)
    require(
        len(raw) == 97 and hashlib.sha256(raw).hexdigest() == POLICY_SHA256,
        "vulnerability policy byte mismatch",
    )
    acquisition, supply = _libraries()
    supply._exceptions(policy, context=SCOPE, expected_sha256=POLICY_SHA256)
    _fields(invocation["acquisition"], "policy context facts")
    request = invocation["acquisition"]
    expected = acquisition.private_policy(request["policy"], request["context"])
    acquisition.private_facts(expected, request["facts"])
    _fields(invocation["bundle"], "path sha256")
    bundle = _bundle(invocation["bundle"])
    paths = (work, trusted, source, bundle["root"], policy)
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            _separate(left, right)
    require(
        isinstance(invocation["logical_image"], str)
        and len(invocation["logical_image"]) <= 512
        and re.fullmatch(
            r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", invocation["logical_image"]
        )
        and invocation["logical_image"].endswith(
            "@" + request["facts"]["manifest_digest"]
        ),
        "independent logical image mismatch",
    )
    maximum = invocation["layout_max_bytes"]
    require(
        type(maximum) is int and 0 < maximum <= TOTAL_LIMIT,
        "finite layout admission bound required",
    )
    reserve = (
        2 * supply.local_oci_scan.WORK_LIMIT
        + supply.local_oci_scan.FILE_LIMIT
        + 8 * JSON_LIMIT
    )
    require(
        bundle["bytes"] + int(request["facts"]["archive_size"]) + maximum + reserve
        <= TOTAL_LIMIT,
        "whole caller admission exceeds 4 GiB",
    )
    return expected, bundle, reserve


def _environment(home):
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(home),
        "TMPDIR": str(home),
    }


def _write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    require(len(raw) <= JSON_LIMIT, "internal configuration too large")
    with (
        _libraries()[0].oci.directory(path.parent) as parent,
        _libraries()[0].oci.new_oci_file(parent, path.name) as stream,
    ):
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _execute(argv, *, env, work, seconds, check):
    stdout, stderr = work / ".child-stdout", work / ".child-stderr"
    process = None
    started = time.monotonic()
    try:
        oci = _libraries()[0].oci
        with (
            oci.directory(work) as parent,
            oci.new_oci_file(parent, stdout.name) as out,
            oci.new_oci_file(parent, stderr.name) as err,
        ):
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=env,
                cwd=work,
                close_fds=True,
                start_new_session=True,
                umask=0o077,
            )

            def bounded():
                require(
                    time.monotonic() - started <= seconds, "child deadline exceeded"
                )
                require(
                    stdout.stat().st_size + stderr.stat().st_size <= JSON_LIMIT,
                    "child output exceeded bound",
                )
                check()

            while process.poll() is None:
                bounded()
                time.sleep(0.05)
            bounded()
            require(process.wait(timeout=5) == 0, "trusted child failed")
        raw = _read(stdout, allow_empty=True)
        require(len(raw) <= JSON_LIMIT, "child output grew after exit")
        return raw
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        stdout.unlink(missing_ok=True)
        stderr.unlink(missing_ok=True)


def _verify_tooling(root, expected, work, check):
    env = _environment(work / "scan-home") | {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    command = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(root),
    ]
    revision = _execute(
        command + ["rev-parse", "HEAD"], env=env, work=work, seconds=30, check=check
    )
    require(revision.decode().strip() == expected, "tooling revision mismatch")
    status = _execute(
        command + ["status", "--porcelain=v1", "--untracked-files=all"],
        env=env,
        work=work,
        seconds=30,
        check=check,
    )
    require(status == b"", "tooling checkout must be clean")
    tree = _execute(
        command + ["ls-tree", "-r", expected, "--", ".github/scripts/workflow"],
        env=env,
        work=work,
        seconds=30,
        check=check,
    )
    entries = []
    for line in tree.decode().splitlines():
        metadata, name = line.split("\t")
        mode, kind, identity = metadata.split()
        require(
            mode in ("100644", "100755") and kind == "blob", "unsupported tooling entry"
        )
        target = _relative(root, name)
        _read(target, 2 * 1024**2)
        entries.append((target, identity))
    require(
        0 < len(entries) <= 64 and Path(__file__).resolve() in {p for p, _ in entries},
        "reviewed caller absent from tooling tree",
    )
    actual = _execute(
        command + ["hash-object", "--no-filters", "--", *(str(p) for p, _ in entries)],
        env=env,
        work=work,
        seconds=30,
        check=check,
    )
    require(
        actual.decode().splitlines() == [identity for _, identity in entries],
        "tooling bytes differ from reviewed P",
    )


def _receipt(invocation, expected, work, summary):
    acquisition, _ = _libraries()
    facts = invocation["acquisition"]["facts"]
    original = {
        "kind": "authenticated-private-core-handoff",
        **facts,
        **expected,
        **FLAGS,
    }
    _fields(summary, " ".join((*original, "acquisition_receipt")))
    require(
        {k: summary[k] for k in original} == original,
        "acquisition summary identity mismatch",
    )
    descriptor = summary["acquisition_receipt"]
    _fields(descriptor, "path sha256 size_bytes")
    require(
        descriptor["path"] == "acquisition-receipt.json"
        and type(descriptor["size_bytes"]) is int
        and 0 < descriptor["size_bytes"] <= JSON_LIMIT,
        "fixed bounded receipt required",
    )
    destination = work / "acquisition"
    path = destination / "acquisition-receipt.json"
    raw = _read(path)
    require(
        path.stat().st_mode & 0o777 == 0o600
        and len(raw) == descriptor["size_bytes"]
        and hashlib.sha256(raw).hexdigest() == _hash(descriptor["sha256"]),
        "receipt byte descriptor mismatch",
    )
    receipt = _document(raw)
    _fields(receipt, " ".join((*original, "schema_version", "layout", "verification")))
    require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == 1
        and all(receipt[k] == v for k, v in original.items())
        and all(receipt[k] is False and summary[k] is False for k in FLAGS)
        and receipt["verification"] == VERIFICATION,
        "unauthenticated receipt identity or checks",
    )
    layout = receipt["layout"]
    _fields(
        layout, "path manifest_digest config_digest diff_ids os architecture reference"
    )
    require(
        layout["path"] == "layout"
        and layout["reference"] == "core"
        and layout["os"] == "linux"
        and layout["architecture"] == "amd64"
        and layout["manifest_digest"] == facts["manifest_digest"],
        "receipt layout identity mismatch",
    )
    require(
        _tree_bytes(destination / "layout") <= invocation["layout_max_bytes"],
        "layout exceeds admitted size",
    )
    with acquisition.oci.directory(destination / "layout") as root:
        digest, config, _ = acquisition.oci.checked_image(root, "core")
        index = acquisition.oci.document(
            acquisition.oci.contents(root, "index.json", JSON_LIMIT)
        )
        manifest = acquisition.oci.blob(
            root, index["manifests"][0], {acquisition.oci.MANIFEST}, json_blob=True
        )
    require(
        digest == facts["manifest_digest"]
        and manifest["config"]["digest"] == layout["config_digest"]
        and isinstance(layout["diff_ids"], list)
        and layout["diff_ids"] == config["rootfs"]["diff_ids"],
        "receipt config or ordered DiffID substitution",
    )
    local = _libraries()[1].local_oci_scan
    require(
        (destination / "core-oci.zip").stat().st_size == int(facts["archive_size"])
        and local.sha256(destination / "core-oci.zip") == facts["archive_sha256"],
        "acquired archive substitution",
    )
    return receipt


def _result(invocation, expected, summary, receipt):
    return dict(
        kind="private-core-vulnerability-gate",
        schema_version=1,
        vulnerability_gate="success",
        decision="clean",
        scope=SCOPE,
        policy_sha256=POLICY_SHA256,
        bundle_sha256=invocation["bundle"]["sha256"],
        acquisition_receipt_sha256=summary["acquisition_receipt"]["sha256"],
        producer_sha=expected["producer_sha"],
        source_sha=expected["source_sha"],
        run_id=expected["run_id"],
        run_attempt=expected["run_attempt"],
        manifest_digest=receipt["layout"]["manifest_digest"],
        config_digest=receipt["layout"]["config_digest"],
        upstream_signature="blocked",
        **FLAGS,
    )


def _inspect(*args, **kwargs):
    return _libraries()[1].inspect_image(*args, **kwargs)


def scan_child(config_path, expected_hash):
    require(
        set(os.environ) <= {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"},
        "scan child inherited unauthorized environment",
    )
    config = _checked_document({"path": str(config_path), "sha256": expected_hash})
    _fields(config, "invocation work summary")
    work = _absolute(config["work"])
    require(
        config_path == work / "scan-input.json", "fixed scan configuration required"
    )
    invocation = config["invocation"]
    expected, bundle, _ = _preflight(invocation, work)
    receipt = _receipt(invocation, expected, work, config["summary"])
    local = _libraries()[1].local_oci_scan
    layout = receipt["layout"]
    db = bundle["db"]
    value = local.LocalOCIInput(
        layout=work / "acquisition/layout",
        manifest_digest=layout["manifest_digest"],
        config_digest=layout["config_digest"],
        diff_ids=tuple(layout["diff_ids"]),
        **bundle["tools"],
        runtime_files=bundle["runtime"],
        db_cache=bundle["root"] / "db",
        db_sha256=bundle["installed"].sha256,
        db_size=db["installed"]["size_bytes"],
        import_sha256=bundle["imported"].sha256,
        preparation_receipt=bundle["prepared"],
        db_archive_sha256=db["archive"]["sha256"],
        scratch=work / "scratch",
        handoff_receipt=local.TrustedFile(
            work / "acquisition/acquisition-receipt.json",
            config["summary"]["acquisition_receipt"]["sha256"],
        ),
        private_binding=local.PrivateBinding(
            config["summary"]["acquisition_receipt"]["sha256"],
            expected["repository"],
            int(expected["run_id"]),
            int(expected["run_attempt"]),
            invocation["acquisition"]["facts"]["policy_sha256"],
        ),
    )
    manifest = _inspect(
        invocation["logical_image"],
        work / "reports",
        expected["source_sha"],
        Path(invocation["policy"]["path"]),
        expected_syft_version="1.34.2",
        expected_grype_version="0.101.1",
        expected_policy_sha256=POLICY_SHA256,
        local_input=value,
        **SCOPE,
    )
    evidence = _document(_read(manifest))
    security = evidence["security"]
    require(
        evidence["image"] == invocation["logical_image"]
        and evidence["digest"] == layout["manifest_digest"][7:]
        and evidence["source_sha"] == expected["source_sha"]
        and evidence["policy_sha256"] == POLICY_SHA256
        and security["gate"] == "success"
        and security["decision"] == "clean"
        and security["scope"] == SCOPE
        and security["policy_sha256"] == POLICY_SHA256
        and security["applied_exceptions"] == []
        and security["exception_summary"] == [],
        "vulnerability gate did not pass reviewed empty-exception policy",
    )
    native = evidence["local_input"]
    require(
        native["private_binding"] == value.private_binding._asdict()
        and native["manifest_digest"] == value.manifest_digest
        and native["config_digest"] == value.config_digest
        and native["diff_ids"] == list(value.diff_ids),
        "native input binding mismatch",
    )
    database = native["database"]
    require(
        all(
            database[key] == expected_value
            for key, expected_value in {
                "installed_sha256": value.db_sha256,
                "installed_size_bytes": value.db_size,
                "import_metadata_sha256": value.import_sha256,
                "archive_sha256": value.db_archive_sha256,
                "preparation_receipt_sha256": value.preparation_receipt.sha256,
            }.items()
        ),
        "native database identity mismatch",
    )
    status = local.check_db_status(database["status"], datetime.now(UTC))
    require(
        status["schemaVersion"] == db["schemaVersion"]
        and status["built"] == db["built"],
        "native DB status differs from preparation",
    )
    _bundle(invocation["bundle"])
    return _result(invocation, expected, config["summary"], receipt)


@contextmanager
def _workspace(work):
    oci = _libraries()[0].oci
    with oci.directory(work.parent) as parent:
        info = os.fstat(parent)
        require(
            info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022,
            "owned protected work parent required",
        )
        os.mkdir(work.name, mode=0o700, dir_fd=parent)
        with oci.subdirectory(parent, work.name) as descriptor:
            identity = os.fstat(descriptor)
            require(
                identity.st_uid == os.geteuid() and identity.st_mode & 0o777 == 0o700,
                "owned private workspace required",
            )
            try:
                yield
            finally:
                current = os.stat(work.name, dir_fd=parent, follow_symlinks=False)
                require(
                    (current.st_dev, current.st_ino, current.st_uid)
                    == (identity.st_dev, identity.st_ino, identity.st_uid)
                    and stat.S_ISDIR(current.st_mode),
                    "cleanup refused changed workspace",
                )
                require(
                    shutil.rmtree.avoids_symlink_attacks,
                    "descriptor-safe cleanup required",
                )
                shutil.rmtree(work.name, dir_fd=parent)


def supervise(path, expected_hash, work):
    require(
        os.environ.get("SECURITY_FINDINGS_BYPASS", "false") == "false",
        "bypass forbidden",
    )
    invocation = _checked_document({"path": str(path), "sha256": expected_hash})
    work = _absolute(work)
    _separate(work, _absolute(path))
    expected, bundle, reserve = _preflight(invocation, work)
    require(not work.exists() and not work.is_symlink(), "fresh workspace required")
    require(
        shutil.disk_usage(work.parent).free
        >= int(invocation["acquisition"]["facts"]["archive_size"])
        + invocation["layout_max_bytes"]
        + reserve,
        "insufficient caller workspace capacity",
    )
    secrets = {
        name: os.environ.get(name, "")
        for name in ("GH_TOKEN", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY")
    }
    require(all(secrets.values()), "acquisition credentials required")

    def interrupted(signum, frame):
        raise InterruptedError("private acquisition/scan interrupted")

    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    previous_umask = os.umask(0o077)
    try:
        for sig in handlers:
            signal.signal(sig, interrupted)
        with _workspace(work):
            for name in ("auth-home", "scan-home", "scratch", "reports"):
                (work / name).mkdir(mode=0o700)

            def check():
                require(
                    _tree_bytes(bundle["root"]) + _tree_bytes(work) + reserve
                    <= TOTAL_LIMIT,
                    "whole caller budget exceeded",
                )
                require(
                    shutil.disk_usage(work).free >= reserve,
                    "caller free-space reserve exhausted",
                )
                layout = work / "acquisition/layout"
                if layout.exists():
                    require(
                        _tree_bytes(layout) <= invocation["layout_max_bytes"],
                        "layout admission exceeded",
                    )

            trusted = Path(invocation["trusted_root"])
            _verify_tooling(trusted, expected["producer_sha"], work, check)
            request = invocation["acquisition"]
            env = (
                _environment(work / "auth-home")
                | secrets
                | {
                    "CORE_HANDOFF_POLICY": json.dumps(request["policy"]),
                    "CORE_HANDOFF_CONTEXT": json.dumps(request["context"]),
                    "CORE_HANDOFF_FACTS": json.dumps(request["facts"]),
                }
            )
            summary = _document(
                _execute(
                    [
                        PYTHON,
                        "-I",
                        "-B",
                        "-X",
                        "pycache_prefix="
                        + str(
                            trusted / ".github/scripts/workflow/private_core_scan.py"
                        ),
                        str(
                            trusted
                            / ".github/scripts/workflow/core_build_acquisition.py"
                        ),
                        "acquire",
                        "--output",
                        str(work / "acquisition"),
                    ],
                    env=env,
                    work=work,
                    seconds=1200,
                    check=check,
                )
            )
            check()
            receipt = _receipt(invocation, expected, work, summary)
            shutil.rmtree(work / "auth-home")
            config = work / "scan-input.json"
            config_hash = _write(
                config,
                {"invocation": invocation, "work": str(work), "summary": summary},
            )
            raw = _execute(
                [
                    PYTHON,
                    "-I",
                    "-B",
                    "-X",
                    "pycache_prefix="
                    + str(trusted / ".github/scripts/workflow/private_core_scan.py"),
                    str(trusted / ".github/scripts/workflow/private_core_scan.py"),
                    "--scan-child",
                    str(config),
                    "--expected-config-sha256",
                    config_hash,
                ],
                env=_environment(work / "scan-home"),
                work=work,
                seconds=1800,
                check=check,
            )
            check()
            _bundle(invocation["bundle"])
            check()
            result = _document(raw)
            require(
                result == _result(invocation, expected, summary, receipt)
                and all(result[k] is False for k in FLAGS),
                "scan child result substitution",
            )
        return result
    finally:
        os.umask(previous_umask)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--invocation", type=Path)
    parser.add_argument("--expected-invocation-sha256")
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--scan-child", type=Path)
    parser.add_argument("--expected-config-sha256")
    args = parser.parse_args(argv)
    try:
        if args.scan_child:
            require(
                not any(
                    (args.invocation, args.expected_invocation_sha256, args.work_root)
                ),
                "invalid internal child invocation",
            )
            result = scan_child(args.scan_child, args.expected_config_sha256)
        else:
            require(
                args.invocation is not None
                and args.work_root is not None
                and args.expected_config_sha256 is None,
                "independent invocation and workspace required",
            )
            result = supervise(
                args.invocation, args.expected_invocation_sha256, args.work_root
            )
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        RuntimeError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ):
        print("Private core scan rejected; details withheld", file=sys.stderr)
        return 1


if __name__ == "__main__":
    require(sys.flags.isolated, "trusted isolated Python bootstrap required")
    raise SystemExit(main())
