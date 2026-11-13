"""Local execution boundary; callers must authenticate tools and handoff receipts.

Hashes bind bytes, not authority. Inputs must live in caller-controlled storage
without concurrent writers. Resource polling is not a filesystem quota.
"""

import base64
import hashlib
import importlib.util
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

_spec = importlib.util.spec_from_file_location(
    "local_scan_oci", Path(__file__).with_name("oci_layout.py")
)
oci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oci)
require = oci.require
OUTPUT_LIMIT = 4 * 1024**2
FILE_LIMIT = 64 * 1024**2
WORK_LIMIT = 128 * 1024**2
TOTAL_LIMIT = 4 * 1024**3
WALL_SECONDS = 240
VERSIONS = {"syft": "1.34.2", "grype": "0.101.1"}
REPORT_NAMES = ("sbom.spdx.json", "vulnerabilities.json")
MANAGED_OUTPUTS = ("scan-evidence.json", "provenance.json", *REPORT_NAMES)
GRYPE_CONFIG = """check-for-app-update: false
external-sources:
  enable: false
ignore: []
exclude: []
vex-documents: []
db:
  cache-dir: /db
  auto-update: false
  require-update-check: false
  validate-by-hash-on-start: true
  validate-age: true
  max-allowed-built-age: 120h
"""
SYFT_CONFIG = """check-for-app-update: false
scope: squashed
parallelism: 2
java:
  use-network: false
  use-maven-local-repository: false
  resolve-transitive-dependencies: false
javascript:
  search-remote-licenses: false
golang:
  search-remote-licenses: false
  search-local-mod-cache-licenses: false
  search-local-vendor-licenses: false
file:
  metadata:
    selection: owned-by-package
    digests: [sha256]
relationships:
  package-file-ownership: true
  package-file-ownership-overlap: true
"""


class TrustedFile(NamedTuple):
    path: Path
    sha256: str


class PrivateBinding(NamedTuple):
    receipt_sha256: str
    producer_repository: str
    producer_run_id: int
    producer_run_attempt: int
    handoff_policy_sha256: str


class RuntimeFile(NamedTuple):
    source: TrustedFile
    destination: str


class LocalOCIInput(NamedTuple):
    layout: Path
    manifest_digest: str
    config_digest: str
    diff_ids: tuple[str, ...]
    syft: TrustedFile
    grype: TrustedFile
    bwrap: TrustedFile
    prlimit: TrustedFile
    runtime_files: tuple[RuntimeFile, ...]
    db_cache: Path
    db_sha256: str
    db_size: int
    import_sha256: str
    preparation_receipt: TrustedFile
    db_archive_sha256: str
    scratch: Path
    private_binding: PrivateBinding
    handoff_receipt: TrustedFile


def sha256(path: Path) -> str:
    with oci.directory(path.parent) as parent:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(info.st_mode) and info.st_size <= TOTAL_LIMIT,
                "invalid scan input file",
            )
            checksum = hashlib.sha256()
            total = 0
            deadline = time.monotonic() + WALL_SECONDS
            while chunk := stream.read(1024**2):
                total += len(chunk)
                require(
                    total <= info.st_size and time.monotonic() <= deadline,
                    "scan input hash limit exceeded",
                )
                checksum.update(chunk)
            require(total == info.st_size, "scan input truncated")
            result = checksum.hexdigest()
            after = os.fstat(stream.fileno())
            require(
                all(
                    getattr(info, key) == getattr(after, key)
                    for key in (
                        "st_dev",
                        "st_ino",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    )
                ),
                "scan input changed while hashing",
            )
            return result


def private_directory(path: Path):
    require(path.is_absolute(), "private directory must be absolute")
    with oci.directory(path) as fd:
        info = os.fstat(fd)
        require(
            info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "scan directory must be owned and mode 0700",
        )


def file_state(path: Path):
    digest = sha256(path)
    info = path.stat(follow_symlinks=False)
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        digest,
    )


def tree_state(path: Path):
    result = {}
    total = 0
    deadline = time.monotonic() + WALL_SECONDS
    with oci.directory(path):
        for count, entry in enumerate(path.rglob("*")):
            require(
                count < 4096 and time.monotonic() <= deadline,
                "scan input tree limit exceeded",
            )
            info = entry.lstat()
            require(
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                "unsafe scan tree entry",
            )
            if stat.S_ISREG(info.st_mode):
                total += max(info.st_size, info.st_blocks * 512)
                require(total <= TOTAL_LIMIT, "scan input tree byte limit exceeded")
                result[str(entry.relative_to(path))] = file_state(entry)
    return result


def charged(path: Path):
    total = 0
    for count, entry in enumerate(path.rglob("*")):
        require(count < 4096, "scan file count limit exceeded")
        info = entry.lstat()
        require(
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
            "unsafe writable scan entry",
        )
        if stat.S_ISREG(info.st_mode):
            total += max(info.st_size, info.st_blocks * 512)
    return total


def execute(argv: list[str], work: Path) -> bytes:
    """Execute only a constructed sandbox argv; always check bounds after exit."""
    out, err = work / "stdout", work / "stderr"
    started = time.monotonic()
    process = None
    try:
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env={"LANG": "C", "LC_ALL": "C"},
                cwd=work,
                close_fds=True,
                start_new_session=True,
            )

            def check():
                require(
                    time.monotonic() - started <= WALL_SECONDS,
                    "local scan deadline exceeded",
                )
                require(
                    out.stat().st_size + err.stat().st_size <= OUTPUT_LIMIT,
                    "local scan output limit exceeded",
                )
                require(charged(work) <= WORK_LIMIT, "local scan disk limit exceeded")
                require(
                    shutil.disk_usage(work).free >= FILE_LIMIT,
                    "insufficient scan scratch space",
                )

            while process.poll() is None:
                check()
                time.sleep(0.02)
            check()
            require(process.wait(timeout=5) == 0, "local sandbox command failed")
        with out.open("rb") as stream:
            raw = stream.read(OUTPUT_LIMIT + 1)
        require(len(raw) <= OUTPUT_LIMIT, "local scan output grew after exit")
        return raw
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        out.unlink(missing_ok=True)
        err.unlink(missing_ok=True)


def sandbox(value: LocalOCIInput, work: Path, command: list[str]):
    argv = [
        str(value.prlimit.path),
        "--as=3221225472:3221225472",
        f"--fsize={FILE_LIMIT}:{FILE_LIMIT}",
        "--cpu=240:245",
        "--nofile=256:256",
        "--core=0:0",
        "--",
        str(value.bwrap.path),
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/dev",
        "--dir",
        "/etc",
    ]
    for key, val in {
        "PATH": "/tools",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/scratch/home",
        "TMPDIR": "/scratch/tmp",
        "XDG_CACHE_HOME": "/scratch/cache",
        "XDG_CONFIG_HOME": "/scratch/home",
        "GOMEMLIMIT": "768MiB",
        "GOMAXPROCS": "2",
    }.items():
        argv += ["--setenv", key, val]
    for tool, target in ((value.syft, "/tools/syft"), (value.grype, "/tools/grype")):
        argv += ["--ro-bind", str(tool.path), target]
    for runtime in value.runtime_files:
        argv += ["--ro-bind", str(runtime.source.path), runtime.destination]
    for path, target in (
        (value.layout, "/layout"),
        (value.db_cache, "/db"),
        (work / "config", "/config"),
    ):
        argv += ["--ro-bind", str(path), target]
    argv += [
        "--bind",
        str(work / "scratch"),
        "/scratch",
        "--bind",
        str(work / "scratch/tmp"),
        "/tmp",
        "--bind",
        str(work / "reports"),
        "/reports",
        "--remount-ro",
        "/",
        "--chdir",
        "/scratch",
        "--",
        *command,
    ]
    return argv


def check_db_status(value, now: datetime):
    require(
        now.tzinfo is not None and now.utcoffset().total_seconds() == 0,
        "UTC scan clock required",
    )
    require(
        isinstance(value, dict)
        and value.get("valid") is True
        and not value.get("error"),
        "invalid native DB status",
    )
    require(
        isinstance(value.get("schemaVersion"), str)
        and re.fullmatch(r"v6\.\d+\.\d+", value["schemaVersion"]),
        "DB model 6 required",
    )
    stamp = value.get("built")
    require(
        isinstance(stamp, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", stamp),
        "DB build timestamp requires explicit UTC Z",
    )
    age = (now - datetime.fromisoformat(stamp)).total_seconds()
    require(-300 <= age <= 432000, "DB freshness outside allowed bounds")
    require(value.get("path") == "/db/6/vulnerability.db", "DB cache path mismatch")
    return {key: value[key] for key in ("valid", "built", "schemaVersion", "path")}


def check_reports(value: LocalOCIInput, sbom, scan, now: datetime):
    require(
        isinstance(sbom, dict) and isinstance(scan, dict), "invalid scanner documents"
    )
    require(sbom.get("SPDXID") == "SPDXRef-DOCUMENT", "invalid SPDX document identity")
    roots = {
        r.get("relatedSpdxElement")
        for r in sbom.get("relationships", [])
        if isinstance(r, dict)
        and r.get("spdxElementId") == sbom.get("SPDXID")
        and r.get("relationshipType") == "DESCRIBES"
    }
    packages = [
        p
        for p in sbom.get("packages", [])
        if isinstance(p, dict) and p.get("SPDXID") in roots
    ]
    require(
        len(roots) == len(packages) == 1
        and {
            c.get("checksumValue")
            for c in packages[0].get("checksums", [])
            if isinstance(c, dict) and c.get("algorithm") == "SHA256"
        }
        == {value.manifest_digest[7:]},
        "SPDX root manifest checksum mismatch",
    )
    source = scan.get("source", {})
    require(source.get("type") == "image", "native image source required")
    target = source.get("target", {})
    require(
        target.get("manifestDigest") == value.manifest_digest
        and target.get("imageID") == value.config_digest,
        "Grype manifest/config identity mismatch",
    )
    require(
        [v.get("digest") for v in target.get("layers", [])] == list(value.diff_ids),
        "Grype ordered DiffID mismatch",
    )
    documents = {}
    for key, digest in (
        ("manifest", value.manifest_digest),
        ("config", value.config_digest),
    ):
        raw = base64.b64decode(target[key], validate=True)
        documents[key] = oci.metadata_document(raw, digest)
    config, manifest = documents["config"], documents["manifest"]
    oci.platform(config)
    require(
        config.get("rootfs", {}).get("diff_ids") == list(value.diff_ids),
        "raw config DiffID mismatch",
    )
    require(
        manifest.get("config", {}).get("digest") == value.config_digest,
        "raw manifest config mismatch",
    )
    for key, wanted in (("architecture", "amd64"), ("os", "linux")):
        require(target.get(key) in ("", wanted), "conflicting Grype platform")
    return check_db_status(scan["descriptor"]["db"]["status"], now)


def _trusted_files(value: LocalOCIInput):
    return (
        value.syft,
        value.grype,
        value.bwrap,
        value.prlimit,
        value.preparation_receipt,
        value.handoff_receipt,
        *(v.source for v in value.runtime_files),
    )


def validate_output_relationships(
    value: LocalOCIInput, output: Path, *, exceptions: Path | None = None
):
    """Reject aliases/overlaps without deleting or modifying any supplied path."""
    private_directory(output)
    roots = [value.layout, value.db_cache, output, value.scratch]
    for root in roots:
        require(root.is_absolute() and root != Path("/"), "absolute scan path required")
        oci.safe_path(root)
    roots = [path.resolve() for path in roots]
    for i, first in enumerate(roots):
        for second in roots[i + 1 :]:
            require(
                first != second
                and first not in second.parents
                and second not in first.parents,
                "scan directories must not overlap",
            )
    inputs = [v.path for v in _trusted_files(value)]
    if exceptions is not None:
        inputs.append(exceptions)
    for path in inputs:
        require(path.is_absolute(), "absolute scan input path required")
        oci.safe_path(path)
        resolved = path.resolve()
        for writable in (output.resolve(), value.scratch.resolve()):
            require(
                resolved != writable
                and writable not in resolved.parents
                and resolved not in writable.parents,
                "scan input overlaps writable output/scratch",
            )


def _cleanup_managed(output: Path):
    failures = []
    for name in MANAGED_OUTPUTS:
        try:
            (output / name).unlink(missing_ok=True)
        except OSError as error:
            failures.append(error)
    if failures:
        error = OSError("managed scan output cleanup failed")
        for failure in failures:
            error.add_note(str(failure))
        raise error from failures[0]


def _cleanup_failure(output: Path, original: BaseException):
    try:
        _cleanup_managed(output)
    except OSError as error:
        original.add_note(
            f"managed output cleanup failed: {error}; {getattr(error, '__notes__', ())}"
        )


def _publish_reports(output: Path, reports: list[bytes]):
    with tempfile.TemporaryDirectory(
        prefix=".local-oci-reports-", dir=output
    ) as temporary:
        staged = Path(temporary)
        for name, raw in zip(REPORT_NAMES, reports, strict=True):
            descriptor = os.open(
                staged / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
        for name in REPORT_NAMES:
            os.replace(staged / name, output / name)


def _validate(value: LocalOCIInput):
    private_directory(value.scratch)
    binding = value.private_binding
    for digest in (
        binding.receipt_sha256,
        binding.handoff_policy_sha256,
        value.db_sha256,
        value.import_sha256,
        value.db_archive_sha256,
    ):
        require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "invalid private binding hash",
        )
    require(
        len(binding.producer_repository) <= 256
        and re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", binding.producer_repository
        ),
        "invalid producer repository",
    )
    require(
        type(binding.producer_run_id) is int
        and binding.producer_run_id > 0
        and type(binding.producer_run_attempt) is int
        and binding.producer_run_attempt > 0,
        "invalid producer run/attempt",
    )
    trusted = _trusted_files(value)
    require(
        value.handoff_receipt.sha256 == binding.receipt_sha256,
        "handoff receipt identity mismatch",
    )
    for item in trusted:
        require(
            item.path.is_absolute() and sha256(item.path) == item.sha256,
            "trusted file identity mismatch",
        )
    require(len(value.runtime_files) <= 32, "too many runtime files")
    destinations = set()
    for runtime in value.runtime_files:
        require(
            re.fullmatch(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_+./-]+", runtime.destination)
            and ".." not in Path(runtime.destination).parts
            and runtime.destination not in destinations,
            "runtime binds must be explicit unique system library files",
        )
        destinations.add(runtime.destination)
    for tool in (value.syft, value.grype, value.bwrap, value.prlimit):
        require(os.access(tool.path, os.X_OK), "trusted tool is not executable")
    before = (
        tree_state(value.layout),
        tree_state(value.db_cache),
        {str(v.path): file_state(v.path) for v in trusted},
    )
    oci.expected_digest(value.config_digest)
    with oci.directory(value.layout) as root:
        verified = oci.verify_diff_ids(root, "core", value.manifest_digest)
        require(tuple(verified) == value.diff_ids, "expected verified DiffID mismatch")
        index = oci.document(oci.contents(root, "index.json", oci.MAX_JSON_BYTES))
        manifest = oci.blob(root, index["manifests"][0], {oci.MANIFEST}, json_blob=True)
        require(
            manifest["config"]["digest"] == value.config_digest,
            "layout config mismatch",
        )
    db = value.db_cache / "6/vulnerability.db"
    require(
        type(value.db_size) is int
        and value.db_size > 0
        and db.stat().st_size == value.db_size
        and sha256(db) == value.db_sha256,
        "installed DB identity mismatch",
    )
    require(
        sha256(value.db_cache / "6/import.json") == value.import_sha256,
        "DB import metadata mismatch",
    )
    return trusted, before


def scan(value: LocalOCIInput, output: Path, *, now: datetime | None = None) -> dict:
    """Scan a caller-authenticated local handoff; never acquire or import inputs."""
    validate_output_relationships(value, output)
    try:
        _cleanup_managed(output)
        return _scan(value, output, now=now)
    except BaseException as error:
        _cleanup_failure(output, error)
        raise


def _scan(value: LocalOCIInput, output: Path, *, now: datetime | None = None) -> dict:
    clock = lambda: datetime.now(UTC) if now is None else now
    trusted, before = _validate(value)
    input_bytes = (
        charged(value.layout)
        + charged(value.db_cache)
        + sum(v.path.stat().st_size for v in trusted)
    )
    require(
        input_bytes
        + charged(value.scratch)
        + charged(output)
        + 2 * WORK_LIMIT
        + FILE_LIMIT
        <= TOTAL_LIMIT,
        "local scan total disk budget exceeded",
    )
    require(
        shutil.disk_usage(value.scratch).free >= WORK_LIMIT,
        "insufficient private scratch space",
    )
    with tempfile.TemporaryDirectory(
        prefix="local-oci-scan-", dir=value.scratch
    ) as temporary:
        work = Path(temporary)
        for name in (
            "config",
            "scratch",
            "scratch/tmp",
            "scratch/home",
            "scratch/cache",
            "reports",
        ):
            (work / name).mkdir(mode=0o700)
        (work / "config/syft.yaml").write_text(SYFT_CONFIG)
        (work / "config/grype.yaml").write_text(GRYPE_CONFIG)
        versions = {}
        for name, expected in VERSIONS.items():
            raw = execute(sandbox(value, work, ["/tools/" + name, "version"]), work)
            require(len(raw) <= 4096, "local scanner version output limit exceeded")
            raw = raw.decode()
            require(
                re.search(r"(?m)^Version:\s*" + re.escape(expected) + r"\s*$", raw)
                is not None,
                "unexpected local scanner version",
            )
            versions[name] = raw.strip()
        command = [
            "/tools/grype",
            "-c",
            "/config/grype.yaml",
            "db",
            "status",
            "-o",
            "json",
        ]
        pre = check_db_status(
            oci.document(execute(sandbox(value, work, command), work)), clock()
        )
        for name, fmt, filename in (
            ("syft", "spdx-json", "sbom.spdx.json"),
            ("grype", "json", "vulnerabilities.json"),
        ):
            execute(
                sandbox(
                    value,
                    work,
                    [
                        "/tools/" + name,
                        "-c",
                        "/config/" + name + ".yaml",
                        "oci-dir:/layout",
                        "-o",
                        fmt,
                        "--file",
                        "/reports/" + filename,
                    ],
                ),
                work,
            )
        reports = []
        raw_reports = []
        for name in ("sbom.spdx.json", "vulnerabilities.json"):
            with oci.directory(work / "reports") as fd:
                raw = oci.contents(fd, name, FILE_LIMIT)
                raw_reports.append(raw)
                reports.append(oci.document(raw))
        reported = check_reports(value, *reports, clock())
        post = check_db_status(
            oci.document(execute(sandbox(value, work, command), work)), clock()
        )
        require(pre == reported == post, "native DB metadata changed")
        after = (
            tree_state(value.layout),
            tree_state(value.db_cache),
            {str(v.path): file_state(v.path) for v in trusted},
        )
        require(before == after, "local scan input mutated")
        require(charged(work) <= WORK_LIMIT, "local scan disk budget exceeded")
        check_db_status(post, clock())
        _publish_reports(output, raw_reports)
    evaluated_at = clock()
    check_db_status(post, evaluated_at)
    return {
        "tools": versions,
        "private_binding": value.private_binding._asdict(),
        "manifest_digest": value.manifest_digest,
        "config_digest": value.config_digest,
        "diff_ids": list(value.diff_ids),
        "database": {
            "installed_sha256": value.db_sha256,
            "installed_size_bytes": value.db_size,
            "import_metadata_sha256": value.import_sha256,
            "archive_sha256": value.db_archive_sha256,
            "preparation_receipt_sha256": value.preparation_receipt.sha256,
            "status": post,
            "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        },
    }
