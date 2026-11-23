"""Acquire legacy consistency evidence or an independently pinned private handoff.

The default transport requires a trusted gh executable, credential configuration
and TLS roots. Credential forwarding on legacy asset redirects is delegated to
that trusted CLI. Private base metadata uses a separate anonymous transport.
Injected transports are test seams, not authenticated-observation attestations.
The caller selects a parent whose contents are controlled by the current user or
a trusted administrator. Its descriptor must be effective-user- or root-owned,
without group/other write. mkdir/open is not atomic: adoption relies on that
trusted-parent assumption, excluding hostile same-UID or privileged actors.
Ancestors may be renamed: all writes remain anchored to retained descriptors.
Failures retain private partials for caller-directed inspection, never deletion.
"""

import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import zipfile
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import NamedTuple
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location(
    "acquisition_binding", Path(__file__).with_name("core_build_binding.py")
)
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
pipeline, oci, require = binding.pipeline, binding.oci, binding.require
BASE = "repos/luminusOS/images/actions/"
MAX_LOG, MAX_JSON = 8 * 1024**2, 4 * 1024**2
MAX_ZIP, MAX_EXPANDED, DISK_BUDGET = 2 * 1024**3, 6 * 1024**3, 8 * 1024**3
MAX_MEMBERS, RESERVE = 10000, 128 * 1024**2


class Policy(NamedTuple):
    run_id: int
    run_attempt: int
    job_id: int
    source_sha: str
    artifact_id: int
    workflow: str
    job_name: str


class GhTransport:
    def stream(self, endpoint, limit, deadline):
        require(
            re.fullmatch(
                re.escape(BASE)
                + r"(?:runs/[1-9][0-9]*(?:/attempts/[1-9][0-9]*/jobs\?per_page=100&page=[1-9][0-9]*)?|artifacts/[1-9][0-9]*(?:/zip)?|jobs/[1-9][0-9]*/steps/[1-9][0-9]*/logs)",
                endpoint,
            ),
            "invalid fixed GitHub endpoint",
        )
        env = {
            key: value
            for key, value in os.environ.items()
            if key
            in (
                "PATH",
                "HOME",
                "XDG_CONFIG_HOME",
                "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_CONFIG_DIR",
                "LANG",
                "LC_ALL",
            )
        }
        env["GH_PROMPT_DISABLED"] = "1"
        process = subprocess.Popen(
            [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "--allow-escape-sequences",
                endpoint,
            ],
            env=env,
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        count, errors = 0, 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("GitHub acquisition deadline exceeded")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 1024**2)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif key.fileobj is process.stdout:
                            count += len(chunk)
                            require(
                                count <= limit, "GitHub response byte limit exceeded"
                            )
                            yield chunk
                        else:
                            errors += len(chunk)
                            require(errors <= 65536, "GitHub stderr limit exceeded")
                try:
                    status = process.wait(
                        timeout=max(0.001, deadline - time.monotonic())
                    )
                except subprocess.TimeoutExpired:
                    raise TimeoutError("GitHub acquisition deadline exceeded") from None
                require(status == 0, "GitHub request failed; response bodies withheld")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()


def receive(transport, endpoint, limit, deadline, sink=None):
    checksum, chunks, size = hashlib.sha256(), [], 0
    stream = transport.stream(BASE + endpoint, limit, deadline)
    try:
        for chunk in stream:
            require(time.monotonic() < deadline, "acquisition deadline exceeded")
            require(type(chunk) is bytes, "transport must yield raw bytes")
            size += len(chunk)
            require(size <= limit, "response byte limit exceeded")
            checksum.update(chunk)
            if sink is None:
                chunks.append(chunk)
            else:
                sink.write(chunk)
    finally:
        stream.close()
    return b"".join(chunks), {"raw_bytes": size, "raw_sha256": checksum.hexdigest()}


def snapshot(policy, transport, deadline):
    def api(endpoint):
        return oci.document(
            receive(
                transport, endpoint, MAX_JSON, min(deadline, time.monotonic() + 60)
            )[0]
        )

    run = api(f"runs/{policy.run_id}")
    binding.equal_fields(
        run,
        id=policy.run_id,
        run_attempt=policy.run_attempt,
        head_sha=policy.source_sha,
        path=policy.workflow,
        status="completed",
        conclusion="success",
    )
    require(
        run.get("event")
        in ("pull_request", "push", "workflow_dispatch", "schedule", "workflow_call"),
        "invalid run event",
    )
    for name in ("repository", "head_repository"):
        binding.equal_fields(
            run.get(name, {}), id=1118572971, full_name="luminusOS/images"
        )
    require(isinstance(run.get("head_branch"), str), "missing run branch")
    jobs, total, page = [], None, 1
    while total is None or len(jobs) < total:
        data = api(
            f"runs/{policy.run_id}/attempts/{policy.run_attempt}/jobs?per_page=100&page={page}"
        )
        count = binding.positive(data.get("total_count"))
        require(
            count <= 100000 and (total is None or total == count),
            "inconsistent jobs pagination",
        )
        total = count
        batch = data.get("jobs")
        require(
            isinstance(batch, list) and len(batch) == min(100, total - len(jobs)),
            "incomplete jobs pagination",
        )
        jobs.extend(batch)
        page += 1
    ids, selected = set(), []
    for job in jobs:
        number = binding.positive(job.get("id"))
        require(number not in ids, "duplicate attempt job")
        ids.add(number)
        binding.equal_fields(
            job,
            run_id=policy.run_id,
            run_attempt=policy.run_attempt,
            head_sha=policy.source_sha,
        )
        if job.get("name") == policy.job_name:
            selected.append(job)
    require(len(selected) == 1, "ambiguous or missing core job")
    job = selected[0]
    binding.equal_fields(
        job, id=policy.job_id, status="completed", conclusion="success"
    )
    steps = job.get("steps")
    require(isinstance(steps, list) and 0 < len(steps) <= 1000, "invalid job steps")
    numbers = [binding.positive(step.get("number")) for step in steps]
    require(numbers == sorted(set(numbers)), "unordered or duplicate steps")
    protected = [step for step in steps if step.get("name") in binding.STEPS]
    require(
        tuple(step["name"] for step in protected) == binding.STEPS,
        "missing or duplicate protected step",
    )
    end = 0
    for step in protected:
        binding.equal_fields(step, status="completed", conclusion="success")
        start, completed = (
            binding.timestamp(step.get("started_at")),
            binding.timestamp(step.get("completed_at")),
        )
        require(end <= start <= completed, "invalid protected step window")
        end = completed
    artifact = api(f"artifacts/{policy.artifact_id}")
    binding.equal_fields(
        artifact, id=policy.artifact_id, name="core-oci", expired=False
    )
    size = binding.positive(artifact.get("size_in_bytes"))
    require(
        size <= MAX_ZIP and size + RESERVE < DISK_BUDGET, "artifact exceeds disk budget"
    )
    pipeline.matches(artifact.get("digest"), pipeline.DIGEST, "artifact digest")
    require(
        binding.timestamp(artifact.get("expires_at")) > time.time_ns(),
        "artifact expired",
    )
    binding.equal_fields(
        artifact.get("workflow_run", {}),
        id=policy.run_id,
        repository_id=1118572971,
        head_repository_id=1118572971,
        head_sha=policy.source_sha,
        head_branch=run["head_branch"],
    )
    return run, job, artifact


def log_text(raw, export=False):
    text = raw.removeprefix(b"\xef\xbb\xbf").decode("utf-8", errors="strict")
    if export:
        text = re.sub(
            r"\x1b\[(?:(?:0|1|3[0-7]|9[0-7])(?:;(?:0|1|3[0-7]|9[0-7]))*)m", "", text
        )
    text = text.replace("\r\n", "\n")
    require(
        all(c.isprintable() or c in "\n\t" for c in text),
        "unsupported log controls or BOM",
    )
    return text


def export_identity(text, window):
    grouped, previous, records = False, None, []
    for line in text.splitlines():
        stamp, separator, body = line.partition(" ")
        instant = binding.timestamp(stamp)
        require(
            separator
            and window[0] <= instant < window[1]
            and (previous is None or instant >= previous),
            "invalid export log framing",
        )
        previous = instant
        if body.startswith("##[group]"):
            require(not grouped, "nested export group")
            grouped = True
        elif body == "##[endgroup]":
            require(grouped, "unmatched export group")
            grouped = False
        elif "manifest_digest" in body:
            require(
                not grouped and body.startswith("{") and body.endswith("}"),
                "echoed export record",
            )
            record = oci.document(body.encode())
            binding.record(record, "manifest_digest skopeo_version")
            pipeline.matches(
                record["manifest_digest"], pipeline.DIGEST, "export digest"
            )
            pipeline.matches(
                record["skopeo_version"],
                re.compile(r"skopeo version [A-Za-z0-9.+ -]{1,200}\Z"),
                "skopeo version",
            )
            records.append(record)
    require(not grouped and len(records) == 1, "incomplete or duplicate export record")
    return records[0]


def require_space(root, size):
    usage = os.fstatvfs(root)
    require(usage.f_bavail * usage.f_frsize >= size, "insufficient free disk space")


@contextmanager
def workspace(output):
    with oci.directory(output.parent) as parent:
        info = os.fstat(parent)
        require(
            info.st_uid in (os.geteuid(), 0) and not info.st_mode & 0o022,
            "private owned output parent required before directory adoption",
        )
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        with oci.subdirectory(parent, output.name) as root:
            created = os.fstat(root)
            require(
                created.st_uid == os.geteuid() and created.st_mode & 0o777 == 0o700,
                "private owned output directory required",
            )
            yield root


def zip_preflight(archive, archive_bytes, root):
    entries = archive.infolist()
    size = sum(entry.file_size for entry in entries)
    require(
        len(entries) <= min(MAX_MEMBERS, pipeline.MAX_FILES)
        and size <= MAX_EXPANDED
        and size + archive_bytes + RESERVE <= DISK_BUDGET,
        "ZIP resource budget exceeded",
    )
    seen, files = set(), set()
    for entry in entries:
        name = entry.filename[:-1] if entry.is_dir() else entry.filename
        relative = pipeline.relative(name)
        require(
            len(relative.parts) <= 16 and len(name.encode("utf-8")) <= 1024,
            "ZIP path resource budget exceeded",
        )
        mode = entry.external_attr >> 16
        require(
            name not in seen
            and entry.filename == entry.orig_filename
            and all(c.isprintable() for c in name),
            "duplicate or invalid ZIP path",
        )
        require(
            stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)
            and (not stat.S_IFMT(mode) or stat.S_ISDIR(mode) == entry.is_dir()),
            "special ZIP member",
        )
        require(
            not entry.flag_bits & 1 and entry.compress_type in (0, 8),
            "unsupported ZIP encoding",
        )
        require(not entry.is_dir() or entry.file_size == 0, "nonempty ZIP directory")
        seen.add(name)
        if not entry.is_dir():
            files.add(name)
    require(
        all(
            str(parent) not in files
            for name in seen
            for parent in PurePosixPath(name).parents
        ),
        "ZIP parent collision",
    )
    require_space(root, size + RESERVE)
    return {"members": len(entries), "expanded_bytes": size}


def extract_archive(archive, layout):
    total = 0
    for entry in archive.infolist():
        parts = pipeline.relative(entry.filename.rstrip("/")).parts
        with ExitStack() as stack:
            parent = layout
            for name in parts if entry.is_dir() else parts[:-1]:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                parent = stack.enter_context(oci.subdirectory(parent, name))
            if not entry.is_dir():
                with oci.new_oci_file(parent, parts[-1]) as destination:
                    with archive.open(entry) as source:
                        written = 0
                        while chunk := source.read(pipeline.CHUNK_SIZE):
                            written += len(chunk)
                            total += len(chunk)
                            require(
                                written <= entry.file_size and total <= MAX_EXPANDED,
                                "ZIP expansion exceeds declared resource budget",
                            )
                            destination.write(chunk)
                        require(written == entry.file_size, "ZIP entry size mismatch")
                    destination.flush()
                    os.fsync(destination.fileno())
            else:
                with archive.open(entry) as source:
                    require(source.read(1) == b"", "nonempty ZIP directory")


def acquire(policy: Policy, output: Path, *, transport=None):
    """Return byte-consistency facts; caller pins are not source authorization."""
    require(type(policy) is Policy, "explicit acquisition policy required")
    for field in ("run_id", "run_attempt", "job_id", "artifact_id"):
        binding.positive(getattr(policy, field))
    pipeline.matches(policy.source_sha, pipeline.COMMIT, "source SHA")
    pipeline.matches(
        policy.workflow,
        re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml\Z"),
        "workflow",
    )
    require(
        isinstance(policy.job_name, str) and 0 < len(policy.job_name) <= 512,
        "invalid job name",
    )
    require(
        threading.current_thread() is threading.main_thread()
        and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        "acquisition requires an unoccupied main-thread timer",
    )
    output = oci.safe_path(output)
    resources = ExitStack()
    deadline = time.monotonic() + 1200
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise TimeoutError("total acquisition deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 1200)
    try:
        root = resources.enter_context(workspace(output))
        transport = GhTransport() if transport is None else transport
        before = snapshot(policy, transport, deadline)
        artifact, records, export = before[2], [], None
        for step in before[1]["steps"]:
            if step["name"] not in binding.STEPS[1:]:
                continue
            raw, facts = receive(
                transport,
                f"jobs/{policy.job_id}/steps/{step['number']}/logs",
                MAX_LOG,
                min(deadline, time.monotonic() + 60),
            )
            window = (
                binding.timestamp(step["started_at"])
                // binding.SECOND
                * binding.SECOND,
                (binding.timestamp(step["completed_at"]) // binding.SECOND + 1)
                * binding.SECOND,
            )
            if step["name"] == binding.STEPS[1]:
                export = export_identity(log_text(raw, export=True), window)
            else:
                identity = binding.upload_identity(log_text(raw), window)
                require(
                    identity
                    == (
                        policy.artifact_id,
                        artifact["digest"],
                        artifact["size_in_bytes"],
                    ),
                    "upload metadata mismatch",
                )
            records.append({"number": step["number"], "name": step["name"], **facts})
        require_space(root, artifact["size_in_bytes"] + RESERVE)
        descriptor = os.open(
            "archive.zip.part",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=root,
        )
        with os.fdopen(descriptor, "w+b") as sink:
            _, facts = receive(
                transport,
                f"artifacts/{policy.artifact_id}/zip",
                artifact["size_in_bytes"],
                min(deadline, time.monotonic() + 600),
                sink,
            )
            sink.flush()
            os.fsync(sink.fileno())
            require(
                facts["raw_bytes"] == artifact["size_in_bytes"]
                and os.fstat(sink.fileno()).st_size == artifact["size_in_bytes"]
                and "sha256:" + facts["raw_sha256"] == artifact["digest"],
                "archive bytes mismatch",
            )
            os.rename(
                "archive.zip.part",
                "archive.verified.zip",
                src_dir_fd=root,
                dst_dir_fd=root,
            )
            require(
                snapshot(policy, transport, deadline) == before,
                "metadata changed during acquisition",
            )
            sink.seek(0)
            with zipfile.ZipFile(sink) as archive:
                inventory = zip_preflight(archive, facts["raw_bytes"], root)
                os.mkdir("layout", mode=0o700, dir_fd=root)
                with oci.subdirectory(root, "layout") as layout:
                    extract_archive(archive, layout)
                    digest, config, layers = oci.checked_image(layout, "core")
        require(
            digest == export["manifest_digest"],
            "stored OCI manifest differs from export",
        )
        return {
            "kind": "local-core-acquisition",
            "production_ready": False,
            "observations_authenticated": False,
            "runtime_verified": False,
            "archive_bytes_verified": True,
            "oci_layout_verified": True,
            "repository": "luminusOS/images",
            "repository_id": 1118572971,
            **policy._asdict(),
            "archive": facts,
            "step_logs": records,
            "zip": inventory,
            "core_digest": digest,
            "layer_count": layers,
            "observed_labels": config.get("config", {}).get("Labels", {}),
            "workspace_identity": {
                "device": os.fstat(root).st_dev,
                "inode": os.fstat(root).st_ino,
            },
            "filesystem_boundary": "Caller-selected parent contents controlled by current user/trusted administrator; current-UID or root ownership, no group/other write; output current-UID-owned and private; descriptor-anchored operations, non-atomic mkdir/open adoption; failed partials retained.",
            "exclusions": [
                "source authorization",
                "base ancestry",
                "checkout execution",
                "decompressed diff IDs",
                "guest/runtime verification",
                "hostile same-UID or privileged filesystem actors",
            ],
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        resources.close()


PRIVATE_ACTIONS = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
)
PRIVATE_ACTIONS_SHA256 = hashlib.sha256(
    ("\n".join(PRIVATE_ACTIONS) + "\n").encode()
).hexdigest()
PRIVATE_WORKFLOW = "luminusOS/images/.github/workflows/private-core-producer.yml"
R2_HOST = "89e6fc75aed6d04cd84a0c7d11a5594e.r2.cloudflarestorage.com"
R2_BUCKET = "luminus-images-staging"
R2_TRANSACTION_SECONDS = 600


def private_policy(approved, context):
    require(
        isinstance(approved, dict) and isinstance(context, dict),
        "operator policy required",
    )
    require(
        set(approved)
        == {
            "repository",
            "repository_id",
            "producer_sha",
            "source_sha",
            "caller_ref",
            "caller_workflow",
            "fedora",
            "base_digest",
            "actions_sha256",
        },
        "missing or unknown operator policy fields",
    )
    for key in ("producer_sha", "source_sha"):
        pipeline.matches(approved[key], pipeline.COMMIT, "approved revision")
    pipeline.matches(approved["base_digest"], pipeline.DIGEST, "approved base")
    pipeline.matches(
        approved["caller_ref"],
        re.compile(r"refs/heads/[A-Za-z0-9_./-]+\Z"),
        "approved caller ref",
    )
    pipeline.matches(
        approved["caller_workflow"],
        re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml\Z"),
        "approved caller workflow",
    )
    require(
        approved["repository"] == context.get("repository") == "luminusOS/images"
        and approved["repository_id"] == context.get("repository_id") == "1118572971"
        and approved["fedora"] == "45"
        and approved["actions_sha256"] == PRIVATE_ACTIONS_SHA256
        and context.get("sha") == approved["source_sha"]
        and context.get("ref") == approved["caller_ref"]
        and context.get("workflow_ref")
        == f"luminusOS/images/{approved['caller_workflow']}@{approved['caller_ref']}"
        and context.get("producer_sha") == approved["producer_sha"]
        and context.get("producer_ref")
        == f"{PRIVATE_WORKFLOW}@{approved['producer_sha']}"
        and context.get("event_name") == "workflow_dispatch"
        and context.get("runner_environment") == "github-hosted",
        "independent operator policy identity mismatch",
    )
    for key in ("run_id", "run_attempt"):
        require(
            isinstance(context.get(key), str)
            and re.fullmatch(r"[1-9][0-9]{0,19}", context[key]),
            "invalid run identity",
        )
    return dict(approved, run_id=context["run_id"], run_attempt=context["run_attempt"])


def private_key(policy):
    return f"core-candidates/1118572971/{policy['run_id']}/{policy['run_attempt']}/{policy['source_sha']}/core-oci.zip"


def private_policy_sha256(policy):
    approved = {
        key: value
        for key, value in policy.items()
        if key not in ("run_id", "run_attempt")
    }
    return hashlib.sha256(
        json.dumps(approved, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def private_facts(policy, facts):
    require(
        isinstance(facts, dict)
        and set(facts)
        == {
            "archive_sha256",
            "archive_size",
            "manifest_digest",
            "object_key",
            "policy_sha256",
        },
        "invalid producer outputs",
    )
    require(
        facts["policy_sha256"] == private_policy_sha256(policy),
        "producer operator policy mismatch",
    )
    pipeline.matches(
        facts["archive_sha256"], re.compile(r"[0-9a-f]{64}\Z"), "archive hash"
    )
    pipeline.matches(facts["manifest_digest"], pipeline.DIGEST, "core manifest")
    require(
        isinstance(facts["archive_size"], str)
        and re.fullmatch(r"[1-9][0-9]{0,10}", facts["archive_size"]),
        "invalid archive size",
    )
    require(
        int(facts["archive_size"]) <= MAX_ZIP
        and facts["object_key"] == private_key(policy),
        "invalid private object identity",
    )
    return facts


def bounded_command(argv):
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "HOME", "LANG", "GH_TOKEN")
    }
    env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1")
    process = subprocess.Popen(
        argv,
        cwd="/",
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    raw, errors = bytearray(), 0
    deadline = time.monotonic() + 180
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "trusted command deadline exceeded")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        raw.extend(chunk)
                        require(
                            len(raw) <= MAX_JSON,
                            "trusted command output limit exceeded",
                        )
                    else:
                        errors += len(chunk)
                        require(errors <= 65536, "trusted command error limit exceeded")
        require(
            process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
            "trusted command failed; output withheld",
        )
        return bytes(raw)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


@contextmanager
def r2_deadline(deadline):
    require(
        threading.current_thread() is threading.main_thread()
        and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        "R2 transaction requires an unoccupied main-thread timer",
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("R2 transaction deadline exceeded")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise TimeoutError("R2 transaction deadline exceeded")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


BASE_METADATA_SECONDS = 60


class FedoraMetadataTransport:
    def get(self, kind, digest, deadline):
        require(kind in ("manifests", "blobs"), "invalid Fedora metadata operation")
        oci.expected_digest(digest)
        host = "quay.io"
        path = f"/v2/fedora/fedora-bootc/{kind}/{digest}"
        try:
            for redirected in (False, True):
                require(
                    time.monotonic() < deadline, "Fedora metadata deadline exceeded"
                )
                connection, response = None, None
                try:
                    connection = http.client.HTTPSConnection(
                        host, timeout=min(15, deadline - time.monotonic())
                    )
                    connection.request(
                        "GET",
                        path,
                        headers={
                            "Accept": f"{oci.INDEX}, {oci.MANIFEST}, {oci.CONFIG}, application/octet-stream",
                            "Accept-Encoding": "identity",
                        },
                    )
                    response = connection.getresponse()
                    if response.status == 302:
                        require(
                            kind == "blobs" and not redirected,
                            "Fedora metadata redirect rejected",
                        )
                        locations = [
                            v
                            for k, v in response.getheaders()
                            if k.lower() == "location"
                        ]
                        require(
                            len(locations) == 1
                            and len(locations[0]) <= 8192
                            and not re.search(r"[\x00-\x20\x7f#]", locations[0]),
                            "Fedora metadata redirect rejected",
                        )
                        target = urlsplit(locations[0])
                        expected_path = (
                            f"/quayio-production-s3/sha256/{digest[7:9]}/{digest[7:]}"
                        )
                        require(
                            target.scheme == "https"
                            and target.netloc in ("cdn01.quay.io", "cdn01.quay.io:443")
                            and target.path == expected_path,
                            "Fedora metadata redirect rejected",
                        )
                        host = "cdn01.quay.io"
                        path = target.path + (
                            "?" + target.query if target.query else ""
                        )
                        continue
                    require(response.status == 200, "Fedora metadata response rejected")
                    headers = response.getheaders()
                    lengths = [v for k, v in headers if k.lower() == "content-length"]
                    transfers = [
                        v for k, v in headers if k.lower() == "transfer-encoding"
                    ]
                    require(
                        not transfers or (transfers == ["chunked"] and not lengths),
                        "ambiguous Fedora metadata framing",
                    )
                    require(
                        len(lengths) <= 1
                        and (not lengths or re.fullmatch(r"[0-9]{1,10}", lengths[0])),
                        "invalid Fedora metadata length",
                    )
                    size = int(lengths[0]) if lengths else None
                    require(
                        size is None or 0 < size <= oci.MAX_JSON_BYTES,
                        "Fedora metadata size limit exceeded",
                    )
                    encodings = [
                        v for k, v in headers if k.lower() == "content-encoding"
                    ]
                    require(
                        not encodings or encodings == ["identity"],
                        "Fedora metadata encoding rejected",
                    )
                    media = [v for k, v in headers if k.lower() == "content-type"]
                    allowed = (
                        {oci.INDEX, oci.MANIFEST}
                        if kind == "manifests"
                        else {oci.CONFIG, "application/octet-stream"}
                    )
                    require(
                        len(media) == 1 and media[0] in allowed,
                        "Fedora metadata content type rejected",
                    )
                    chunks, total = [], 0
                    while True:
                        require(
                            time.monotonic() < deadline,
                            "Fedora metadata deadline exceeded",
                        )
                        chunk = response.read(
                            min(65536, oci.MAX_JSON_BYTES + 1 - total)
                        )
                        if not chunk:
                            break
                        require(type(chunk) is bytes, "invalid Fedora metadata bytes")
                        total += len(chunk)
                        require(
                            total <= oci.MAX_JSON_BYTES,
                            "Fedora metadata size limit exceeded",
                        )
                        chunks.append(chunk)
                    require(
                        total > 0 and (size is None or total == size),
                        "truncated Fedora metadata",
                    )
                    require(
                        time.monotonic() < deadline, "Fedora metadata deadline exceeded"
                    )
                    return b"".join(chunks)
                finally:
                    try:
                        if response is not None:
                            response.close()
                    finally:
                        if connection is not None:
                            connection.close()
        except (OSError, ValueError, http.client.HTTPException):
            raise ValueError(
                "Fedora base metadata request rejected; response details withheld"
            ) from None
        raise ValueError("Fedora metadata redirect rejected")


def load_base_diff_ids(expected, *, transport=None):
    oci.expected_digest(expected)
    transport = FedoraMetadataTransport() if transport is None else transport
    deadline = time.monotonic() + BASE_METADATA_SECONDS
    with r2_deadline(deadline):
        index = transport.get("manifests", expected, deadline)
        manifest_descriptor = oci.base_manifest(index, expected)
        manifest = transport.get("manifests", manifest_descriptor["digest"], deadline)
        config_descriptor, _ = oci.base_manifest_config(manifest, manifest_descriptor)
        config = transport.get("blobs", config_descriptor["digest"], deadline)
        result = oci.base_diff_ids(index, manifest, config, expected)
        require(time.monotonic() < deadline, "Fedora metadata deadline exceeded")
        return result


class R2Transport:
    def request(self, method, key, payload_hash, *, size=0, source=None, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + R2_TRANSACTION_SECONDS
        require(
            re.fullmatch(
                r"core-candidates/1118572971/[1-9][0-9]{0,19}/[1-9][0-9]{0,19}/[0-9a-f]{40}/core-oci\.zip",
                key,
            ),
            "invalid fixed R2 key",
        )
        require(method in ("GET", "PUT"), "invalid R2 operation")
        access, secret = (
            os.environ.get("R2_ACCESS_KEY_ID", ""),
            os.environ.get("R2_SECRET_ACCESS_KEY", ""),
        )
        require(
            re.fullmatch(r"[A-Za-z0-9]{16,128}", access)
            and re.fullmatch(r"[A-Za-z0-9/+_=.-]{16,256}", secret),
            "dedicated R2 credentials required",
        )
        now = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        scope = f"{now[:8]}/auto/s3/aws4_request"
        path = f"/{R2_BUCKET}/{key}"
        headers = {
            "host": R2_HOST,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": now,
        }
        if method == "PUT":
            headers.update({"content-length": str(size), "if-none-match": "*"})
        names = ";".join(sorted(headers))
        canonical = "\n".join(
            (
                method,
                path,
                "",
                "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)),
                names,
                payload_hash,
            )
        )
        signing = ("AWS4" + secret).encode()
        for value in (now[:8], "auto", "s3", "aws4_request"):
            signing = hmac.digest(signing, value.encode(), "sha256")
        signature = hmac.new(
            signing,
            f"AWS4-HMAC-SHA256\n{now}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}".encode(),
            "sha256",
        ).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
        )
        with r2_deadline(deadline):
            connection = http.client.HTTPSConnection(R2_HOST, timeout=30)
            try:
                connection.putrequest(
                    method, path, skip_host=True, skip_accept_encoding=True
                )
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.endheaders()
                if source is not None:
                    sent = 0
                    while chunk := source.read(1024**2):
                        sent += len(chunk)
                        require(
                            sent <= size and time.monotonic() < deadline,
                            "R2 upload budget exceeded",
                        )
                        connection.send(chunk)
                    require(sent == size, "R2 upload size changed")
                response = connection.getresponse()
                require(
                    response.status == 200, "R2 request rejected; response withheld"
                )
                yield response
            finally:
                connection.close()

    def stream(self, key, limit, deadline):
        request = self.request(
            "GET", key, hashlib.sha256(b"").hexdigest(), deadline=deadline
        )
        try:
            response = next(request)
            require(
                response.getheader("Content-Length") == str(limit),
                "R2 content length mismatch",
            )
            size = 0
            while chunk := response.read(1024**2):
                size += len(chunk)
                require(
                    size <= limit and time.monotonic() < deadline,
                    "R2 download budget exceeded",
                )
                yield chunk
            require(size == limit, "truncated R2 object")
        finally:
            request.close()

    def upload(self, key, source, facts):
        request = self.request(
            "PUT",
            key,
            facts["archive_sha256"],
            size=int(facts["archive_size"]),
            source=source,
        )
        try:
            next(request)
        finally:
            request.close()


def private_download(policy, facts, output, *, transport=None, _verified_layout=None):
    private_facts(policy, facts)
    output = oci.safe_path(output)
    transport = R2Transport() if transport is None else transport
    with workspace(output) as root:
        size = int(facts["archive_size"])
        require_space(root, size + RESERVE)
        with oci.new_oci_file(root, "core-oci.zip") as sink:
            checksum, count = hashlib.sha256(), 0
            deadline = time.monotonic() + 600
            stream = transport.stream(private_key(policy), size, deadline)
            try:
                for chunk in stream:
                    require(
                        time.monotonic() < deadline,
                        "private acquisition deadline exceeded",
                    )
                    require(type(chunk) is bytes, "transport must yield bytes")
                    count += len(chunk)
                    require(count <= size, "private archive exceeds size")
                    checksum.update(chunk)
                    sink.write(chunk)
            finally:
                stream.close()
            sink.flush()
            os.fsync(sink.fileno())
        require(
            count == size and checksum.hexdigest() == facts["archive_sha256"],
            "private archive byte mismatch",
        )
        descriptor = os.open("core-oci.zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root)
        with os.fdopen(descriptor, "rb") as source, zipfile.ZipFile(source) as archive:
            zip_preflight(archive, size, root)
            require(
                archive.getinfo("core-handoff-policy.json").file_size <= MAX_JSON,
                "embedded policy exceeds limit",
            )
            require(
                archive.read("core-handoff-policy.json")
                == json.dumps(policy, sort_keys=True, separators=(",", ":")).encode(),
                "archive embedded producer policy mismatch",
            )
            os.mkdir("layout", mode=0o700, dir_fd=root)
            with oci.subdirectory(root, "layout") as layout:
                extract_archive(archive, layout)
                require(
                    oci.checked_image(layout, "core")[0] == facts["manifest_digest"],
                    "private OCI manifest mismatch",
                )
                with r2_deadline(time.monotonic() + oci.DIFFID_TIMEOUT_SECONDS):
                    verified = oci.verify_diff_ids(
                        layout, "core", facts["manifest_digest"]
                    )
                oci.require_base_prefix(
                    load_base_diff_ids(policy["base_digest"]), verified
                )
                if _verified_layout is not None:
                    index = oci.document(oci.contents(layout, "index.json", MAX_JSON))
                    manifest = oci.blob(
                        layout, index["manifests"][0], {oci.MANIFEST}, json_blob=True
                    )
                    _verified_layout.update(
                        path="layout",
                        manifest_digest=facts["manifest_digest"],
                        config_digest=manifest["config"]["digest"],
                        diff_ids=verified,
                        os="linux",
                        architecture="amd64",
                        reference="core",
                    )
        return dict(facts)


class HandoffStageError(ValueError):
    pass


def verify_native(policy, archive, facts, *, command=bounded_command):
    private_facts(policy, facts)
    try:
        raw = command(
            [
                "gh",
                "attestation",
                "verify",
                str(archive),
                "--hostname",
                "github.com",
                "--repo",
                "luminusOS/images",
                "--signer-workflow",
                PRIVATE_WORKFLOW,
                "--signer-digest",
                policy["producer_sha"],
                "--source-digest",
                policy["source_sha"],
                "--source-ref",
                policy["caller_ref"],
                "--deny-self-hosted-runners",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--format",
                "json",
            ]
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        raise HandoffStageError(
            "Native gh verification failed or required identity-policy flags are unsupported; output withheld"
        ) from None
    results = oci.document(b'{"results":' + raw + b"}")["results"]
    require(
        isinstance(results, list) and 0 < len(results) <= 100,
        "native verifier returned no bounded results",
    )
    invocation = f"https://github.com/luminusOS/images/actions/runs/{policy['run_id']}/attempts/{policy['run_attempt']}"
    for result in results:
        statement = result.get("verificationResult", {}).get("statement", {})
        require(
            statement.get("_type") == "https://in-toto.io/Statement/v1"
            and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
            and statement.get("subject")
            == [{"name": "core-oci.zip", "digest": {"sha256": facts["archive_sha256"]}}]
            and statement.get("predicate", {})
            .get("runDetails", {})
            .get("metadata", {})
            .get("invocationId")
            == invocation,
            "native provenance subject or exact attempt mismatch",
        )


def private_attempt(policy, *, completed=True, command=bounded_command):
    def api(path):
        return oci.document(
            command(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    "--method",
                    "GET",
                    BASE + path,
                ]
            )
        )

    run = api(f"runs/{policy['run_id']}/attempts/{policy['run_attempt']}")
    binding.equal_fields(
        run,
        id=int(policy["run_id"]),
        run_attempt=int(policy["run_attempt"]),
        head_sha=policy["source_sha"],
        event="workflow_dispatch",
        path=policy["caller_workflow"],
    )
    for field in ("repository", "head_repository"):
        binding.equal_fields(
            run.get(field, {}), id=1118572971, full_name="luminusOS/images"
        )
    require(
        run.get("head_branch") == policy["caller_ref"].removeprefix("refs/heads/"),
        "attempt ref mismatch",
    )
    require(
        (run.get("status"), run.get("conclusion"))
        in (("in_progress", None), ("completed", "success")),
        "private run is not active or successful",
    )
    jobs, total, page = [], None, 1
    while total is None or len(jobs) < total:
        data = api(
            f"runs/{policy['run_id']}/attempts/{policy['run_attempt']}/jobs?per_page=100&page={page}"
        )
        count = binding.positive(data.get("total_count"))
        require(
            count <= 1000 and (total is None or total == count),
            "invalid private jobs pagination",
        )
        total = count
        batch = data.get("jobs")
        require(
            isinstance(batch, list) and len(batch) == min(100, total - len(jobs)),
            "incomplete private jobs",
        )
        jobs.extend(batch)
        page += 1
    ids = [binding.positive(job.get("id")) for job in jobs]
    require(len(set(ids)) == len(ids), "duplicate private jobs")
    for name in (
        ("Private core producer", "Private core attestation")
        if completed
        else ("Private core producer",)
    ):
        selected = [
            job
            for job in jobs
            if job.get("name", "").endswith(" / " + name) or job.get("name") == name
        ]
        require(len(selected) == 1, "missing or ambiguous private job")
        binding.equal_fields(
            selected[0],
            run_id=int(policy["run_id"]),
            run_attempt=int(policy["run_attempt"]),
            head_sha=policy["source_sha"],
            status="completed",
            conclusion="success",
        )
    return run, jobs


def acquire_private(policy, facts, output):
    private_facts(policy, facts)
    output = oci.safe_path(output)
    tooling = Path(__file__).resolve().parents[3]
    require(
        output != tooling
        and tooling not in output.parents
        and output not in tooling.parents,
        "acquisition output must be separate from trusted tooling",
    )
    receipt_name = "acquisition-receipt.json"
    with oci.directory(output.parent) as parent:
        info = os.fstat(parent)
        require(
            info.st_uid in (os.geteuid(), 0) and not info.st_mode & 0o022,
            "private owned output parent required before receipt cleanup",
        )
        try:
            existing = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require(
                stat.S_ISDIR(existing.st_mode)
                and existing.st_uid == os.geteuid()
                and existing.st_mode & 0o777 == 0o700,
                "private owned output directory required before receipt cleanup",
            )
            with oci.subdirectory(parent, output.name) as root:
                try:
                    marker = os.stat(receipt_name, dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    marker = None
                if marker is not None:
                    require(
                        stat.S_ISREG(marker.st_mode)
                        and marker.st_uid == os.geteuid()
                        and marker.st_nlink == 1,
                        "receipt must be an owned regular file without aliases",
                    )
                    os.unlink(receipt_name, dir_fd=root)
            raise FileExistsError(
                "acquisition workspace already exists; partials retained"
            )
    before = private_attempt(policy)
    layout = {}
    result = private_download(policy, facts, output, _verified_layout=layout)
    verify_native(policy, output / "core-oci.zip", result)
    require(
        private_attempt(policy) == before, "attempt changed during private acquisition"
    )
    summary = {
        "kind": "authenticated-private-core-handoff",
        **result,
        **policy,
        "production_ready": False,
        "runtime_verified": False,
        "release_authorized": False,
    }
    # policy_sha256 authenticates the handoff policy, not vulnerability exceptions.
    receipt = {
        "schema_version": 1,
        **summary,
        "layout": layout,
        "verification": {
            "archive": "completed",
            "oci": "completed",
            "diff_ids": "completed",
            "base_prefix": "completed",
            "attempt": "completed",
            "private_handoff_attestation": "completed",
            "upstream_signature": "not_evaluated",
            "vulnerability_policy": "not_evaluated",
            "vulnerability_scan": "not_run",
            "vm": "not_run",
        },
    }
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    descriptor = {
        "path": receipt_name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }
    with oci.directory(output) as root:
        stage = ".acquisition-receipt-" + secrets.token_hex(16)
        staged = False
        try:
            with oci.new_oci_file(root, stage) as sink:
                staged = True
                os.fchmod(sink.fileno(), 0o600)
                sink.write(raw)
            os.replace(stage, receipt_name, src_dir_fd=root, dst_dir_fd=root)
        finally:
            if staged:
                try:
                    os.unlink(stage, dir_fd=root)
                except FileNotFoundError:
                    pass
    return {**summary, "acquisition_receipt": descriptor}


def private_pack(policy, layout, output):
    layout, output = oci.safe_path(layout), oci.safe_path(output)
    with oci.directory(layout) as root, workspace(output) as destination:
        digest = oci.checked_image(root, "core")[0]
        total, members = 0, 0
        with (
            oci.new_oci_file(destination, "core-oci.zip") as sink,
            zipfile.ZipFile(
                sink, "w", compression=zipfile.ZIP_STORED, allowZip64=True
            ) as archive,
        ):

            def append(parent, prefix=""):
                nonlocal total, members
                for name in sorted(os.listdir(parent)):
                    relative = prefix + name
                    require(
                        relative != "core-handoff-policy.json",
                        "export cannot supply producer policy",
                    )
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    members += 1
                    require(
                        members <= MAX_MEMBERS
                        and len(PurePosixPath(relative).parts) <= 16,
                        "export member budget exceeded",
                    )
                    if stat.S_ISDIR(info.st_mode):
                        with oci.subdirectory(parent, name) as child:
                            append(child, relative + "/")
                    else:
                        require(stat.S_ISREG(info.st_mode), "nonregular export member")
                        total += info.st_size
                        require(
                            total <= MAX_ZIP - 1024**2,
                            "private export exceeds ZIP budget",
                        )
                        with archive.open(relative, "w", force_zip64=True) as target:
                            oci.contents(
                                parent, name, MAX_ZIP, collect=False, sink=target
                            )

            append(root)
            archive.writestr(
                "core-handoff-policy.json",
                json.dumps(policy, sort_keys=True, separators=(",", ":")).encode(),
            )
        raw_hash = hashlib.sha256()
        descriptor = os.open(
            "core-oci.zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=destination
        )
        with os.fdopen(descriptor, "rb") as source:
            while chunk := source.read(1024**2):
                raw_hash.update(chunk)
            size = source.tell()
        return private_facts(
            policy,
            {
                "archive_sha256": raw_hash.hexdigest(),
                "policy_sha256": private_policy_sha256(policy),
                "archive_size": str(size),
                "manifest_digest": digest,
                "object_key": private_key(policy),
            },
        )


def private_main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("build", "pack", "upload", "download", "acquire")
    )
    parser.add_argument("--layout", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = private_policy(
            oci.document(os.environ["CORE_HANDOFF_POLICY"].encode()),
            oci.document(os.environ["CORE_HANDOFF_CONTEXT"].encode()),
        )
        if args.action == "build":
            require(
                not any(key.startswith(("R2_", "CORE_R2_")) for key in os.environ),
                "R2 credentials forbidden during build",
            )
            source = Path(os.environ["GITHUB_WORKSPACE"]) / "source"
            output = oci.safe_path(args.output)
            require(
                output != source and source not in output.parents,
                "export must be outside source checkout",
            )
            tooling = Path(__file__).resolve().parents[3]
            require(
                tooling == Path(os.environ["GITHUB_WORKSPACE"]) / "trusted-tooling",
                "untrusted host tooling path",
            )
            require(
                not (source / "editions/core/Containerfile").is_symlink(),
                "symlink recipe forbidden",
            )
            with oci.directory(source / "editions/core") as recipe:
                oci.contents(recipe, "Containerfile", MAX_JSON)
            revision = (
                bounded_command(["git", "-C", str(source), "rev-parse", "HEAD"])
                .decode()
                .strip()
            )
            require(revision == policy["source_sha"], "source checkout mismatch")
            subprocess.run(
                [
                    "docker",
                    "buildx",
                    "build",
                    "--builder",
                    "default",
                    "--platform",
                    "linux/amd64",
                    "--no-cache",
                    "--network",
                    "default",
                    "--load",
                    "--provenance=false",
                    "--sbom=false",
                    "--file",
                    str(source / "editions/core/Containerfile"),
                    "--tag",
                    "private-core:handoff",
                    "--build-arg",
                    f"base=quay.io/fedora/fedora-bootc:45@{policy['base_digest']}",
                    "--build-arg",
                    "fedora_version=45",
                    "--build-arg",
                    f"distro_version=45.{policy['source_sha'][:12]}",
                    str(source),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=7200,
            )
            oci.export_layout(
                "private-core:handoff",
                args.output,
                "core",
                docker_host="unix:///var/run/docker.sock",
            )
            return 0
        elif args.action == "pack":
            require(args.layout is not None, "layout required")
            result = private_pack(policy, args.layout, args.output)
        else:
            facts = private_facts(
                policy, oci.document(os.environ["CORE_HANDOFF_FACTS"].encode())
            )
            if args.action == "upload":
                with oci.directory(args.output) as root:
                    descriptor = os.open(
                        "core-oci.zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root
                    )
                    with os.fdopen(descriptor, "rb") as source:
                        require(
                            stat.S_ISREG(os.fstat(source.fileno()).st_mode)
                            and os.fstat(source.fileno()).st_size
                            == int(facts["archive_size"]),
                            "upload archive changed",
                        )
                        checksum = hashlib.file_digest(source, "sha256").hexdigest()
                        require(
                            checksum == facts["archive_sha256"], "upload hash changed"
                        )
                        source.seek(0)
                        R2Transport().upload(private_key(policy), source, facts)
                result = facts
            elif args.action == "download":
                private_attempt(policy, completed=False)
                result = private_download(policy, facts, args.output)
            else:
                result = acquire_private(policy, facts, args.output)
        if args.action == "acquire":
            try:
                print(json.dumps(result), flush=True)
            except Exception:
                with oci.directory(oci.safe_path(args.output)) as root:
                    os.unlink("acquisition-receipt.json", dir_fd=root)
                raise
        else:
            oci.outputs(result)
        return 0
    except HandoffStageError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        zipfile.BadZipFile,
        http.client.HTTPException,
        subprocess.SubprocessError,
    ):
        print(
            "Private core handoff rejected; command output and response bodies withheld",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(private_main())
