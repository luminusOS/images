"""Evaluate supplied API projections, not their authenticity.

A reviewed trusted acquisition adapter must independently acquire the exact
attempt's run, complete jobs pages, step-attributed untruncated upload output,
artifact metadata and ZIP. Provider step acquisition is unverified. The caller
must approve producer source and pinned nested workflow/actions, including the
exact nested job name. Labels and dictionary/log matching establish neither
step attribution nor authenticity or completeness.
"""

import datetime as dt
import hashlib
import importlib.util
import itertools
import os
import re
import stat
import tempfile
from pathlib import Path


def module(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py")
    )
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


pipeline = module("release_pipeline")
oci = module("oci_layout")
require = pipeline.require
POLICY = "repository repository_id run_id run_attempt source_sha workflow job_name fedora channel architecture base_digest policy_sha256 inputs_sha256"
STEPS = ("Build core", "Export built core OCI layout", "Upload built core OCI layout")
SECOND = 1_000_000_000


def record(value, fields):
    require(
        isinstance(value, dict) and value.keys() == set(fields.split()),
        "invalid observation fields",
    )
    return value


def positive(value):
    require(type(value) is int and value > 0, "invalid positive integer")
    return value


def timestamp(value):
    require(
        isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
            value,
        ),
        "invalid log/step timestamp",
    )
    elapsed = dt.datetime.fromisoformat(value[:19] + "Z") - dt.datetime(
        1970, 1, 1, tzinfo=dt.UTC
    )
    fraction = value[20:-1] if value[19] == "." else ""
    return (elapsed.days * 86400 + elapsed.seconds) * SECOND + int(
        fraction.ljust(9, "0")
    )


def equal_fields(value, **expected):
    for key, expected_value in expected.items():
        require(
            type(value.get(key)) is type(expected_value)
            and value[key] == expected_value,
            f"binding mismatch: {key}",
        )


def policy_check(policy):
    record(policy, POLICY)
    for key in ("repository_id", "run_id", "run_attempt"):
        positive(policy[key])
    for key, pattern in (
        ("repository", pipeline.REPO),
        ("source_sha", pipeline.COMMIT),
        ("base_digest", pipeline.DIGEST),
        ("policy_sha256", pipeline.SHA),
        ("inputs_sha256", pipeline.SHA),
    ):
        pipeline.matches(policy[key], pattern, key)
    require(
        policy["workflow"]
        in (".github/workflows/publish.yml", ".github/workflows/auto-testing.yml"),
        "unapproved entry workflow",
    )
    require(
        isinstance(policy["job_name"], str) and 0 < len(policy["job_name"]) <= 512,
        "invalid protected job name",
    )
    pipeline.matches(policy["fedora"], re.compile(r"[1-9][0-9]*\Z"), "Fedora")
    equal_fields(policy, channel="testing", architecture="x86_64")


def select_job(policy, observations):
    run = record(
        observations["run"],
        "id run_attempt head_sha head_branch path repository head_repository status conclusion event",
    )
    equal_fields(
        run,
        id=policy["run_id"],
        run_attempt=policy["run_attempt"],
        head_sha=policy["source_sha"],
        head_branch="main",
        path=policy["workflow"],
        status="completed",
        conclusion="success",
    )
    require(
        run["event"] in ("workflow_dispatch", "schedule", "workflow_call"),
        "invalid producer event",
    )
    for key in ("repository", "head_repository"):
        equal_fields(
            record(run[key], "id full_name"),
            id=policy["repository_id"],
            full_name=policy["repository"],
        )
    pages = observations["jobs_pages"]
    require(
        isinstance(pages, list) and 0 < len(pages) <= 1000, "missing attempt jobs pages"
    )
    jobs, total = [], None
    for page in pages:
        record(page, "total_count jobs")
        count = positive(page["total_count"])
        require(total is None or count == total, "inconsistent jobs total")
        total = count
        require(
            isinstance(page["jobs"], list) and 0 < len(page["jobs"]) <= 100,
            "invalid jobs page",
        )
        jobs.extend(page["jobs"])
    require(len(jobs) == total, "incomplete jobs pagination")
    ids, selected = set(), []
    for job in jobs:
        record(job, "id run_id run_attempt head_sha name status conclusion steps")
        identity = positive(job["id"])
        require(identity not in ids, "duplicate attempt job")
        ids.add(identity)
        equal_fields(
            job,
            run_id=policy["run_id"],
            run_attempt=policy["run_attempt"],
            head_sha=policy["source_sha"],
        )
        require(isinstance(job["name"], str), "invalid job name")
        if job["name"] == policy["job_name"]:
            selected.append(job)
    require(len(selected) == 1, "ambiguous or missing protected core job")
    job = selected[0]
    equal_fields(job, status="completed", conclusion="success")
    steps = job["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= 1000, "invalid job steps")
    numbers, relevant = [], []
    for step in steps:
        record(step, "number name status conclusion started_at completed_at")
        require(isinstance(step["name"], str), "invalid API step name")
        numbers.append(positive(step["number"]))
        if step["name"] in STEPS:
            equal_fields(step, status="completed", conclusion="success")
            start, end = timestamp(step["started_at"]), timestamp(step["completed_at"])
            require(start <= end, "invalid step window")
            relevant.append((step["name"], start, end))
    require(numbers == sorted(set(numbers)), "unordered or duplicate step numbers")
    require(
        tuple(item[0] for item in relevant) == STEPS,
        "missing or duplicate core build steps",
    )
    require(
        all(
            left[2] // SECOND <= right[1] // SECOND
            for left, right in itertools.pairwise(relevant)
        ),
        "overlapping core steps",
    )
    projections = observations["step_logs"]
    require(
        isinstance(projections, list) and 0 < len(projections) <= len(steps),
        "invalid step log projections",
    )
    by_number = {step["number"]: step["name"] for step in steps}
    seen, protected = set(), []
    for projection in projections:
        record(projection, "number name log")
        number = positive(projection["number"])
        require(
            number not in seen and number in by_number,
            "duplicate or unknown step log number",
        )
        equal_fields(projection, name=by_number[number])
        require(isinstance(projection["log"], str), "invalid step log")
        seen.add(number)
        if projection["name"] == STEPS[-1]:
            protected.append(projection["log"])
    require(len(protected) == 1, "missing protected upload projection")
    start, end = relevant[-1][1:]
    return (
        job["id"],
        protected[0],
        (start // SECOND * SECOND, (end // SECOND + 1) * SECOND),
    )


def upload_identity(log, window):
    require(
        isinstance(log, str) and 0 < len(log) <= 8 * 1024 * 1024,
        "missing or oversized protected step log",
    )
    ids, digests, confirmations, grouped = {}, [], [], False
    previous = None
    for line in log.splitlines():
        stamp, separator, text = line.partition(" ")
        require(bool(separator), "unframed job log")
        time = timestamp(stamp)
        require(window[0] <= time < window[1], "step log outside quantized API window")
        require(previous is None or previous <= time, "unordered job log")
        previous = time
        if text.startswith("##[group]"):
            require(not grouped, "nested log group")
            grouped = True
            continue
        if text == "##[endgroup]":
            require(grouped, "unmatched log group")
            grouped = False
            continue
        if (
            "Artifact ID" not in text
            and "SHA256 digest of uploaded artifact" not in text
        ):
            continue
        require(
            not grouped,
            "upload record inside command group",
        )
        digest = re.fullmatch(
            r"SHA256 digest of uploaded artifact(?: zip)? is ([0-9a-f]{64})", text
        )
        identity = re.fullmatch(
            r"(Artifact ID: |Artifact core-oci successfully finalized\. Artifact ID )([1-9][0-9]*)",
            text,
        )
        confirmation = re.fullmatch(
            r"Artifact core-oci has been successfully uploaded! Final size is ([1-9][0-9]*) bytes\. Artifact ID is ([1-9][0-9]*)",
            text,
        )
        require(
            bool(digest or identity or confirmation),
            "unrecognized or echoed upload record",
        )
        if digest:
            digests.append("sha256:" + digest[1])
        if identity:
            require(identity[1] not in ids, "duplicate upload identity form")
            ids[identity[1]] = int(identity[2])
        if confirmation:
            confirmations.append((int(confirmation[1]), int(confirmation[2])))
    require(
        not grouped
        and "Artifact core-oci successfully finalized. Artifact ID " in ids
        and len(set(ids.values())) == len(digests) == len(confirmations) == 1,
        "incomplete or duplicate upload identity",
    )
    require(
        confirmations[0][1] == next(iter(ids.values())),
        "upload confirmation mismatch",
    )
    return confirmations[0][1], digests[0], confirmations[0][0]


def evaluate_binding(expected_policy, trusted_observations, archive):
    """Return conditional observations only; no authentication, proof or signing."""
    policy_check(expected_policy)
    record(trusted_observations, "run jobs_pages step_logs artifact")
    job_id, log, window = select_job(expected_policy, trusted_observations)
    artifact_id, archive_digest, confirmed_size = upload_identity(log, window)
    artifact = record(
        trusted_observations["artifact"],
        "id name expired workflow_run digest size_in_bytes",
    )
    equal_fields(
        artifact,
        id=artifact_id,
        name="core-oci",
        expired=False,
        digest=archive_digest,
    )
    provenance = record(
        artifact["workflow_run"],
        "id repository_id head_repository_id head_sha head_branch",
    )
    equal_fields(
        provenance,
        id=expected_policy["run_id"],
        repository_id=expected_policy["repository_id"],
        head_repository_id=expected_policy["repository_id"],
        head_sha=expected_policy["source_sha"],
        head_branch="main",
    )
    size = positive(artifact["size_in_bytes"])
    require(
        size <= pipeline.size_limit("RELEASE_MAX_TOTAL_BYTES", pipeline.MAX_ARCHIVE),
        "archive too large",
    )
    require(
        confirmed_size == size,
        "upload size confirmation mismatch",
    )
    with tempfile.TemporaryDirectory(prefix="core-build-binding-") as temporary:
        staged, layout = Path(temporary) / "verified.zip", Path(temporary) / "oci"
        descriptor = os.open(
            archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
        with os.fdopen(descriptor, "rb") as source, staged.open("xb") as destination:
            require(
                stat.S_ISREG(os.fstat(source.fileno()).st_mode),
                "archive is not regular",
            )
            checksum, written = hashlib.sha256(), 0
            while chunk := source.read(pipeline.CHUNK_SIZE):
                written += len(chunk)
                require(written <= size, "archive exceeds declared size")
                pipeline.require_space(Path(temporary), len(chunk))
                checksum.update(chunk)
                destination.write(chunk)
            require(
                written == size and "sha256:" + checksum.hexdigest() == archive_digest,
                "archive bytes mismatch",
            )
        pipeline.extract_archive(staged, layout)
        with oci.directory(layout) as root:
            core_digest, config, _ = oci.checked_image(root, "core")
        metadata = config.get("config")
        require(isinstance(metadata, dict), "missing core config metadata")
        labels = metadata.get("Labels")
        require(isinstance(labels, dict), "invalid core labels")
        equal_fields(
            labels,
            **{
                "org.luminusos.core.fedora": expected_policy["fedora"],
                "org.luminusos.core.inputs-sha256": expected_policy["inputs_sha256"],
            },
        )
    return {
        "kind": "conditional-core-output-observation",
        "production_ready": False,
        "observations_authenticated": False,
        "runtime_verified": False,
        "repository": expected_policy["repository"],
        "repository_id": expected_policy["repository_id"],
        "run_id": expected_policy["run_id"],
        "run_attempt": expected_policy["run_attempt"],
        "source_sha": expected_policy["source_sha"],
        "workflow": expected_policy["workflow"],
        "job_id": job_id,
        "artifact_id": artifact_id,
        "archive_sha256": archive_digest,
        "archive_size_bytes": size,
        "core_digest": core_digest,
        "limitation": "Requires a reviewed trusted acquisition adapter and independently approved producer source; provider step acquisition is unverified. Supplied labels and confirmation do not prove step attribution, untruncated output, authenticity or base ancestry.",
    }
