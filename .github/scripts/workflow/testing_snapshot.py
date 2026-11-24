import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import feature_boot_evidence as feature
import release_pipeline as pipeline

MIB = 1024 * 1024
MAX_ARCHIVE = 8 * MIB
RELEASE = Path(__file__).resolve().parents[3] / "editions/workstation/sysext/release.py"
STAGING_KEYRING = RELEASE.with_name("testing-feature-staging.pgp")
REPOSITORY = "luminusOS/images"
REPOSITORY_ID = 1118572971
WORKFLOW = ".github/workflows/testing-feature-candidate.yml"
VALIDATION_WORKFLOW = ".github/workflows/installation-validation.yml"
RECEIPT_SCOPE = "isolated-testing; not promotion evidence"
ACCOUNT = "89e6fc75aed6d04cd84a0c7d11a5594e"
DECIMAL = re.compile(r"[1-9][0-9]*")


def object_key(run_id: int, attempt: int) -> str:
    pipeline.require(
        all(type(n) is int and n > 0 for n in (run_id, attempt)),
        "invalid isolated run identity",
    )
    return f"candidates/{run_id}/{attempt}/snapshot.tar"


def snapshot_key(run: dict) -> str:
    authorize_main_dispatch(run, WORKFLOW)
    return object_key(run["id"], run["run_attempt"])


def authorize_main_dispatch(run: dict, workflow: str) -> None:
    pipeline.authorize_run(run, REPOSITORY, run.get("id"), {workflow})
    pipeline.require(
        run["head_branch"] == "main"
        and run["event"] == "workflow_dispatch"
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] > 0
        and all(
            run[k].get("id") == REPOSITORY_ID for k in ("repository", "head_repository")
        ),
        "not a canonical isolated main dispatch",
    )


def read_candidate(directory: Path, run_id: int, sha: str | None = None) -> dict:
    candidate = pipeline.candidate(
        directory / "candidate.json", pipeline.CANDIDATE_PUBLIC_KEY, legacy_only=True
    )
    pipeline.require(
        candidate["repository"] == REPOSITORY
        and candidate["run_id"] == run_id
        and (sha is None or candidate["source_sha"] == sha)
        and candidate["channel"] == "testing"
        and pipeline.release_kind(candidate) == "image",
        "not the isolated testing image candidate",
    )
    return candidate


def artifact_name(attempt: int) -> str:
    return f"testing-feature-candidate-{attempt}"


def fetch_candidate(run_id: int, output: Path) -> str:
    run = pipeline.run_info(REPOSITORY, run_id, {WORKFLOW})
    key = snapshot_key(run)
    pipeline.download(REPOSITORY, run_id, artifact_name(run["run_attempt"]), output)
    candidate = read_candidate(output, run_id, run["head_sha"])
    pipeline.candidate_outputs(candidate, output / "candidate.json")
    return key


def aws(operation: str, key: str, *args: str) -> bytes:
    account = os.environ.get("TESTING_FEATURE_R2_ACCOUNT_ID", "")
    bucket = os.environ.get("TESTING_FEATURE_R2_BUCKET", "")
    pipeline.require(
        account == ACCOUNT
        and re.fullmatch(r"luminusos-testing-features(?:-[a-z0-9]{1,20})?", bucket),
        "invalid private testing bucket configuration",
    )
    access = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    pipeline.require(access and secret, "missing scoped R2 credentials")
    with tempfile.TemporaryDirectory() as home:
        result = subprocess.run(
            [
                "aws",
                "--no-cli-pager",
                "--endpoint-url",
                f"https://{account}.r2.cloudflarestorage.com",
                "s3api",
                operation,
                "--bucket",
                bucket,
                "--key",
                key,
                *args,
            ],
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": home,
                "AWS_ACCESS_KEY_ID": access,
                "AWS_SECRET_ACCESS_KEY": secret,
                "AWS_DEFAULT_REGION": "auto",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_REQUEST_CHECKSUM_CALCULATION": "when_required",
                "AWS_RESPONSE_CHECKSUM_VALIDATION": "when_required",
            },
            capture_output=True,
            timeout=90,
            check=False,
        )
    pipeline.require(result.returncode == 0, f"private testing R2 {operation} failed")
    return result.stdout


def download(directory: Path, output: Path, key: str) -> None:
    match = re.fullmatch(r"candidates/([1-9][0-9]*)/([1-9][0-9]*)/snapshot\.tar", key)
    pipeline.require(match, "invalid snapshot object key")
    candidate = read_candidate(directory, int(match[1]))
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        temporary = Path(temporary)
        archive = temporary / "snapshot.tar"
        staging = temporary / "verified"
        metadata = json.loads(
            aws("get-object", key, "--range", f"bytes=0-{MAX_ARCHIVE}", str(archive))
        )
        size = archive.stat().st_size
        pipeline.require(
            0 < size <= MAX_ARCHIVE
            and metadata.get("ContentRange") == f"bytes 0-{size - 1}/{size}",
            "incomplete or oversized private snapshot download",
        )
        extract(archive, staging, candidate["build_version"])
        verify(staging, candidate)
        pipeline.require(
            not output.exists() and not output.is_symlink(),
            "snapshot destination exists",
        )
        staging.rename(output)


def members(version: str) -> dict[str, int]:
    pipeline.require(
        re.fullmatch(r"[1-9][0-9]*\.[0-9]{8}(?:\.[1-9][0-9]*)?", version),
        "invalid testing snapshot version",
    )
    names = {
        "workstation-oci.json": MIB,
        f"luminusos-dummy_{version}.json": 64 * 1024,
        f"luminusos-dummy_{version}.raw": 4 * MIB,
        f"luminusos-dummy_{version}.raw.xz": MIB,
    }
    for name in ("SHA256SUMS", "SHA256SUMS.raw", "release.json"):
        names[name] = names[f"{name}.gpg"] = 64 * 1024
    return names


def extract(archive: Path, output: Path, version: str) -> None:
    expected = members(version)
    pipeline.require(
        not output.exists() and not output.is_symlink(), "snapshot destination exists"
    )
    pipeline.require(
        archive.is_file()
        and not archive.is_symlink()
        and 0 < archive.stat().st_size <= MAX_ARCHIVE,
        "invalid snapshot archive size or type",
    )
    with (
        tempfile.TemporaryDirectory(dir=output.parent) as temporary,
        tarfile.open(archive, "r:") as stream,
    ):
        staging = Path(temporary) / "snapshot"
        staging.mkdir(mode=0o700)
        seen = set()
        for member in stream:
            name = member.name
            pipeline.require(
                name in expected
                and name not in seen
                and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                and not member.pax_headers
                and 0 < member.size <= expected[name],
                "unexpected snapshot member",
            )
            source = stream.extractfile(member)
            with source, (staging / name).open("xb") as target:
                shutil.copyfileobj(source, target)
            seen.add(name)
        pipeline.require(seen == expected.keys(), "incomplete snapshot")
        staging.rename(output)


def verify(directory: Path, candidate: dict) -> str:
    pipeline.require(
        candidate["channel"] == "testing"
        and pipeline.release_kind(candidate) == "image",
        "snapshot intake requires a verified testing image candidate",
    )
    version = candidate["build_version"]
    manifest = feature.platform_manifest(
        directory, pipeline.binding(candidate)["candidate_digest"]
    )
    descriptor = pipeline.load(pipeline.safe_file(directory, "release.json"))
    pipeline.require(
        type(descriptor.get("format")) is int
        and descriptor["format"] == 1
        and descriptor.get("architecture") == "x86-64"
        and isinstance(descriptor.get("features"), dict)
        and set(descriptor["features"]) == {"dummy"},
        "unexpected testing snapshot descriptor",
    )
    subprocess.run(
        [
            sys.executable,
            str(RELEASE),
            "verify",
            str(directory),
            "--keyring",
            str(STAGING_KEYRING),
            "--version",
            version,
            "--image-digest",
            manifest,
            "--raw",
        ],
        check=True,
        timeout=60,
    )
    return manifest


def record(candidate_dir: Path, snapshot_dir: Path, receipts: Path, key: str) -> Path:
    match = re.fullmatch(r"candidates/([1-9][0-9]*)/([1-9][0-9]*)/snapshot\.tar", key)
    pipeline.require(match, "invalid observed snapshot object key")
    candidate = read_candidate(candidate_dir, int(match[1]))
    manifest = verify(snapshot_dir, candidate)
    descriptor_path = pipeline.safe_file(snapshot_dir, "release.json")
    descriptor = pipeline.load(descriptor_path)
    raw = descriptor["features"]["dummy"]["raw_sha256"]
    pipeline.require(
        isinstance(raw, str) and pipeline.SHA.fullmatch(raw), "invalid signed raw hash"
    )
    observed = pipeline.load(
        pipeline.safe_file(receipts, "diagnostics/feature-observation.json")
    )
    feature.validate_observation(observed, candidate["build_version"], manifest, raw)
    run_id, attempt = (
        os.environ.get(k, "") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    )
    sha = os.environ.get("GITHUB_SHA", "")
    pipeline.require(
        DECIMAL.fullmatch(run_id)
        and DECIMAL.fullmatch(attempt)
        and pipeline.COMMIT.fullmatch(sha)
        and os.environ.get("GITHUB_WORKFLOW_SHA") == sha,
        "untrusted validator run identity",
    )
    output = receipts / "isolated-feature-receipt"
    output.mkdir(mode=0o700)
    statement = output / "feature-boot.json"
    pipeline.write(
        statement,
        {
            "schema": 1,
            "scope": RECEIPT_SCOPE,
            "repository": REPOSITORY,
            "candidate": {
                "run_id": candidate["run_id"],
                "run_attempt": int(match[2]),
                "source_sha": candidate["source_sha"],
                "workstation": candidate["images"]["workstation"],
                "build_version": candidate["build_version"],
            },
            "validator": {
                "run_id": int(run_id),
                "run_attempt": int(attempt),
                "source_sha": sha,
            },
            "snapshot_sha256": pipeline.digest(descriptor_path),
            "observations": observed,
        },
    )
    pipeline.sign(statement, pipeline.CANDIDATE_PUBLIC_KEY, tlog_upload=False)
    return statement


def verify_receipt(
    statement: Path,
    candidate_dir: Path,
    snapshot_dir: Path,
    producer: dict,
    validator: dict,
) -> None:
    """Verify isolated evidence against authenticated, completed GitHub run records."""
    authorize_main_dispatch(producer, WORKFLOW)
    authorize_main_dispatch(validator, VALIDATION_WORKFLOW)
    candidate = read_candidate(candidate_dir, producer["id"], producer["head_sha"])
    path = pipeline.safe_file(statement.parent, statement.name)
    pipeline.verify(path, pipeline.CANDIDATE_PUBLIC_KEY)
    receipt = pipeline.load(path)
    identity = receipt.get("candidate")
    attestor = receipt.get("validator")
    pipeline.require(
        type(receipt.get("schema")) is int
        and receipt["schema"] == 1
        and receipt.get("scope") == RECEIPT_SCOPE
        and receipt.get("repository") == REPOSITORY
        and isinstance(identity, dict)
        and isinstance(attestor, dict)
        and all(
            type(entry.get(field)) is int
            for entry in (identity, attestor)
            for field in ("run_id", "run_attempt")
        )
        and identity
        == {
            "run_id": producer["id"],
            "run_attempt": producer["run_attempt"],
            "source_sha": producer["head_sha"],
            "workstation": candidate["images"]["workstation"],
            "build_version": candidate["build_version"],
        }
        and attestor
        == {
            "run_id": validator["id"],
            "run_attempt": validator["run_attempt"],
            "source_sha": validator["head_sha"],
        },
        "isolated boot receipt does not match the authorized runs and candidate",
    )
    descriptor = pipeline.checked_file(
        snapshot_dir, "release.json", receipt.get("snapshot_sha256"), True
    )
    manifest = verify(snapshot_dir, candidate)
    raw = pipeline.load(descriptor)["features"]["dummy"]["raw_sha256"]
    observed = receipt.get("observations")
    pipeline.require(isinstance(observed, dict), "missing isolated boot observations")
    feature.validate_observation(observed, candidate["build_version"], manifest, raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch-candidate")
    fetch.add_argument("run_id")
    fetch.add_argument("directory", type=Path)
    get = commands.add_parser("download")
    get.add_argument("directory", type=Path)
    get.add_argument("output", type=Path)
    receipt = commands.add_parser("record-feature-boot")
    receipt.add_argument("directory", type=Path)
    receipt.add_argument("snapshot", type=Path)
    receipt.add_argument("receipts", type=Path)
    inspect = commands.add_parser("verify-feature-boot")
    inspect.add_argument("producer", type=int)
    inspect.add_argument("validator", type=int)
    inspect.add_argument("directory", type=Path)
    inspect.add_argument("snapshot", type=Path)
    inspect.add_argument("statement", type=Path)
    args = parser.parse_args()
    if args.command == "verify-feature-boot":
        producer = pipeline.run_info(REPOSITORY, args.producer, {WORKFLOW})
        validator = pipeline.run_info(REPOSITORY, args.validator, {VALIDATION_WORKFLOW})
        verify_receipt(
            args.statement, args.directory, args.snapshot, producer, validator
        )
        return
    pipeline.require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID)
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_WORKFLOW_REF")
        == f"{REPOSITORY}/{VALIDATION_WORKFLOW}@refs/heads/main",
        "snapshot intake requires canonical main installation validation",
    )
    if args.command == "fetch-candidate":
        pipeline.require(DECIMAL.fullmatch(args.run_id), "invalid candidate run ID")
        key = fetch_candidate(int(args.run_id), args.directory)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            print(f"snapshot_key={key}", file=output)
    elif args.command == "download":
        download(args.directory, args.output, os.environ["SNAPSHOT_KEY"])
    else:
        record(args.directory, args.snapshot, args.receipts, os.environ["SNAPSHOT_KEY"])


if __name__ == "__main__":
    main()
