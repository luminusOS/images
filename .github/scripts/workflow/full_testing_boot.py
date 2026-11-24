import argparse
import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import testing_feature_producer as producer
import testing_snapshot as snapshot

pipeline = snapshot.pipeline
WORKFLOW = ".github/workflows/full-testing-boot.yml"
SCOPE = "full-testing-boot; not promotion evidence"
KEYRING = (
    snapshot.RELEASE.parents[3] / "shared/release/hosted-validation/snapshot.pgp.b64"
)
FINGERPRINT = "AC8D8447108CE5ABF6475DDEAEACC4B325F16C76"


def run_identity(env):
    pipeline.require(
        all(
            env.get(name) == value
            for name, value in (
                ("GITHUB_REPOSITORY", snapshot.REPOSITORY),
                ("GITHUB_REPOSITORY_ID", str(snapshot.REPOSITORY_ID)),
                ("GITHUB_REF", "refs/heads/main"),
                ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                (
                    "GITHUB_WORKFLOW_REF",
                    f"{snapshot.REPOSITORY}/{WORKFLOW}@refs/heads/main",
                ),
            )
        )
        and pipeline.COMMIT.fullmatch(env.get("GITHUB_SHA", ""))
        and env.get("GITHUB_WORKFLOW_SHA") == env["GITHUB_SHA"]
        and all(
            snapshot.DECIMAL.fullmatch(env.get(name, ""))
            for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        ),
        "full testing boot requires canonical main manual dispatch",
    )
    return int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"]), env["GITHUB_SHA"]


def require_candidate(candidate, run_id, sha):
    pipeline.require(
        candidate["repository"] == snapshot.REPOSITORY
        and candidate["run_id"] == run_id
        and candidate["source_sha"] == sha
        and candidate["channel"] == "testing"
        and pipeline.release_kind(candidate) == "full"
        and "feature/profile.json" not in candidate["artifacts"],
        "expected a full testing candidate from this run without a promotion profile",
    )


def verify_payload(directory, candidate):
    for name, limit in snapshot.members(candidate["build_version"]).items():
        path = pipeline.safe_file(directory, name)
        pipeline.require(
            0 < path.stat().st_size <= limit, f"invalid snapshot size: {name}"
        )
    with tempfile.TemporaryDirectory(prefix="full-testing-keyring-") as temp:
        keyring = Path(temp) / "snapshot.pgp"
        write_keyring(keyring)
        manifest = snapshot.verify_payload(directory, candidate, keyring)
    descriptor = pipeline.load(directory / "release.json")
    return (
        manifest,
        descriptor,
        (
            *snapshot.MIRROR_METADATA,
            f"luminusos-dummy_{candidate['build_version']}.raw.xz",
        ),
    )


def write_keyring(path):
    path.write_bytes(base64.b64decode(KEYRING.read_bytes().strip(), validate=True))


def download_candidate(run_id, attempt, destination):
    try:
        pipeline.download(
            snapshot.REPOSITORY, run_id, snapshot.artifact_name(attempt), destination
        )
    except ValueError as error:
        if str(error) != "expected exactly one artifact":
            raise
        raise ValueError(
            "full testing candidate missing or ambiguous for this attempt; rerun all jobs"
        ) from error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "seal", "boot"))
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    work = args.work
    run_id, attempt, sha = run_identity(os.environ)
    candidate_dir = work / "candidate"
    if args.action == "build":
        work.mkdir(mode=0o700)
        download_candidate(run_id, attempt, candidate_dir)
    candidate_file = candidate_dir / "candidate.json"
    candidate = pipeline.candidate(
        candidate_file, pipeline.CANDIDATE_PUBLIC_KEY, legacy_only=True
    )
    require_candidate(candidate, run_id, sha)
    keyring = work / "snapshot.pgp"
    if args.action == "build":
        write_keyring(keyring)
        producer.build_payload(work, candidate, keyring)
    elif args.action == "seal":
        os.environ["TESTING_FEATURE_OPENPGP_FINGERPRINT"] = FINGERPRINT
        producer.sign_payload(work, candidate, keyring)
    else:
        manifest, _, _ = verify_payload(work / "snapshot", candidate)
        receipts = work / "receipts"
        receipts.mkdir(mode=0o700)
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("validation_driver.py")),
                "--candidate",
                str(candidate_file),
                "--artifacts",
                str(candidate_dir),
                "--receipts",
                str(receipts),
                "--fixture-base",
                str(work / "fixture-base"),
                "--candidate-mirror",
                str(work / "candidate-mirror"),
                "--validation-snapshot",
                str(work / "snapshot"),
            ],
            check=True,
            env={
                key: os.environ[key]
                for key in (
                    "PATH",
                    "HOME",
                    "RUNNER_TEMP",
                    "GITHUB_REPOSITORY",
                    "GITHUB_REPOSITORY_ID",
                    "GITHUB_REF",
                    "GITHUB_EVENT_NAME",
                    "GITHUB_WORKFLOW_REF",
                    "GITHUB_WORKFLOW_SHA",
                    "GITHUB_SHA",
                    "GITHUB_RUN_ID",
                    "GITHUB_RUN_ATTEMPT",
                )
            },
        )
        observed = pipeline.load(
            receipts / "diagnostics/validation-boot-observation.json"
        )
        pipeline.write(
            work / "testing-boot-evidence.json",
            {
                "scope": SCOPE,
                "run_attempt": attempt,
                "binding": pipeline.binding(candidate),
                "platform_manifest_digest": manifest,
                "observations": observed,
            },
        )


if __name__ == "__main__":
    main()
