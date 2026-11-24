import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import testing_snapshot as snapshot

pipeline = snapshot.pipeline
WORKSTATION = snapshot.RELEASE.parents[1]
KEYRING = snapshot.STAGING_KEYRING


def build(work: Path, run_id: int, attempt: int, sha: str) -> None:
    pipeline.require(KEYRING.stat().st_size > 0, "candidate OpenPGP keyring is empty")
    work.mkdir(mode=0o700)
    try:
        pipeline.download(
            snapshot.REPOSITORY,
            run_id,
            snapshot.artifact_name(attempt),
            work / "candidate",
        )
    except ValueError as error:
        if str(error) == "expected exactly one artifact":
            raise ValueError(
                "isolated candidate artifact missing or ambiguous for this attempt; rerun all jobs"
            ) from error
        raise
    candidate = snapshot.read_candidate(work / "candidate", run_id, sha)
    build_payload(work, candidate, KEYRING)


def build_payload(work: Path, candidate: dict, keyring: Path) -> None:
    reference = candidate["images"]["workstation"]
    repository, index = reference.split("@")
    directory = work / "snapshot"
    directory.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(dir=work) as temp:
        auth = str(Path(temp) / "auth.json")
        env = {k: v for k, v in os.environ.items() if k != "GH_TOKEN"}
        subprocess.run(
            [
                "podman",
                "login",
                "--authfile",
                auth,
                "-u",
                env["GITHUB_ACTOR"],
                "--password-stdin",
                "ghcr.io",
            ],
            input=os.environ["GH_TOKEN"],
            text=True,
            check=True,
            env=env,
        )
        raw_index = subprocess.check_output(
            ["skopeo", "inspect", "--authfile", auth, "--raw", f"docker://{reference}"],
            env=env,
        )
        pipeline.require(
            len(raw_index) <= snapshot.MIB
            and f"sha256:{hashlib.sha256(raw_index).hexdigest()}" == index,
            "downloaded workstation index differs from signed candidate",
        )
        (directory / "workstation-oci.json").write_bytes(raw_index)
        manifest = snapshot.feature.platform_manifest(directory, index)
        image = f"{repository}@{manifest}"
        subprocess.run(
            ["podman", "pull", "--authfile", auth, image], check=True, env=env
        )
        installed_keyring = subprocess.check_output(
            [
                "podman",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "cat",
                image,
                "/usr/share/luminusos/sysupdate/luminusos.pgp",
            ],
            env=env,
        )
        pipeline.require(
            installed_keyring == keyring.read_bytes(), "candidate keyring mismatch"
        )
        subprocess.run(
            [
                "bash",
                str(WORKSTATION / "build-sysext.sh"),
                str(WORKSTATION / "features/dummy"),
                image,
                str(directory),
            ],
            check=True,
            env=env | {"SYSEXT_BUILD_NETWORK": "none"},
        )


def seal(work: Path, candidate: dict) -> None:
    sign_payload(work, candidate, KEYRING)
    version = candidate["build_version"]
    directory = work / "snapshot"
    names = snapshot.members(version)
    with tarfile.open(
        work / "snapshot.tar", "x", format=tarfile.USTAR_FORMAT
    ) as archive:
        for name in sorted(names):
            path = pipeline.safe_file(directory, name)
            pipeline.require(
                0 < path.stat().st_size <= names[name],
                "snapshot member exceeds its budget",
            )
            archive.add(path, arcname=name, recursive=False)
    pipeline.require(
        (work / "snapshot.tar").stat().st_size <= snapshot.MAX_ARCHIVE,
        "snapshot exceeds its budget",
    )


def sign_payload(work: Path, candidate: dict, keyring: Path) -> None:
    version = candidate["build_version"]
    directory = work / "snapshot"
    manifest = snapshot.feature.platform_manifest(
        directory, pipeline.binding(candidate)["candidate_digest"]
    )
    fingerprint = os.environ["TESTING_FEATURE_OPENPGP_FINGERPRINT"]
    pipeline.require(
        re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint),
        "invalid signing fingerprint",
    )
    with tempfile.TemporaryDirectory(dir=work) as home:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": home,
            "GNUPGHOME": home,
            "SYSEXT_SIGNING_PASSPHRASE": os.environ.get(
                "SYSEXT_SIGNING_PASSPHRASE", ""
            ),
        }
        subprocess.run(
            ["gpg", "--batch", "--import"],
            input=os.environ["TESTING_FEATURE_OPENPGP_KEY"],
            text=True,
            check=True,
            capture_output=True,
            env=env,
        )
        try:
            subprocess.run(
                [
                    sys.executable,
                    str(snapshot.RELEASE),
                    "assemble",
                    str(directory),
                    "--version",
                    version,
                    "--image-digest",
                    manifest,
                ],
                check=True,
                env=env,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(snapshot.RELEASE),
                    "sign",
                    str(directory),
                    "--key",
                    fingerprint,
                ],
                check=True,
                env=env,
            )
        finally:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, check=False)
    snapshot.verify_payload(directory, candidate, keyring)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "seal", "upload"))
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    env = os.environ
    pipeline.require(
        env.get("GITHUB_REPOSITORY") == snapshot.REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == str(snapshot.REPOSITORY_ID)
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_WORKFLOW_REF")
        == f"{snapshot.REPOSITORY}/{snapshot.WORKFLOW}@refs/heads/main"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_WORKFLOW_SHA") == env.get("GITHUB_SHA")
        and pipeline.COMMIT.fullmatch(env.get("GITHUB_SHA", "")),
        "untrusted isolated producer context",
    )
    run_id, attempt, sha = (
        int(env["GITHUB_RUN_ID"]),
        int(env["GITHUB_RUN_ATTEMPT"]),
        env["GITHUB_SHA"],
    )
    key = snapshot.object_key(run_id, attempt)
    if args.action == "build":
        build(args.work, run_id, attempt, sha)
    elif args.action == "seal":
        seal(args.work, snapshot.read_candidate(args.work / "candidate", run_id, sha))
    else:
        archive = pipeline.safe_file(args.work, "snapshot.tar")
        snapshot.aws("put-object", key, "--if-none-match", "*", "--body", str(archive))


if __name__ == "__main__":
    main()
