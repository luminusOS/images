"""Promote already-built OCI images without rebuilding their content."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_policy import REQUIRED_GATES, validate_candidate

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CANDIDATE_KEY = Path(__file__).resolve().parents[3] / "shared/release/candidate.pub"
OFFICIAL_KEY = (
    Path(__file__).resolve().parents[3]
    / "shared/trust/etc/pki/containers/luminusos.pub"
)
PUBLIC_REPOSITORIES = {
    "core": "luminusos",
    "workstation": "luminusos-workstation",
    "installer": "luminusos-workstation",
}


def public_repository(role: str, repository: str) -> str:
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "").lower()
    if (
        role not in PUBLIC_REPOSITORIES
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", owner)
        or repository.split("/", 1)[0].lower() != owner
    ):
        raise ValueError("invalid role or repository owner")
    return f"ghcr.io/{owner}/{PUBLIC_REPOSITORIES[role]}"


CHANNEL_TAGS = {
    # channel: (version, branch, floating tag)
    "testing": (r"testing-[0-9]+\.[0-9]{8}(?:\.[0-9]+)?", r"testing-[0-9]+", "testing"),
    "stable": (r"[0-9]+\.[0-9]{8}(?:\.[0-9]+)?", r"[0-9]+", "latest"),
}


def destination_tags(
    destination_repository: str, destinations: list[str], role: str
) -> list[str]:
    """Return the tags, version first, when they all belong to one channel."""
    suffix = "-iso" if role == "installer" else ""
    tags = []
    for destination in destinations:
        prefix = destination_repository + ":"
        if not destination.startswith(prefix):
            raise ValueError("destination repository does not match role")
        tags.append(destination[len(prefix) :])
    for version, branch, floating in CHANNEL_TAGS.values():
        found = [tag for tag in tags if re.fullmatch(version + suffix, tag)]
        if all(
            re.fullmatch(version + suffix, tag)
            or re.fullmatch(branch + suffix, tag)
            or (role != "installer" and tag == floating)
            for tag in tags
        ):
            if len(found) != 1 or len(tags) != len(set(tags)):
                raise ValueError("exactly one version tag is required")
            return found + [tag for tag in tags if tag != found[0]]
    raise ValueError("invalid destination tag")


def inspect_version(reference: str) -> str | None:
    try:
        result = subprocess.run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{reference}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        error = exc.stderr or ""
        repository, tag = reference.rsplit(":", 1)
        missing = r"(?:manifest unknown(?:: manifest unknown)?|manifest not found)"
        # skopeo exits 2 for a missing image; older releases used 1.
        if exc.returncode in (1, 2) and (
            re.fullmatch(missing, error.strip(), re.IGNORECASE)
            or re.search(
                "reading manifest "
                + re.escape(tag)
                + " in "
                + re.escape(repository)
                + ": "
                + missing
                + r'"?\s*$',
                error,
                re.IGNORECASE,
            )
        ):
            return None
        raise ValueError(f"cannot inspect version tag: {reference}") from exc
    digest = result.stdout.strip()
    if not DIGEST.fullmatch(digest):
        raise ValueError(f"cannot inspect version tag: {reference}")
    return digest


def verify_evidence_artifacts(evidence: dict, directory: Path) -> None:
    for name in REQUIRED_GATES:
        item = evidence["evidence"][name]
        relative = Path(item["artifact"])
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in ("..", ".") for part in relative.parts)
        ):
            raise ValueError(f"invalid artifact path for {name}")
        path = directory
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError(f"symlinked artifact path for {name}")
        if not path.is_file():
            raise ValueError(f"missing artifact for {name}")
        with path.open("rb") as artifact:
            actual = hashlib.file_digest(artifact, "sha256").hexdigest()
        if actual != item["sha256"]:
            raise ValueError(f"artifact checksum mismatch for {name}")


def promote(
    source: str,
    expected_digest: str,
    destinations: list[str],
    public_key: Path,
    evidence_path: Path,
    evidence_signature: Path,
    expected_repository: str,
    expected_commit: str,
    role: str | None = None,
) -> None:
    if not DIGEST.fullmatch(expected_digest):
        raise ValueError("expected digest must be a sha256 digest")
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"release evidence is unavailable: {exc}") from exc
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected_repository):
        raise ValueError("invalid expected repository")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("invalid expected commit")
    destination_repository = public_repository(role, expected_repository)
    owner = os.environ["GITHUB_REPOSITORY_OWNER"].lower()
    if source != f"ghcr.io/{owner}/luminusos-candidates@{expected_digest}":
        raise ValueError(
            "source does not match signed image binding or candidate repository"
        )
    if public_key.resolve() != CANDIDATE_KEY.resolve():
        raise ValueError("candidate key required")
    tags = destination_tags(destination_repository, destinations, role)
    versions = tags[:1]
    candidate_digest = expected_digest
    if role is not None:
        images = evidence.get("images")
        if role not in {"core", "workstation", "installer"} or not isinstance(
            images, dict
        ):
            raise ValueError("invalid image role or missing image bindings")
        expected_source = images.get(role)
        workstation = images.get("workstation")
        if not isinstance(expected_source, str) or not isinstance(workstation, str):
            raise ValueError("missing signed image binding")
        if source != expected_source or not source.endswith("@" + expected_digest):
            raise ValueError("source does not match signed image binding")
        if not re.search(r"@sha256:[0-9a-f]{64}\Z", workstation):
            raise ValueError("invalid workstation binding")
        candidate_digest = workstation.split("@", 1)[1]
    errors = validate_candidate(
        evidence, candidate_digest, expected_repository, expected_commit
    )
    if errors:
        raise ValueError("release evidence rejected: " + "; ".join(errors))
    if not public_key.is_file():
        raise ValueError(f"trusted public key not found: {public_key}")
    if not evidence_signature.is_file():
        raise ValueError("signed evidence is required")
    subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(public_key),
            "--signature",
            str(evidence_signature),
            str(evidence_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    verify_evidence_artifacts(evidence, evidence_path.parent)
    source_digest = subprocess.run(
        ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{source}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if source_digest != expected_digest:
        raise ValueError(f"registry returned an invalid digest for {source}")
    repository = source.split("@", 1)[0] if "@" in source else source.rsplit(":", 1)[0]
    immutable_source = f"{repository}@{source_digest}"
    subprocess.run(
        ["cosign", "verify", "--key", str(public_key), immutable_source],
        check=True,
        capture_output=True,
        text=True,
    )
    version_destination = f"{destination_repository}:{versions[0]}"
    current = inspect_version(version_destination)
    if current is not None and current != expected_digest:
        raise ValueError("version tag already references a different digest")

    def copy(destination: str) -> None:
        subprocess.run(
            [
                "skopeo",
                "copy",
                "--all",
                "--preserve-digests",
                f"docker://{immutable_source}",
                f"docker://{destination}",
            ],
            check=True,
        )
        actual = subprocess.run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{destination}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != source_digest:
            raise ValueError(f"promotion changed digest for {destination}: {actual}")

    copy(version_destination)
    immutable_destination = f"{destination_repository}@{expected_digest}"
    subprocess.run(
        [
            "cosign",
            "sign",
            "--yes",
            "--key",
            "env://COSIGN_PRIVATE_KEY",
            immutable_destination,
        ],
        check=True,
    )
    subprocess.run(
        ["cosign", "verify", "--key", str(OFFICIAL_KEY), immutable_destination],
        check=True,
        capture_output=True,
        text=True,
    )
    for destination in destinations:
        if destination != version_destination:
            copy(destination)
    for destination in destinations:
        actual = subprocess.run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{destination}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != expected_digest:
            raise ValueError(f"destination tag changed after promotion: {destination}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--evidence-signature", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument(
        "--image-kind", choices=("core", "workstation", "installer"), required=True
    )
    parser.add_argument("destinations", nargs="+")
    args = parser.parse_args()
    try:
        promote(
            args.source,
            args.expected_digest,
            args.destinations,
            args.public_key,
            args.evidence,
            args.evidence_signature,
            args.repository,
            args.commit,
            args.image_kind,
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"promotion refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
