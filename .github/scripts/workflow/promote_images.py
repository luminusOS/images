"""Promote already-built OCI images without rebuilding their content."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_policy import REQUIRED_GATES, validate_candidate

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


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
    source_repository = (
        source.split("@", 1)[0] if "@" in source else source.rsplit(":", 1)[0]
    )
    if not destinations or any(
        not re.fullmatch(
            re.escape(source_repository) + r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", dest
        )
        for dest in destinations
    ):
        raise ValueError("destination must be a tag in the source repository")
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
    for destination in destinations:
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
