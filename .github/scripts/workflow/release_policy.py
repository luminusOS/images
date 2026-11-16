"""Validate externally collected, run-bound release evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

REQUIRED_GATES = (
    "quality",
    "boot",
    "installation",
    "signature",
    "sbom",
    "vulnerability",
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REGISTRY_REPOSITORY = re.compile(
    r"[a-z0-9.-]+\.[a-z]{2,}(?::[0-9]+)?(?:/[a-z0-9._-]+)+\Z"
)
BASE_RISK_KIND = "fedora-bootc-upstream-signature-risk"
BASE_RISK_MAX_AGE = timedelta(days=30)


def validate_candidate(
    document: object,
    expected_digest: str | None = None,
    expected_repository: str | None = None,
    expected_commit: str | None = None,
) -> list[str]:
    if not isinstance(document, dict):
        return ["manifest must be a JSON object"]
    errors: list[str] = []
    candidate = document.get("candidate_digest")
    if not isinstance(candidate, str) or not DIGEST.fullmatch(candidate):
        errors.append("candidate_digest must be a sha256 digest")
    if expected_digest is not None and candidate != expected_digest:
        errors.append("candidate_digest does not match the requested digest")
    if (
        expected_repository is not None
        and document.get("repository") != expected_repository
    ):
        errors.append("repository does not match the requested repository")

    source = document.get("source")
    if not isinstance(source, dict):
        errors.append("source must identify the authorized evidence run")
    else:
        if source.get("repository") != document.get("repository"):
            errors.append("evidence source repository mismatch")
        if source.get("ref") != "refs/heads/main":
            errors.append("evidence must come from refs/heads/main")
        if expected_commit is not None and source.get("commit") != expected_commit:
            errors.append("evidence source commit mismatch")
        if not isinstance(source.get("run_id"), int) or source["run_id"] <= 0:
            errors.append("evidence source run_id is invalid")

    gates = document.get("gates")
    evidence = document.get("evidence")
    if not isinstance(gates, dict):
        errors.append("gates must be an object")
        gates = {}
    if not isinstance(evidence, dict):
        errors.append("evidence must contain artifacts for every gate")
        evidence = {}
    for name in REQUIRED_GATES:
        if gates.get(name) is not True:
            errors.append(f"required gate is missing or failed: {name}")
        item = evidence.get(name)
        if not isinstance(item, dict):
            errors.append(f"required gate evidence is missing: {name}")
            continue
        if not isinstance(item.get("artifact"), str) or not item["artifact"]:
            errors.append(f"gate evidence artifact is missing: {name}")
        if not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(
            item["sha256"]
        ):
            errors.append(f"gate evidence sha256 is invalid: {name}")
        if item.get("candidate_digest") != candidate:
            errors.append(f"gate evidence candidate digest mismatch: {name}")
    return errors


def _instant(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def validate_base_risk(
    record: object, base_reference: str, fedora_version: str, now: datetime
) -> list[str]:
    """Check the accepted risk of building on an upstream-unsigned Fedora base.

    The record never stands in for a signature: it only allows a digest-pinned
    reference from the recorded repository and release while it is in force.
    """
    if not isinstance(record, dict):
        return ["base risk record must be a JSON object"]
    if now.tzinfo is None:
        return ["base risk evaluation time must be timezone-aware"]
    errors: list[str] = []
    version = record.get("schema_version")
    if type(version) is not int or version != 1 or record.get("kind") != BASE_RISK_KIND:
        errors.append("base risk record kind or schema is unsupported")
    if not isinstance(record.get("owner"), str) or not record["owner"].strip():
        errors.append("base risk record needs an owner")
    mitigations = record.get("mitigations")
    if (
        not isinstance(mitigations, list)
        or not mitigations
        or not all(isinstance(item, str) and item.strip() for item in mitigations)
    ):
        errors.append("base risk record needs its mitigations")
    accepted = _instant(record.get("accepted_at"))
    expires = _instant(record.get("expires_at"))
    if accepted is None or expires is None:
        errors.append("base risk record needs timezone-aware accepted_at/expires_at")
    elif not accepted <= now < expires:
        errors.append("base risk record is not in force")
    elif expires - accepted > BASE_RISK_MAX_AGE:
        errors.append("base risk record exceeds the 30-day review window")
    repository = record.get("repository")
    if (
        not isinstance(repository, str)
        or not REGISTRY_REPOSITORY.fullmatch(repository)
        or not re.fullmatch(
            re.escape(repository) + r"@sha256:[0-9a-f]{64}", base_reference
        )
    ):
        errors.append("base reference is not digest-pinned to the recorded repository")
    release = record.get("fedora_version")
    if not (
        isinstance(release, str)
        and isinstance(fedora_version, str)
        and release == fedora_version
    ):
        errors.append("base risk record covers a different Fedora release")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--candidate-digest", required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read release evidence: {exc}", file=sys.stderr)
        return 2
    errors = validate_candidate(manifest, args.candidate_digest)
    if errors:
        print("Refusing release promotion:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(args.candidate_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
