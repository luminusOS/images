"""Validate externally collected, run-bound release evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
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
