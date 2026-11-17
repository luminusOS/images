"""Carry a testing candidate through installation validation to publication.

Runs on workflow_run after Auto Testing. Events created with GITHUB_TOKEN start
no workflows except workflow_dispatch, so this job dispatches validation,
waits for that exact run, and then dispatches publication itself instead of
relying on a second workflow_run. Every dispatched workflow re-verifies its
inputs, signatures and run identities; this step only decides when to go on.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

AUTO_TESTING = ".github/workflows/auto-testing.yml"
POLL_SECONDS = 60
# The job may run 360 minutes; leave room to report a timeout.
BUDGET_SECONDS = 345 * 60
MAX_PAGES = 10


class GitHub:
    def __init__(self, repository: str):
        self.repository = repository

    def api(self, path: str, *args: str) -> dict:
        result = subprocess.run(
            ["gh", "api", *args, f"repos/{self.repository}/{path}"],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def artifact_names(self, run_id: int) -> list[str]:
        page = self.api(f"actions/runs/{run_id}/artifacts?per_page=100")
        return [a["name"] for a in page["artifacts"] if a.get("expired") is False]

    def candidate_runs_after(self, run_id: int) -> list[int]:
        # Only Auto Testing candidates count: each has its own chain, so stepping
        # aside for one never leaves the channel without a release in progress.
        newer = []
        for page in range(1, MAX_PAGES + 1):
            runs = self.api(
                "actions/workflows/auto-testing.yml/runs"
                f"?branch=main&status=success&per_page=100&page={page}"
            )["workflow_runs"]
            for item in runs:
                if item["id"] > run_id and "release-candidate" in self.artifact_names(
                    item["id"]
                ):
                    newer.append(item["id"])
            if not runs or min(item["id"] for item in runs) <= run_id:
                return newer
        raise ValueError("cannot rule out newer candidates")

    def run(self, run_id: int) -> dict:
        return self.api(f"actions/runs/{run_id}")

    def dispatch(self, workflow: str, inputs: dict[str, str]) -> int:
        fields = ["-X", "POST", "-f", "ref=main", "-F", "return_run_details=true"]
        for key, value in inputs.items():
            fields += ["-f", f"inputs[{key}]={value}"]
        response = self.api(f"actions/workflows/{workflow}/dispatches", *fields)
        run_id = response.get("workflow_run_id")
        if type(run_id) is not int or run_id <= 0:
            raise ValueError(f"dispatch of {workflow} returned no run")
        return run_id


def trusted(run: dict, repository: str) -> bool:
    return (
        str(run.get("path", "")).split("@", 1)[0] == AUTO_TESTING
        and run.get("conclusion") == "success"
        and run.get("head_branch") == "main"
        and run.get("event") in ("schedule", "workflow_dispatch")
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
    )


def wait(
    github, run_id: int, *, deadline: float, sleep=time.sleep, clock=time.monotonic
):
    while clock() < deadline:
        try:
            run = github.run(run_id)
        except subprocess.CalledProcessError as error:
            # A fresh dispatch can 404 briefly and a long poll meets the odd
            # 5xx; neither says anything about the run itself.
            print(f"polling run {run_id} failed ({error}); retrying", flush=True)
            run = {}
        if run.get("status") == "completed":
            return run.get("conclusion")
        sleep(POLL_SECONDS)
    raise ValueError(f"run {run_id} did not finish in time")


def resume_hint(candidate: int, validation: int) -> str:
    return (
        "resume by hand with: gh workflow run publish.yml -f channel=testing"
        f" -f candidate_run_id={candidate} -f validation_run_id={validation}"
    )


def advance(
    run: dict, repository: str, github, *, wait_for=wait, clock=time.monotonic
) -> int | None:
    deadline = clock() + BUDGET_SECONDS
    if not trusted(run, repository):
        print("not a successful main Auto Testing run; nothing to do")
        return None
    candidate = run["id"]
    if "release-candidate" not in github.artifact_names(candidate):
        print(f"run {candidate} produced no release candidate; nothing to do")
        return None
    validation = github.dispatch(
        "installation-validation.yml", {"candidate_run_id": str(candidate)}
    )
    print(f"validating candidate {candidate} in run {validation}", flush=True)
    try:
        conclusion = wait_for(github, validation, deadline=deadline)
    except ValueError as error:
        raise ValueError(f"{error}; {resume_hint(candidate, validation)}") from None
    if conclusion != "success":
        raise ValueError(f"validation run {validation} ended with {conclusion}")
    newer = github.candidate_runs_after(candidate)
    if newer:
        print(f"candidate {candidate} is superseded by {sorted(newer)}; not publishing")
        return None
    publication = github.dispatch(
        "publish.yml",
        {
            "channel": "testing",
            "candidate_run_id": str(candidate),
            "validation_run_id": str(validation),
        },
    )
    print(f"publishing candidate {candidate} in run {publication}", flush=True)
    try:
        conclusion = wait_for(github, publication, deadline=deadline)
    except ValueError as error:
        raise ValueError(f"{error}; check run {publication}") from None
    if conclusion != "success":
        raise ValueError(f"publication run {publication} ended with {conclusion}")
    print(f"published candidate {candidate}")
    return publication


def main() -> int:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repository = os.environ["GITHUB_REPOSITORY"]
    try:
        advance(event["workflow_run"], repository, GitHub(repository))
    except (KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"testing release chain failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
