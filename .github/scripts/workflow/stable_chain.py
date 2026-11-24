"""Carry stable candidates from detection to the approval gate.

Runs in Auto Stable on main, one job per active release line. It dispatches
Auto Stable on the line and waits for it, then takes the run's candidate,
dispatches validation on the line, waits for it, resumes publish.yml there
and stops once that run waits for the protected stable environment.
The orchestration stays in one main run because runs dispatched with the
workflow token raise no workflow_run events, and because the run stays in
flight until the gate, so the line's detector does not prepare a duplicate.
Approving or rejecting the deployment stays with the environment's reviewers;
nothing here can publish stable.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import release_chain
from stable_detect import FirstReleasePending, require_published_base

AUTO_STABLE = ".github/workflows/auto-stable.yml"
LINE = re.compile(r"release/([1-9][0-9]*)")


def stable_lines(config: Path) -> set[str]:
    for line in config.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r'STABLE_LINES="([0-9 ]*)"', line.strip())
        if match:
            return set(match.group(1).split())
    raise ValueError("config/releases.env defines no STABLE_LINES")


def trusted(run: dict, repository: str, lines: set[str]) -> str | None:
    """Return the release line of a successful Auto Stable candidate run."""
    line = LINE.fullmatch(str(run.get("head_branch", "")))
    if (
        str(run.get("path", "")).split("@", 1)[0] == AUTO_STABLE
        and run.get("conclusion") == "success"
        and run.get("event") == "workflow_dispatch"
        and line
        and line.group(1) in lines
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
    ):
        return line.group(0)
    return None


def wait_for_approval(
    github,
    run_id: int,
    *,
    deadline: float,
    sleep=time.sleep,
    clock=time.monotonic,
) -> str:
    while clock() < deadline:
        try:
            run = github.run(run_id)
        except subprocess.CalledProcessError as error:
            print(f"polling run {run_id} failed ({error}); retrying", flush=True)
            run = {}
        if run.get("status") == "waiting":
            return "waiting"
        if run.get("status") == "completed":
            return str(run.get("conclusion"))
        sleep(release_chain.POLL_SECONDS)
    raise ValueError(f"run {run_id} did not reach the approval gate in time")


def version_taken(version: str, github) -> bool:
    # Stable versions are numbered from the stable tags that exist when the
    # build starts; promotion refuses to move an existing tag to other bytes.
    if github.tag_exists(version):
        print(f"{version} was already released from another build; skipping")
        return True
    return False


def advance(
    run: dict,
    repository: str,
    lines: set[str],
    github,
    *,
    scheduled: bool,
    wait_for=release_chain.wait,
    wait_for_gate=wait_for_approval,
    clock=time.monotonic,
    deadline: float | None = None,
) -> int | None:
    if deadline is None:
        deadline = clock() + release_chain.BUDGET_SECONDS
    branch = trusted(run, repository, lines)
    if branch is None:
        print("not a successful Auto Stable run on an active line; nothing to do")
        return None
    candidate = run["id"]
    if "release-candidate" not in github.artifact_names(candidate):
        print(f"run {candidate} produced no release candidate; nothing to do")
        return None
    version = (
        github.scheduled_candidate_version(run, AUTO_STABLE)
        if scheduled
        else github.candidate_version(candidate)
    )
    if version_taken(version, github):
        return None
    validation = github.dispatch(
        "installation-validation.yml", {"candidate_run_id": str(candidate)}, branch
    )
    print(f"validating candidate {candidate} in run {validation}", flush=True)
    conclusion = wait_for(github, validation, deadline=deadline)
    if conclusion != "success":
        raise ValueError(f"validation run {validation} ended with {conclusion}")
    newer = github.candidate_runs_after(candidate, "auto-stable.yml", branch)
    if newer:
        print(f"candidate {candidate} is superseded by {sorted(newer)}; stopping")
        return None
    if version_taken(version, github):
        return None
    publication = github.dispatch(
        "publish.yml",
        {
            "channel": "stable",
            "candidate_run_id": str(candidate),
            "validation_run_id": str(validation),
        },
        branch,
    )
    print(f"preparing approval of candidate {candidate} in run {publication}")
    state = wait_for_gate(github, publication, deadline=deadline)
    if state != "waiting":
        raise ValueError(f"publication run {publication} ended with {state}")
    print(
        f"run {publication} waits for approval in the stable environment;"
        " review its approval summary before approving"
    )
    return publication


def run_line(
    line: str,
    lines: set[str],
    repository: str,
    github,
    orchestrator: int,
    *,
    scheduled: bool,
    wait_for=release_chain.wait,
    wait_for_gate=wait_for_approval,
    clock=time.monotonic,
) -> int | None:
    """Prepare one line's candidate and carry it to the approval gate.

    Each line runs in its own job, so one line's build or validation time
    never eats into another's budget; both phases share this job's deadline.
    """
    if line not in lines:
        raise ValueError(f"release/{line} is not an active stable line")
    require_published_base(repository, line)
    deadline = clock() + release_chain.BUDGET_SECONDS
    run_id = github.dispatch(
        "auto-stable.yml", {"orchestrator_run_id": str(orchestrator)}, f"release/{line}"
    )
    print(f"Auto Stable for release/{line} runs as {run_id}", flush=True)
    conclusion = wait_for(github, run_id, deadline=deadline)
    if conclusion != "success":
        raise ValueError(f"Auto Stable run {run_id} ended with {conclusion}")
    return advance(
        github.run(run_id),
        repository,
        lines,
        github,
        scheduled=scheduled,
        wait_for=wait_for,
        wait_for_gate=wait_for_gate,
        clock=clock,
        deadline=deadline,
    )


def main(argv: list[str]) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    scheduled = os.environ.get("GITHUB_EVENT_NAME") == "schedule"
    try:
        lines = stable_lines(Path("config/releases.env"))
        if argv == ["lines"]:
            print(json.dumps(sorted(lines, key=int)))
            return 0
        if len(argv) != 2 or argv[0] != "line":
            raise ValueError("usage: stable_chain.py lines | line <N>")
        run_line(
            argv[1],
            lines,
            repository,
            release_chain.GitHub(repository),
            int(os.environ["GITHUB_RUN_ID"]),
            # The child is always workflow_dispatch, even for a scheduled parent.
            scheduled=scheduled,
        )
    except FirstReleasePending as pending:
        # A line waiting for its first manual full release is not a failed
        # release attempt; only the schedule treats it as a notice, and nothing
        # was dispatched.
        if not scheduled:
            print(f"stable release chain failed: {pending}", file=sys.stderr)
            return 1
        print(f"::notice::{pending}", flush=True)
        return 0
    except (
        KeyError,
        ValueError,
        OSError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
    ) as error:
        print(f"stable release chain failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
