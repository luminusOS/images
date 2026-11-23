"""Decide whether a stable line needs a new candidate.

Runs in Auto Stable on release/<N>. A candidate is built when the Fedora base
digest differs from the one in the line's published stable image, or when that
image's version was never released. Nothing is built while an earlier stable
candidate is still on its way to the approval gate or waiting there: its
orchestrating Auto Stable run on main, its validation, or its publish.yml run.
A duplicate would waste a build, and a second queued publish.yml run would
make GitHub cancel the one already waiting.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import published_base

ACTIVE = ("queued", "in_progress", "waiting", "pending", "requested")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def require_published_base(repository: str, fedora: str) -> None:
    try:
        published_base.newest_release(
            published_base.list_releases(repository), repository, "stable", fedora
        )
    except published_base.NoPublishedRelease as error:
        raise ValueError(
            f"{error}; start preparation with: gh workflow run publish.yml "
            f"--repo {repository} --ref release/{fedora} "
            "-f channel=stable -f artifacts=full"
        ) from None


def gh(path: str) -> dict:
    result = subprocess.run(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def in_flight(branch: str, ignored: set[int]) -> list[int]:
    """Active runs that may carry a stable candidate of this line."""
    queries = [
        (workflow, branch)
        for workflow in (
            "publish.yml",
            "installation-validation.yml",
            "auto-stable.yml",
        )
    ] + [("auto-stable.yml", "main")]
    runs = []
    # The runs list can omit the newest run when filtered by status, so the
    # status is checked here on the most recent runs of each branch.
    for workflow, ref in queries:
        page = gh(f"actions/workflows/{workflow}/runs?branch={ref}&per_page=100")
        runs += [
            r["id"]
            for r in page["workflow_runs"]
            if r.get("status") in ACTIVE and r["id"] not in ignored
        ]
    return sorted(set(runs))


def published(image: str) -> tuple[str, str]:
    """Return the base digest and version labels, or blanks if never built.

    The published images are public, so no registry login is needed.
    """
    result = subprocess.run(
        ["skopeo", "inspect", "--no-tags", "--retry-times", "3", f"docker://{image}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # Only a missing tag means never built; any other error must not
        # look like a change and start a build.
        if re.search(
            r"manifest unknown|name unknown|not found", result.stderr, re.IGNORECASE
        ):
            return "", ""
        raise ValueError(f"cannot inspect {image}: {result.stderr.strip()}")
    labels = json.loads(result.stdout).get("Labels") or {}
    return (
        labels.get("org.opencontainers.image.base.digest", ""),
        labels.get("org.opencontainers.image.version", ""),
    )


def released(version: str) -> bool:
    if not version:
        return False
    refs = gh(f"git/matching-refs/tags/{version}")
    return any(item.get("ref") == f"refs/tags/{version}" for item in refs)


def decide(
    live: str, current: str, version: str, is_released: bool, running: list[int]
) -> bool:
    if not DIGEST.fullmatch(live):
        raise ValueError(f"invalid live Fedora bootc digest {live!r}")
    if running:
        print(f"stable runs {running} are still in flight; not building")
        return False
    if live != current:
        print(f"Fedora base changed: published '{current}', live {live}")
        return True
    if not is_released:
        print(f"published image version '{version}' has no release; rebuilding")
        return True
    print("Fedora base unchanged and released; nothing to build")
    return False


def parse_lines(config: str) -> set[str]:
    match = re.search(r'^STABLE_LINES="([0-9 ]*)"$', config, re.MULTILINE)
    if not match:
        raise ValueError("main defines no STABLE_LINES")
    lines = set(match.group(1).split())
    if not all(re.fullmatch(r"[1-9][0-9]*", line) for line in lines):
        raise ValueError("invalid STABLE_LINES")
    return lines


def stable_lines() -> set[str]:
    subprocess.run(
        ["git", "fetch", "--quiet", "--depth=1", "origin", "main"], check=True
    )
    config = subprocess.check_output(
        ["git", "show", "FETCH_HEAD:config/releases.env"], text=True
    )
    return parse_lines(config)


def main() -> int:
    ref = os.environ["GITHUB_REF"]
    line = re.fullmatch(r"refs/heads/release/([1-9][0-9]*)", ref)
    try:
        if not line or line.group(1) not in stable_lines():
            raise ValueError(f"{ref} is not an active stable line")
        fedora = line.group(1)
        require_published_base(os.environ["GITHUB_REPOSITORY"], fedora)
        owner = os.environ["GITHUB_REPOSITORY_OWNER"].lower()
        live = subprocess.check_output(
            [sys.executable, "tools/fedora-bootc-digest.py", fedora], text=True
        ).strip()
        current, version = published(f"ghcr.io/{owner}/luminusos-workstation:{fedora}")
        # The orchestrating main run that dispatched this one is in flight by
        # design; only it may be ignored besides this run.
        orchestrator = os.environ.get("ORCHESTRATOR_RUN_ID", "")
        if not re.fullmatch(r"(?:[1-9][0-9]*)?", orchestrator):
            raise ValueError("invalid orchestrator run id")
        ignored = {int(os.environ["GITHUB_RUN_ID"])}
        if orchestrator:
            ignored.add(int(orchestrator))
        build = decide(
            live,
            current,
            version,
            released(version),
            in_flight(f"release/{fedora}", ignored),
        )
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"stable detection failed: {error}", file=sys.stderr)
        return 1
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        print(f"build={str(build).lower()}", file=out)
        print(f"fedora_version={fedora}", file=out)
        print(f"fedora_bootc_digest={live}", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
