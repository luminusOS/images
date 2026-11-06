import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import release_pipeline

DRIVER = Path("/usr/local/libexec/luminusos/validate-candidate")
PUBLIC_KEY = Path("shared/trust/etc/pki/containers/luminusos.pub")


def reject_symlink_components(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f"symlink in path: {part}")
    return path


def trusted_driver(path=DRIVER):
    path = reject_symlink_components(path)
    for component in (path, *path.parents):
        info = component.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"untrusted driver path ownership or mode: {component}")
        if component == path:
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise ValueError("validation driver must be an executable regular file")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"driver ancestor is not a directory: {component}")
    return path


def owned_directory(path):
    path = reject_symlink_components(path)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise ValueError(f"untrusted runner directory: {path}")
    return path


def validate_output_tree(directory):
    for root, directories, files in os.walk(directory, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            info = path.lstat()
            if (
                not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o022
            ):
                raise ValueError(f"unsafe validation output: {path}")


def run_validation(candidate_dir, runner_temp, run_id, repository):
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("candidate run ID must be a positive decimal integer")
    candidate_dir = owned_directory(candidate_dir)
    runner_temp = owned_directory(runner_temp)
    driver = trusted_driver()
    candidate_path = candidate_dir / "candidate.json"
    candidate = release_pipeline.candidate(candidate_path, PUBLIC_KEY)
    if candidate["run_id"] != int(run_id) or candidate["repository"] != repository:
        raise ValueError("candidate repository or run ID mismatch")
    receipts = Path(tempfile.mkdtemp(prefix="luminusos-validation-", dir=runner_temp))
    os.chmod(receipts, 0o700)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(
            secret in key.upper()
            for secret in ("TOKEN", "SECRET", "PASSWORD", "COSIGN_PRIVATE_KEY")
        )
    }
    subprocess.run(
        [
            str(driver),
            "--candidate",
            str(candidate_path),
            "--artifacts",
            str(candidate_dir),
            "--receipts",
            str(receipts),
        ],
        check=True,
        env=environment,
    )
    owned_directory(receipts)
    validate_output_tree(receipts)
    current = release_pipeline.candidate(candidate_path, PUBLIC_KEY)
    if current != candidate:
        raise ValueError("candidate changed during validation")
    receipt_paths = sorted(receipts.glob("*.json"))
    if any(path.is_symlink() or not path.is_file() for path in receipt_paths):
        raise ValueError("invalid receipt file")
    receipt_data = [
        json.loads(path.read_text(encoding="utf-8")) for path in receipt_paths
    ]
    release_pipeline.validate_receipts(receipt_data, receipts, candidate)
    return receipts


def main():
    env = os.environ
    if (
        env.get("GITHUB_REF") != "refs/heads/main"
        or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
    ):
        raise ValueError("validation is restricted to main workflow_dispatch")
    receipts = run_validation(
        Path("candidate"),
        Path(env["RUNNER_TEMP"]),
        env["CANDIDATE_RUN_ID"],
        env["GITHUB_REPOSITORY"],
    )
    value = str(receipts)
    if "\n" in value or "\r" in value:
        raise ValueError("invalid output path")
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        print(f"receipts={value}", file=output)


if __name__ == "__main__":
    try:
        main()
    except (
        KeyError,
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        print(f"installation validation failed: {error}", file=sys.stderr)
        sys.exit(1)
