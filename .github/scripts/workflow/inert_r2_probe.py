import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = "luminusOS/images"
REPOSITORY_ID = 1118572971
WORKFLOW = ".github/workflows/publish.yml"
MARKER = "LUMINUS_IMAGES_R2_HANDOFF_V1="
ENDPOINT = "https://89e6fc75aed6d04cd84a0c7d11a5594e.r2.cloudflarestorage.com"
PRIVATE_BUCKET = "luminus-images-staging"
PAYLOAD = b"luminusos-private-r2-probe-v1\n"
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DECIMAL = re.compile(r"[1-9][0-9]*\Z")
Runner = Callable[..., subprocess.CompletedProcess[str]]


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Context:
    run_id: str
    run_attempt: str
    source_sha: str

    @property
    def key(self) -> str:
        return f"inert-r2/images-{REPOSITORY_ID}/{self.run_id}/{self.run_attempt}/payload.bin"


def _context(env: Mapping[str, str]) -> Context:
    required = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
        "INERT_R2_PROBE": "true",
    }
    require(
        all(env.get(key) == value for key, value in required.items()),
        "inert images workflow context rejected",
    )
    require(
        not env.get("GITHUB_HEAD_REF") and not env.get("GITHUB_BASE_REF"),
        "pull request context rejected",
    )
    run_id, attempt, sha = (
        env.get(name, "")
        for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    )
    require(
        all(
            isinstance(value, str) and DECIMAL.fullmatch(value)
            for value in (run_id, attempt)
        ),
        "run identity rejected",
    )
    require(
        isinstance(sha, str)
        and COMMIT.fullmatch(sha)
        and env.get("GITHUB_WORKFLOW_SHA") == sha,
        "workflow commit rejected",
    )
    return Context(run_id, attempt, sha)


def execute(
    mode: str, env: Mapping[str, str], runner: Runner = subprocess.run
) -> dict[str, Any] | None:
    """Transfer only fixed inert bytes; workflow guards and credentials stay caller-owned."""
    require(mode in ("upload", "record"), "inert operation rejected")
    context = _context(env)
    credentials = tuple(
        env.get(name, "")
        for name in ("R2_PROBE_ACCESS_KEY_ID", "R2_PROBE_SECRET_ACCESS_KEY")
    )
    require(
        all(
            isinstance(value, str) and re.fullmatch(r"[!-~]{1,256}", value)
            for value in credentials
        ),
        "inert credentials missing or invalid",
    )
    with tempfile.TemporaryDirectory(prefix="luminus-images-inert-") as temporary:
        home = Path(temporary)
        aws_env = {
            "PATH": env.get("PATH") or os.defpath,
            "HOME": str(home),
            "TMPDIR": str(home),
            "AWS_ACCESS_KEY_ID": credentials[0],
            "AWS_SECRET_ACCESS_KEY": credentials[1],
            "AWS_DEFAULT_REGION": "auto",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_PAGER": "",
            "AWS_MAX_ATTEMPTS": "1",
        }

        def aws(operation: str, args: list[str]) -> subprocess.CompletedProcess[str]:
            return runner(
                [
                    "aws",
                    "--no-cli-pager",
                    "--endpoint-url",
                    ENDPOINT,
                    "s3api",
                    operation,
                    "--bucket",
                    PRIVATE_BUCKET,
                    "--key",
                    context.key,
                    *args,
                ],
                env=aws_env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        if mode == "upload":
            initial = aws("head-object", [])
            require(
                initial.returncode != 0
                and re.search(
                    r"An error occurred \((404|NoSuchKey|NotFound)\)",
                    initial.stderr or "",
                ),
                "inert object preflight rejected",
            )
            payload = home / "payload.bin"
            payload.write_bytes(PAYLOAD)
            uploaded = aws(
                "put-object", ["--body", str(payload), "--if-none-match", "*"]
            )
            require(uploaded.returncode == 0, "inert conditional upload failed")
        readback = home / "readback.bin"
        downloaded = aws(
            "get-object", ["--range", f"bytes=0-{len(PAYLOAD)}", str(readback)]
        )
        require(downloaded.returncode == 0, "inert object read failed")
        with readback.open("rb") as stream:
            require(
                stream.read(len(PAYLOAD) + 1) == PAYLOAD, "inert object bytes rejected"
            )
    if mode == "upload":
        return None
    return {
        "schema": 1,
        "kind": "inert-r2-handoff-record",
        "production_ready": False,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "source_sha": context.source_sha,
        "bucket": PRIVATE_BUCKET,
        "key": context.key,
        "payload_sha256": PAYLOAD_SHA256,
        "object_size": len(PAYLOAD),
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    runner: Runner = subprocess.run,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in ("upload", "record"):
        print("Usage: r2_images_producer {upload|record}", file=sys.stderr)
        return 2
    try:
        record = execute(args[0], os.environ if env is None else env, runner)
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Inert R2 operation failed.", file=sys.stderr)
        return 1
    if record is not None:
        print(MARKER + json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
