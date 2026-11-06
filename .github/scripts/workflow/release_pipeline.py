"""Import and bind signed release candidates and trusted validation evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

CHECKS = (
    "sirius_install",
    "first_boot",
    "live_isolation",
    "expected_key",
    "unsigned_rejected",
    "foreign_key_rejected",
    "update",
    "rollback",
    "selinux_enforcing",
    "firewall",
    "secure_boot",
)
GATES = ("quality", "boot", "signature", "sbom", "vulnerability")
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
GIB = 1024**3
MAX_FILE = 20 * GIB
MAX_ARCHIVE = 64 * GIB
MAX_FILES = 1000
CHUNK_SIZE = 1024 * 1024


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def size_limit(variable: str, maximum: int) -> int:
    value = os.environ.get(variable)
    if value is None:
        return maximum
    require(value.isascii() and value.isdigit(), f"invalid {variable}")
    number = int(value)
    require(0 < number <= maximum, f"invalid {variable}")
    return number


def require_space(directory: Path, size: int) -> None:
    require(shutil.disk_usage(directory).free >= size, "insufficient free disk space")


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"not an object: {path}")
    return value


def relative(value: object) -> PurePosixPath:
    require(isinstance(value, str) and bool(value), "invalid relative path")
    require("\\" not in value and "\x00" not in value, "invalid relative path")
    parts = value.split("/")
    require(all(p not in ("", ".", "..") for p in parts), "invalid relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute(), "absolute path forbidden")
    return path


def safe_file(base: Path, name: object) -> Path:
    path = base
    for part in relative(name).parts:
        path = path / part
        require(not path.is_symlink(), f"symlink forbidden: {path}")
    require(path.is_file(), f"missing file: {path}")
    return path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_file(
    base: Path, name: object, expected: object, nonempty: bool = False
) -> Path:
    require(isinstance(expected, str) and SHA.fullmatch(expected), "invalid sha256")
    path = safe_file(base, name)
    require(not nonempty or path.stat().st_size > 0, f"empty evidence: {path}")
    require(digest(path) == expected, f"checksum mismatch: {path}")
    return path


def verify(path: Path, key: Path) -> None:
    require(key.is_file(), "public key missing")
    sig = safe_file(path.parent, path.name + ".sig")
    subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(key),
            "--signature",
            str(sig),
            str(path),
        ],
        check=True,
        capture_output=True,
    )


def sign(path: Path, key: Path) -> None:
    signature = Path(str(path) + ".sig")
    require(not signature.is_symlink(), "symlink signature destination")
    signature.unlink(missing_ok=True)
    subprocess.run(
        [
            "cosign",
            "sign-blob",
            "--yes",
            "--key",
            "env://COSIGN_PRIVATE_KEY",
            "--output-signature",
            str(path) + ".sig",
            str(path),
        ],
        check=True,
        capture_output=True,
    )
    verify(path, key)


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), "symlink output destination")
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def candidate(path: Path, key: Path) -> dict:
    safe_file(path.parent, path.name)
    verify(path, key)
    c = load(path)
    validate_candidate(c, path.parent)
    return c


def validate_candidate(c: dict, directory: Path) -> None:
    require(
        c.get("version") == 1 and type(c.get("version")) is int,
        "invalid candidate version",
    )
    repo = c.get("repository")
    require(isinstance(repo, str) and REPO.fullmatch(repo), "invalid repository")
    require(
        isinstance(c.get("source_sha"), str) and COMMIT.fullmatch(c["source_sha"]),
        "invalid source sha",
    )
    require(type(c.get("run_id")) is int and c["run_id"] > 0, "invalid source run")
    require(c.get("channel") in ("testing", "stable"), "invalid channel")
    for field in ("version_tag", "build_version"):
        require(
            isinstance(c.get(field), str)
            and re.fullmatch(r"[A-Za-z0-9_.-]+", c[field]),
            f"invalid {field}",
        )
    require(
        isinstance(c.get("fedora_version"), str)
        and re.fullmatch(r"[0-9]+", c["fedora_version"]),
        "invalid fedora version",
    )
    require(
        isinstance(c.get("fedora_bootc_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", c["fedora_bootc_digest"]),
        "invalid bootc digest",
    )
    images = c.get("images")
    require(
        isinstance(images, dict)
        and set(images) == {"core", "workstation", "installer"},
        "invalid images",
    )
    owner = repo.split("/")[0].lower()
    for name, image in images.items():
        image_name = {
            "core": "luminusos",
            "workstation": "luminusos-workstation",
            "installer": "luminusos-workstation",
        }[name]
        require(
            isinstance(image, str)
            and re.fullmatch(
                rf"ghcr\.io/{re.escape(owner)}/{image_name}@sha256:[0-9a-f]{{64}}",
                image,
            ),
            f"invalid {name} image",
        )
    artifacts = c.get("artifacts")
    require(
        isinstance(artifacts, dict) and bool(artifacts), "missing candidate artifacts"
    )
    for name, value in artifacts.items():
        checked_file(directory, name, value)


def create_candidate(metadata: Path, directory: Path, output: Path, key: Path) -> dict:
    require(
        directory.is_dir() and not directory.is_symlink(), "invalid artifact directory"
    )
    require(
        output.name == "candidate.json"
        and output.parent.resolve() == directory.resolve(),
        "output must be candidate.json in artifact directory",
    )
    require(
        not output.is_symlink() and not Path(str(output) + ".sig").is_symlink(),
        "symlink candidate destination",
    )
    c = load(metadata)
    fields = {
        "version",
        "repository",
        "source_sha",
        "run_id",
        "channel",
        "version_tag",
        "build_version",
        "fedora_version",
        "fedora_bootc_digest",
        "images",
    }
    require(set(c) == fields, "invalid metadata fields")
    require(
        c.get("repository") == os.environ.get("GITHUB_REPOSITORY")
        and os.environ.get("GITHUB_REF") == "refs/heads/main",
        "untrusted producer repository/ref",
    )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    require(
        run_id.isascii()
        and run_id.isdigit()
        and type(c.get("run_id")) is int
        and c["run_id"] == int(run_id),
        "producer run mismatch",
    )
    require(
        c.get("source_sha") == os.environ.get("GITHUB_SHA"), "producer source mismatch"
    )
    artifacts = {}

    def raise_walk_error(error: OSError) -> None:
        raise error

    for root, dirs, files in os.walk(
        directory, followlinks=False, onerror=raise_walk_error
    ):
        for name in (*dirs, *files):
            item = Path(root) / name
            require(not item.is_symlink(), f"symlink forbidden: {item}")
        for name in files:
            item = Path(root) / name
            rel = item.relative_to(directory).as_posix()
            relative(rel)
            if name in ("candidate.json", "candidate.json.sig") or item == output:
                continue
            if item.suffix.lower() in {
                ".iso",
                ".qcow2",
                ".ppm",
                ".png",
                ".json",
                ".log",
                ".sig",
                ".txt",
            }:
                require(item.is_file(), f"invalid artifact: {item}")
                artifacts[rel] = digest(item)
    c["artifacts"] = artifacts
    validate_candidate(c, directory)
    write(output, c)
    sign(output, key)
    return c


def candidate_outputs(c: dict, path: Path) -> None:
    outputs = (
        {f"{name}_candidate": image for name, image in c["images"].items()}
        | {
            k: c[k]
            for k in (
                "source_sha",
                "version_tag",
                "build_version",
                "fedora_version",
                "fedora_bootc_digest",
            )
        }
        | {"candidate_file": str(path)}
    )
    if os.environ.get("GITHUB_OUTPUT"):
        require(
            all(
                "\n" not in str(value) and "\r" not in str(value)
                for value in outputs.values()
            ),
            "invalid output value",
        )
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.writelines(f"{k}={value}\n" for k, value in outputs.items())
    print(json.dumps(outputs))


def run_info(repository: str, run_id: int, workflows: set[str]) -> dict:
    require(
        bool(REPO.fullmatch(repository)) and run_id > 0, "invalid repository or run id"
    )
    run = json.loads(
        subprocess.run(
            ["gh", "api", f"repos/{repository}/actions/runs/{run_id}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    require(
        run.get("id") == run_id
        and run.get("repository", {}).get("full_name") == repository,
        "run repository/id mismatch",
    )
    require(
        run.get("head_repository", {}).get("full_name") == repository,
        "run head repository mismatch",
    )
    require(run.get("path") in workflows, "untrusted workflow")
    require(
        run.get("head_branch") == "main"
        and isinstance(run.get("head_sha"), str)
        and COMMIT.fullmatch(run["head_sha"]),
        "untrusted run ref",
    )
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "run not successful",
    )
    require(
        run.get("event") in {"workflow_dispatch", "schedule", "workflow_call"},
        "untrusted run event",
    )
    return run


def extract_archive(archive: Path, output: Path) -> None:
    file_limit = size_limit("RELEASE_MAX_FILE_BYTES", MAX_FILE)
    total_limit = size_limit("RELEASE_MAX_TOTAL_BYTES", MAX_ARCHIVE)
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        total = sum(e.file_size for e in entries)
        require(
            len(entries) <= MAX_FILES
            and total <= total_limit
            and all(e.file_size <= file_limit for e in entries),
            "archive too large",
        )
        output.mkdir(parents=True, exist_ok=True)
        require_space(output, total)
        seen: set[str] = set()
        for item in entries:
            name = item.filename.rstrip("/")
            rel = relative(name)
            require(name not in seen, "duplicate archive path")
            seen.add(name)
            mode = item.external_attr >> 16
            require(
                not stat.S_ISLNK(mode)
                and (not stat.S_IFMT(mode) or stat.S_ISREG(mode) or stat.S_ISDIR(mode)),
                "unsafe archive entry",
            )
            dest = output.joinpath(*rel.parts)
            for parent in (dest, *dest.parents):
                if parent == output.parent:
                    break
                require(not parent.is_symlink(), "symlink in extraction path")
            if item.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(item) as src, dest.open("xb") as dst:
                    written = 0
                    while chunk := src.read(CHUNK_SIZE):
                        written += len(chunk)
                        require(
                            written <= item.file_size and written <= file_limit,
                            "archive entry exceeds declared size",
                        )
                        dst.write(chunk)
                    require(written == item.file_size, "archive entry size mismatch")


def download(repository: str, run_id: int, name: str, output: Path) -> None:
    result = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    pages = json.loads(result.stdout)
    artifacts = [
        a
        for page in pages
        for a in page.get("artifacts", [])
        if a.get("name") == name and not a.get("expired")
    ]
    require(
        len(artifacts) == 1 and type(artifacts[0].get("id")) is int,
        "expected exactly one artifact",
    )
    total_limit = size_limit("RELEASE_MAX_TOTAL_BYTES", MAX_ARCHIVE)
    require(
        type(artifacts[0].get("size_in_bytes")) is int
        and 0 < artifacts[0]["size_in_bytes"] <= total_limit,
        "invalid artifact size",
    )
    require(
        not output.exists()
        or (output.is_dir() and not output.is_symlink() and not any(output.iterdir())),
        "output directory must be empty",
    )
    output.mkdir(parents=True, exist_ok=True)
    require_space(output, artifacts[0]["size_in_bytes"])
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        archive = Path(temp) / "artifact.zip"
        with subprocess.Popen(
            [
                "gh",
                "api",
                f"repos/{repository}/actions/artifacts/{artifacts[0]['id']}/zip",
            ],
            stdout=subprocess.PIPE,
        ) as process:
            try:
                written = 0
                with archive.open("wb") as stream:
                    assert process.stdout is not None
                    while chunk := process.stdout.read(CHUNK_SIZE):
                        written += len(chunk)
                        require(written <= total_limit, "archive too large")
                        require_space(Path(temp), len(chunk))
                        stream.write(chunk)
                require(process.wait() == 0, "artifact download failed")
                require(written > 0, "empty artifact download")
            except BaseException:
                process.kill()
                process.wait()
                raise
        extract_archive(archive, output)


def binding(c: dict) -> dict:
    return {k: c[k] for k in ("repository", "source_sha", "images", "artifacts")} | {
        "source_run_id": c["run_id"],
        "candidate_digest": c["images"]["workstation"].split("@", 1)[1],
    }


def timestamp(value: object) -> dt.datetime:
    require(isinstance(value, str), "timestamp must be a string")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    require(
        parsed.tzinfo is not None and parsed.utcoffset() is not None,
        "timestamp must have timezone",
    )
    return parsed


def validate_receipts(receipts: object, base: Path, c: dict) -> None:
    require(
        isinstance(receipts, list) and len(receipts) == len(CHECKS), "missing receipts"
    )
    names = set()
    for r in receipts:
        require(isinstance(r, dict), "invalid receipt")
        name = r.get("name")
        require(
            isinstance(name, str) and name in CHECKS and name not in names,
            "invalid or duplicate receipt",
        )
        names.add(name)
        require(r.get("binding") == binding(c), "receipt candidate binding mismatch")
        command = r.get("command")
        require(
            isinstance(command, list)
            and bool(command)
            and all(isinstance(x, str) and bool(x) for x in command),
            "invalid receipt command",
        )
        require(
            type(r.get("exit_code")) is int and r["exit_code"] == 0, "receipt failed"
        )
        require(
            timestamp(r.get("started_at")) <= timestamp(r.get("finished_at")),
            "receipt timestamps out of order",
        )
        checked_file(base, r.get("log"), r.get("sha256"), True)


def validate_validation(path: Path, key: Path, c: dict) -> dict:
    verify(path, key)
    v = load(path)
    require(
        type(v.get("version")) is int and v["version"] == 1,
        "invalid validation version",
    )
    require(v.get("binding") == binding(c), "validation candidate mismatch")
    require(
        isinstance(v.get("runner_sha"), str) and COMMIT.fullmatch(v["runner_sha"]),
        "invalid runner sha",
    )
    require(
        type(v.get("validation_run_id")) is int and v["validation_run_id"] > 0,
        "invalid validation run id",
    )
    require(
        v.get("runner_repository") == c["repository"]
        and v.get("runner_ref") == "refs/heads/main",
        "invalid validation runner",
    )
    validate_receipts(v.get("receipts"), path.parent, c)
    return v


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create-candidate")
    for x in ("metadata", "directory", "output", "public-key"):
        create.add_argument("--" + x, required=True, type=Path)
    f = sub.add_parser("fetch-candidate")
    for x in ("repository", "run-id", "output", "public-key"):
        f.add_argument(
            "--" + x,
            required=True,
            type=int
            if x == "run-id"
            else Path
            if x in ("output", "public-key")
            else str,
        )
    f.add_argument(
        "--workflow",
        choices=[".github/workflows/publish.yml", ".github/workflows/auto-testing.yml"],
        default=None,
    )
    r = sub.add_parser("record-validation")
    for x in ("candidate", "receipts", "output", "public-key"):
        r.add_argument("--" + x, required=True, type=Path)
    v = sub.add_parser("fetch-validation")
    for x in ("repository", "run-id", "candidate", "output", "public-key"):
        v.add_argument(
            "--" + x,
            required=True,
            type=int
            if x == "run-id"
            else Path
            if x in ("candidate", "output", "public-key")
            else str,
        )
    v.add_argument(
        "--workflow", default=".github/workflows/installation-validation.yml"
    )
    e = sub.add_parser("assemble-evidence")
    for x in ("candidate", "validation", "results", "output", "public-key"):
        e.add_argument("--" + x, required=True, type=Path)
    a = parser.parse_args()
    try:
        if a.action == "create-candidate":
            c = create_candidate(a.metadata, a.directory, a.output, a.public_key)
            candidate_outputs(c, a.output)
        elif a.action == "fetch-candidate":
            workflows = (
                {a.workflow}
                if a.workflow
                else {
                    ".github/workflows/publish.yml",
                    ".github/workflows/auto-testing.yml",
                }
            )
            run = run_info(a.repository, a.run_id, workflows)
            download(a.repository, a.run_id, "release-candidate", a.output)
            path = a.output / "candidate.json"
            c = candidate(path, a.public_key)
            require(
                c["repository"] == a.repository
                and c["run_id"] == a.run_id
                and c["source_sha"] == run["head_sha"],
                "candidate run mismatch",
            )
            candidate_outputs(c, path)
        elif a.action == "record-validation":
            c = candidate(a.candidate, a.public_key)
            require(
                os.environ.get("GITHUB_REPOSITORY") == c["repository"]
                and os.environ.get("GITHUB_REF") == "refs/heads/main",
                "untrusted executor repository/ref",
            )
            runner_sha = os.environ.get("GITHUB_SHA", "")
            run_id = os.environ.get("GITHUB_RUN_ID", "")
            require(
                bool(COMMIT.fullmatch(runner_sha))
                and run_id.isdigit()
                and int(run_id) > 0,
                "invalid executor metadata",
            )
            receipts = [load(p) for p in sorted(a.receipts.glob("*.json"))]
            validate_receipts(receipts, a.receipts, c)
            require(
                a.output.parent.resolve() == a.receipts.resolve(),
                "validation output must be in receipts directory",
            )
            value = {
                "version": 1,
                "binding": binding(c),
                "runner_repository": c["repository"],
                "runner_ref": "refs/heads/main",
                "runner_sha": runner_sha,
                "validation_run_id": int(run_id),
                "receipts": receipts,
            }
            write(a.output, value)
            sign(a.output, a.public_key)
            print(json.dumps({"validation_file": str(a.output)}))
        elif a.action == "fetch-validation":
            require(
                a.workflow == ".github/workflows/installation-validation.yml",
                "workflow not locally allowlisted",
            )
            c = candidate(a.candidate, a.public_key)
            require(c["repository"] == a.repository, "candidate repository mismatch")
            run = run_info(a.repository, a.run_id, {a.workflow})
            download(a.repository, a.run_id, "installation-validation", a.output)
            path = a.output / "validation.json"
            value = validate_validation(path, a.public_key, c)
            require(
                value["validation_run_id"] == a.run_id
                and value["runner_sha"] == run["head_sha"],
                "validation run mismatch",
            )
            print(json.dumps({"validation_file": str(path)}))
        else:
            c = candidate(a.candidate, a.public_key)
            validation = validate_validation(a.validation, a.public_key, c)
            results = load(a.results)
            require(set(results) == set(GATES), "missing or extra gate results")
            evidence = {}
            a.output.parent.mkdir(parents=True, exist_ok=True)
            for gate in GATES:
                item = results[gate]
                require(
                    isinstance(item, dict)
                    and item.get("conclusion") == "success"
                    and item.get("binding") == binding(c),
                    f"invalid {gate} result",
                )
                source = checked_file(
                    a.results.parent, item.get("artifact"), item.get("sha256"), True
                )
                dest = a.output.parent / "evidence" / gate / source.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                require(not dest.is_symlink(), "symlink evidence destination")
                if source.resolve() != dest.resolve():
                    shutil.copyfile(source, dest)
                evidence[gate] = {
                    "artifact": dest.relative_to(a.output.parent).as_posix(),
                    "sha256": digest(dest),
                    "candidate_digest": binding(c)["candidate_digest"],
                }
            dest = a.output.parent / "evidence" / "installation" / "validation.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            require(not dest.is_symlink(), "symlink evidence destination")
            if a.validation.resolve() != dest.resolve():
                shutil.copyfile(a.validation, dest)
            signature = safe_file(a.validation.parent, a.validation.name + ".sig")
            shutil.copyfile(signature, dest.with_name("validation.json.sig"))
            for receipt in validation["receipts"]:
                source = safe_file(a.validation.parent, receipt["log"])
                target = dest.parent.joinpath(*relative(receipt["log"]).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                require(not target.is_symlink(), "symlink evidence destination")
                if source.resolve() != target.resolve():
                    shutil.copyfile(source, target)
            evidence["installation"] = {
                "artifact": dest.relative_to(a.output.parent).as_posix(),
                "sha256": digest(dest),
                "candidate_digest": binding(c)["candidate_digest"],
            }
            value = {
                "repository": c["repository"],
                "candidate_digest": binding(c)["candidate_digest"],
                "tested_digest": binding(c)["candidate_digest"],
                "source": {
                    "repository": c["repository"],
                    "ref": "refs/heads/main",
                    "commit": c["source_sha"],
                    "run_id": c["run_id"],
                },
                "images": c["images"],
                "artifacts": c["artifacts"],
                "gates": {gate: True for gate in (*GATES, "installation")},
                "evidence": evidence,
            }
            write(a.output, value)
            sign(a.output, a.public_key)
            print(json.dumps({"evidence_file": str(a.output)}))
        return 0
    except (
        ValueError,
        OSError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"release pipeline rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
