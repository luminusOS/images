"""Import and bind signed release candidates and trusted validation evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
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
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
GIB = 1024**3
MAX_FILE = 20 * GIB
MAX_ARCHIVE = 64 * GIB
MAX_FILES = 1000
MAX_CORE_BUILD_BYTES = 64 * 1024
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
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_keys,
        parse_constant=invalid_constant,
    )
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


def candidate(
    path: Path, key: Path, *, context: dict | None = None, legacy_only: bool = False
) -> dict:
    safe_file(path.parent, path.name)
    verify(path, key)
    c = load(path)
    if legacy_only:
        legacy_candidate(c)
    validate_candidate(
        c,
        path.parent,
        context=context,
        official_key_fingerprint=digest(key) if c.get("schema_version") == 2 else None,
    )
    return c


def validate_candidate(
    c: dict,
    directory: Path,
    *,
    context: dict | None = None,
    official_key_fingerprint: str | None = None,
) -> None:
    require(isinstance(c, dict), "invalid candidate object")
    if "schema_version" in c:
        require(
            type(c["schema_version"]) is int
            and c["schema_version"] == 2
            and "version" not in c,
            "invalid candidate version",
        )
        validate_core_candidate(
            c,
            directory,
            context=context,
            official_key_fingerprint=official_key_fingerprint,
        )
        return
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


def object_fields(value: object, fields: set[str], name: str) -> dict:
    require(isinstance(value, dict) and set(value) == fields, f"invalid {name} fields")
    return value


def matches(value: object, pattern: re.Pattern, name: str) -> None:
    require(isinstance(value, str) and pattern.fullmatch(value), f"invalid {name}")


def core_inputs_hash(root: Path, fedora: str, base: str) -> str:
    spec = importlib.util.spec_from_file_location(
        "release_core_reuse", Path(__file__).with_name("core_reuse.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inputs_hash(root, fedora, base)


def core_context(run: dict, source_root: Path, expected: dict) -> dict:
    """Bind trusted API run data and protected inputs to a clean source checkout.

    The caller supplies independently authorized run data and configuration, never
    values copied from the candidate. The checkout must be the producer revision.
    """
    object_fields(
        expected,
        {"fedora", "channel", "architecture", "base_digest", "policy_sha256"},
        "trusted core inputs",
    )
    matches(expected["fedora"], re.compile(r"[1-9][0-9]*\Z"), "trusted Fedora")
    matches(expected["base_digest"], DIGEST, "trusted base digest")
    matches(expected["policy_sha256"], SHA, "trusted policy hash")
    require(expected["architecture"] == "x86_64", "invalid trusted architecture")
    require(expected["channel"] in ("testing", "stable"), "invalid trusted channel")
    repository = run.get("repository", {}).get("full_name")
    run_id = run.get("id")
    require(isinstance(repository, str) and type(run_id) is int, "invalid trusted run")
    authorize_run(
        run,
        repository,
        run_id,
        {".github/workflows/publish.yml", ".github/workflows/auto-testing.yml"},
    )
    require(
        type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
        "invalid trusted run attempt",
    )
    require(
        isinstance(source_root, Path)
        and source_root.is_dir()
        and not source_root.is_symlink(),
        "missing trusted source",
    )
    head = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    require(head == run["head_sha"], "trusted source revision mismatch")
    status = subprocess.run(
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored",
            "--",
            "editions/core",
            "shared/trust",
            "shared/scripts/dnf-releasever.py",
            "shared/scripts/os-release-set.py",
            "shared/scripts/rpmdb-repair.py",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    require(not status, "dirty trusted core inputs")
    return expected | {
        "repository": repository,
        "source_sha": run["head_sha"],
        "source_ref": "refs/heads/" + run["head_branch"],
        "run_id": run_id,
        "run_attempt": run["run_attempt"],
        "workflow": run["path"],
        "inputs_sha256": core_inputs_hash(
            source_root, expected["fedora"], expected["base_digest"]
        ),
    }


def validate_core_candidate(
    c: dict,
    directory: Path,
    *,
    context: dict | None = None,
    official_key_fingerprint: str | None = None,
) -> None:
    object_fields(
        c,
        {
            "kind",
            "schema_version",
            "evidence_class",
            "identity",
            "components",
            "artifacts",
            "installed",
            "core_dependency",
            "validation_images",
        },
        "candidate v2",
    )
    require(
        type(c["schema_version"]) is int and c["schema_version"] == 2,
        "invalid candidate version",
    )
    require(c["kind"] == "candidate", "invalid candidate kind")
    require(
        c["evidence_class"] == "runtime",
        "invalid candidate version: v2 requires runtime evidence, not synthetic examples",
    )
    identity = object_fields(
        c["identity"],
        {
            "repository",
            "source_sha",
            "source_ref",
            "run_id",
            "run_attempt",
            "fedora",
            "architecture",
            "selection",
            "channel",
            "build_version",
            "base_digest",
            "core_digest",
            "policy_sha256",
        },
        "candidate identity",
    )
    require(identity["selection"] == "core", "v2 workstation/all reader requires T5")
    matches(identity["repository"], REPO, "repository")
    matches(identity["source_sha"], COMMIT, "source sha")
    for field in ("run_id", "run_attempt"):
        require(
            type(identity[field]) is int and identity[field] > 0, f"invalid {field}"
        )
    matches(identity["fedora"], re.compile(r"[1-9][0-9]*\Z"), "Fedora line")
    require(identity["architecture"] == "x86_64", "invalid architecture")
    require(identity["channel"] in ("testing", "stable"), "invalid channel")
    expected_ref = (
        "refs/heads/main"
        if identity["channel"] == "testing"
        else f"refs/heads/release/{identity['fedora']}"
    )
    require(
        identity["source_ref"] == expected_ref, "source branch/channel/Fedora mismatch"
    )
    matches(
        identity["build_version"],
        re.compile(rf"{identity['fedora']}\.[0-9]{{8}}(?:\.[1-9][0-9]*)?\Z"),
        "build version",
    )
    date = identity["build_version"].split(".")[1]
    dt.date(int(date[:4]), int(date[4:6]), int(date[6:]))
    for field in ("base_digest", "core_digest"):
        matches(identity[field], DIGEST, field)
    matches(identity["policy_sha256"], SHA, "policy hash")
    owner = identity["repository"].split("/")[0].lower()
    matches(owner, re.compile(r"[a-z0-9-]+\Z"), "image namespace")
    repository = f"ghcr.io/{owner}/luminusos"
    components = object_fields(c["components"], {"core"}, "core components")
    image = object_fields(components["core"], {"repository", "digest"}, "core image")
    require(
        image == {"repository": repository, "digest": identity["core_digest"]},
        "core image identity mismatch",
    )
    object_fields(c["artifacts"], set(), "core artifacts")
    installed = object_fields(c["installed"], {"core"}, "installed editions")["core"]
    target = ("testing-" if identity["channel"] == "testing" else "") + identity[
        "fedora"
    ]
    require(
        installed
        == {
            "edition": "core",
            "channel": identity["channel"],
            "fedora": identity["fedora"],
            "reference": f"{repository}:{target}",
            "digest": identity["core_digest"],
        },
        "installed identity mismatch",
    )
    dependency = object_fields(
        c["core_dependency"],
        {
            "mode",
            "digest",
            "evidence_sha256",
            "source_sha",
            "source_ref",
            "fedora",
            "channel",
            "architecture",
            "base_digest",
            "policy_sha256",
        },
        "core dependency",
    )
    require(dependency["mode"] == "built", "v2 core reuse requires T5")
    require(
        dependency["digest"] == identity["core_digest"],
        "core dependency digest mismatch",
    )
    for field in (
        "source_sha",
        "source_ref",
        "fedora",
        "channel",
        "architecture",
        "base_digest",
        "policy_sha256",
    ):
        require(
            dependency[field] == identity[field], f"core dependency {field} mismatch"
        )
    matches(dependency["evidence_sha256"], SHA, "core evidence hash")
    object_fields(
        context,
        {
            "repository",
            "source_sha",
            "source_ref",
            "run_id",
            "run_attempt",
            "workflow",
            "fedora",
            "channel",
            "architecture",
            "base_digest",
            "policy_sha256",
            "inputs_sha256",
        },
        "trusted core context",
    )
    for field in context.keys() - {"workflow", "inputs_sha256"}:
        require(
            type(context[field]) is type(identity[field])
            and context[field] == identity[field],
            f"trusted core {field} mismatch",
        )
    matches(context["inputs_sha256"], SHA, "trusted inputs hash")
    require(
        context["workflow"]
        in {".github/workflows/publish.yml", ".github/workflows/auto-testing.yml"},
        "untrusted core workflow",
    )
    proof_path = safe_file(directory, "core/core-build.json")
    require(
        0 < proof_path.stat().st_size <= MAX_CORE_BUILD_BYTES,
        "invalid core build proof size",
    )
    checked_file(directory, "core/core-build.json", dependency["evidence_sha256"], True)
    proof = load(proof_path)
    object_fields(
        proof,
        {
            "kind",
            "schema_version",
            "digest",
            "source_sha",
            "source_ref",
            "fedora",
            "channel",
            "architecture",
            "base_digest",
            "policy_sha256",
            "inputs_sha256",
            "run_id",
            "run_attempt",
            "workflow",
        },
        "core build proof",
    )
    require(
        proof["kind"] == "core-build"
        and type(proof["schema_version"]) is int
        and proof["schema_version"] == 2,
        "invalid core build proof kind/version",
    )
    require(proof["digest"] == identity["core_digest"], "core build digest mismatch")
    for field in proof.keys() - {"kind", "schema_version", "digest"}:
        require(
            type(proof[field]) is type(context[field])
            and proof[field] == context[field],
            f"core build {field} mismatch",
        )
    matches(official_key_fingerprint, SHA, "official key fingerprint")
    inputs = object_fields(c["validation_images"], {"core"}, "validation editions")[
        "core"
    ]
    object_fields(
        inputs, {"update", "signed", "unsigned", "foreign"}, "validation images"
    )
    for role, item in inputs.items():
        object_fields(
            item,
            {
                "digest",
                "derived_from",
                "logical_reference",
                "signing_key_fingerprint",
                "producer",
                "producer_evidence",
            },
            f"{role} image",
        )
        matches(item["digest"], DIGEST, f"{role} digest")
        matches(item["derived_from"], DIGEST, f"{role} source digest")
        require(
            item["logical_reference"] == f"{repository}@{item['digest']}",
            f"{role} logical reference mismatch",
        )
        if role == "unsigned":
            require(
                item["signing_key_fingerprint"] is None, "unsigned fixture has signer"
            )
        else:
            matches(item["signing_key_fingerprint"], SHA, f"{role} signing key")
        producer = object_fields(
            item["producer"],
            {
                "repository",
                "source_sha",
                "source_ref",
                "workflow",
                "run_id",
                "run_attempt",
            },
            f"{role} producer",
        )
        require(
            all(
                type(producer[field]) is type(context[field])
                and producer[field] == context[field]
                for field in (
                    "repository",
                    "source_sha",
                    "source_ref",
                    "workflow",
                    "run_id",
                    "run_attempt",
                )
            ),
            "validation image producer requires T5",
        )
        files = item["producer_evidence"]
        require(
            isinstance(files, list) and 0 < len(files) <= MAX_FILES,
            "missing producer evidence",
        )
        paths = set()
        for entry in files:
            object_fields(
                entry, {"path", "sha256", "size_bytes"}, "evidence descriptor"
            )
            matches(
                entry["path"],
                re.compile(
                    r"[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*\Z"
                ),
                "evidence path",
            )
            require(entry["path"] not in paths, "duplicate producer evidence")
            paths.add(entry["path"])
            require(
                type(entry["size_bytes"]) is int
                and 0 < entry["size_bytes"] <= MAX_FILE,
                "invalid evidence size",
            )
            path = safe_file(directory, entry["path"])
            require(
                path.stat().st_size == entry["size_bytes"], "evidence size mismatch"
            )
            checked_file(directory, entry["path"], entry["sha256"], True)
    b_digest = inputs["update"]["digest"]
    require(
        b_digest != identity["core_digest"]
        and inputs["update"]["derived_from"] == identity["core_digest"]
        and inputs["signed"]["digest"] == b_digest
        and all(
            inputs[role]["derived_from"] == b_digest
            for role in ("signed", "unsigned", "foreign")
        )
        and len({inputs[role]["digest"] for role in ("signed", "unsigned", "foreign")})
        == 3,
        "validation image derivation mismatch",
    )
    require(
        inputs["update"]["signing_key_fingerprint"] == official_key_fingerprint
        and inputs["signed"]["signing_key_fingerprint"] == official_key_fingerprint
        and inputs["foreign"]["signing_key_fingerprint"] != official_key_fingerprint,
        "validation image signing identity mismatch",
    )


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
    legacy_candidate(c)
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
    legacy_candidate(c)
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
    return authorize_run(run, repository, run_id, workflows)


def authorize_run(run: dict, repository: str, run_id: int, workflows: set[str]) -> dict:
    require(
        type(run.get("id")) is int
        and run["id"] == run_id
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
    matches(repository, REPO, "repository")
    require(type(run_id) is int and run_id > 0, "invalid artifact run id")
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
    require(isinstance(pages, list) and bool(pages), "invalid artifact pages")
    artifacts = []
    for page in pages:
        require(
            isinstance(page, dict) and isinstance(page.get("artifacts"), list),
            "invalid artifact page",
        )
        for artifact in page["artifacts"]:
            require(isinstance(artifact, dict), "invalid artifact metadata")
            if artifact.get("name") == name and artifact.get("expired") is False:
                artifacts.append(artifact)
    require(
        len(artifacts) == 1
        and type(artifacts[0].get("id")) is int
        and artifacts[0]["id"] > 0,
        "expected exactly one artifact",
    )
    artifact = artifacts[0]
    workflow_run = artifact.get("workflow_run")
    require(
        isinstance(workflow_run, dict)
        and type(workflow_run.get("id")) is int
        and workflow_run["id"] == run_id,
        "artifact run binding mismatch",
    )
    require(
        isinstance(artifact.get("digest"), str)
        and DIGEST.fullmatch(artifact["digest"]),
        "unsupported artifact digest: expected lowercase sha256",
    )
    total_limit = size_limit("RELEASE_MAX_TOTAL_BYTES", MAX_ARCHIVE)
    require(
        type(artifact.get("size_in_bytes")) is int
        and 0 < artifact["size_in_bytes"] <= total_limit,
        "invalid artifact size",
    )
    require(
        not output.exists()
        or (output.is_dir() and not output.is_symlink() and not any(output.iterdir())),
        "output directory must be empty",
    )
    output.mkdir(parents=True, exist_ok=True)
    require_space(output, artifact["size_in_bytes"])
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        archive = Path(temp) / "artifact.zip"
        with subprocess.Popen(
            [
                "gh",
                "api",
                f"repos/{repository}/actions/artifacts/{artifact['id']}/zip",
            ],
            stdout=subprocess.PIPE,
        ) as process:
            try:
                written = 0
                checksum = hashlib.sha256()
                with archive.open("wb") as stream:
                    assert process.stdout is not None
                    while chunk := process.stdout.read(CHUNK_SIZE):
                        written += len(chunk)
                        require(written <= total_limit, "archive too large")
                        require(
                            written <= artifact["size_in_bytes"],
                            "artifact exceeds declared size",
                        )
                        require_space(Path(temp), len(chunk))
                        stream.write(chunk)
                        checksum.update(chunk)
                require(process.wait() == 0, "artifact download failed")
                require(written == artifact["size_in_bytes"], "artifact size mismatch")
                require(
                    "sha256:" + checksum.hexdigest() == artifact["digest"],
                    "artifact digest mismatch",
                )
            except BaseException:
                process.kill()
                process.wait()
                raise
        extract_archive(archive, output)


def binding(c: dict) -> dict:
    legacy_candidate(c)
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
    legacy_candidate(c)
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
    legacy_candidate(c)
    verify(path, key)
    v = load(path)
    require(
        "schema_version" not in v
        and type(v.get("version")) is int
        and v["version"] == 1,
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


def legacy_candidate(c: dict) -> None:
    require("schema_version" not in c, "v2 legacy consumers require T5")
    require(
        type(c.get("version")) is int and c["version"] == 1, "invalid candidate version"
    )


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
    f.add_argument("--source-root", type=Path)
    for field in ("fedora", "base-digest", "policy-sha256", "channel"):
        f.add_argument("--" + field)
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
            context = None
            if a.source_root is not None:
                context = core_context(
                    run,
                    a.source_root,
                    {
                        "fedora": a.fedora,
                        "base_digest": a.base_digest,
                        "policy_sha256": a.policy_sha256,
                        "channel": a.channel,
                        "architecture": "x86_64",
                    },
                )
            c = candidate(path, a.public_key, context=context)
            if c.get("schema_version") == 2:
                print(
                    json.dumps(
                        {"schema_version": 2, "selection": "core", "read_only": True}
                    )
                )
                return 0
            require(
                c["repository"] == a.repository
                and c["run_id"] == a.run_id
                and c["source_sha"] == run["head_sha"],
                "candidate run mismatch",
            )
            candidate_outputs(c, path)
        elif a.action == "record-validation":
            c = candidate(a.candidate, a.public_key, legacy_only=True)
            legacy_candidate(c)
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
            c = candidate(a.candidate, a.public_key, legacy_only=True)
            legacy_candidate(c)
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
            c = candidate(a.candidate, a.public_key, legacy_only=True)
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
