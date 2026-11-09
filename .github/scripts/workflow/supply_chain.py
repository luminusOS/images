import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote


class SupplyChainError(ValueError):
    pass


def authorize_bypass() -> bool:
    requested = os.environ.get("SECURITY_FINDINGS_BYPASS", "false")
    if requested == "false":
        return False
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if (
        requested != "true"
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or os.environ.get("GITHUB_WORKFLOW_REF")
        != f"{repository}/.github/workflows/auto-testing.yml@refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("BYPASS_CHANNEL") != "testing"
        or any(
            os.environ.get(f"BYPASS_{field}")
            for field in (
                "CANDIDATE",
                "VALIDATION",
                "TESTING",
                "TESTING_VALIDATION",
                "VERSION",
            )
        )
        or not os.environ.get("GITHUB_ACTOR")
        or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ID", ""))
    ):
        raise SupplyChainError(
            "security findings bypass requires a fresh manual Auto Testing run on main"
        )
    return True


def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv, check=True, capture_output=True, text=True, **kwargs
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SupplyChainError(f"command failed: {argv[0]}") from error
    return result


def _digest_image(image: str) -> str:
    match = re.fullmatch(r".+@sha256:([0-9a-f]{64})", image)
    if not match:
        raise SupplyChainError("image must be pinned to a sha256 digest")
    return match.group(1)


def _version(tool: str, expected: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", expected):
        raise SupplyChainError(f"invalid expected {tool} version")
    result = _run([tool, "version"])
    reported = result.stdout.strip() or result.stderr.strip()
    match = re.search(
        r"(?m)^Version:\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s*$", reported
    )
    if not match or match.group(1) != expected:
        raise SupplyChainError(f"unexpected {tool} version")
    return reported


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SupplyChainError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise SupplyChainError(f"invalid JSON constant: {value}")


def _decode_json(raw, label):
    try:
        return json.loads(
            raw, object_pairs_hook=_json_pairs, parse_constant=_invalid_constant
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SupplyChainError(f"invalid JSON: {label}") from error


def _load_json(path: Path) -> object:
    try:
        return _decode_json(path.read_text(encoding="utf-8"), path.name)
    except (OSError, UnicodeError) as error:
        raise SupplyChainError(f"invalid JSON output: {path.name}") from error


def _require(condition, message):
    if not condition:
        raise SupplyChainError(message)


def _matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


EXACT_NAME = r"[A-Za-z0-9][A-Za-z0-9._+:/@-]*"
SHA256 = r"[0-9a-f]{64}"
ADVISORY = (
    r"(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
    r"[23456789cfghjmpqrvwx]{4}|GO-[0-9]{4}-[0-9]{4,})"
)
SCOPE_FIELDS = ("edition", "component_scope", "channel", "fedora")
EXCEPTION_FIELDS = {
    "advisory",
    "package",
    "package_version",
    *SCOPE_FIELDS,
    "owner",
    "reason",
    "classification",
    "component_type",
    "evidence",
    "issued_at",
    "expires_at",
}


def _safe_bytes(path, limit=1024 * 1024):
    path = Path(path)
    _require(".." not in path.parts, "unsafe policy/evidence path")
    absolute = Path(os.path.abspath(path))
    directory = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(absolute.anchor, flags)
        for part in absolute.parts[1:-1]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            _require(
                stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= limit,
                "policy/evidence must be a bounded nonempty regular file",
            )
            data = stream.read(limit + 1)
            _require(0 < len(data) <= limit, "policy/evidence size limit exceeded")
            return data
    except OSError as error:
        raise SupplyChainError(f"cannot safely read policy/evidence: {path}") from error
    finally:
        if directory is not None:
            os.close(directory)


def _clock(now):
    value = datetime.now(UTC) if now is None else now
    _require(
        isinstance(value, datetime) and value.utcoffset() == timedelta(0),
        "evaluation clock must be an aware UTC datetime",
    )
    return value


def _timestamp(value):
    match = (
        re.fullmatch(
            r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
            r"(?:\.([0-9]+))?Z",
            value,
        )
        if isinstance(value, str)
        else None
    )
    _require(match is not None, "exception timestamps must use RFC3339 UTC Z")
    try:
        whole = datetime.fromisoformat(match[1]).replace(tzinfo=UTC)
    except ValueError as error:
        raise SupplyChainError("invalid exception calendar timestamp") from error
    return whole, (match[2] or "").rstrip("0")


def _scope(context):
    _require(
        isinstance(context, dict) and set(context) == set(SCOPE_FIELDS),
        "v2 exceptions require independent edition/component/channel/Fedora context",
    )
    scopes = {
        "core": {"core_payload"},
        "workstation": {"workstation_payload", "installer_live"},
    }
    _require(
        isinstance(context["edition"], str)
        and context["edition"] in scopes
        and isinstance(context["component_scope"], str)
        and context["component_scope"] in scopes[context["edition"]]
        and context["channel"] in ("testing", "stable")
        and _matches(r"[1-9][0-9]*", context["fedora"]),
        "unknown or incompatible exception scope",
    )


def _exception_key(entry):
    return tuple(
        entry[name]
        for name in ("advisory", "package", "package_version", *SCOPE_FIELDS)
    )


def _exception_hash(entry):
    raw = (
        json.dumps(entry, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        + "\n"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _exceptions(path, *, context=None, now=None, expected_sha256=None):
    """Only exact reviewed advisory records authorize matches, never scanner aliases."""
    clock = _clock(now)
    if path is None:
        return {}, None
    _scope(context)
    _require(_matches(SHA256, expected_sha256), "v2 policy requires expected SHA-256")
    data = _safe_bytes(path)
    digest = hashlib.sha256(data).hexdigest()
    _require(digest == expected_sha256, "exception policy SHA-256 mismatch")
    try:
        raw = _decode_json(data.decode("utf-8"), Path(path).name)
    except UnicodeError as error:
        raise SupplyChainError("policy must be UTF-8 JSON") from error
    _require(
        isinstance(raw, dict)
        and set(raw) == {"kind", "schema_version", "evidence_class", "exceptions"}
        and raw["kind"] == "policy"
        and type(raw["schema_version"]) is int
        and raw["schema_version"] == 2
        and raw["evidence_class"] == "runtime"
        and isinstance(raw["exceptions"], list),
        "legacy, synthetic or malformed exception policy; scoped runtime v2 required",
    )
    approved = {}
    evaluation = (clock.replace(microsecond=0), f"{clock.microsecond:06d}".rstrip("0"))
    for entry in raw["exceptions"]:
        _require(isinstance(entry, dict), "exception must be an object")
        embedded = entry.get("component_type") == "embedded_go"
        _require(
            set(entry) == EXCEPTION_FIELDS | ({"binary"} if embedded else set()),
            "unknown or missing exception fields",
        )
        _require(
            entry["component_type"] in ("rpm", "embedded_go"), "unknown component type"
        )
        _require(_matches(ADVISORY, entry["advisory"]), "invalid exact advisory")
        for field in ("package", "package_version"):
            _require(
                _matches(EXACT_NAME, entry[field]) and entry[field] != "all",
                f"invalid exact {field}",
            )
        _scope({name: entry[name] for name in SCOPE_FIELDS})
        _require(
            all(entry[name] == context[name] for name in SCOPE_FIELDS),
            "out-of-scope exception policy",
        )
        _require(
            isinstance(entry["owner"], str) and entry["owner"].strip(),
            "exception requires owner",
        )
        _require(
            isinstance(entry["reason"], str) and len(entry["reason"].strip()) >= 10,
            "exception requires reviewed reason",
        )
        _require(
            entry["classification"] in ("accepted_risk", "proven_false_positive"),
            "unknown exception classification",
        )
        issued, expires = (
            _timestamp(entry["issued_at"]),
            _timestamp(entry["expires_at"]),
        )
        try:
            deadline = (issued[0] + timedelta(days=30), issued[1])
        except OverflowError as error:
            raise SupplyChainError("invalid exception deadline") from error
        _require(
            issued <= evaluation < expires <= deadline,
            "exception is not currently valid for at most 30 days",
        )
        if embedded:
            binary = entry["binary"]
            _require(
                isinstance(binary, dict)
                and set(binary) == {"path", "sha256", "rpm_nevra"},
                "embedded Go requires owning binary identity",
            )
            binary_path = binary["path"]
            _require(
                _matches(r"/(?:usr/)?(?:s?bin|libexec)/[A-Za-z0-9._/-]+", binary_path)
                and PurePosixPath(binary_path).as_posix() == binary_path
                and ".." not in PurePosixPath(binary_path).parts
                and _matches(SHA256, binary["sha256"])
                and _matches(EXACT_NAME, binary["rpm_nevra"])
                and binary["rpm_nevra"] != "all",
                "invalid owning binary identity",
            )
        evidence = entry["evidence"]
        _require(isinstance(evidence, list) and evidence, "exception requires evidence")
        seen = set()
        for descriptor in evidence:
            _require(
                isinstance(descriptor, dict)
                and set(descriptor) == {"path", "sha256", "size_bytes"},
                "invalid exception evidence descriptor",
            )
            name = descriptor["path"]
            _require(
                _matches(
                    r"[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*",
                    name,
                )
                and not any(part in (".", "..") for part in name.split("/"))
                and name not in seen
                and _matches(SHA256, descriptor["sha256"])
                and type(descriptor["size_bytes"]) is int
                and descriptor["size_bytes"] > 0,
                "unsafe, duplicate or malformed exception evidence",
            )
            seen.add(name)
            content = _safe_bytes(Path(path).parent / name, 8 * 1024 * 1024)
            _require(
                len(content) == descriptor["size_bytes"]
                and hashlib.sha256(content).hexdigest() == descriptor["sha256"],
                "exception evidence bytes mismatch",
            )
        key = _exception_key(entry)
        _require(key not in approved, "duplicate or conflicting exception")
        approved[key] = entry
    return approved, digest


def _rpm_nevra(package):
    identities = set()
    for ref in package.get("externalRefs", []):
        if not isinstance(ref, dict) or ref.get("referenceType") != "purl":
            continue
        locator = ref.get("referenceLocator")
        match = (
            re.fullmatch(r"pkg:rpm/[^/]+/([^@?]+)@([^?]+)\?(.+)", locator)
            if isinstance(locator, str)
            else None
        )
        if not match:
            continue
        query = parse_qs(match[3], keep_blank_values=True)
        arch, epoch = query.get("arch", []), query.get("epoch", ["0"])
        if len(arch) != 1 or len(epoch) != 1 or not _matches(r"[0-9]+", epoch[0]):
            continue
        version = unquote(match[2])
        if epoch[0] != "0":
            version = epoch[0] + ":" + version
        if (
            unquote(match[1]) == package.get("name")
            and version == package.get("versionInfo")
            and _matches(EXACT_NAME, arch[0])
        ):
            identities.add(f"{package['name']}-{version}.{arch[0]}")
    return identities


def _binary_matches(binary, artifact, sbom):
    locations = artifact.get("locations")
    if not isinstance(locations, list) or not locations:
        return False
    if any(
        not isinstance(item, dict)
        or item.get("accessPath", item.get("path")) != binary["path"]
        for item in locations
    ):
        return False
    files, relationships = sbom.get("files"), sbom.get("relationships")
    if not isinstance(files, list) or not isinstance(relationships, list):
        return False
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        return False
    packages_by_id = {}
    for package in packages:
        if not isinstance(package, dict):
            return False
        package_id = package.get("SPDXID")
        if not _matches(r"[A-Za-z0-9.-]+", package_id):
            return False
        if package_id in packages_by_id:
            return False
        packages_by_id[package_id] = package
    identities = set()
    for file in files:
        if not isinstance(file, dict) or not isinstance(file.get("fileName"), str):
            return False
        if "/" + file["fileName"].removeprefix("/") != binary["path"]:
            continue
        checksums = file.get("checksums", [])
        if not isinstance(checksums, list):
            return False
        hashes = {
            item.get("checksumValue")
            for item in checksums
            if isinstance(item, dict)
            and item.get("algorithm") == "SHA256"
            and _matches(SHA256, item.get("checksumValue"))
        }
        if len(hashes) != 1 or not isinstance(file.get("SPDXID"), str):
            return False
        owners = []
        for item in relationships:
            if (
                not isinstance(item, dict)
                or item.get("relationshipType") != "CONTAINS"
                or item.get("relatedSpdxElement") != file["SPDXID"]
            ):
                continue
            owner = item.get("spdxElementId")
            if not _matches(r"[A-Za-z0-9.-]+", owner):
                return False
            if owner not in packages_by_id:
                return False
            owners.append(owner)
        if not owners:
            return False
        for owner in owners:
            nevras = _rpm_nevra(packages_by_id[owner])
            if len(nevras) != 1:
                return False
            identities.add((binary["path"], next(iter(hashes)), next(iter(nevras))))
    return identities == {(binary["path"], binary["sha256"], binary["rpm_nevra"])}


def inspect_image(
    image: str,
    output: Path,
    source_sha: str,
    exceptions: Path | None = None,
    *,
    expected_syft_version: str,
    expected_grype_version: str,
    edition: str | None = None,
    component_scope: str | None = None,
    channel: str | None = None,
    fedora: str | None = None,
    expected_policy_sha256: str | None = None,
    now: datetime | None = None,
) -> Path:
    bypass = authorize_bypass()
    context = dict(zip(SCOPE_FIELDS, (edition, component_scope, channel, fedora)))
    if any(value is not None for value in context.values()):
        _scope(context)
    _clock(now)
    digest = _digest_image(image)
    if not re.fullmatch(r"[0-9a-f]{40,64}", source_sha):
        raise SupplyChainError("invalid source commit")
    syft_version = _version("syft", expected_syft_version)
    grype_version = _version("grype", expected_grype_version)
    output.mkdir(parents=True, exist_ok=True)
    sbom_path = output / "sbom.spdx.json"
    vulnerabilities_path = output / "vulnerabilities.json"
    _run(["syft", image, "-o", "spdx-json", "--file", str(sbom_path)])
    sbom = _load_json(sbom_path)
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") is None
        or not isinstance(sbom.get("packages"), list)
    ):
        raise SupplyChainError("malformed SPDX SBOM")
    _run(["grype", image, "-o", "json", "--file", str(vulnerabilities_path)])
    scan = _load_json(vulnerabilities_path)
    matches = scan.get("matches") if isinstance(scan, dict) else None
    if not isinstance(matches, list):
        raise SupplyChainError("malformed Grype scan")
    evaluated_at = _clock(now)
    approved, policy_hash = _exceptions(
        exceptions,
        context=context,
        now=evaluated_at,
        expected_sha256=expected_policy_sha256,
    )
    applied = {}
    blocked = set()
    for match in matches:
        if not isinstance(match, dict):
            raise SupplyChainError("malformed Grype match")
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            raise SupplyChainError("malformed Grype vulnerability")
        vulnerability_id = vulnerability.get("id")
        package = artifact.get("name")
        severity = vulnerability.get("severity")
        if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
            raise SupplyChainError("malformed Grype vulnerability id")
        if not isinstance(package, str) or not package.strip():
            raise SupplyChainError("malformed Grype package name")
        version = artifact.get("version")
        if not isinstance(version, str) or not version.strip():
            raise SupplyChainError("malformed Grype package version")
        if not isinstance(severity, str) or severity not in {
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            "Unknown",
        }:
            raise SupplyChainError("unknown Grype severity")
        fix = vulnerability.get("fix", {})
        if not isinstance(fix, dict):
            raise SupplyChainError("malformed Grype fix")
        versions = fix.get("versions", [])
        if not isinstance(versions, list) or any(
            not isinstance(value, str) or not value.strip() for value in versions
        ):
            raise SupplyChainError("malformed Grype fix versions")
        if severity in {"High", "Critical", "Unknown"}:
            entry = approved.get(
                (
                    vulnerability_id,
                    package,
                    version,
                    *(context[name] for name in SCOPE_FIELDS),
                )
            )
            accepted = entry is not None and (
                entry["component_type"] == "rpm"
                and artifact.get("type") == "rpm"
                or entry["component_type"] == "embedded_go"
                and artifact.get("type") == "go-module"
                and _binary_matches(entry["binary"], artifact, sbom)
            )
            if accepted:
                applied[_exception_hash(entry)] = entry
            else:
                fixes = ", ".join(versions)
                blocked.add(
                    f"{severity} {vulnerability_id}: {package} {version} "
                    f"(fixed versions: {fixes or 'unknown'})"
                )
    if blocked and not bypass:
        raise SupplyChainError(
            "unexcepted vulnerabilities:\n" + "\n".join(sorted(blocked))
        )
    security = {
        "gate": "bypassed" if bypass else "success",
        "actor": os.environ.get("GITHUB_ACTOR"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_url": _run_url(),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "findings": sorted(blocked),
        "decision": "diagnostic" if bypass else "accepted_risk" if applied else "clean",
        "policy_sha256": policy_hash,
        "policy_schema_version": 2 if exceptions is not None else None,
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        "scope": context if exceptions is not None else None,
        "applied_exceptions": sorted(applied),
        "exception_summary": [applied[key] for key in sorted(applied)],
    }
    if bypass:
        message = (
            f"Security findings gate BYPASSED for {image}; "
            f"actor={security['actor']}, run={security['run_id']}, "
            f"findings={len(blocked)}. Diagnostic artifacts are NOT eligible for promotion."
        )
        print(f"::warning::{message}")
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(summary).open("a", encoding="utf-8") as stream:
                stream.write(
                    f"\n### Security bypass: diagnostics only\n\n{message}\n\n"
                )
                stream.write(
                    "\n".join(f"- {finding}" for finding in sorted(blocked)) + "\n"
                )
    provenance_path = output / "provenance.json"
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://luminusos.org/provenance/v1",
        "subject": [{"name": image, "digest": {"sha256": digest}}],
        "predicate": {
            "security": security,
            "source": {
                "commit": source_sha,
                "repository": os.environ.get("GITHUB_REPOSITORY"),
                "ref": os.environ.get("GITHUB_REF"),
                "workflow": os.environ.get("GITHUB_WORKFLOW"),
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "run_url": _run_url(),
            },
            "inputs": {"exceptions_sha256": policy_hash},
            "tools": {"syft": syft_version, "grype": grype_version},
            "materials": {
                "sbom.spdx.json": _file_hash(sbom_path),
                "vulnerabilities.json": _file_hash(vulnerabilities_path),
            },
        },
    }
    provenance_path.write_text(
        json.dumps(provenance, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    manifest = output / "scan-evidence.json"
    manifest.write_text(
        json.dumps(
            {
                "image": image,
                "digest": digest,
                "source_sha": source_sha,
                "security": security,
                "policy_sha256": policy_hash,
                "scan": None
                if bypass
                else {
                    "decision": security["decision"],
                    "applied_exceptions": sorted(applied),
                    "reports": [
                        {
                            "path": path.name,
                            "sha256": _file_hash(path),
                            "size_bytes": path.stat().st_size,
                        }
                        for path in (sbom_path, vulnerabilities_path)
                    ],
                },
                "tools": {"syft": syft_version, "grype": grype_version},
                "files": {
                    name: _file_hash(output / name)
                    for name in (
                        "sbom.spdx.json",
                        "vulnerabilities.json",
                        "provenance.json",
                    )
                },
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _run_url() -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    return (
        f"{server}/{repo}/actions/runs/{run_id}" if server and repo and run_id else None
    )


def _file_hash(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def write_checksums(directory: Path) -> Path:
    allowed_suffixes = {".iso", ".qcow2"}
    allowed_names = {
        "sbom.spdx.json",
        "provenance.json",
        "vulnerabilities.json",
        "scan-evidence.json",
        "release-evidence.json",
        "candidate.json",
        "validation.json",
    }
    root = directory.resolve(strict=True)
    files = []
    for path in directory.rglob("*"):
        if path.name == "SHA256SUMS" or path.name.endswith(".sig"):
            continue
        if path.is_symlink():
            raise SupplyChainError("symlinks are not allowed in checksum inputs")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if any(character in relative for character in "\r\n\\"):
            raise SupplyChainError("unsafe checksum path")
        resolved = path.resolve(strict=True)
        if resolved != root and root not in resolved.parents:
            raise SupplyChainError("checksum input escapes directory")
        if path.suffix.lower() in allowed_suffixes or path.name in allowed_names:
            files.append((relative, path))
    files.sort(key=lambda item: item[0])
    if not files:
        raise SupplyChainError("no allowed artifacts found")
    target = directory / "SHA256SUMS"
    target.write_text(
        "".join(f"{_file_hash(path)}  {name}\n" for name, path in files),
        encoding="utf-8",
    )
    return target


def sign_file(path: Path, public_key: Path) -> Path:
    if not os.environ.get("COSIGN_PRIVATE_KEY"):
        raise SupplyChainError("COSIGN_PRIVATE_KEY must use cosign's env:// provider")
    signature = Path(f"{path}.sig")
    _run(
        [
            "cosign",
            "sign-blob",
            "--key",
            "env://COSIGN_PRIVATE_KEY",
            "--tlog-upload=false",
            "--output-signature",
            str(signature),
            str(path),
        ]
    )
    _run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            str(public_key),
            "--signature",
            str(signature),
            str(path),
        ]
    )
    return signature


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-bypass")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--image", required=True)
    inspect.add_argument("--output", type=Path, required=True)
    inspect.add_argument("--source-sha", required=True)
    inspect.add_argument("--exceptions", type=Path)
    inspect.add_argument("--edition")
    inspect.add_argument("--component-scope")
    inspect.add_argument("--channel")
    inspect.add_argument("--fedora")
    inspect.add_argument("--policy-sha256")
    inspect.add_argument("--syft-version", required=True)
    inspect.add_argument("--grype-version", required=True)
    checksums = commands.add_parser("checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--file", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-bypass":
            authorize_bypass()
        elif args.command == "inspect":
            inspect_image(
                args.image,
                args.output,
                args.source_sha,
                args.exceptions,
                expected_syft_version=args.syft_version,
                expected_grype_version=args.grype_version,
                edition=args.edition,
                component_scope=args.component_scope,
                channel=args.channel,
                fedora=args.fedora,
                expected_policy_sha256=args.policy_sha256,
            )
        elif args.command == "checksums":
            write_checksums(args.directory)
        else:
            sign_file(args.file, args.public_key)
    except SupplyChainError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
