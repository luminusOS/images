import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, date, datetime
from pathlib import Path


class SupplyChainError(ValueError):
    pass


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


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SupplyChainError(f"invalid JSON output: {path.name}") from error


def _exceptions(path: Path | None) -> set[tuple[str, str]]:
    if path is None:
        return set()
    raw = _load_json(path)
    entries = raw.get("exceptions") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise SupplyChainError("exceptions must contain an exceptions array")
    approved: set[tuple[str, str]] = set()
    today = datetime.now(UTC).date()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "cve",
            "package",
            "reason",
            "expires",
        }:
            raise SupplyChainError(
                "exception must specify only cve, package, reason, expires"
            )
        cve, package, reason, expires = (
            entry[key] for key in ("cve", "package", "reason", "expires")
        )
        if (
            not isinstance(cve, str)
            or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)
            or not isinstance(package, str)
            or not package.strip()
            or package.strip() in {"*", "all"}
            or not isinstance(reason, str)
            or len(reason.strip()) < 10
            or not isinstance(expires, str)
        ):
            raise SupplyChainError("invalid or unjustified vulnerability exception")
        try:
            expiry = date.fromisoformat(expires)
        except ValueError as error:
            raise SupplyChainError("exception expiry must be an ISO date") from error
        if expiry <= today:
            raise SupplyChainError("expired vulnerability exception")
        approved.add((cve, package))
    return approved


def inspect_image(
    image: str,
    output: Path,
    source_sha: str,
    exceptions: Path | None = None,
    *,
    expected_syft_version: str,
    expected_grype_version: str,
) -> Path:
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
    approved = _exceptions(exceptions)
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
        if severity not in {
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            "Unknown",
        }:
            raise SupplyChainError("unknown Grype severity")
        if severity in {"High", "Critical", "Unknown"}:
            key = (vulnerability_id, package)
            if key not in approved:
                raise SupplyChainError(f"unexcepted {severity} vulnerability")
    provenance_path = output / "provenance.json"
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://luminusos.org/provenance/v1",
        "subject": [{"name": image, "digest": {"sha256": digest}}],
        "predicate": {
            "source": {
                "commit": source_sha,
                "repository": os.environ.get("GITHUB_REPOSITORY"),
                "ref": os.environ.get("GITHUB_REF"),
                "workflow": os.environ.get("GITHUB_WORKFLOW"),
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "run_url": _run_url(),
            },
            "inputs": {
                "exceptions_sha256": _file_hash(exceptions) if exceptions else None
            },
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
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--image", required=True)
    inspect.add_argument("--output", type=Path, required=True)
    inspect.add_argument("--source-sha", required=True)
    inspect.add_argument("--exceptions", type=Path)
    inspect.add_argument("--syft-version", required=True)
    inspect.add_argument("--grype-version", required=True)
    checksums = commands.add_parser("checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--file", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            inspect_image(
                args.image,
                args.output,
                args.source_sha,
                args.exceptions,
                expected_syft_version=args.syft_version,
                expected_grype_version=args.grype_version,
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
