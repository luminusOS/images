import argparse
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

GATES = ("quality", "boot", "signature", "sbom", "vulnerability")
SCAN_SCOPES = {
    "core": ("core", "core_payload"),
    "workstation": ("workstation", "workstation_payload"),
    "installer": ("workstation", "installer_live"),
}
SUMMARY_EXCEPTION_FIELDS = (
    "advisory",
    "package",
    "package_version",
    "classification",
    "owner",
    "expires_at",
)
CANDIDATE_KEY = "shared/release/candidate.pub"
OFFICIAL_KEY = "shared/trust/etc/pki/containers/luminusos.pub"
EVIDENCE_NAMES = {
    "sbom.spdx.json",
    "provenance.json",
    "vulnerabilities.json",
    "scan-evidence.json",
    "release-evidence.json",
    "candidate.json",
    "validation.json",
}


def checksum_inputs(directory: Path) -> dict[str, Path]:
    files = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in publication directory")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", relative) or ".." in relative.split(
            "/"
        ):
            raise ValueError("unsafe publication path")
        if path.name in EVIDENCE_NAMES or (
            path.parent == directory and path.suffix in {".iso", ".qcow2"}
        ):
            files[relative] = path
    return files


def verify_checksums(directory: Path) -> None:
    manifest = directory / "SHA256SUMS"
    signature = directory / "SHA256SUMS.sig"
    if any(path.is_symlink() or not path.is_file() for path in (manifest, signature)):
        raise ValueError("publication checksum signature missing or unsafe")
    subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            OFFICIAL_KEY,
            "--signature",
            str(signature),
            str(manifest),
        ],
        check=True,
        capture_output=True,
    )
    expected = "".join(
        f"{sha256(path)}  {name}\n"
        for name, path in sorted(checksum_inputs(directory).items())
    )
    if not expected or manifest.read_text(encoding="utf-8") != expected:
        raise ValueError("publication checksum manifest mismatch")


def load_helper(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py")
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"{name} helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_configuration(fedora_version: str) -> dict:
    config = load_helper("build_metadata").releases(
        Path("config/releases.env").read_text(encoding="utf-8")
    )
    if fedora_version not in config["SUPPORTED_RELEASES"].split():
        raise ValueError("unsupported Fedora release")
    return config


def check_fedora_ga(fedora_version: str) -> None:
    upstream = subprocess.run(
        ["skopeo", "inspect", "docker://quay.io/fedora/fedora-bootc:latest"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    upstream_data = json.loads(upstream)
    if not isinstance(upstream_data, dict) or not isinstance(
        upstream_data.get("Labels"), dict
    ):
        raise TypeError("cannot determine Fedora GA release from upstream latest")
    labels = upstream_data["Labels"]
    version_label = labels.get("org.opencontainers.image.version") or labels.get(
        "version"
    )
    if not isinstance(version_label, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+)*", version_label
    ):
        raise ValueError("cannot determine Fedora GA release from upstream latest")
    if int(fedora_version) > int(version_label.split(".")[0]):
        raise ValueError("candidate Fedora release is not yet GA")


def utc_now() -> datetime:
    return datetime.now(UTC)


def instant(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"invalid {name} timestamp")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def in_force(value: object, name: str, now: datetime) -> str:
    if not instant(value, name) > now:
        raise ValueError(f"{name} expired before promotion")
    return value


def approval_summary(
    candidate: dict, directory: Path, root: Path, now: datetime
) -> dict:
    """Describe what an approver accepts, rechecked against the checkout.

    The summary holds no evaluation time, so the same candidate, policies and
    records always produce the same bytes; a later digest mismatch therefore
    means something the approver saw has changed.
    """
    if candidate.get("channel") != "stable":
        raise ValueError("approval summaries describe stable candidates only")
    fedora = candidate["fedora_version"]
    policy = load_helper("release_policy")
    record_path = root / "shared/release/base-trust-risk-stable.json"
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"the release line has no readable stable base risk record: {error}"
        ) from error
    errors = policy.validate_base_risk(
        record,
        f"quay.io/fedora/fedora-bootc@{candidate['fedora_bootc_digest']}",
        fedora,
        now,
    )
    if errors:
        raise ValueError("base risk record expired or invalid: " + "; ".join(errors))
    exclusion_records = {
        sha256(path): path.name
        for path in sorted((root / "shared/release").glob("flatpak-scan-risk*.json"))
    }
    roles = {}
    for role, (edition, scope) in SCAN_SCOPES.items():
        name = f"scan/{role}/scan-evidence.json"
        path = directory / name
        if candidate["artifacts"].get(name) != sha256(path):
            raise ValueError(f"{role} scan evidence is not signed by the candidate")
        scan = json.loads(path.read_text(encoding="utf-8"))
        security = scan.get("security") or {}
        digest = candidate["images"][role].split("@sha256:", 1)[1]
        policy_file = (
            root
            / "shared/release/exceptions"
            / f"{edition}-{scope}-stable-{fedora}.json"
        )
        if (
            scan.get("digest") != digest
            or security.get("gate") != "success"
            or security.get("scope")
            != {
                "edition": edition,
                "component_scope": scope,
                "channel": "stable",
                "fedora": fedora,
            }
        ):
            raise ValueError(f"{role} scan is not this candidate's stable gate")
        if security.get("policy_sha256") != sha256(policy_file):
            raise ValueError(f"{role} policy changed since the candidate was scanned")
        exceptions = [
            {field: entry[field] for field in SUMMARY_EXCEPTION_FIELDS}
            for entry in security.get("exception_summary", [])
        ]
        for entry in exceptions:
            in_force(entry["expires_at"], f"{entry['advisory']} exception", now)
        exclusions = []
        for entry in (scan.get("scan") or {}).get("exclusions", []):
            if entry.get("record_sha256") not in exclusion_records:
                raise ValueError(f"{role} scan exclusion record changed")
            exclusions.append(
                {
                    "path": entry["path"],
                    "record": exclusion_records[entry["record_sha256"]],
                    "expires_at": in_force(
                        entry.get("expires_at"), "scan exclusion", now
                    ),
                }
            )
        roles[role] = {
            "image": candidate["images"][role],
            "decision": security.get("decision"),
            "policy": policy_file.name,
            "policy_sha256": security["policy_sha256"],
            "exceptions": sorted(
                exceptions, key=lambda e: json.dumps(e, sort_keys=True)
            ),
            "exclusions": exclusions,
        }
    return {
        "candidate": {
            field: candidate[field]
            for field in (
                "repository",
                "source_sha",
                "run_id",
                "channel",
                "build_version",
                "fedora_version",
                "fedora_bootc_digest",
                "images",
            )
        },
        "base_risk": {
            "record": record_path.name,
            "sha256": sha256(record_path),
            "owner": record["owner"],
            "expires_at": record["expires_at"],
        },
        "roles": roles,
    }


def summary_bytes(summary: dict) -> bytes:
    return (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8")


def summary_digest(summary: dict) -> str:
    return hashlib.sha256(summary_bytes(summary)).hexdigest()


def summary_markdown(summary: dict, digest: str) -> str:
    c = summary["candidate"]
    lines = [
        f"## Stable approval: LuminusOS {c['build_version']}",
        "",
        f"Summary SHA-256: `{digest}`",
        "",
        f"- Source: `{c['repository']}` at `{c['source_sha']}` (run {c['run_id']})",
        f"- Fedora {c['fedora_version']} base: `{c['fedora_bootc_digest']}`",
        (
            f"- Base signature risk: accepted by {summary['base_risk']['owner']} "
            f"until {summary['base_risk']['expires_at']}"
        ),
        "",
    ]
    for role, value in summary["roles"].items():
        lines += [
            f"### {role}: {value['decision']}",
            "",
            f"- Image: `{value['image']}`",
            f"- Policy: `{value['policy']}` (`{value['policy_sha256']}`)",
        ]
        lines += [
            f"- Scan exclusion `{e['path']}` ({e['record']}) until {e['expires_at']}"
            for e in value["exclusions"]
        ]
        if value["exceptions"]:
            lines += [
                "",
                "| Advisory | Package | Classification | Owner | Expires |",
                "| --- | --- | --- | --- | --- |",
            ]
            lines += [
                f"| {e['advisory']} | {e['package']} {e['package_version']} | "
                f"{e['classification']} | {e['owner']} | {e['expires_at']} |"
                for e in value["exceptions"]
            ]
        else:
            lines.append("- No accepted findings")
        lines.append("")
    return "\n".join(lines)


@contextlib.contextmanager
def branch_records(ref: str):
    """Yield the release records as they are now on the protected branch.

    The workflow code stays pinned to the dispatched commit; only the policy
    and risk records come from the branch tip, so a change merged while the
    approval waited is seen.
    """
    if not re.fullmatch(r"refs/heads/release/[1-9][0-9]*", ref):
        raise ValueError("stable records come only from a release line")
    subprocess.run(
        ["git", "fetch", "--quiet", "--depth=1", "origin", ref],
        check=True,
        capture_output=True,
    )
    archive = subprocess.run(
        ["git", "archive", "--format=tar", "FETCH_HEAD", "shared/release"],
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="luminus-records-") as temp:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(temp, filter="data")
        yield Path(temp)


def publish_approval_summary(
    candidate_path: Path,
    evidence_path: Path,
    key: Path,
    output: Path,
    expected: str | None,
    policy_ref: str,
) -> None:
    candidate = verify_release(candidate_path, evidence_path, key)
    with branch_records(policy_ref) as root:
        summary = approval_summary(candidate, candidate_path.parent, root, utc_now())
    digest = summary_digest(summary)
    if expected == "":
        raise ValueError("no approval summary digest was recorded before approval")
    if expected is not None and digest != expected:
        raise ValueError("approval summary differs from the one shown before approval")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(summary_bytes(summary))
    if step := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(step).open("a", encoding="utf-8") as stream:
            stream.write(summary_markdown(summary, digest) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        print(f"summary_sha256={digest}", file=stream)
    print(json.dumps({"summary": str(output), "sha256": digest}))


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def prepare_gates(directory: Path) -> None:
    if os.environ.get("SECURITY_FINDINGS_BYPASS", "false") != "false":
        raise ValueError("security bypass cannot authorize release gates")
    for name in ("QUALITY_RESULT", "BOOT_RESULT", "SCAN_RESULT"):
        if os.environ.get(name) != "success":
            raise ValueError(f"required job did not succeed: {name}")
    images = {
        name: os.environ[name.upper()] for name in ("core", "workstation", "installer")
    }
    files = {}
    for name, image in images.items():
        subprocess.run(
            ["cosign", "verify", "--key", CANDIDATE_KEY, image],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        scan = directory / "scan" / name / "scan-evidence.json"
        data = json.loads(scan.read_text(encoding="utf-8"))
        security = data.get("security")
        if not isinstance(security, dict) or security.get("gate") != "success":
            raise ValueError(
                "scan without a successful security gate (or a bypass) cannot authorize release gates"
            )
        source_sha = (
            os.environ.get("SOURCE_IMAGE_SHA", os.environ["GITHUB_SHA"])
            if name in ("core", "workstation")
            else os.environ["GITHUB_SHA"]
        )
        if data.get("image") != image or data.get("source_sha") != source_sha:
            raise ValueError(f"scan is not bound to {name} candidate")
        for filename, expected in data["files"].items():
            if filename not in {
                "sbom.spdx.json",
                "vulnerabilities.json",
                "provenance.json",
            }:
                raise ValueError("unexpected scan output")
            path = scan.parent / filename
            if sha256(path) != expected:
                raise ValueError("scan output checksum mismatch")
        if set(data["files"]) != {
            "sbom.spdx.json",
            "vulnerabilities.json",
            "provenance.json",
        }:
            raise ValueError("incomplete scan outputs")
        files[scan.relative_to(directory).as_posix()] = sha256(scan)
    for mode in ("iso", "disk"):
        log = directory / "boot" / mode / "serial.log"
        screenshots = sorted((directory / "boot" / mode).glob("screen-*.ppm"))
        if (
            not screenshots
            or not screenshots[-1].is_file()
            or not screenshots[-1].stat().st_size
        ):
            raise ValueError(f"missing boot screenshot for {mode}")
        if log.is_file():
            files[log.relative_to(directory).as_posix()] = sha256(log)
        screen = screenshots[-1]
        files[screen.relative_to(directory).as_posix()] = sha256(screen)
    for gate in GATES:
        write(
            directory / "gates" / f"{gate}.json",
            {
                "gate": gate,
                "conclusion": "success",
                "repository": os.environ["GITHUB_REPOSITORY"],
                "source_sha": os.environ["GITHUB_SHA"],
                "source_image_sha": os.environ.get(
                    "SOURCE_IMAGE_SHA", os.environ["GITHUB_SHA"]
                ),
                "run_id": int(os.environ["GITHUB_RUN_ID"]),
                "images": images,
                "artifacts": files,
            },
        )


def prepare_results(directory: Path) -> None:
    pipeline = load_helper("release_pipeline")
    candidate = pipeline.candidate(directory / "candidate.json", Path(CANDIDATE_KEY))
    candidate_digest = candidate["images"]["workstation"].split("@", 1)[1]
    binding = {
        key: candidate[key]
        for key in ("repository", "source_sha", "images", "artifacts")
    }
    binding.update(source_run_id=candidate["run_id"], candidate_digest=candidate_digest)
    results = {}
    for gate in GATES:
        artifact = f"gates/{gate}.json"
        actual = sha256(directory / artifact)
        if candidate["artifacts"].get(artifact) != actual:
            raise ValueError(f"unsigned gate evidence: {gate}")
        report = json.loads((directory / artifact).read_text(encoding="utf-8"))
        if (
            report.get("gate") != gate
            or report.get("conclusion") != "success"
            or report.get("repository") != candidate["repository"]
            or report.get("source_sha") != candidate["source_sha"]
            or report.get("run_id") != candidate["run_id"]
            or report.get("images") != candidate["images"]
            or not isinstance(report.get("artifacts"), dict)
            or not report["artifacts"]
        ):
            raise ValueError(f"invalid recorded gate outcome: {gate}")
        for path, checksum in report["artifacts"].items():
            pipeline.checked_file(directory, path, checksum)
        results[gate] = {
            "conclusion": "success",
            "artifact": artifact,
            "sha256": actual,
            "candidate_digest": candidate_digest,
            "binding": binding,
        }
    write(directory / "results.json", results)


def verify_release(candidate_path: Path, evidence_path: Path, key: Path) -> dict:
    pipeline = load_helper("release_pipeline")
    promotion = load_helper("promote_images")
    candidate = pipeline.candidate(candidate_path, key)
    pipeline.verify(evidence_path, key)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if (
        evidence.get("images") != candidate["images"]
        or evidence.get("artifacts") != candidate["artifacts"]
    ):
        raise ValueError("release evidence does not match candidate")
    workstation_digest = candidate["images"]["workstation"].split("@", 1)[1]
    errors = promotion.validate_candidate(
        evidence,
        workstation_digest,
        candidate["repository"],
        candidate["source_sha"],
        expected_ref=pipeline.release_ref(
            candidate["channel"], candidate["fedora_version"]
        ),
    )
    if errors:
        raise ValueError("release evidence rejected: " + "; ".join(errors))
    promotion.verify_evidence_artifacts(evidence, evidence_path.parent)
    boot_report = candidate_path.parent / "gates" / "boot.json"
    if candidate["artifacts"].get("gates/boot.json") != sha256(boot_report):
        raise ValueError("boot report is not signed by candidate")
    gate = json.loads(boot_report.read_text(encoding="utf-8"))
    for path, expected in gate["artifacts"].items():
        pipeline.checked_file(candidate_path.parent, path, expected)
    build_version = candidate["build_version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]{8}(?:\.[0-9]+)?", build_version):
        raise ValueError("invalid release build version")
    expected_tag = (
        f"testing-{build_version}"
        if candidate["channel"] == "testing"
        else build_version
    )
    if candidate["version_tag"] != expected_tag:
        raise ValueError("candidate version tag does not match build version")
    return candidate


def verify_staged_distribution(
    candidate_path: Path,
    evidence_path: Path,
    directory: Path,
    candidate: dict,
    key: Path,
) -> None:
    verify_checksums(directory)
    release_artifacts(directory, candidate)
    pipeline = load_helper("release_pipeline")
    pipeline.verify(directory / "candidate.json", key)
    pipeline.verify(directory / "release-evidence.json", key)
    if sha256(directory / "candidate.json") != sha256(candidate_path):
        raise ValueError("staged candidate does not match verified candidate")
    if sha256(directory / "release-evidence.json") != sha256(evidence_path):
        raise ValueError("staged release evidence does not match verified evidence")
    for name, expected in candidate["artifacts"].items():
        path = Path(name)
        if path.suffix in {".iso", ".qcow2"} or path.name in EVIDENCE_NAMES:
            staged = directory / (
                canonical_artifact_name(path, candidate)
                if path.suffix in {".iso", ".qcow2"}
                else path
            )
            if (
                not staged.is_file()
                or staged.is_symlink()
                or sha256(staged) != expected
            ):
                raise ValueError(f"staged candidate artifact mismatch: {name}")


def promote(
    candidate_path: Path,
    evidence_path: Path,
    key: Path,
    directory: Path,
    expected_channel: str | None = None,
) -> None:
    candidate = verify_release(candidate_path, evidence_path, key)
    if expected_channel is not None and candidate["channel"] != expected_channel:
        raise ValueError("requested channel does not match candidate")
    release_artifacts(candidate_path.parent, candidate)
    if not (directory / "SHA256SUMS").exists():
        stage(candidate_path, evidence_path, directory, key)
    verify_staged_distribution(candidate_path, evidence_path, directory, candidate, key)
    release_preflight(candidate, directory, release_artifacts(directory, candidate))
    promotion = load_helper("promote_images")
    config = release_configuration(candidate["fedora_version"])
    if candidate["channel"] == "stable":
        check_fedora_ga(candidate["fedora_version"])
    for image in candidate["images"].values():
        subprocess.run(
            ["cosign", "verify", "--key", str(key), image],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        actual = subprocess.run(
            ["skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + image],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != image.split("@", 1)[1]:
            raise ValueError("registry digest does not match candidate")
    channel = candidate["channel"]
    version = (
        candidate["version_tag"] if channel == "testing" else candidate["build_version"]
    )
    branch = (
        f"testing-{candidate['fedora_version']}"
        if channel == "testing"
        else candidate["fedora_version"]
    )
    for role in ("core", "workstation", "installer"):
        image = candidate["images"][role]
        _, digest = image.split("@", 1)
        repository = promotion.public_repository(role, candidate["repository"])
        suffix = "-iso" if role == "installer" else ""
        destinations = [
            f"{repository}:{version}{suffix}",
            f"{repository}:{branch}{suffix}",
        ]
        if (
            role != "installer"
            and candidate["fedora_version"] == config["LATEST_RELEASE"]
        ):
            destinations.append(
                f"{repository}:{'testing' if channel == 'testing' else 'latest'}"
            )
        promotion.promote(
            image,
            digest,
            destinations,
            key,
            evidence_path,
            Path(str(evidence_path) + ".sig"),
            candidate["repository"],
            candidate["source_sha"],
            role,
        )


def canonical_artifact_name(path: Path, candidate: dict) -> str:
    version = (
        candidate["version_tag"]
        if candidate["channel"] == "testing"
        else candidate["build_version"]
    )
    return f"luminusos-workstation-{version}{path.suffix}"


def release_artifacts(directory: Path, candidate: dict) -> list[Path]:
    version = (
        candidate["version_tag"]
        if candidate["channel"] == "testing"
        else candidate["build_version"]
    )
    expected = {
        f"luminusos-workstation-{version}.iso",
        f"luminusos-workstation-{version}.qcow2",
    }
    images = [p for p in directory.iterdir() if p.suffix in {".iso", ".qcow2"}]
    if {p.name for p in images} != expected or any(
        not p.is_file() or p.is_symlink() for p in images
    ):
        raise ValueError("candidate must contain exactly the versioned ISO and qcow2")
    return sorted(images)


def stage(
    candidate_path: Path, evidence_path: Path, directory: Path, key: Path
) -> None:
    candidate = verify_release(candidate_path, evidence_path, key)
    release_artifacts(candidate_path.parent, candidate)
    destination = directory.resolve()
    source = candidate_path.parent.resolve()
    if (
        destination == source
        or source in destination.parents
        or destination in source.parents
    ):
        raise ValueError("distribution and candidate directories must be separate")
    evidence_directory = evidence_path.parent.resolve()
    if destination != evidence_directory and (
        evidence_directory in destination.parents
        or destination in evidence_directory.parents
    ):
        raise ValueError("distribution and evidence directories must be separate")
    allowed = (
        {"release-evidence.json", "release-evidence.json.sig", "evidence"}
        if destination == evidence_directory
        else set()
    )
    if directory.exists() and any(
        entry.name not in allowed or entry.is_symlink() for entry in directory.iterdir()
    ):
        raise ValueError("distribution directory has unexpected files")
    directory.mkdir(parents=True, exist_ok=True)
    names = {"candidate.json", "candidate.json.sig"}
    boot_gate = json.loads(
        (candidate_path.parent / "gates" / "boot.json").read_text(encoding="utf-8")
    )
    screenshot_paths = {
        candidate_path.parent / name
        for name in boot_gate["artifacts"]
        if name.endswith(".ppm")
    }
    for source in candidate_path.parent.rglob("*"):
        if source.is_symlink():
            raise ValueError("symlink in candidate artifact")
        if (
            source.is_file()
            and source.suffix in {".iso", ".qcow2"}
            and source.parent != candidate_path.parent
        ):
            raise ValueError("disk artifacts must be at candidate root")
        if source.is_file() and (
            source.name in names
            or source in screenshot_paths
            or source.suffix in {".iso", ".qcow2"}
            or source.name
            in {
                "sbom.spdx.json",
                "provenance.json",
                "vulnerabilities.json",
                "scan-evidence.json",
            }
        ):
            dest = directory / (
                canonical_artifact_name(source, candidate)
                if source.suffix in {".iso", ".qcow2"}
                else source.relative_to(candidate_path.parent)
            )
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(source, dest)
            except OSError:
                shutil.copyfile(source, dest)
    if destination != evidence_directory:
        shutil.copytree(evidence_path.parent, directory, dirs_exist_ok=True)
    supply = load_helper("supply_chain")
    sums = supply.write_checksums(directory)
    supply.sign_file(sums, Path(OFFICIAL_KEY))
    verify_checksums(directory)


def publish_downloads(candidate_path: Path, directory: Path, key: Path) -> None:
    candidate = verify_release(candidate_path, directory / "release-evidence.json", key)
    channel = candidate["channel"]
    version = (
        candidate["version_tag"] if channel == "testing" else candidate["build_version"]
    )
    artifacts = release_artifacts(directory, candidate)
    verify_staged_distribution(
        candidate_path, directory / "release-evidence.json", directory, candidate, key
    )
    release_files = release_preflight(candidate, directory, artifacts)
    username = os.environ["SF_USER"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", username):
        raise ValueError("invalid SourceForge username")
    with tempfile.TemporaryDirectory(prefix="luminus-publish-") as temp:
        root = Path(temp)
        identity, known = root / "identity", root / "known_hosts"
        identity.write_text(os.environ["SF_SSH_KEY"] + "\n", encoding="utf-8")
        identity.chmod(0o600)
        scan = subprocess.run(
            ["ssh-keyscan", "-t", "ed25519", "frs.sourceforge.net"],
            check=True,
            capture_output=True,
            text=True,
        )
        known.write_text(scan.stdout, encoding="utf-8")
        fingerprints = subprocess.run(
            ["ssh-keygen", "-lf", str(known), "-E", "sha256"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if {
            line.split()[1]
            for line in fingerprints.splitlines()
            if len(line.split()) >= 2
        } != {"SHA256:209BDmH3jsRyO9UeGPPgLWPSegKmYCBIya0nR/AWWCY"}:
            raise ValueError("SourceForge host fingerprint mismatch")
        ssh = f"ssh -i {identity} -o UserKnownHostsFile={known} -o StrictHostKeyChecking=yes"
        subprocess.run(
            [
                "rsync",
                "-a",
                "--rsh",
                ssh,
                str(directory) + "/",
                f"{username}@frs.sourceforge.net:/home/frs/project/luminusos/{version}/",
            ],
            check=True,
        )
    subprocess.run(
        [
            "python3",
            ".github/scripts/publish-r2.py",
            channel,
            version,
            str(directory),
            "--require-evidence",
        ],
        check=True,
    )
    github_release(
        release_files,
        version,
        candidate["source_sha"],
        f"LuminusOS {candidate['build_version']}",
        channel,
    )


def release_preflight(candidate: dict, directory: Path, artifacts) -> dict[str, Path]:
    """Refuse a version that is already published with other contents.

    Runs before image tags move and again before downloads, so a conflict
    stops the release before its first public write.
    """
    channel = candidate["channel"]
    version = (
        candidate["version_tag"] if channel == "testing" else candidate["build_version"]
    )
    release_root = Path(tempfile.mkdtemp(prefix="luminus-release-"))
    files = {name: directory / name for name in ("SHA256SUMS", "SHA256SUMS.sig")} | {
        "evidence.tar.gz": release_root / "evidence.tar.gz",
        "notes.md": release_root / "notes.md",
    }
    release_notes(files["notes.md"], candidate, version, artifacts)
    evidence_bundle(directory, artifacts, files["evidence.tar.gz"])
    check_release(files, version, channel)
    check_downloads(files["SHA256SUMS"], channel, version)
    return files


def release_notes(path: Path, candidate: dict, version: str, artifacts) -> None:
    channel = candidate["channel"]
    lines = [
        f"LuminusOS {candidate['build_version']}",
        "",
        "## Downloads",
        "",
        "| File | SHA256 |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| [{p.name}](https://download.luminusos.org/{channel}/{version}/{p.name}) | `{sha256(p)}` |"
        for p in artifacts
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evidence_bundle(directory: Path, artifacts, bundle: Path) -> None:
    # Fixed metadata makes a rerun produce the same bytes as the asset an
    # earlier attempt may already have uploaded.
    def normalized(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mode = 0o644
        return info

    with (
        bundle.open("wb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path not in artifacts:
                tar.add(
                    path,
                    arcname=path.relative_to(directory).as_posix(),
                    recursive=False,
                    filter=normalized,
                )


RELEASE_ASSETS = ("SHA256SUMS", "SHA256SUMS.sig", "evidence.tar.gz")


def existing_release(version: str) -> dict | None:
    try:
        view = subprocess.run(
            ["gh", "release", "view", version, "--json", "isPrerelease,assets"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        # Only a confirmed missing release is absence; an authentication or
        # API failure must not skip the conflict check.
        if "release not found" in (error.stderr or ""):
            return None
        raise
    return json.loads(view)


def verify_blob(manifest: Path, signature: Path, key: str = OFFICIAL_KEY) -> None:
    subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--insecure-ignore-tlog",
            "--key",
            key,
            "--signature",
            str(signature),
            str(manifest),
        ],
        check=True,
        capture_output=True,
    )


def bundle_content(data: bytes) -> dict[str, bytes]:
    # Signatures are not byte-stable, so a retry is compared by what was
    # signed; signature members are checked by bundle_signatures.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {
            member.name: tar.extractfile(member).read()
            for member in tar.getmembers()
            if member.isfile() and not member.name.endswith(".sig")
        }


def signature_names(data: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {
            member.name
            for member in tar.getmembers()
            if member.isfile() and member.name.endswith(".sig")
        }


def bundle_signatures(data: bytes) -> set[str]:
    """Verify every signature in a bundle over its document; return their names."""
    with (
        tempfile.TemporaryDirectory() as temp,
        tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar,
    ):
        tar.extractall(temp, filter="data")
        root = Path(temp)
        names = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*.sig")
            if path.is_file()
        }
        for name in names:
            document = root / name.removesuffix(".sig")
            if not document.is_file():
                raise ValueError(f"bundled signature without its document: {name}")
            key = OFFICIAL_KEY if document.name == "SHA256SUMS" else CANDIDATE_KEY
            verify_blob(document, root / name, key)
    return names


def check_release(files: dict[str, Path], version: str, channel: str) -> list[str]:
    """Return the assets still missing from a release this run may resume.

    A rerun after a partial failure may find its own release; anything else
    under the tag is a conflict and is never overwritten.
    """
    release = existing_release(version)
    if release is None:
        return list(RELEASE_ASSETS)
    names = [asset["name"] for asset in release.get("assets", [])]
    if release.get("isPrerelease") is not (channel == "testing") or not set(
        names
    ) <= set(RELEASE_ASSETS):
        raise ValueError(f"release {version} already exists with other contents")
    for name in names:
        published = subprocess.run(
            ["gh", "release", "download", version, "--pattern", name, "--output", "-"],
            check=True,
            capture_output=True,
        ).stdout
        local = files[name].read_bytes()
        if name == "SHA256SUMS.sig":
            with tempfile.TemporaryDirectory() as temp:
                signature = Path(temp) / name
                signature.write_bytes(published)
                try:
                    verify_blob(files["SHA256SUMS"], signature)
                except (subprocess.CalledProcessError, ValueError) as error:
                    raise ValueError(
                        f"release {version} already exists with other contents"
                    ) from error
            same = True
        elif name == "evidence.tar.gz":
            try:
                same = bundle_content(published) == bundle_content(
                    local
                ) and bundle_signatures(published) == signature_names(local)
            except (
                tarfile.TarError,
                OSError,
                EOFError,
                ValueError,
                subprocess.CalledProcessError,
            ):
                same = False
        else:
            same = published == local
        if not same:
            raise ValueError(f"release {version} already exists with other contents")
    return [name for name in RELEASE_ASSETS if name not in names]


def check_downloads(sums: Path, channel: str, version: str) -> None:
    url = f"https://download.luminusos.org/{channel}/{version}/SHA256SUMS"
    # Cloudflare in front of the download site answers 403 to the default
    # Python-urllib agent, even for files that exist.
    request = urllib.request.Request(
        url, headers={"User-Agent": "luminusos-release-publish"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            published = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
        raise
    if published != sums.read_bytes():
        raise ValueError(f"downloads for {version} already exist with other contents")


def github_release(
    files: dict[str, Path], version: str, source_sha: str, title: str, channel: str
) -> None:
    missing = check_release(files, version, channel)
    if existing_release(version) is not None:
        if missing:
            subprocess.run(
                ["gh", "release", "upload", version]
                + [str(files[name]) for name in missing],
                check=True,
            )
        return
    command = [
        "gh",
        "release",
        "create",
        version,
        "--target",
        source_sha,
        "--title",
        title,
        "--notes-file",
        str(files["notes.md"]),
    ]
    if channel == "testing":
        command.append("--prerelease")
    command.extend(str(files[name]) for name in RELEASE_ASSETS)
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "prepare-gates",
            "prepare-results",
            "approval-summary",
            "stage",
            "promote",
            "publish",
            "publish-downloads",
            "verify-release",
        ),
    )
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--directory", dest="output_directory", type=Path)
    parser.add_argument("--channel", choices=("testing", "stable"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expect-sha256")
    parser.add_argument("--policy-ref")
    args = parser.parse_args()
    if args.action == "approval-summary":
        if not (
            args.candidate
            and args.evidence
            and args.public_key
            and args.output
            and args.policy_ref
        ):
            parser.error(
                "approval-summary needs candidate, evidence, key, output and policy ref"
            )
        publish_approval_summary(
            args.candidate,
            args.evidence,
            args.public_key,
            args.output,
            args.expect_sha256,
            args.policy_ref,
        )
        return
    if args.action in (
        "stage",
        "promote",
        "publish",
        "publish-downloads",
        "verify-release",
    ):
        if not args.candidate or not args.public_key:
            parser.error("candidate and public-key are required")
        if (
            args.action in ("stage", "promote", "publish", "verify-release")
            and not args.evidence
        ):
            parser.error("evidence is required")
        if args.action in ("promote", "publish") and not args.channel:
            parser.error("channel is required")
        if (
            args.action in ("stage", "publish", "publish-downloads")
            and not args.output_directory
        ):
            parser.error("directory is required")
        if args.action == "verify-release":
            verify_release(args.candidate, args.evidence, args.public_key)
        elif args.action == "stage":
            stage(args.candidate, args.evidence, args.output_directory, args.public_key)
        elif args.action == "promote":
            promote(
                args.candidate,
                args.evidence,
                args.public_key,
                args.output_directory or args.evidence.parent,
                args.channel,
            )
        elif args.action == "publish":
            candidate = verify_release(args.candidate, args.evidence, args.public_key)
            if candidate["channel"] != args.channel:
                raise ValueError("requested channel does not match candidate")
            if sha256(args.evidence) != sha256(
                args.output_directory / "release-evidence.json"
            ):
                raise ValueError(
                    "publication evidence does not match requested evidence"
                )
            publish_downloads(args.candidate, args.output_directory, args.public_key)
        else:
            publish_downloads(args.candidate, args.output_directory, args.public_key)
    else:
        if args.directory is None:
            parser.error("directory is required")
        (prepare_gates if args.action == "prepare-gates" else prepare_results)(
            args.directory
        )


if __name__ == "__main__":
    main()
