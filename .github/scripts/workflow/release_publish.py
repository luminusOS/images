import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

GATES = ("quality", "boot", "signature", "sbom", "vulnerability")
KEY = "shared/trust/etc/pki/containers/luminusos.pub"
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


def verify_checksums(directory: Path, key: Path) -> None:
    manifest = directory / "SHA256SUMS"
    load_helper("release_pipeline").verify(manifest, key)
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


def verify_source(candidate_path: Path, public_key: Path, version: str) -> None:
    module = load_helper("release_pipeline")
    candidate = module.candidate(candidate_path, public_key)
    if (
        candidate["channel"] != "testing"
        or candidate["version_tag"] != f"testing-{version}"
    ):
        raise ValueError("stable source is not the requested testing candidate")
    release_configuration(candidate["fedora_version"])
    check_fedora_ga(candidate["fedora_version"])
    for role in ("core", "workstation"):
        subprocess.run(
            ["cosign", "verify", "--key", str(public_key), candidate["images"][role]],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    digest = candidate["images"]["workstation"].split("@", 1)[1]
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        print(f"workstation_digest={digest}", file=output)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def prepare_gates(directory: Path) -> None:
    for name in ("QUALITY_RESULT", "BOOT_RESULT", "SCAN_RESULT"):
        if os.environ.get(name) != "success":
            raise ValueError(f"required job did not succeed: {name}")
    images = {
        name: os.environ[name.upper()] for name in ("core", "workstation", "installer")
    }
    files = {}
    for name, image in images.items():
        subprocess.run(
            ["cosign", "verify", "--key", KEY, image],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        scan = directory / "scan" / name / "scan-evidence.json"
        data = json.loads(scan.read_text(encoding="utf-8"))
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
    candidate = pipeline.candidate(directory / "candidate.json", Path(KEY))
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
        evidence, workstation_digest, candidate["repository"], candidate["source_sha"]
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
    valid_tags = (
        {f"testing-{build_version}"}
        if candidate["channel"] == "testing"
        else {build_version, f"testing-{build_version}"}
    )
    if candidate["version_tag"] not in valid_tags:
        raise ValueError("candidate version tag does not match build version")
    return candidate


def verify_staged_distribution(
    candidate_path: Path,
    evidence_path: Path,
    directory: Path,
    candidate: dict,
    key: Path,
) -> None:
    verify_checksums(directory, key)
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
    release_artifacts(candidate_path.parent, candidate, original=True)
    if not (directory / "SHA256SUMS").exists():
        stage(candidate_path, evidence_path, directory, key)
    verify_staged_distribution(candidate_path, evidence_path, directory, candidate, key)
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
        repository, digest = image.split("@", 1)
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


def release_artifacts(
    directory: Path, candidate: dict, original: bool = False
) -> list[Path]:
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
    original_testing = {
        f"luminusos-workstation-testing-{candidate['build_version']}.{extension}"
        for extension in ("iso", "qcow2")
    }
    names = {p.name for p in images}
    allowed = names == expected or (
        original and candidate["channel"] == "stable" and names == original_testing
    )
    if not allowed or any(not p.is_file() or p.is_symlink() for p in images):
        raise ValueError("candidate must contain exactly the versioned ISO and qcow2")
    return sorted(images)


def stage(
    candidate_path: Path, evidence_path: Path, directory: Path, key: Path
) -> None:
    candidate = verify_release(candidate_path, evidence_path, key)
    release_artifacts(candidate_path.parent, candidate, original=True)
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
    supply.sign_file(sums, key)
    verify_checksums(directory, key)


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
    notes = directory / "notes.md"
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
    notes.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bundle = directory / "evidence.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path not in artifacts and path not in {bundle, notes}:
                archive.add(path, arcname=path.relative_to(directory), recursive=False)
    command = [
        "gh",
        "release",
        "create",
        version,
        "--target",
        candidate["source_sha"],
        "--title",
        f"LuminusOS {candidate['build_version']}",
        "--notes-file",
        str(notes),
    ]
    if channel == "testing":
        command.append("--prerelease")
    command.extend(
        str(path)
        for path in [directory / "SHA256SUMS", directory / "SHA256SUMS.sig", bundle]
    )
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "prepare-gates",
            "prepare-results",
            "verify-source",
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
    parser.add_argument("--promote-version")
    parser.add_argument("--channel", choices=("testing", "stable"))
    args = parser.parse_args()
    if args.action == "verify-source":
        if not args.candidate or not args.public_key or not args.promote_version:
            parser.error(
                "verify-source requires --candidate, --public-key and --promote-version"
            )
        verify_source(args.candidate, args.public_key, args.promote_version)
    elif args.action in (
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
