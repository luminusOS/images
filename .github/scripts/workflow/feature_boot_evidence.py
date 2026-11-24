"""Verify a signed feature boot receipt for an already authenticated candidate."""

import re
import subprocess
from pathlib import Path

import release_pipeline as pipeline

SNAPSHOT_KEYRING = (
    Path(__file__).resolve().parents[3]
    / "editions/workstation/files/system/usr/share/luminusos/sysupdate/luminusos.pgp"
)
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
FEATURE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def validate_observation(observed: dict, version: str, manifest: str, raw: str) -> None:
    before = observed.get("before_boot_id")
    after = observed.get("after_boot_id")
    fetched = observed.get("fetched")
    pipeline.require(
        isinstance(before, str)
        and isinstance(after, str)
        and BOOT_ID.fullmatch(before)
        and BOOT_ID.fullmatch(after)
        and before != after,
        "feature observation does not contain two distinct boot IDs",
    )
    payload = f"/{version}/luminusos-dummy_{version}.raw.xz"
    required = {f"/{version}/release.json.gpg", payload}
    allowed = required | {
        f"/{version}/{name}"
        for name in ("release.json", "SHA256SUMS", "SHA256SUMS.gpg")
    }
    pipeline.require(
        isinstance(fetched, list)
        and all(isinstance(path, str) for path in fetched)
        and required <= set(fetched) <= allowed
        and observed.get("discovered_features") == ["dummy"]
        and observed.get("platform_manifest_digest") == manifest
        and observed.get("raw_sha256") == raw
        and observed.get("selinux") == "Enforcing"
        and observed.get("service") == "active"
        and observed.get("merge") == "provisioned",
        "feature observation does not match the signed payload or active guest",
    )


def platform_manifest(directory: Path, index_digest: str) -> str:
    path = pipeline.checked_file(
        directory, "workstation-oci.json", index_digest.removeprefix("sha256:"), True
    )
    index = pipeline.load(path)
    manifests = index.get("manifests")
    pipeline.require(
        type(index.get("schemaVersion")) is int
        and index["schemaVersion"] == 2
        and index.get("mediaType") in INDEX_TYPES
        and isinstance(manifests, list),
        "expected a workstation OCI index",
    )
    matches = []
    for entry in manifests:
        platform = entry.get("platform") if isinstance(entry, dict) else None
        if isinstance(platform, dict) and (
            platform.get("os"),
            platform.get("architecture"),
        ) == ("linux", "amd64"):
            matches.append(entry)
    pipeline.require(len(matches) == 1, "expected exactly one linux/amd64 manifest")
    digest = matches[0].get("digest")
    pipeline.require(
        matches[0].get("mediaType") in MANIFEST_TYPES
        and isinstance(digest, str)
        and pipeline.DIGEST.fullmatch(digest),
        "invalid linux/amd64 manifest descriptor",
    )
    return digest


def validate(
    directory: Path,
    candidate: dict,
    expected_feature: str,
    *,
    stable_approved: frozenset[str] = frozenset(),
) -> None:
    binding = pipeline.binding(candidate)
    manifest = platform_manifest(directory, binding["candidate_digest"])
    receipt_path = pipeline.safe_file(directory, "feature-boot.json")
    pipeline.verify(receipt_path, pipeline.CANDIDATE_PUBLIC_KEY)
    receipt = pipeline.load(receipt_path)
    pipeline.require(
        type(receipt.get("version")) is int
        and receipt["version"] == 1
        and receipt.get("binding") == binding
        and receipt.get("platform_manifest_digest") == manifest,
        "feature boot receipt does not match candidate",
    )
    snapshot = pipeline.checked_file(
        directory, "release.json", receipt.get("snapshot_sha256"), True
    )
    signature = pipeline.safe_file(directory, "release.json.gpg")
    subprocess.run(
        ["gpgv", "--keyring", str(SNAPSHOT_KEYRING), signature, snapshot],
        check=True,
        capture_output=True,
    )
    descriptor = pipeline.load(snapshot)
    pipeline.require(
        type(descriptor.get("format")) is int
        and descriptor["format"] == 1
        and descriptor.get("architecture") == "x86-64"
        and descriptor.get("version") == candidate["build_version"]
        and descriptor.get("image_digest") == manifest,
        "signed feature descriptor does not match candidate platform image",
    )
    features = descriptor.get("features")
    pipeline.require(
        isinstance(features, dict)
        and expected_feature in features
        and all(FEATURE_ID.fullmatch(name) for name in features),
        "expected feature not in signed descriptor or invalid feature ID",
    )
    discovered = receipt.get("discovered_features")
    pipeline.require(
        isinstance(discovered, list)
        and all(isinstance(name, str) for name in discovered)
        and sorted(discovered) == sorted(features),
        "boot discovery differs from signed feature descriptor",
    )
    if candidate["channel"] == "stable":
        pipeline.require(
            "dummy" not in features and features.keys() <= stable_approved,
            "stable requires only approved real features",
        )
    selected = features[expected_feature]
    raw_hash = selected.get("raw_sha256") if isinstance(selected, dict) else None
    pipeline.require(
        receipt.get("feature") == expected_feature
        and type(receipt.get("exit_code")) is int
        and receipt["exit_code"] == 0
        and isinstance(raw_hash, str)
        and pipeline.SHA.fullmatch(raw_hash)
        and receipt.get("raw_sha256") == raw_hash,
        "feature boot did not verify the expected signed payload",
    )
    pipeline.checked_file(
        directory, "feature-boot.log", receipt.get("log_sha256"), True
    )
