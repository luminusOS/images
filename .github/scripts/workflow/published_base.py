"""Resolve the published channel image an image-only candidate upgrades from.

The base is authenticated by release history, never by registry labels alone:
the newest published GitHub release of the channel and Fedora line must carry a
SHA256SUMS signed with the official key, its release-evidence.json must be
listed there, and that evidence must name the exact index digest the line tag
serves for each edition.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OFFICIAL_KEY = ROOT / "shared/trust/etc/pki/containers/luminusos.pub"
EDITIONS = {"core": "luminusos", "workstation": "luminusos-workstation"}
ASSETS = {
    "SHA256SUMS": 1024**2,
    "SHA256SUMS.sig": 64 * 1024,
    "evidence.tar.gz": 512 * 1024**2,
}
MAX_EVIDENCE = 4 * 1024**2
MAX_BUNDLE_BYTES = 4 * 1024**3
MAX_BUNDLE_MEMBERS = 10000
RELEASE_AUTHOR = "github-actions[bot]"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
FIRST_RELEASE = "first image release of a line needs a manual full release"


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def helper(name: str):
    spec = importlib.util.spec_from_file_location(
        f"published_base_{name}", Path(__file__).with_name(f"{name}.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv: list[str], *, text: bool = True) -> str | bytes:
    return subprocess.run(argv, check=True, capture_output=True, text=text).stdout


def release_tag(channel: str, fedora: str) -> re.Pattern:
    require(re.fullmatch(r"[1-9][0-9]*", fedora), "invalid Fedora line")
    if channel == "testing":
        return re.compile(rf"testing-{fedora}\.[0-9]{{8}}(?:\.[1-9][0-9]*)?\Z")
    require(channel == "stable", "invalid channel")
    return re.compile(rf"{fedora}\.[0-9]{{8}}\.[1-9][0-9]*\Z")


def newest_release(releases: list, repository: str, channel: str, fedora: str) -> dict:
    pattern = release_tag(channel, fedora)
    order = helper("release_pipeline").version_order
    found = {}
    for release in releases:
        require(isinstance(release, dict), "invalid release metadata")
        tag = release.get("tag_name")
        if (
            not isinstance(tag, str)
            or not pattern.fullmatch(tag)
            or release.get("draft") is not False
            or release.get("prerelease") is not (channel == "testing")
        ):
            continue
        key = order(tag)
        require(key not in found, f"conflicting releases for {tag}")
        found[key] = release
    require(
        found, f"no published {channel} release of Fedora {fedora}: {FIRST_RELEASE}"
    )
    newest = found[max(found)]
    author, url = newest.get("author"), newest.get("url")
    prefix = f"https://api.github.com/repos/{repository}/releases/"
    require(
        isinstance(author, dict)
        and author.get("login") == RELEASE_AUTHOR
        and isinstance(url, str)
        and re.fullmatch(re.escape(prefix) + r"[1-9][0-9]*", url, re.IGNORECASE),
        f"newest release on line {channel}/Fedora {fedora} "
        "was not published by the release workflow",
    )
    return newest


def list_releases(repository: str) -> list:
    pages = json.loads(
        run(
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/releases?per_page=100",
            ]
        )
    )
    require(
        isinstance(pages, list) and all(isinstance(p, list) for p in pages),
        "invalid release pages",
    )
    return [release for page in pages for release in page]


def download_assets(repository: str, release: dict, directory: Path) -> dict:
    assets = {}
    for asset in release.get("assets") or []:
        name = asset.get("name") if isinstance(asset, dict) else None
        if name in ASSETS:
            require(name not in assets, f"duplicate release asset {name}")
            assets[name] = asset
    tag = release["tag_name"]
    require(
        set(assets) == set(ASSETS),
        f"release {tag} lacks signed evidence: {FIRST_RELEASE}",
    )
    paths = {}
    for name, limit in ASSETS.items():
        size = assets[name].get("size")
        require(type(size) is int and 0 < size <= limit, f"invalid {name} size")
        run(
            [
                "gh",
                "release",
                "download",
                tag,
                "--repo",
                repository,
                "--pattern",
                name,
                "--dir",
                str(directory),
            ]
        )
        path = directory / name
        require(
            path.is_file() and not path.is_symlink() and path.stat().st_size == size,
            f"downloaded {name} does not match the release asset",
        )
        paths[name] = path
    return paths


def listed(sums: Path, name: str) -> str:
    entries = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        require(match, "invalid SHA256SUMS line")
        require(match.group(2) not in entries, "duplicate SHA256SUMS entry")
        entries[match.group(2)] = match.group(1)
    require(name in entries, f"{name} is not covered by the signed SHA256SUMS")
    return entries[name]


def bundled_evidence(bundle: Path) -> bytes:
    found = None
    total = 0
    with tarfile.open(bundle, mode="r:gz") as tar:
        for count, member in enumerate(tar, 1):
            total += max(member.size, 0)
            require(
                count <= MAX_BUNDLE_MEMBERS and total <= MAX_BUNDLE_BYTES,
                "evidence bundle too large",
            )
            if member.name != "release-evidence.json":
                continue
            require(found is None, "duplicate release evidence in bundle")
            require(
                member.isreg() and 0 < member.size <= MAX_EVIDENCE,
                "invalid release evidence in bundle",
            )
            stream = tar.extractfile(member)
            found = stream.read(MAX_EVIDENCE + 1)
            require(len(found) == member.size, "truncated release evidence")
    require(found is not None, "evidence bundle has no release-evidence.json")
    return found


def raw(reference: str) -> bytes:
    return run(["skopeo", "inspect", "--raw", f"docker://{reference}"], text=False)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def image_identity(repository: str, tag: str, version: str) -> dict:
    index_bytes = raw(f"{repository}:{tag}")
    index_digest = sha(index_bytes)
    index = json.loads(index_bytes)
    require(
        isinstance(index, dict) and isinstance(index.get("manifests"), list),
        f"{repository}:{tag} must point to an image index, not a single manifest",
    )
    platforms = [
        entry
        for entry in index["manifests"]
        if isinstance(entry, dict)
        and isinstance(platform := entry.get("platform"), dict)
        and platform.get("architecture") == "amd64"
        and platform.get("os") == "linux"
    ]
    require(len(platforms) == 1, f"{repository}:{tag} needs one linux/amd64 manifest")
    manifest_digest = platforms[0].get("digest")
    require(
        isinstance(manifest_digest, str) and DIGEST.fullmatch(manifest_digest),
        "invalid platform manifest digest",
    )
    manifest_bytes = raw(f"{repository}@{manifest_digest}")
    require(sha(manifest_bytes) == manifest_digest, "platform manifest digest mismatch")
    config_digest = (json.loads(manifest_bytes).get("config") or {}).get("digest")
    require(
        isinstance(config_digest, str) and DIGEST.fullmatch(config_digest),
        "invalid image config digest",
    )
    config_bytes = run(
        [
            "skopeo",
            "inspect",
            "--config",
            "--raw",
            f"docker://{repository}@{manifest_digest}",
        ],
        text=False,
    )
    require(sha(config_bytes) == config_digest, "image config digest mismatch")
    labels = (json.loads(config_bytes).get("config") or {}).get("Labels") or {}
    require(
        labels.get("org.opencontainers.image.version")
        == version.removeprefix("testing-"),
        f"{repository}:{tag} version label differs from release {version}",
    )
    return {
        "index_digest": index_digest,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
    }


def line_digest(repository_ref: str, line: str) -> str:
    return sha(raw(f"{repository_ref}:{line}"))


def line_tag(channel: str, fedora: str) -> str:
    return ("testing-" if channel == "testing" else "") + fedora


def image_repository(repository: str, edition: str) -> str:
    owner = repository.split("/", 1)[0].lower()
    require(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", owner), "invalid owner")
    return f"ghcr.io/{owner}/{EDITIONS[edition]}"


def release_evidence(repository: str, channel: str, fedora: str):
    """Return the newest release of the line with its authenticated evidence."""
    pipeline = helper("release_pipeline")
    publish = helper("release_publish")
    release = newest_release(list_releases(repository), repository, channel, fedora)
    version = release["tag_name"]
    with tempfile.TemporaryDirectory(prefix="luminus-base-") as temp:
        assets = download_assets(repository, release, Path(temp))
        publish.verify_blob(
            assets["SHA256SUMS"], assets["SHA256SUMS.sig"], str(OFFICIAL_KEY)
        )
        evidence_bytes = bundled_evidence(assets["evidence.tar.gz"])
        evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
        require(
            listed(assets["SHA256SUMS"], "release-evidence.json") == evidence_sha,
            "release evidence differs from the signed SHA256SUMS",
        )
    evidence = json.loads(evidence_bytes)
    source = evidence.get("source") if isinstance(evidence, dict) else None
    require(
        isinstance(source, dict)
        and evidence.get("repository") == repository
        and source.get("repository") == repository
        and source.get("ref") == pipeline.release_ref(channel, fedora),
        f"release {version} evidence is not from this repository's {channel} line",
    )
    require(isinstance(evidence.get("images"), dict), "release evidence has no images")
    return version, evidence, evidence_sha


def resolve(repository: str, channel: str, fedora: str) -> dict:
    line = line_tag(channel, fedora)
    version, evidence, evidence_sha = release_evidence(repository, channel, fedora)
    official = hashlib.sha256(OFFICIAL_KEY.read_bytes()).hexdigest()
    result = {}
    for edition in EDITIONS:
        repository_ref = image_repository(repository, edition)
        reference = f"{repository_ref}:{line}"
        identity = image_identity(repository_ref, line, version)
        signed = evidence["images"].get(edition)
        require(
            isinstance(signed, str) and signed.endswith("@" + identity["index_digest"]),
            f"{reference} is not the {edition} image of release {version}",
        )
        run(
            [
                "cosign",
                "verify",
                "--key",
                str(OFFICIAL_KEY),
                f"{repository_ref}@{identity['index_digest']}",
            ]
        )
        result[edition] = {
            "reference": reference,
            **identity,
            "version": version,
            "release_evidence_sha256": evidence_sha,
            "official_key_sha256": official,
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--channel", choices=("testing", "stable"), required=True)
    parser.add_argument("--fedora", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository),
            "invalid repository",
        )
        base = resolve(args.repository, args.channel, args.fedora)
        args.output.write_text(
            json.dumps(base, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"published base rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(base, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
