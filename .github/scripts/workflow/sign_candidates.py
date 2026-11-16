import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DIGEST = re.compile(r"\bdigest:\s*(sha256:[0-9a-f]{64})\b")
KEY = Path("shared/release/candidate.pub")
PLACEHOLDER = "placeholder"
DENIED = (401, 403)


def _anonymous_status(repository: str, tag: str) -> int:
    host, path = repository.split("/", 1)
    query = urllib.parse.urlencode(
        {"scope": f"repository:{path}:pull", "service": host}
    )
    try:
        with urllib.request.urlopen(
            f"https://{host}/token?{query}", timeout=30
        ) as response:
            token = json.load(response)["token"]
    except urllib.error.HTTPError as error:
        return error.code
    request = urllib.request.Request(
        f"https://{host}/v2/{path}/manifests/{tag}",
        method="HEAD",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.oci.image.index.v1+json, "
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.v2+json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status if hasattr(response, "status") else 200
    except urllib.error.HTTPError as error:
        return error.code


def _require_denied(repository: str, tag: str) -> None:
    status = _anonymous_status(repository, tag)
    if status not in DENIED:
        raise ValueError(
            f"candidate staging must be private: anonymous {repository}:{tag} "
            f"returned HTTP {status}"
        )


def require_private_staging(repository: str) -> None:
    # GitHub cannot make a public package private again, and the first push from a
    # public repository may create it public. Push only into a package that already
    # exists (authenticated read of the placeholder) and denies anonymous pulls.
    subprocess.run(
        ["docker", "manifest", "inspect", f"{repository}:{PLACEHOLDER}"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _require_denied(repository, PLACEHOLDER)


def push_and_sign(image: str) -> str:
    if os.environ.get("SECURITY_FINDINGS_BYPASS", "false") != "false":
        raise ValueError("diagnostic bypass cannot publish or sign candidates")
    if "COSIGN_PRIVATE_KEY" in os.environ:
        raise ValueError("official COSIGN_PRIVATE_KEY must not be present")
    if not os.environ.get("CANDIDATE_COSIGN_PRIVATE_KEY"):
        raise ValueError("CANDIDATE_COSIGN_PRIVATE_KEY is required")
    if "@" in image or not re.fullmatch(
        r"ghcr\.io/[a-z0-9][a-z0-9-]*/luminusos-candidates:(?:core|workstation|workstation-iso)-candidate-[A-Za-z0-9_][A-Za-z0-9_.-]{0,90}",
        image,
    ):
        raise ValueError("invalid candidate image reference")
    result = subprocess.run(
        ["docker", "push", image], check=True, capture_output=True, text=True
    )
    matches = DIGEST.findall(result.stdout + "\n" + result.stderr)
    if len(matches) != 1:
        raise ValueError(f"push did not return one manifest digest for {image}")
    immutable = f"{image.rsplit(':', 1)[0]}@{matches[0]}"
    subprocess.run(
        [
            "cosign",
            "sign",
            "--yes",
            "--key",
            "env://CANDIDATE_COSIGN_PRIVATE_KEY",
            immutable,
        ],
        check=True,
    )
    subprocess.run(
        ["cosign", "verify", "--key", str(KEY), immutable],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return immutable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installer-only", action="store_true")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("images", nargs="+")
    args = parser.parse_args()
    try:
        if args.metadata:
            if args.installer_only or len(args.images) != 3:
                raise ValueError("metadata requires core, workstation and installer")
            metadata = {
                "version": 1,
                "repository": os.environ["GITHUB_REPOSITORY"],
                "source_sha": os.environ["GITHUB_SHA"],
                "run_id": int(os.environ["GITHUB_RUN_ID"]),
                "channel": os.environ["CHANNEL"],
                "version_tag": os.environ["VERSION_TAG"],
                "build_version": os.environ["BUILD_VERSION"],
                "fedora_version": os.environ["FEDORA_VERSION"],
                "fedora_bootc_digest": os.environ["FEDORA_BOOTC_DIGEST"],
                "images": dict(
                    zip(("core", "workstation", "installer"), args.images, strict=True)
                ),
            }
            args.metadata.write_text(
                json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
            )
            return 0
        if args.installer_only and len(args.images) != 1:
            raise ValueError("expected one installer image")
        if not args.installer_only and len(args.images) not in (2, 3):
            raise ValueError("expected core and workstation, optionally installer")
        if "COSIGN_PRIVATE_KEY" in os.environ:
            raise ValueError("official COSIGN_PRIVATE_KEY must not be present")
        if not os.environ.get("CANDIDATE_COSIGN_PRIVATE_KEY"):
            raise ValueError("CANDIDATE_COSIGN_PRIVATE_KEY is required")
        if not KEY.is_file():
            raise ValueError("trusted signing key is unavailable")
        if os.environ.get("SECURITY_FINDINGS_BYPASS", "false") != "false":
            raise ValueError("diagnostic bypass cannot publish or sign candidates")
        repositories = {image.rsplit(":", 1)[0] for image in args.images}
        if len(repositories) != 1:
            raise ValueError("candidates must share one staging repository")
        repository = repositories.pop()
        require_private_staging(repository)
        references = [push_and_sign(image) for image in args.images]
        for image in args.images:
            _require_denied(repository, image.rsplit(":", 1)[1])
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            names = (
                ("installer",)
                if args.installer_only
                else ("core", "workstation", "installer")[: len(references)]
            )
            for name, reference in zip(names, references, strict=True):
                print(f"{name}={reference}", file=output)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"candidate publication failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
