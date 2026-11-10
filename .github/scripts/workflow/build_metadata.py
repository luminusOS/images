import datetime
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from config_values import read_config


def releases(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if (
            not separator
            or key not in ("SUPPORTED_RELEASES", "LATEST_RELEASE")
            or key in values
        ):
            raise ValueError("invalid releases configuration")
        tokens = shlex.split(value, comments=True)
        if len(tokens) != 1 or not re.fullmatch(r"[0-9 ]+", tokens[0]):
            raise ValueError("invalid releases value")
        values[key] = tokens[0]
    if set(values) != {"SUPPORTED_RELEASES", "LATEST_RELEASE"}:
        raise ValueError("incomplete releases configuration")
    return values


def metadata(env, config, supported, base_digest, today, sequence=0):
    channel = env.get("CHANNEL", "testing")
    if channel not in ("testing", "stable") or config["UPDATE_CHANNEL"] not in (
        "testing",
        "stable",
    ):
        raise ValueError("invalid channel")
    if env.get("PUBLISH") == "true" or env.get("BUILDER_MODE", "local") not in (
        "local",
        "registry",
    ):
        raise ValueError("reusable build is read-only")
    if channel == "stable":
        version = env.get("PROMOTE_VERSION", "")
        if not re.fullmatch(r"[0-9]+\.[0-9]{8}(?:\.[0-9]+)?", version):
            raise ValueError("invalid promote_version")
        fedora = version.split(".")[0]
    else:
        branch = re.fullmatch(r"f([0-9]+)", env.get("GITHUB_REF_NAME", ""))
        fedora = env.get("FEDORA_VERSION") or (
            branch.group(1) if branch else config["DEFAULT_FEDORA_VERSION"]
        )
        version = f"{fedora}.{today}" + (f".{sequence}" if sequence else "")
    if (
        not re.fullmatch(r"[0-9]+", fedora)
        or fedora not in supported["SUPPORTED_RELEASES"].split()
    ):
        raise ValueError("unsupported Fedora version")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", base_digest):
        raise ValueError("invalid Fedora bootc digest")
    owner = env["GITHUB_REPOSITORY_OWNER"].lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", owner):
        raise ValueError("invalid image namespace")
    candidate = (
        env.get("CANDIDATE_ID") or f"{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    )
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,90}", candidate):
        raise ValueError("invalid candidate_id")
    override = env.get("SIRIUS_VERSION", "")
    checksum = env.get("SIRIUS_SHA256", "") if override else config["SIRIUS_SHA256"]
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("sirius_version override requires sirius_sha256")
    if override and not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", override
    ):
        raise ValueError("invalid sirius_version")
    tag = f"testing-{version}"
    target = fedora if config["UPDATE_CHANNEL"] == "stable" else f"testing-{fedora}"
    registry = f"ghcr.io/{owner}"
    candidate_tag = f"candidate-{candidate}"
    workstation = f"{registry}/luminusos-workstation:{candidate_tag if channel == 'testing' else tag}"
    result = {
        "fedora_version": fedora,
        "fedora_bootc_digest": base_digest,
        "version_tag": tag,
        "build_version": version,
        "branch_tag": fedora if channel == "stable" else f"testing-{fedora}",
        "channel_tag": "latest" if channel == "stable" else "testing",
        "release_tag": f"v{version}" if channel == "stable" else tag,
        "target_tag": target,
        "image_namespace": owner,
        "core_image": f"{registry}/luminusos:{candidate_tag if channel == 'testing' else tag}",
        "workstation_image": workstation,
        "workstation_iso_image": f"{registry}/luminusos-workstation:{candidate_tag}-iso",
        "sirius_version": override or config["SIRIUS_VERSION"],
        "sirius_rpm_version": override.replace("-rc.", "~rc.")
        or config["SIRIUS_RPM_VERSION"],
        "sirius_sha256": checksum,
        "publish_channel": str(fedora == supported["LATEST_RELEASE"]).lower(),
    }
    for key in (
        "AURORA_SHELL_VERSION",
        "AURORA_SHELL_SHA256",
        "ELASTIC_SWAP_VERSION",
        "ELASTIC_SWAP_SHA256",
    ):
        result[key.lower()] = config[key]
    return result


def main():
    env = os.environ
    subprocess.run(
        ["git", "fetch", "--quiet", "--depth=1", "origin", "main"], check=True
    )
    source = subprocess.check_output(
        ["git", "show", "FETCH_HEAD:config/releases.env"], text=True
    )
    config = read_config()
    channel = env.get("CHANNEL", "testing")
    if channel == "stable":
        fedora = env.get("PROMOTE_VERSION", "").split(".")[0]
    else:
        match = re.fullmatch(r"f([0-9]+)", env.get("GITHUB_REF_NAME", ""))
        fedora = env.get("FEDORA_VERSION") or (
            match.group(1) if match else config["DEFAULT_FEDORA_VERSION"]
        )
    base = subprocess.check_output(
        [sys.executable, "tools/fedora-bootc-digest.py", fedora], text=True
    ).strip()
    today = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d")
    sequence = 0
    if channel == "testing" and env.get("BUILD_SEQUENCE") == "true":
        prefix = f"testing-{fedora}.{today}."
        refs = subprocess.check_output(
            ["git", "ls-remote", "--tags", "origin", f"refs/tags/{prefix}*"], text=True
        )
        numbers = [
            int(m.group(1))
            for line in refs.splitlines()
            if (m := re.search(re.escape(prefix) + r"([0-9]+)$", line))
        ]
        sequence = max(numbers, default=0) + 1
    values = metadata(env, config, releases(source), base, today, sequence)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        for key, value in values.items():
            print(f"{key}={value}", file=out)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"metadata: {exc}", file=sys.stderr)
        sys.exit(1)
