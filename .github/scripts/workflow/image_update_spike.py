"""Diagnostics only: boot a disk built from the published image and update it.

Answers whether an image-only release can be validated without an ISO. The
script never writes receipts that a release can consume and runs without any
signing credential; its output is a diagnostics directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import release_pipeline
import validation_driver as driver
from validation_driver import FIXTURE, CheckFailed, Guest, Machine, vmlib

CANDIDATE_KEY = HERE.parents[2] / "shared/release/candidate.pub"
DROP_INS = (
    driver.FIXTURE_KEY_PATH,
    "/etc/containers/registries.d/zz-validation-fixture.yaml",
    "/etc/containers/registries.conf.d/zz-validation-fixture.conf",
)


class Probe:
    def __init__(self, output: Path):
        self.output = output
        self.started = time.monotonic()
        self.results: list[dict] = []

    def record(self, name: str, ok: bool, detail: object = None) -> None:
        self.results.append(
            {
                "name": name,
                "ok": ok,
                "seconds": round(time.monotonic() - self.started),
                "detail": detail,
                "host_free_gib": round(
                    shutil.disk_usage(self.output).free / vmlib.GIB, 1
                ),
            }
        )
        (self.output / "summary.json").write_text(json.dumps(self.results, indent=1))

    def check(self, name: str, function, *args) -> tuple[bool, object]:
        try:
            value = function(*args)
        except (CheckFailed, subprocess.SubprocessError, OSError) as error:
            self.record(name, False, str(error))
            return False, None
        self.record(name, True, value)
        return True, value


class Discard:
    def __init__(self):
        self.names: list[str] = []

    def write(self, name, command, started, log) -> None:
        self.names.append(name)


def platform_digest(layout: Path) -> str:
    index = json.loads((layout / "index.json").read_text())
    return next(
        m["digest"]
        for m in index["manifests"]
        if m.get("annotations", {}).get("org.opencontainers.image.ref.name") == "base"
    )


def deployments(guest: Guest, name: str) -> dict:
    _, _, document = driver.status(guest, name)
    state = document.get("status") or {}
    return {
        slot: ((state.get(slot) or {}).get("image") or {}).get("imageDigest")
        for slot in ("booted", "staged", "rollback")
    } | {
        "version": ((state.get("booted") or {}).get("image") or {}).get("version"),
        "reference": (
            ((state.get("booted") or {}).get("image") or {}).get("image") or {}
        ).get("image"),
    }


def guest_disk(guest: Guest, name: str) -> str:
    return guest.run(name, "df -B1 --output=size,avail / /var")[1].stdout


def restore_official_trust(guest: Guest) -> None:
    _, result = guest.run(
        "restore-trust",
        "cp /usr/etc/containers/policy.json /etc/containers/policy.json && rm -f "
        + " ".join(DROP_INS),
    )
    if result.returncode != 0:
        raise CheckFailed("cannot restore the image's trust policy")


def push_candidate(work: Path, layout: Path, diagnostics: Path) -> tuple[str, str]:
    log = diagnostics / "candidate-mirror.txt"
    digest_file = work / "candidate.digest"
    driver.host(
        [
            "skopeo",
            "copy",
            "--preserve-digests",
            "--dest-tls-verify=false",
            "--digestfile",
            str(digest_file),
            f"oci:{layout}:base",
            f"docker://{FIXTURE}:candidate",
        ],
        log,
    )
    mirrored = digest_file.read_text().strip()
    if mirrored != platform_digest(layout):
        raise CheckFailed(f"mirror changed the candidate digest to {mirrored}")
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    prefix = work / "spike-cosign"
    driver.host(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
        log,
        env=env,
    )
    driver.host(
        [
            "cosign",
            "sign",
            "--yes",
            "--tlog-upload=false",
            "--allow-http-registry",
            "--key",
            f"{prefix}.key",
            f"{FIXTURE}@{mirrored}",
        ],
        log,
        env=env,
    )
    Path(f"{prefix}.key").unlink()
    return mirrored, Path(f"{prefix}.pub").read_text()


def run(args: argparse.Namespace) -> int:
    output = args.output
    output.mkdir(mode=0o700, parents=True)
    work = Path(os.environ.get("RUNNER_TEMP", output.parent)) / "image-spike-vm"
    work.mkdir(mode=0o700)
    probe = Probe(output)
    code, template = driver.secure_firmware(os.environ)
    variables = work / "vars.fd"
    shutil.copyfile(template, variables)
    key = work / "ssh-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    disk = work / "base.qcow2"
    shutil.move(args.disk, disk)
    probe.record(
        "disk",
        True,
        driver.host(["qemu-img", "info", str(disk)], output / "qemu-img.txt"),
    )
    vm = vmlib.VM(
        cid=args.cid,
        disk=disk,
        key=key,
        public_key=key.with_suffix(".pub").read_text().strip(),
        output=output,
        code=code,
        variables=variables,
    )
    guest = Guest(vm, output)
    machine = Machine(vm, output)
    registry = None
    try:
        registry = driver.start_registry(work, output)
        mirrored_ok, mirrored = probe.check(
            "mirror_candidate", push_candidate, work, args.candidate_layout, output
        )
        booted_ok, _ = probe.check("boot_published_disk", machine.start, None)
        if not booted_ok:
            return 1
        _, base = probe.check("base_state", deployments, guest, "base-status")
        probe.record(
            "base_matches_published",
            bool(base) and base["booted"] == args.base_manifest,
            {"want": args.base_manifest},
        )
        probe.check("base_disk", guest_disk, guest, "base-df")
        receipts = Discard()
        for name, function in (
            ("base_expected_key", driver.expected_key),
            ("base_secure_boot", driver.secure_boot),
            ("base_no_tcp_ssh", driver.no_tcp_ssh),
        ):
            probe.check(name, function, guest, receipts)
        if not mirrored_ok:
            return 1
        digest, public_key = mirrored
        probe.check(
            "install_fixture_trust", driver.install_fixture_trust, guest, public_key
        )
        _, switch = guest.run(
            "switch-candidate", f"bootc switch {FIXTURE}@{digest}", timeout=3600
        )
        probe.record("switch_candidate", switch.returncode == 0, switch.stderr[-2000:])
        if switch.returncode != 0:
            return 1
        machine.stop()
        candidate_ok, _ = probe.check("boot_candidate", machine.start, None)
        if not candidate_ok:
            return 1
        _, after = probe.check(
            "candidate_state", deployments, guest, "candidate-status"
        )
        probe.record(
            "candidate_booted_rollback_is_base",
            bool(after)
            and after["booted"] == digest
            and after["rollback"] == args.base_manifest,
            {"want_booted": digest, "want_rollback": args.base_manifest},
        )
        probe.check("restore_official_trust", restore_official_trust, guest)
        for name, function in (
            ("candidate_expected_key", driver.expected_key),
            ("candidate_selinux_firewall", driver.security_state),
            ("candidate_no_tcp_ssh", driver.no_tcp_ssh),
            ("candidate_secure_boot", driver.secure_boot),
        ):
            probe.check(name, function, guest, receipts)
        probe.check("candidate_disk", guest_disk, guest, "candidate-df")
        machine.stop()
    finally:
        machine.kill()
        if registry is not None:
            driver.terminate(registry)
        probe.record("cleanup", True)
        shutil.rmtree(work, ignore_errors=True)
    return 0 if all(result["ok"] for result in probe.results) else 1


def base_tag(candidate: dict, version: str) -> str:
    # The base comes from the candidate's own channel and Fedora line, so a
    # stable candidate is never updated from a testing image.
    line = (
        f"testing-{candidate['fedora_version']}"
        if candidate["channel"] == "testing"
        else candidate["fedora_version"]
    )
    if not re.fullmatch(r"[1-9][0-9]*", candidate["fedora_version"]):
        raise ValueError("invalid candidate Fedora version")
    if not version:
        return line
    if not re.fullmatch(re.escape(line) + r"\.[0-9]{8}(?:\.[0-9]+)?", version):
        raise ValueError(f"base version {version!r} is not on line {line}")
    return version


def main(argv: list[str] | None = None) -> int:
    if (
        os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
    ):
        print(
            "image update spike runs only from main by workflow_dispatch",
            file=sys.stderr,
        )
        return 2
    if any(
        word in name.upper()
        for name in os.environ
        for word in ("COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD", "SECRET")
    ):
        print(
            "image update spike refuses to run with signing credentials",
            file=sys.stderr,
        )
        return 2
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["base-tag"]:
        parser = argparse.ArgumentParser()
        parser.add_argument("--candidate", type=Path, required=True)
        parser.add_argument("--version", default="")
        options = parser.parse_args(argv[1:])
        candidate = release_pipeline.candidate(options.candidate, CANDIDATE_KEY)
        try:
            print(base_tag(candidate, options.version))
        except ValueError as error:
            print(f"image update spike: {error}", file=sys.stderr)
            return 2
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk", type=Path, required=True)
    parser.add_argument("--base-manifest", required=True)
    parser.add_argument("--candidate-layout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cid", type=int, default=3 + os.getpid() % 10000)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
