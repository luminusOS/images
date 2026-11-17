"""Install the verified candidate with Sirius and record the release receipts.

Runs on a hosted KVM runner from the checkout of the dispatching main commit.
Every receipt describes a check observed inside a disposable VM; a failed check
aborts the run, so a receipt only exists for a check that passed.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
import install_feasibility as vmlib
import release_pipeline
from qemu_security import secure_firmware

REGISTRY_HOST = "registry.validation.test"
REGISTRY = f"{REGISTRY_HOST}:5000"
FIXTURE = f"{REGISTRY}/fixture"
FIXTURE_KEY_PATH = "/etc/pki/containers/validation-fixture.pub"
MARKER = "/usr/share/luminusos-validation/marker"
TRUST = ROOT / "shared/trust"
OFFICIAL_FILES = (
    "etc/containers/policy.json",
    "etc/containers/registries.d/luminusos.yaml",
    "etc/pki/containers/luminusos.pub",
)
LIVE_ONLY = (
    "/usr/bin/sirius",
    "/etc/sirius",
    "/usr/share/sirius",
    "/usr/share/polkit-1/rules.d/50-sirius-live.rules",
    "/usr/lib/systemd/user/luminusos-sirius.service",
    "/usr/share/wayland-sessions/live-installer.desktop",
    "/usr/share/gnome-session/sessions/live-installer.session",
    "/usr/share/gnome-shell/modes/live-installer.json",
    "/var/lib/AccountsService/users/liveuser",
    "/etc/dconf/db/local.d/00-iso-live-mode",
)


class CheckFailed(RuntimeError):
    pass


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


class Receipts:
    def __init__(self, directory: Path, candidate: dict):
        self.directory = directory
        self.binding = release_pipeline.binding(candidate)
        self.names: list[str] = []

    def write(self, name: str, command: list[str], started: str, log: str) -> None:
        if name not in release_pipeline.CHECKS or name in self.names:
            raise CheckFailed(f"unexpected receipt {name}")
        data = log.encode()
        (self.directory / f"{name}.log").write_bytes(data)
        receipt = {
            "name": name,
            "binding": self.binding,
            "command": command,
            "exit_code": 0,
            "started_at": started,
            "finished_at": now(),
            "log": f"{name}.log",
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        (self.directory / f"{name}.json").write_text(json.dumps(receipt, indent=1))
        self.names.append(name)


def transcript(argv: list[str], result: subprocess.CompletedProcess) -> str:
    return (
        f"$ {json.dumps(argv)}\n--- stdout\n{result.stdout}\n--- stderr\n"
        f"{result.stderr}\n--- exit {result.returncode}\n"
    )


def text(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def terminate(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class Guest:
    def __init__(self, vm: vmlib.VM, diagnostics: Path):
        self.vm = vm
        self.diagnostics = diagnostics

    def run(self, name: str, command: str, *, timeout: int = 900, stdin=None):
        argv = vmlib.ssh_argv(self.vm, command)
        try:
            result = subprocess.run(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            partial = subprocess.CompletedProcess(
                argv, -1, text(error.output), text(error.stderr)
            )
            (self.diagnostics / f"{name}.txt").write_text(transcript(argv, partial))
            raise CheckFailed(f"{name} timed out after {timeout} s") from None
        (self.diagnostics / f"{name}.txt").write_text(transcript(argv, result))
        return argv, result


def qemu_argv(vm: vmlib.VM, *, iso: Path | None, serial: Path) -> list[str]:
    argv = vmlib.qemu_argv(vm, iso=iso)
    argv[argv.index("q35")] = "q35,smm=on"
    argv[argv.index(next(a for a in argv if a.startswith("file:")))] = f"file:{serial}"
    return argv + [
        "-global",
        "driver=cfi.pflash01,property=secure,value=on",
        "-nic",
        "user,model=virtio-net-pci",
    ]


class Machine:
    def __init__(self, vm: vmlib.VM, diagnostics: Path):
        self.vm = vm
        self.diagnostics = diagnostics
        self.process: subprocess.Popen | None = None
        self.boots = 0

    def start(self, iso: Path | None) -> None:
        self.boots += 1
        label = f"boot{self.boots}-{'live' if iso else 'disk'}"
        argv = qemu_argv(self.vm, iso=iso, serial=self.diagnostics / f"{label}.serial")
        (self.diagnostics / f"{label}.qemu.json").write_text(json.dumps(argv))
        self.process = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=(self.diagnostics / f"{label}.qemu.stderr").open("w"),
            start_new_session=True,
        )
        self.wait_for_ssh(timeout=1200)

    def wait_for_ssh(self, *, timeout: int) -> None:
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if self.process.poll() is not None:
                raise CheckFailed(f"QEMU exited with {self.process.returncode}")
            try:
                result = subprocess.run(
                    vmlib.ssh_argv(self.vm, "true"),
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                result = None
            if result is not None and result.returncode == 0:
                return
            time.sleep(10)
        raise CheckFailed(f"ssh over vsock not ready after {timeout} s")

    def stop(self) -> None:
        if self.process is None:
            return
        subprocess.run(
            vmlib.ssh_argv(self.vm, "systemctl poweroff"),
            capture_output=True,
            timeout=60,
            check=False,
        )
        try:
            self.process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            self.kill()
            raise CheckFailed("guest did not power off") from None
        self.process = None

    def kill(self) -> None:
        if self.process is not None:
            terminate(self.process)
        self.process = None


def find_mount(tree: dict, target: str) -> dict | None:
    stack = list(tree.get("filesystems", []))
    while stack:
        node = stack.pop()
        if node.get("target") == target:
            return node
        stack.extend(node.get("children", []))
    return None


def check_layout(mounts: dict) -> list[str]:
    problems = []
    for target, fstype in (("/sysroot", "btrfs"), ("/var", "btrfs"), ("/boot", "ext4")):
        node = find_mount(mounts, target)
        if node is None or node.get("fstype") != fstype:
            problems.append(f"{target} is {node and node.get('fstype')}, want {fstype}")
    return problems


def booted(status: dict) -> dict:
    image = ((status.get("status") or {}).get("booted") or {}).get("image")
    if not isinstance(image, dict):
        raise CheckFailed("bootc reports no booted image")
    return image


# containers/image reports policy failures as "Source image rejected: <reason>";
# the reason distinguishes a missing signature from one made by another key.
POLICY_REJECTION = "source image rejected:"
NO_SIGNATURE = "a signature was required, but no signature exists"
VERIFICATION_FAILED = ("verification failed", "invalid signature", "not accepted")


def rejected(result: subprocess.CompletedProcess, kind: str) -> bool:
    output = (result.stdout + result.stderr).lower()
    if result.returncode == 0 or POLICY_REJECTION not in output:
        return False
    reason = output.split(POLICY_REJECTION, 1)[1]
    if kind == "unsigned":
        return NO_SIGNATURE in reason
    return NO_SIGNATURE not in reason and any(
        phrase in reason for phrase in VERIFICATION_FAILED
    )


def fixture_policy(policy: dict) -> dict:
    updated = json.loads(json.dumps(policy))
    updated["transports"]["docker"][FIXTURE] = [
        {
            "type": "sigstoreSigned",
            "keyPath": FIXTURE_KEY_PATH,
            "signedIdentity": {"type": "matchRepository"},
        }
    ]
    return updated


def add_marker_layer(layout: Path, base_ref: str, ref: str, marker: str) -> None:
    """Derive an image from base_ref in an OCI layout, reusing every base blob."""

    def blob(digest: str) -> Path:
        return layout / "blobs" / digest.replace(":", "/", 1)

    def put(data: bytes) -> dict:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        blob(digest).write_bytes(data)
        return {"digest": digest, "size": len(data)}

    index = json.loads((layout / "index.json").read_text())
    base = next(
        m
        for m in index["manifests"]
        if m.get("annotations", {}).get("org.opencontainers.image.ref.name") == base_ref
    )
    manifest = json.loads(blob(base["digest"]).read_bytes())
    config = json.loads(blob(manifest["config"]["digest"]).read_bytes())
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        parts = MARKER.strip("/").split("/")
        for depth in range(1, len(parts)):
            info = tarfile.TarInfo("/".join(parts[:depth]))
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
        content = marker.encode() + b"\n"
        info = tarfile.TarInfo("/".join(parts))
        info.size, info.mode = len(content), 0o644
        tar.addfile(info, io.BytesIO(content))
    uncompressed = raw.getvalue()
    layer = put(gzip.compress(uncompressed, mtime=0))
    config["rootfs"]["diff_ids"].append(
        "sha256:" + hashlib.sha256(uncompressed).hexdigest()
    )
    config.setdefault("history", []).append(
        {"created_by": f"luminusos validation fixture: {marker}"}
    )
    config_descriptor = put(json.dumps(config).encode())
    manifest["config"] = {**manifest["config"], **config_descriptor}
    manifest["layers"].append(
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **layer}
    )
    descriptor = put(json.dumps(manifest).encode())
    index["manifests"].append(
        {
            "mediaType": base.get(
                "mediaType", "application/vnd.oci.image.manifest.v1+json"
            ),
            **descriptor,
            "annotations": {"org.opencontainers.image.ref.name": ref},
        }
    )
    (layout / "index.json").write_text(json.dumps(index))


def host(argv: list[str], log: Path, *, env=None, timeout=3600) -> str:
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False, env=env
    )
    with log.open("a") as handle:
        handle.write(transcript(argv, result))
    if result.returncode != 0:
        raise CheckFailed(f"{argv[0]} failed: {result.stderr.strip()[-400:]}")
    return result.stdout


def prepare_fixtures(work: Path, base: Path, diagnostics: Path) -> dict:
    log = diagnostics / "fixtures.txt"
    layout = base
    for ref in ("update", "unsigned", "foreign"):
        add_marker_layer(layout, "base", ref, ref)
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    keys = {}
    for name in ("fixture", "foreign"):
        prefix = work / f"{name}-cosign"
        host(
            ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
            log,
            env=env,
        )
        keys[name] = prefix
    digests = {}
    for ref in ("update", "unsigned", "foreign"):
        digest_file = work / f"{ref}.digest"
        host(
            [
                "skopeo",
                "copy",
                "--dest-tls-verify=false",
                "--digestfile",
                str(digest_file),
                f"oci:{layout}:{ref}",
                f"docker://{FIXTURE}:{ref}",
            ],
            log,
        )
        digests[ref] = digest_file.read_text().strip()
    for ref, key in (("update", "fixture"), ("foreign", "foreign")):
        host(
            [
                "cosign",
                "sign",
                "--yes",
                "--tlog-upload=false",
                "--allow-http-registry",
                "--key",
                f"{keys[key]}.key",
                f"{FIXTURE}@{digests[ref]}",
            ],
            log,
            env=env,
        )
    for prefix in keys.values():
        Path(f"{prefix}.key").unlink()
    return {
        "digests": digests,
        "public_key": Path(f"{keys['fixture']}.pub").read_text(),
    }


def start_registry(work: Path, diagnostics: Path) -> subprocess.Popen:
    config = work / "registry.yml"
    config.write_text(
        json.dumps(
            {
                "version": 0.1,
                "storage": {"filesystem": {"rootdirectory": str(work / "registry")}},
                "http": {"addr": "127.0.0.1:5000"},
            }
        )
    )
    process = subprocess.Popen(
        ["docker-registry", "serve", str(config)],
        stdout=(diagnostics / "registry.log").open("w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    for _ in range(30):
        if process.poll() is not None:
            raise CheckFailed("fixture registry exited")
        if registry_ready():
            return process
        time.sleep(2)
    terminate(process)
    raise CheckFailed("fixture registry did not start")


def registry_ready() -> bool:
    try:
        with urllib.request.urlopen(f"http://{REGISTRY}/v2/", timeout=5) as response:
            return response.status == 200
    except OSError:
        return False


def base_diff_ids(layout: Path) -> list[str]:
    index = json.loads((layout / "index.json").read_text())
    base = next(
        m
        for m in index["manifests"]
        if m.get("annotations", {}).get("org.opencontainers.image.ref.name") == "base"
    )

    def blob(digest: str) -> bytes:
        return (layout / "blobs" / digest.replace(":", "/", 1)).read_bytes()

    manifest = json.loads(blob(base["digest"]))
    return json.loads(blob(manifest["config"]["digest"]))["rootfs"]["diff_ids"]


def validate(args: argparse.Namespace) -> None:
    candidate = json.loads(args.candidate.read_text())
    receipts = Receipts(args.receipts, candidate)
    diagnostics = args.receipts / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    work = Path(os.environ.get("RUNNER_TEMP", args.receipts.parent)) / "validation-vm"
    work.mkdir(mode=0o700)
    try:
        _validate(args, candidate, receipts, diagnostics, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _validate(args, candidate, receipts, diagnostics, work) -> None:
    isos = [name for name in candidate["artifacts"] if name.endswith(".iso")]
    if len(isos) != 1:
        raise CheckFailed("candidate must bind exactly one ISO")
    iso = args.artifacts / isos[0]
    vmlib.preflight(work, required_bytes=iso.stat().st_size + 60 * vmlib.GIB)
    code, template = secure_firmware(os.environ)
    variables = work / "vars.fd"
    shutil.copyfile(template, variables)
    key = work / "ssh-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    disk = work / "target.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(disk), "96G"],
        check=True,
        capture_output=True,
    )
    vm = vmlib.VM(
        cid=args.cid,
        disk=disk,
        key=key,
        public_key=key.with_suffix(".pub").read_text().strip(),
        output=diagnostics,
        code=code,
        variables=variables,
    )
    guest = Guest(vm, diagnostics)
    machine = Machine(vm, diagnostics)
    registry = None
    phase = diagnostics / "phase.txt"
    try:
        phase.write_text("fixtures\n")
        registry = start_registry(work, diagnostics)
        candidate_diff_ids = base_diff_ids(args.fixture_base)
        fixtures = prepare_fixtures(work, args.fixture_base, diagnostics)

        phase.write_text("install\n")
        machine.start(iso)
        sirius_install(guest, receipts)
        machine.stop()

        phase.write_text("first boot checks\n")
        machine.start(None)
        base_digest = first_boot(guest, receipts, candidate, candidate_diff_ids)
        live_isolation(guest, receipts)
        expected_key(guest, receipts)
        security_state(guest, receipts)
        secure_boot(guest, receipts)
        install_fixture_trust(guest, fixtures["public_key"])
        for name, ref in (
            ("unsigned_rejected", "unsigned"),
            ("foreign_key_rejected", "foreign"),
        ):
            rejection(guest, receipts, name, ref, base_digest)
        started = now()
        switch_argv, switch = guest.run(
            "switch-update", f"bootc switch {FIXTURE}:update", timeout=3600
        )
        if switch.returncode != 0:
            raise CheckFailed("signed fixture update was refused")
        machine.stop()

        phase.write_text("update\n")
        machine.start(None)
        moved(
            guest,
            receipts,
            "update",
            switch_argv,
            switch,
            started,
            fixtures["digests"]["update"],
            marker="update",
        )
        started = now()
        rollback_argv, rollback = guest.run("rollback", "bootc rollback")
        if rollback.returncode != 0:
            raise CheckFailed("bootc rollback failed")
        machine.stop()

        phase.write_text("rollback\n")
        machine.start(None)
        moved(
            guest,
            receipts,
            "rollback",
            rollback_argv,
            rollback,
            started,
            base_digest,
            marker=None,
        )
        machine.stop()
        phase.write_text("complete\n")
    except BaseException as error:
        with phase.open("a") as handle:
            handle.write(f"failed: {type(error).__name__}: {error}\n")
        raise
    finally:
        machine.kill()
        if registry is not None:
            terminate(registry)
    missing = set(release_pipeline.CHECKS) - set(receipts.names)
    if missing:
        raise CheckFailed(f"checks not run: {sorted(missing)}")


def status(
    guest: Guest, name: str
) -> tuple[list[str], subprocess.CompletedProcess, dict]:
    argv, result = guest.run(name, "bootc status --json")
    if result.returncode != 0:
        raise CheckFailed("bootc status failed")
    return argv, result, json.loads(result.stdout)


def first_boot(
    guest: Guest, receipts: Receipts, candidate: dict, diff_ids: list[str]
) -> str:
    started = now()
    log = []
    argv, state = guest.run("first-boot-state", "systemctl is-system-running --wait")
    log.append(transcript(argv, state))
    if state.stdout.strip() != "running":
        failed = guest.run("first-boot-failed", "systemctl --failed --no-legend")[1]
        raise CheckFailed(
            f"installed system is {state.stdout.strip()!r}: {failed.stdout}"
        )
    status_argv, result, document = status(guest, "first-boot-bootc")
    log.append(transcript(status_argv, result))
    image = booted(document)
    owner = candidate["repository"].split("/")[0].lower()
    reference = image.get("image", {}).get("image", "")
    if not reference.startswith(f"ghcr.io/{owner}/luminusos-workstation:"):
        raise CheckFailed(f"installed system tracks {reference!r}")
    if image.get("version") != candidate["build_version"]:
        raise CheckFailed(
            f"installed version {image.get('version')!r} is not the candidate"
        )
    # The ISO payload is re-encoded, so its manifest digest differs from the
    # registry candidate. ostree-ext records the image config on the deployed
    # commit; identical uncompressed layers there bind the booted system to it.
    checksum = (document["status"]["booted"].get("ostree") or {}).get("checksum")
    if not isinstance(checksum, str) or not checksum.isalnum():
        raise CheckFailed("bootc reports no booted ostree commit")
    config_argv, config = guest.run(
        "first-boot-config",
        "ostree show --repo=/sysroot/ostree/repo"
        f" --print-metadata-key=ostree.container.image-config {checksum}",
    )
    log.append(transcript(config_argv, config))
    if config.returncode != 0:
        raise CheckFailed("the booted commit has no container image config")
    try:
        observed = json.loads(ast.literal_eval(config.stdout.strip()))["rootfs"][
            "diff_ids"
        ]
    except (ValueError, SyntaxError, KeyError, TypeError) as error:
        raise CheckFailed("cannot read the booted image config") from error
    if observed != diff_ids:
        raise CheckFailed("the booted image does not have the candidate's layers")
    mounts_argv, mounts = guest.run(
        "first-boot-mounts", "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS"
    )
    log.append(transcript(mounts_argv, mounts))
    problems = (
        check_layout(json.loads(mounts.stdout))
        if mounts.returncode == 0
        else ["findmnt failed"]
    )
    if problems:
        raise CheckFailed("; ".join(problems))
    receipts.write("first_boot", argv, started, "".join(log))
    return image["imageDigest"]


def live_isolation(guest: Guest, receipts: Receipts) -> None:
    started = now()
    checks = " && ".join(
        ["! id liveuser", "! rpm -q --quiet sirius-installer"]
        + [f"! test -e {path}" for path in LIVE_ONLY]
        + ["! grep -rqsiE '^\\s*AutomaticLoginEnable\\s*=\\s*true' /etc/gdm"]
    )
    argv, result = guest.run("live-isolation", f"{checks} && echo isolated")
    if result.returncode != 0 or result.stdout.splitlines()[-1:] != ["isolated"]:
        raise CheckFailed("live-only state is present on the installed system")
    receipts.write("live_isolation", argv, started, transcript(argv, result))


def expected_key(guest: Guest, receipts: Receipts) -> None:
    started = now()
    paths = " ".join(f"/{path}" for path in OFFICIAL_FILES)
    argv, result = guest.run("expected-key", f"sha256sum {paths}")
    if result.returncode != 0:
        raise CheckFailed("cannot read the official trust files")
    observed = {
        line.split()[1].lstrip("/"): line.split()[0]
        for line in result.stdout.splitlines()
    }
    wanted = {
        path: hashlib.sha256((TRUST / path).read_bytes()).hexdigest()
        for path in OFFICIAL_FILES
    }
    if observed != wanted:
        raise CheckFailed(f"official trust files differ: {observed} != {wanted}")
    receipts.write("expected_key", argv, started, transcript(argv, result))


def sirius_install(guest: Guest, receipts: Receipts) -> None:
    started = now()
    argv, result = guest.run(
        "sirius-run-playbook",
        "sirius run-playbook",
        timeout=5400,
        stdin=vmlib.install_request(vmlib.TARGET_DISK),
    )
    if not vmlib.playbook_finished(result.stdout, result.returncode):
        raise CheckFailed("Sirius did not report Finished")
    receipts.write("sirius_install", argv, started, transcript(argv, result))


def security_state(guest: Guest, receipts: Receipts) -> None:
    exact(guest, receipts, "selinux_enforcing", "getenforce", "Enforcing")
    exact(guest, receipts, "firewall", "firewall-cmd --state", "running")


def exact(guest: Guest, receipts: Receipts, name: str, command: str, want: str) -> None:
    started = now()
    argv, result = guest.run(name, command)
    if result.returncode != 0 or result.stdout.strip() != want:
        raise CheckFailed(f"{command} returned {result.stdout.strip()!r}")
    receipts.write(name, argv, started, transcript(argv, result))


def secure_boot(guest: Guest, receipts: Receipts) -> None:
    started = now()
    argv, result = guest.run("secure-boot", "mokutil --sb-state")
    if result.returncode != 0 or "SecureBoot enabled" not in result.stdout:
        raise CheckFailed(f"Secure Boot is not enabled: {result.stdout.strip()!r}")
    receipts.write("secure_boot", argv, started, transcript(argv, result))


def install_fixture_trust(guest: Guest, public_key: str) -> None:
    # Only this disposable VM learns the ephemeral fixture key, under its own
    # repository scope; the official entries were verified unchanged above.
    _, policy = guest.run("policy-read", "cat /etc/containers/policy.json")
    files = {
        FIXTURE_KEY_PATH: public_key,
        "/etc/containers/policy.json": json.dumps(
            fixture_policy(json.loads(policy.stdout)), indent=1
        ),
        "/etc/containers/registries.d/zz-validation-fixture.yaml": (
            f"docker:\n  {FIXTURE}:\n    use-sigstore-attachments: true\n"
        ),
        "/etc/containers/registries.conf.d/zz-validation-fixture.conf": (
            f'[[registry]]\nlocation = "{REGISTRY}"\ninsecure = true\n'
        ),
    }
    for index, (path, content) in enumerate(files.items()):
        _, result = guest.run(f"fixture-trust-{index}", f"cat > {path}", stdin=content)
        if result.returncode != 0:
            raise CheckFailed(f"cannot write {path}")
    _, result = guest.run(
        "fixture-hosts", f"echo '10.0.2.2 {REGISTRY_HOST}' >> /etc/hosts"
    )
    if result.returncode != 0:
        raise CheckFailed("cannot map the fixture registry")


def rejection(
    guest: Guest, receipts: Receipts, name: str, ref: str, base_digest: str
) -> None:
    started = now()
    argv, result = guest.run(name, f"bootc switch {FIXTURE}:{ref}", timeout=3600)
    if not rejected(result, ref):
        raise CheckFailed(f"{ref} fixture was not rejected for its signature")
    status_argv, after, document = status(guest, f"{name}-status")
    if document["status"].get("staged") is not None:
        raise CheckFailed(f"{ref} fixture was staged despite the rejection")
    if booted(document).get("imageDigest") != base_digest:
        raise CheckFailed(f"{ref} fixture changed the booted image")
    receipts.write(
        name, argv, started, transcript(argv, result) + transcript(status_argv, after)
    )


def moved(guest, receipts, name, argv, action, started, digest, *, marker) -> None:
    status_argv, result, document = status(guest, f"{name}-status")
    image = booted(document)
    if image.get("imageDigest") != digest:
        raise CheckFailed(f"{name}: booted {image.get('imageDigest')}, want {digest}")
    marker_argv, observed = guest.run(f"{name}-marker", f"cat {MARKER}")
    if (marker is None) != (observed.returncode != 0) or (
        marker is not None and observed.stdout.strip() != marker
    ):
        raise CheckFailed(f"{name}: unexpected marker {observed.stdout.strip()!r}")
    receipts.write(
        name,
        argv,
        started,
        transcript(argv, action)
        + transcript(status_argv, result)
        + transcript(marker_argv, observed),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--fixture-base", type=Path, required=True)
    parser.add_argument("--cid", type=int, default=3 + os.getpid() % 10000)
    args = parser.parse_args(argv)
    try:
        validate(args)
    except (
        CheckFailed,
        vmlib.ProbeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"installation validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
