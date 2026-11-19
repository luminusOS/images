import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
import validation_base
import validation_driver as driver

pipeline = driver.release_pipeline

DIFF_IDS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
P_INDEX = "sha256:" + "a" * 64
P_MANIFEST = "sha256:" + "b" * 64
P_CONFIG = "sha256:" + "c" * 64
UPDATE = "sha256:" + "e" * 64
WRONG = "sha256:" + "f" * 64
CANDIDATES = "ghcr.io/owner/luminusos-candidates"


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def done(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def published_base():
    return {
        edition: {
            "reference": f"ghcr.io/owner/{image}:testing-45",
            "index_digest": P_INDEX,
            "manifest_digest": P_MANIFEST,
            "config_digest": P_CONFIG,
            "version": "testing-45.20261117.2",
            "release_evidence_sha256": "d" * 64,
            "official_key_sha256": "0" * 64,
        }
        for edition, image in (
            ("core", "luminusos"),
            ("workstation", "luminusos-workstation"),
        )
    }


def image_candidate(index):
    return {
        "version": 1,
        "release_kind": "image",
        "run_id": 12,
        "repository": "owner/repo",
        "channel": "testing",
        "fedora_version": "45",
        "source_sha": "a" * 40,
        "build_version": "45.20261118",
        "images": {
            "core": f"{CANDIDATES}@sha256:" + "3" * 64,
            "workstation": f"{CANDIDATES}@{index}",
        },
        "artifacts": {"gates/quality.json": "9" * 64},
        "published_base": published_base(),
    }


class Layout:
    """An OCI layout holding the candidate index and its amd64 image."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True)
        (root / "blobs/sha256").mkdir(parents=True)
        (root / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        self.refs = []

    def put(self, data: bytes) -> str:
        digest = sha(data)
        (self.root / "blobs/sha256" / digest.split(":")[1]).write_bytes(data)
        return digest

    def ref(self, name, digest, media):
        self.refs.append(
            {
                "mediaType": media,
                "digest": digest,
                "size": 1,
                "annotations": {"org.opencontainers.image.ref.name": name},
            }
        )
        (self.root / "index.json").write_text(
            json.dumps({"schemaVersion": 2, "manifests": self.refs})
        )


def candidate_layouts(root: Path):
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": DIFF_IDS}}).encode()
    fixture = Layout(root / "fixture-base")
    config_digest = fixture.put(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config_digest, "size": len(config)},
            "layers": [],
        }
    ).encode()
    manifest_digest = fixture.put(manifest)
    fixture.ref("base", manifest_digest, "application/vnd.oci.image.manifest.v1+json")
    mirror = Layout(root / "candidate-mirror/layout")
    mirror.put(config)
    mirror.put(manifest)
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest),
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        }
    ).encode()
    index_digest = mirror.put(index)
    mirror.ref("candidate", index_digest, "application/vnd.oci.image.index.v1+json")
    return (
        fixture.root,
        mirror.root.parent,
        index_digest,
        manifest_digest,
        config_digest,
    )


def signature_line(index, repository=CANDIDATES, signature="c2ln"):
    payload = json.dumps(
        {
            "critical": {
                "identity": {"docker-reference": repository},
                "image": {"docker-manifest-digest": index},
                "type": "cosign container image signature",
            },
            "optional": None,
        }
    ).encode()
    return json.dumps(
        {"Base64Signature": signature, "Payload": base64.b64encode(payload).decode()}
    )


REJECTED_UNSIGNED = (
    "error: Switching: Pulling: Creating importer: failed to invoke method "
    "OpenImage: Source image rejected: A signature was required, but no "
    "signature exists"
)
REJECTED_FOREIGN = (
    "error: Switching: Pulling: Creating importer: failed to invoke method "
    "OpenImage: Source image rejected: cryptographic signature verification failed"
)


class FakeVM:
    """A bootc system: switches stage a deployment that the next boot takes."""

    def __init__(self, candidate_index, candidate_manifest):
        self.candidate_index = candidate_index
        self.candidate_manifest = candidate_manifest
        self.deployments = {
            "booted": (
                P_MANIFEST,
                "45.20261117.2",
                f"ghcr.io/owner/luminusos-workstation@{P_MANIFEST}",
            ),
            "staged": None,
            "rollback": None,
        }
        self.accept_wrong = False
        self.broken_rollback = None
        self.tracks_manifest = False
        self.health = done("running\n")
        self.commands = []

    def boot(self):
        staged = self.deployments["staged"]
        if staged is not None:
            self.deployments = {
                "booted": staged,
                "staged": None,
                "rollback": self.broken_rollback or self.deployments["booted"],
            }

    def status(self):
        def slot(entry):
            if entry is None:
                return None
            digest, version, reference = entry
            return {
                "image": {
                    "image": {"image": reference, "transport": "registry"},
                    "imageDigest": digest,
                    "version": version,
                },
                "ostree": {"checksum": "c" * 64},
            }

        return json.dumps(
            {"status": {name: slot(value) for name, value in self.deployments.items()}}
        )

    def switch(self, target):
        repository, _, digest = target.partition("@")
        if repository == driver.CANDIDATE_REPOSITORY:
            if digest == self.candidate_index:
                tracked = (
                    f"{repository}@{self.candidate_manifest}"
                    if self.tracks_manifest
                    else target
                )
                return self.stage(self.candidate_manifest, "45.20261118", tracked)
            if self.accept_wrong:
                return self.stage(digest, "45.20261118", target)
            return done(code=1, stderr=REJECTED_UNSIGNED)
        ref = target.rsplit(":", 1)[1]
        if ref == "update":
            return self.stage(UPDATE, "45.20261118", target)
        return done(
            code=1, stderr=REJECTED_UNSIGNED if ref == "unsigned" else REJECTED_FOREIGN
        )

    def stage(self, digest, version, reference):
        self.deployments["staged"] = (digest, version, reference)
        return done("Queued for next boot")

    def run(self, command):
        self.commands.append(command)
        official = " ".join(f"/{path}" for path in driver.OFFICIAL_FILES)
        if command == "bootc status --json":
            return done(self.status())
        if command.startswith("bootc switch "):
            return self.switch(command.split()[-1])
        if command == "bootc rollback":
            self.deployments["staged"] = self.deployments["rollback"]
            return done()
        if command == "systemctl is-system-running --wait":
            return self.health
        if command == driver.FAILED_UNITS:
            return done("home.mount loaded failed failed /home\n")
        if command.startswith("ostree show"):
            text = json.dumps(json.dumps({"rootfs": {"diff_ids": DIFF_IDS}}))
            return done(repr(json.loads(text)) + "\n")
        if command.startswith("findmnt"):
            return done(
                json.dumps(
                    {
                        "filesystems": [
                            {"target": "/sysroot", "fstype": "btrfs"},
                            {"target": "/var", "fstype": "btrfs"},
                            {"target": "/boot", "fstype": "ext4"},
                        ]
                    }
                )
            )
        if command == f"sha256sum {official}":
            return done(
                "".join(
                    f"{hashlib.sha256((driver.TRUST / p).read_bytes()).hexdigest()}  /{p}\n"
                    for p in driver.OFFICIAL_FILES
                )
            )
        if command == "getenforce":
            return done("Enforcing\n")
        if command == "firewall-cmd --state":
            return done("running\n")
        if command.startswith("ss -Hltnp"):
            return done("---\n")
        if command == "mokutil --sb-state":
            return done("SecureBoot enabled\n")
        if command == "cat /etc/containers/policy.json":
            return done(
                json.dumps(
                    {"default": [{"type": "reject"}], "transports": {"docker": {}}}
                )
            )
        if command == f"cat {driver.MARKER}":
            marker = "update" if self.deployments["booted"][0] == UPDATE else None
            return done(f"{marker}\n") if marker else done(code=1)
        if command.startswith(("cat > ", "echo ", "cp /usr/etc/")):
            return done()
        raise AssertionError(f"unexpected guest command {command!r}")


class FakeGuest:
    def __init__(self, vm):
        self.vm = vm

    def run(self, name, command, **_kwargs):
        return ["ssh", "root@vsock", command], self.vm.run(command)


class FakeMachine:
    def __init__(self, vm):
        self.vm = vm
        self.boots = 0

    def start(self, iso):
        assert iso is None
        self.boots += 1
        self.vm.boot()

    def stop(self):
        pass

    def kill(self):
        pass


class ImageDriverTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (
            self.fixture_base,
            self.mirror_dir,
            self.index,
            self.manifest,
            self.config,
        ) = candidate_layouts(self.root / "inputs")
        (self.mirror_dir / "signatures.json").write_text(
            signature_line(self.index) + "\n"
        )
        self.candidate = image_candidate(self.index)
        self.receipts_dir = self.root / "receipts"
        self.receipts_dir.mkdir()
        self.vm = FakeVM(self.index, self.manifest)

    def mirror(self):
        return {
            "repository": CANDIDATES,
            "index": self.index,
            "manifest": self.manifest,
            "config": self.config,
        }

    def run_image_flow(self):
        receipts = driver.Receipts(self.receipts_dir, self.candidate)
        diagnostics = self.receipts_dir / "diagnostics"
        diagnostics.mkdir()
        args = argparse.Namespace(
            fixture_base=self.fixture_base, candidate_mirror=self.mirror_dir
        )
        with (
            mock.patch.object(driver, "Guest", lambda vm, d: FakeGuest(self.vm)),
            mock.patch.object(driver, "Machine", lambda vm, d: FakeMachine(self.vm)),
            mock.patch.object(driver, "start_registry", return_value=None),
            mock.patch.object(driver, "mirror_candidate", return_value=self.mirror()),
            mock.patch.object(
                driver,
                "prepare_fixtures",
                return_value={"digests": {"update": UPDATE}, "public_key": "key"},
            ),
            mock.patch.object(driver, "push_wrong_digest", return_value=WRONG),
        ):
            driver._validate_image(
                args, self.candidate, receipts, diagnostics, self.root, None
            )
        return receipts

    def test_image_flow_records_every_image_check_and_nothing_else(self):
        receipts = self.run_image_flow()
        self.assertEqual(sorted(receipts.names), sorted(pipeline.checks("image")))
        data = [
            json.loads(p.read_text()) for p in sorted(self.receipts_dir.glob("*.json"))
        ]
        pipeline.validate_receipts(data, self.receipts_dir, self.candidate)
        for receipt in data:
            self.assertEqual(receipt["binding"]["release_kind"], "image")
            self.assertEqual(
                receipt["binding"]["published_base"], self.candidate["published_base"]
            )
        base = (self.receipts_dir / "base_boot.log").read_text()
        upgrade = (self.receipts_dir / "upgrade_from_published.log").read_text()
        self.assertIn(
            json.dumps(
                {
                    "config_digest": P_CONFIG,
                    "index_digest": P_INDEX,
                    "manifest_digest": P_MANIFEST,
                    "version": "45.20261117.2",
                },
                sort_keys=True,
            ),
            base,
        )
        self.assertIn(
            json.dumps(
                {
                    "config_digest": self.config,
                    "index_digest": self.index,
                    "manifest_digest": self.manifest,
                    "version": "45.20261118",
                },
                sort_keys=True,
            ),
            upgrade,
        )
        self.assertIn(REJECTED_UNSIGNED, upgrade)
        switches = [c for c in self.vm.commands if c.startswith("bootc switch")]
        self.assertEqual(
            switches[:2],
            [
                f"bootc switch {driver.CANDIDATE_REPOSITORY}@{WRONG}",
                f"bootc switch {driver.CANDIDATE_REPOSITORY}@{self.index}",
            ],
        )
        self.assertEqual(self.vm.deployments["booted"][0], self.manifest)
        restore = self.vm.commands.index(
            next(c for c in self.vm.commands if c.startswith("cp /usr/etc/"))
        )
        self.assertLess(
            restore,
            self.vm.commands.index(
                f"sha256sum {' '.join('/' + p for p in driver.OFFICIAL_FILES)}"
            ),
        )
        for path in driver.CANDIDATE_DROP_INS:
            self.assertIn(path, self.vm.commands[restore])

    def test_a_wrong_digest_accepted_under_the_candidate_policy_fails(self):
        self.vm.accept_wrong = True
        with self.assertRaisesRegex(driver.CheckFailed, "wrong digest"):
            self.run_image_flow()
        self.assertNotIn("upgrade_from_published", self.written())

    def test_rollback_other_than_the_published_base_fails(self):
        self.vm.broken_rollback = ("sha256:" + "9" * 64, "x", "y")
        with self.assertRaisesRegex(driver.CheckFailed, "rollback deployment"):
            self.run_image_flow()
        self.assertNotIn("upgrade_from_published", self.written())

    def test_bootc_may_track_the_candidate_by_index_or_manifest(self):
        for tracks_manifest in (False, True):
            with self.subTest(tracks_manifest=tracks_manifest):
                shutil.rmtree(self.receipts_dir)
                self.receipts_dir.mkdir()
                self.vm = FakeVM(self.index, self.manifest)
                self.vm.tracks_manifest = tracks_manifest
                receipts = self.run_image_flow()
                self.assertEqual(
                    sorted(receipts.names), sorted(pipeline.checks("image"))
                )

    def test_candidate_check_refuses_any_other_tracked_reference(self):
        allowed = driver.digest_references(
            driver.CANDIDATE_REPOSITORY,
            self.mirror()["index"],
            self.mirror()["manifest"],
        )
        self.assertEqual(
            allowed,
            (
                f"{driver.CANDIDATE_REPOSITORY}@{self.index}",
                f"{driver.CANDIDATE_REPOSITORY}@{self.manifest}",
            ),
        )
        for tracked in (
            f"{driver.CANDIDATE_REPOSITORY}@sha256:" + "9" * 64,
            f"{driver.CANDIDATE_REPOSITORY}:candidate",
            f"{driver.FIXTURE}@{self.manifest}",
            f"{CANDIDATES}@{self.index}",
        ):
            self.vm.deployments["booted"] = (self.manifest, "45.20261118", tracked)
            with (
                self.subTest(tracked=tracked),
                self.assertRaisesRegex(driver.CheckFailed, "tracks"),
            ):
                driver.first_boot(
                    FakeGuest(self.vm),
                    driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                    self.candidate,
                    DIFF_IDS,
                    references=allowed,
                )

    def test_a_degraded_published_base_fails_before_the_switch(self):
        for health in (
            done("degraded\n", 1),
            done("running\n", 1),
            done("starting\n", 1),
            done("", 255, "ssh: connect failed"),
        ):
            self.vm = FakeVM(self.index, self.manifest)
            self.vm.health = health
            shutil.rmtree(self.receipts_dir)
            self.receipts_dir.mkdir()
            with (
                self.subTest(health=health.stdout or health.stderr),
                self.assertRaisesRegex(driver.CheckFailed, "home.mount"),
            ):
                self.run_image_flow()
            self.assertEqual(self.written(), set())
            self.assertIn(driver.FAILED_UNITS, self.vm.commands)
            self.assertFalse(
                any(c.startswith("bootc switch") for c in self.vm.commands)
            )

    def test_base_boot_receipt_records_the_health_probe(self):
        driver.base_boot(
            FakeGuest(self.vm),
            driver.Receipts(self.receipts_dir, self.candidate),
            self.candidate["published_base"]["workstation"],
        )
        log = (self.receipts_dir / "base_boot.log").read_text()
        self.assertIn("systemctl is-system-running --wait", log)
        self.assertLess(
            log.index("is-system-running"), log.index("bootc status --json")
        )

    def test_base_disk_may_track_the_pinned_index_or_manifest_only(self):
        repository = "ghcr.io/owner/luminusos-workstation"
        for digest in (P_INDEX, P_MANIFEST):
            self.vm.deployments["booted"] = (
                P_MANIFEST,
                "45.20261117.2",
                f"{repository}@{digest}",
            )
            with self.subTest(accepted=digest):
                driver.base_boot(
                    FakeGuest(self.vm),
                    driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                    self.candidate["published_base"]["workstation"],
                )
        for tracked in (
            f"{repository}@sha256:" + "9" * 64,
            f"{repository}:testing-45",
            f"ghcr.io/owner/luminusos@{P_MANIFEST}",
            f"ghcr.io/other/luminusos-workstation@{P_INDEX}",
            f"{repository}@{P_MANIFEST}x",
        ):
            self.vm.deployments["booted"] = (P_MANIFEST, "45.20261117.2", tracked)
            with (
                self.subTest(rejected=tracked),
                self.assertRaisesRegex(driver.CheckFailed, "tracks"),
            ):
                driver.base_boot(
                    FakeGuest(self.vm),
                    driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                    self.candidate["published_base"]["workstation"],
                )

    def test_wrong_digest_must_differ_from_the_candidate_index_and_manifest(self):
        for wrong in (self.index, self.manifest):
            self.vm = FakeVM(self.index, self.manifest)
            with (
                self.subTest(wrong=wrong),
                self.assertRaisesRegex(driver.CheckFailed, "wrong digest"),
            ):
                driver.upgrade_from_published(
                    FakeGuest(self.vm),
                    FakeMachine(self.vm),
                    driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                    self.candidate,
                    self.candidate["published_base"]["workstation"],
                    self.mirror(),
                    wrong,
                )

    def test_restore_removes_exactly_the_mirror_hosts_line(self):
        seen = []

        class Recorder:
            def run(self, name, command, **_kwargs):
                seen.append(command)
                return ["ssh", command], done()

        driver.install_candidate_trust(FakeGuest(self.vm), CANDIDATES)
        self.assertIn(f"echo '{driver.HOSTS_LINE}' >> /etc/hosts", self.vm.commands)
        driver.restore_official_trust(Recorder())
        sed, check = seen[0].split(" && ")[-2:]
        self.assertTrue(sed.startswith("sed -i --follow-symlinks "))
        self.assertTrue(sed.endswith(" /etc/hosts"))
        self.assertEqual(check, f"! grep -Fxq '{driver.HOSTS_LINE}' /etc/hosts")
        hosts = self.root / "hosts"
        lines = [
            "127.0.0.1 localhost",
            driver.HOSTS_LINE,
            f"{driver.HOSTS_LINE}.example",
            f"# {driver.HOSTS_LINE}",
            "10.0.2.20 registry.validation.test",
            driver.HOSTS_LINE,
        ]
        hosts.write_text("\n".join(lines) + "\n")
        script = f"{sed} && {check}".replace("/etc/hosts", str(hosts))
        for _ in range(2):
            subprocess.run(["sh", "-c", script], check=True)
            self.assertEqual(
                hosts.read_text().splitlines(),
                [line for line in lines if line != driver.HOSTS_LINE],
            )

    def test_base_disk_must_boot_the_pinned_published_base(self):
        for slot, broken in (
            ("digest", ("sha256:" + "9" * 64, "45.20261117.2")),
            ("version", (P_MANIFEST, "45.20261116")),
        ):
            digest, version = broken
            self.vm.deployments["booted"] = (
                digest,
                version,
                f"ghcr.io/owner/luminusos-workstation@{digest}",
            )
            with self.subTest(slot=slot), self.assertRaises(driver.CheckFailed):
                driver.base_boot(
                    FakeGuest(self.vm),
                    driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                    self.candidate["published_base"]["workstation"],
                )
        self.vm.deployments["booted"] = (P_MANIFEST, "45.20261117.2", "other@x")
        with self.assertRaisesRegex(driver.CheckFailed, "tracks"):
            driver.base_boot(
                FakeGuest(self.vm),
                driver.Receipts(Path(tempfile.mkdtemp()), self.candidate),
                self.candidate["published_base"]["workstation"],
            )

    def test_the_candidate_is_checked_where_bootc_tracks_the_mirror(self):
        self.vm.candidate_manifest = "sha256:" + "8" * 64
        with self.assertRaisesRegex(driver.CheckFailed, "upgrade booted"):
            self.run_image_flow()

    def test_image_candidates_cannot_record_installer_receipts(self):
        receipts = driver.Receipts(self.receipts_dir, self.candidate)
        for name in ("sirius_install", "live_isolation"):
            with self.subTest(name=name), self.assertRaises(driver.CheckFailed):
                receipts.write(name, ["ssh"], driver.now(), "observed")

        class Passing:
            def run(self, name, command, **_kwargs):
                return ["ssh", command], done("isolated\n")

        with (
            mock.patch.object(driver.vmlib, "playbook_finished", return_value=True),
            mock.patch.object(driver.vmlib, "install_request", return_value="{}"),
        ):
            for check in (driver.sirius_install, driver.live_isolation):
                with (
                    self.subTest(check=check.__name__),
                    self.assertRaisesRegex(driver.CheckFailed, "unexpected"),
                ):
                    check(Passing(), receipts)
        self.assertEqual(self.written(), set())

    def written(self):
        return {p.stem for p in self.receipts_dir.glob("*.json")}

    def mirror_with(
        self, digest, *, served=None, bad_signature=False, real_cosign=False
    ):
        signatures = (self.mirror_dir / "signatures.json").read_text()
        real_host = driver.host

        def host(argv, log, **_kwargs):
            if real_cosign and argv[:2] == ["cosign", "verify-blob"]:
                return real_host(argv, log)
            if argv[:2] == ["skopeo", "copy"]:
                Path(argv[argv.index("--digestfile") + 1]).write_text(digest + "\n")
            if argv[:2] == ["cosign", "verify-blob"] and bad_signature:
                raise driver.CheckFailed("cosign failed: invalid signature")
            if argv[:3] == ["cosign", "download", "signature"]:
                return signatures if served is None else served
            return ""

        work = self.root / "work"
        work.mkdir(exist_ok=True)
        with mock.patch.object(driver, "host", side_effect=host) as calls:
            result = driver.mirror_candidate(
                work, self.mirror_dir, self.candidate, self.fixture_base, self.root
            )
        return result, [call.args[0] for call in calls.call_args_list]

    def test_mirror_preserves_and_requires_the_verified_candidate_digest(self):
        result, calls = self.mirror_with(self.index)
        self.assertEqual(result, self.mirror())
        work = self.root / "work"
        reference = f"{driver.CANDIDATE_REPOSITORY}@{self.index}"
        self.assertEqual(
            calls,
            [
                [
                    "skopeo",
                    "copy",
                    "--all",
                    "--preserve-digests",
                    "--dest-tls-verify=false",
                    "--digestfile",
                    str(work / "candidate-index.digest"),
                    f"oci:{self.mirror_dir / 'layout'}:candidate",
                    f"docker://{driver.CANDIDATE_REPOSITORY}:candidate",
                ],
                [
                    "cosign",
                    "verify-blob",
                    "--key",
                    str(driver.CANDIDATE_KEY),
                    "--signature",
                    str(work / "candidate-signature.b64"),
                    "--insecure-ignore-tlog=true",
                    "--offline=true",
                    str(work / "candidate-payload.json"),
                ],
                [
                    "cosign",
                    "attach",
                    "signature",
                    "--allow-http-registry",
                    "--payload",
                    str(work / "candidate-payload.json"),
                    "--signature",
                    str(work / "candidate-signature.b64"),
                    reference,
                ],
                ["cosign", "download", "signature", "--allow-http-registry", reference],
            ],
        )
        self.assertNotIn(["cosign", "verify"], [c[:2] for c in calls])
        with self.assertRaisesRegex(driver.CheckFailed, "changed the candidate digest"):
            self.mirror_with("sha256:" + "7" * 64)

    def test_a_bad_signature_fails_before_anything_is_attached(self):
        with self.assertRaisesRegex(driver.CheckFailed, "invalid signature"):
            self.mirror_with(self.index, bad_signature=True)

    def test_a_payload_for_another_digest_is_never_attached(self):
        (self.mirror_dir / "signatures.json").write_text(
            signature_line("sha256:" + "7" * 64) + "\n"
        )
        with self.assertRaisesRegex(driver.CheckFailed, "no candidate signature"):
            self.mirror_with(self.index)

    def test_the_mirror_must_serve_exactly_the_attached_signature(self):
        for served, message in (
            (signature_line(self.index, signature="b3RoZXI="), "different candidate"),
            (signature_line("sha256:" + "7" * 64), "another image"),
            (signature_line(self.index, "ghcr.io/other/x"), "another image"),
            ("", "serves 0"),
            (
                signature_line(self.index) + "\n" + signature_line(self.index),
                "serves 2",
            ),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(driver.CheckFailed, message),
            ):
                self.mirror_with(self.index, served=served)

    @unittest.skipUnless(shutil.which("cosign"), "cosign is not installed")
    def test_offline_verification_runs_with_the_real_cosign(self):
        work = self.root / "keys"
        work.mkdir()
        env = {**os.environ, "COSIGN_PASSWORD": ""}
        subprocess.run(
            ["cosign", "generate-key-pair", "--output-key-prefix", str(work / "k")],
            check=True,
            capture_output=True,
            env=env,
        )
        payload = base64.b64decode(json.loads(signature_line(self.index))["Payload"])
        (work / "payload.json").write_bytes(payload)
        signature = subprocess.run(
            [
                "cosign",
                "sign-blob",
                "--yes",
                "--tlog-upload=false",
                "--key",
                str(work / "k.key"),
                str(work / "payload.json"),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        ).stdout.strip()
        (self.mirror_dir / "signatures.json").write_text(
            signature_line(self.index, signature=signature) + "\n"
        )

        subprocess.run(
            ["cosign", "generate-key-pair", "--output-key-prefix", str(work / "other")],
            check=True,
            capture_output=True,
            env=env,
        )
        with mock.patch.object(driver, "CANDIDATE_KEY", work / "k.pub"):
            self.assertEqual(
                self.mirror_with(self.index, real_cosign=True)[0], self.mirror()
            )
        with (
            mock.patch.object(driver, "CANDIDATE_KEY", work / "other.pub"),
            self.assertRaisesRegex(driver.CheckFailed, "cosign failed"),
        ):
            self.mirror_with(self.index, real_cosign=True)

    def test_mirror_refuses_inputs_that_are_not_the_signed_candidate(self):
        self.candidate["images"]["workstation"] = f"{CANDIDATES}@sha256:" + "7" * 64
        with self.assertRaisesRegex(driver.CheckFailed, "verified candidate"):
            self.mirror_with(self.index)
        self.candidate = image_candidate(self.index)
        (self.mirror_dir / "signatures.json").write_text(
            signature_line(self.index, "ghcr.io/other/luminusos-candidates") + "\n"
        )
        with self.assertRaisesRegex(driver.CheckFailed, "no candidate signature"):
            self.mirror_with(self.index)
        index = json.loads((self.fixture_base / "index.json").read_text())
        index["manifests"][0]["digest"] = "sha256:" + "6" * 64
        (self.fixture_base / "index.json").write_text(json.dumps(index))
        with self.assertRaisesRegex(driver.CheckFailed, "fixture base"):
            self.mirror_with(self.index)

    def test_candidate_trust_is_scoped_to_the_mirror_and_the_candidate_key(self):
        writes = {}

        class Recorder(FakeGuest):
            def run(self, name, command, **kwargs):
                if command.startswith("cat > "):
                    writes[command[6:]] = kwargs["stdin"]
                return super().run(name, command, **kwargs)

        driver.install_candidate_trust(Recorder(self.vm), CANDIDATES)
        policy = json.loads(writes["/etc/containers/policy.json"])
        self.assertEqual(
            policy["transports"]["docker"],
            {
                driver.CANDIDATE_REPOSITORY: [
                    {
                        "type": "sigstoreSigned",
                        "keyPath": driver.CANDIDATE_KEY_PATH,
                        "signedIdentity": {
                            "type": "exactRepository",
                            "dockerRepository": CANDIDATES,
                        },
                    }
                ]
            },
        )
        self.assertEqual(policy["default"], [{"type": "reject"}])
        self.assertEqual(
            writes[driver.CANDIDATE_KEY_PATH], driver.CANDIDATE_KEY.read_text()
        )

    def test_kind_inputs_must_match_the_candidate(self):
        full = image_candidate(self.index) | {"release_kind": "full"}
        cases = (
            (self.candidate, None, None, False),
            (self.candidate, Path("d"), None, False),
            (self.candidate, Path("d"), Path("m"), True),
            (full, None, None, True),
            (full, Path("d"), Path("m"), False),
        )
        for candidate, disk, mirror, accepted in cases:
            args = argparse.Namespace(disk=disk, candidate_mirror=mirror)
            with self.subTest(kind=candidate["release_kind"], disk=disk, mirror=mirror):
                if accepted:
                    driver.kind_inputs(args, candidate)
                else:
                    with self.assertRaises(driver.CheckFailed):
                        driver.kind_inputs(args, candidate)

    def test_full_candidates_keep_the_sirius_flow(self):
        full = image_candidate(self.index) | {
            "release_kind": "full",
            "artifacts": {"live.iso": "0" * 64},
        }
        args = argparse.Namespace(
            disk=None, candidate_mirror=None, artifacts=self.root, cid=3
        )
        (self.root / "live.iso").write_bytes(b"iso")
        with (
            mock.patch.object(driver.vmlib, "preflight"),
            mock.patch.object(driver.subprocess, "run"),
            mock.patch.object(driver, "machine_vm", return_value="vm"),
            mock.patch.object(driver, "_validate_full") as full_flow,
            mock.patch.object(driver, "_validate_image") as image_flow,
        ):
            driver._validate(args, full, None, self.root, self.root)
        image_flow.assert_not_called()
        self.assertEqual(full_flow.call_args.args[-1], self.root / "live.iso")

    def test_cancellation_unwinds_through_cleanup(self):
        with (
            mock.patch.object(
                driver, "validate", side_effect=lambda args: driver.cancelled(15, None)
            ),
            mock.patch.object(driver.sys, "stderr", new_callable=io.StringIO) as err,
        ):
            code = driver.main(
                [
                    "--candidate",
                    "c",
                    "--artifacts",
                    "a",
                    "--receipts",
                    "r",
                    "--fixture-base",
                    "f",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("cancelled by signal 15", err.getvalue())

    def test_cancellation_ignores_a_repeated_signal_during_cleanup(self):
        previous = signal.signal(signal.SIGTERM, driver.cancelled)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        with self.assertRaisesRegex(driver.CheckFailed, "cancelled by signal 15"):
            driver.cancelled(signal.SIGTERM, None)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        os.kill(os.getpid(), signal.SIGTERM)

    def test_work_directory_is_removed_when_a_check_fails(self):
        receipts = self.root / "out"
        receipts.mkdir()
        candidate = self.root / "candidate.json"
        candidate.write_text(json.dumps(self.candidate))
        args = argparse.Namespace(candidate=candidate, receipts=receipts)
        with (
            mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}),
            mock.patch.object(
                driver, "_validate", side_effect=driver.CheckFailed("boom")
            ),
            self.assertRaises(driver.CheckFailed),
        ):
            driver.validate(args)
        self.assertFalse((self.root / "validation-vm").exists())


class PublishedBaseCheckTests(unittest.TestCase):
    def test_current_base_gives_the_disk_inputs(self):
        candidate = image_candidate("sha256:" + "4" * 64)
        with mock.patch.object(
            validation_base.published_base,
            "resolve",
            return_value=published_base(),
        ) as resolve:
            outputs = validation_base.check(candidate)
        resolve.assert_called_once_with("owner/repo", "testing", "45")
        self.assertEqual(
            outputs,
            {
                "workstation_image": f"ghcr.io/owner/luminusos-workstation@{P_INDEX}",
                "base_manifest": P_MANIFEST,
                "fedora_version": "45",
                "disk_name": "published-base.qcow2",
            },
        )

    def test_a_moved_base_makes_the_candidate_stale(self):
        candidate = image_candidate("sha256:" + "4" * 64)
        for edition in ("core", "workstation"):
            moved = published_base()
            moved[edition] = moved[edition] | {
                "index_digest": "sha256:" + "5" * 64,
                "version": "testing-45.20261118.1",
            }
            with (
                self.subTest(edition=edition),
                mock.patch.object(
                    validation_base.published_base, "resolve", return_value=moved
                ),
                self.assertRaisesRegex(ValueError, f"stale candidate.*{edition}"),
            ):
                validation_base.check(candidate)

    def test_stale_base_fails_the_step_before_any_output(self):
        candidate = image_candidate("sha256:" + "4" * 64)
        moved = published_base()
        moved["workstation"] = moved["workstation"] | {"manifest_digest": WRONG}
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.touch()
            with (
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                mock.patch.object(
                    validation_base.release_pipeline,
                    "candidate",
                    return_value=candidate,
                ),
                mock.patch.object(
                    validation_base.published_base, "resolve", return_value=moved
                ),
                mock.patch.object(
                    validation_base.sys, "stderr", new_callable=io.StringIO
                ),
            ):
                code = validation_base.main(
                    ["--candidate", "c.json", "--public-key", "k.pub"]
                )
            self.assertEqual(code, 1)
            self.assertEqual(output.read_text(), "")

    def test_full_candidates_have_no_published_base(self):
        full = image_candidate("sha256:" + "4" * 64) | {"release_kind": "full"}
        with (
            mock.patch.object(validation_base.published_base, "resolve") as resolve,
            self.assertRaisesRegex(ValueError, "only image candidates"),
        ):
            validation_base.check(full)
        resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
