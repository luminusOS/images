import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/scripts/workflow"
sys.path.insert(0, str(WORKFLOW))


def load(name):
    spec = importlib.util.spec_from_file_location(name, WORKFLOW / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load("release_pipeline")
policy = load("release_policy")
publish = load("release_publish")
driver = load("validation_driver")
promote_images = load("promote_images")

OFFICIAL_SHA = hashlib.sha256(
    (ROOT / "shared/trust/etc/pki/containers/luminusos.pub").read_bytes()
).hexdigest()


def candidate_images(names):
    return {
        name: "ghcr.io/owner/luminusos-candidates@sha256:" + str(index) * 64
        for index, name in enumerate(names, 1)
    }


def published_base(channel, version):
    prefix = "testing-" if channel == "testing" else ""
    return {
        edition: {
            "reference": f"ghcr.io/owner/{image}:{prefix}45",
            "index_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64,
            "config_digest": "sha256:" + "c" * 64,
            "version": version,
            "release_evidence_sha256": "d" * 64,
            "official_key_sha256": OFFICIAL_SHA,
        }
        for edition, image in (
            ("core", "luminusos"),
            ("workstation", "luminusos-workstation"),
        )
    }


class Fixture:
    def __init__(self, directory: Path):
        self.directory = directory

    def artifact(self, name, data=b"evidence"):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return pipeline.digest(path)

    def base(self, kind, channel="testing", **extra):
        build = "45.20261118.2"
        document = {
            "version": 1,
            "release_kind": kind,
            "repository": "owner/repo",
            "source_sha": "a" * 40,
            "run_id": 123,
            "channel": channel,
            "version_tag": ("testing-" if channel == "testing" else "") + build,
            "build_version": build,
            "fedora_version": "45",
            "fedora_bootc_digest": "sha256:" + "1" * 64,
        }
        return document | extra

    def full(self, channel="testing"):
        return self.base(
            "full",
            channel,
            images=candidate_images(("core", "workstation", "installer")),
            artifacts={
                name: self.artifact(name)
                for name in (
                    "live.iso",
                    "disk.qcow2",
                    "boot/iso/screen-1.ppm",
                    "scan/installer/scan-evidence.json",
                    "gates/boot.json",
                )
            },
        )

    def image(self, channel="testing", base_version=None):
        prefix = "testing-" if channel == "testing" else ""
        return self.base(
            "image",
            channel,
            images=candidate_images(("core", "workstation")),
            artifacts={
                name: self.artifact(name)
                for name in (
                    "scan/core/scan-evidence.json",
                    "scan/workstation/sbom.spdx.json",
                    "gates/quality.json",
                )
            },
            published_base=published_base(
                channel, base_version or f"{prefix}45.20261118.1"
            ),
        )


class ReleaseKindTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.fixture = Fixture(self.directory)

    def accept(self, document):
        pipeline.validate_candidate(document, self.directory)

    def reject(self, document, message):
        with self.assertRaisesRegex(ValueError, message):
            pipeline.validate_candidate(document, self.directory)

    def test_full_and_image_candidates_are_accepted(self):
        for channel in ("testing", "stable"):
            with self.subTest(channel=channel):
                full = self.fixture.full(channel)
                image = self.fixture.image(channel)
                self.accept(full)
                self.accept(image)
                self.assertEqual(pipeline.release_kind(full), "full")
                self.assertEqual(pipeline.release_kind(image), "image")

    def test_unknown_release_kind_is_rejected(self):
        for kind in ("FULL", "", None, 1, "image-only", ["full"]):
            with self.subTest(kind=kind):
                self.reject(self.fixture.full() | {"release_kind": kind}, "kind")

    def test_missing_kind_is_full_only_for_pre_migration_runs(self):
        legacy = self.fixture.full()
        del legacy["release_kind"]
        for run_id in sorted(pipeline.PRE_MIGRATION_RUNS):
            with self.subTest(run_id=run_id):
                document = legacy | {"run_id": run_id}
                self.accept(document)
                self.assertEqual(pipeline.release_kind(document), "full")
        for run_id in (123, 44376008170):
            with self.subTest(run_id=run_id):
                self.reject(legacy | {"run_id": run_id}, "missing release kind")
        image = self.fixture.image()
        del image["release_kind"]
        self.reject(
            image | {"run_id": 44376008169}, "invalid candidate fields|invalid images"
        )

    def test_full_keeps_installer_iso_and_qcow2_and_has_no_published_base(self):
        full = self.fixture.full()
        self.reject(full | {"published_base": published_base("testing", "x")}, "fields")
        for removed in ("live.iso", "disk.qcow2"):
            with self.subTest(removed=removed):
                document = copy.deepcopy(full)
                del document["artifacts"][removed]
                self.reject(document, "ISO and qcow2")
        document = copy.deepcopy(full)
        del document["images"]["installer"]
        self.reject(document, "invalid images")
        self.reject(full | {"unexpected": True}, "fields")

    def test_image_has_no_installer_or_disk_artifacts(self):
        image = self.fixture.image()
        document = copy.deepcopy(image)
        document["images"] = candidate_images(("core", "workstation", "installer"))
        self.reject(document, "invalid images")
        for name in (
            "live.iso",
            "disk.qcow2",
            "nested/DISK.QCOW2",
            "boot/disk/screen-1.ppm",
            "scan/installer/scan-evidence.json",
            "gates/boot.json",
        ):
            with self.subTest(name=name):
                document = copy.deepcopy(image)
                document["artifacts"][name] = self.fixture.artifact(name)
                self.reject(document, "installer or disk")
        self.reject(image | {"artifacts": {}}, "missing candidate artifacts")

    def test_image_published_base_is_closed_per_edition(self):
        image = self.fixture.image()
        document = copy.deepcopy(image)
        del document["published_base"]
        self.reject(document, "fields")
        for editions in (
            {"core"},
            {"core", "workstation", "installer"},
            {"core", "luminusos-workstation"},
        ):
            with self.subTest(editions=editions):
                document = copy.deepcopy(image)
                bases = document["published_base"]
                document["published_base"] = {
                    edition: bases.get(edition, bases["core"]) for edition in editions
                }
                self.reject(document, "published base fields")
        document = copy.deepcopy(image)
        document["published_base"]["core"]["channel"] = "testing"
        self.reject(document, "core published base fields")
        document = copy.deepcopy(image)
        del document["published_base"]["workstation"]["config_digest"]
        self.reject(document, "workstation published base fields")

    def test_image_published_base_reference_follows_channel(self):
        image = self.fixture.image()
        stable = self.fixture.image("stable")
        for document, edition, reference in (
            (image, "core", "ghcr.io/owner/luminusos:45"),
            (image, "core", "ghcr.io/owner/luminusos:testing-44"),
            (image, "core", "ghcr.io/owner/luminusos-workstation:testing-45"),
            (image, "workstation", "ghcr.io/other/luminusos-workstation:testing-45"),
            (image, "core", "ghcr.io/owner/luminusos@sha256:" + "a" * 64),
            (stable, "core", "ghcr.io/owner/luminusos:testing-45"),
            (stable, "workstation", "ghcr.io/owner/luminusos-workstation:latest"),
        ):
            with self.subTest(channel=document["channel"], reference=reference):
                changed = copy.deepcopy(document)
                changed["published_base"][edition]["reference"] = reference
                self.reject(changed, "published base reference")
        changed = copy.deepcopy(stable)
        for base in changed["published_base"].values():
            base["version"] = "testing-45.20261118.1"
        self.reject(changed, "not on the candidate's line")

    def test_image_published_base_digests_and_hashes(self):
        image = self.fixture.image()
        for field, value in (
            ("index_digest", "a" * 64),
            ("manifest_digest", "sha256:" + "A" * 64),
            ("config_digest", "sha256:" + "a" * 63),
            ("index_digest", None),
            ("release_evidence_sha256", "sha256:" + "d" * 64),
            ("release_evidence_sha256", "d" * 63),
        ):
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(image)
                document["published_base"]["core"][field] = value
                self.reject(document, f"core published base {field.split('_')[0]}")

    def test_image_published_base_must_use_the_official_key(self):
        candidate_key = hashlib.sha256(
            (ROOT / "shared/release/candidate.pub").read_bytes()
        ).hexdigest()
        for value in (candidate_key, "0" * 64, OFFICIAL_SHA.upper(), None):
            with self.subTest(value=value):
                document = self.fixture.image()
                document["published_base"]["workstation"]["official_key_sha256"] = value
                self.reject(document, "official key")

    def test_published_base_must_be_strictly_older(self):
        for channel, prefix in (("testing", "testing-"), ("stable", "")):
            for version, accepted in (
                ("45.20261118.1", True),
                ("45.20261118", True),
                ("45.20261117.9", True),
                ("45.20261118.2", False),
                ("45.20261118.3", False),
                ("45.20261119", False),
                ("45.20261231.1", False),
                ("45.2026111", False),
                ("45.20261318.1", False),
                ("45.20261118.0", False),
            ):
                with self.subTest(channel=channel, version=version):
                    document = self.fixture.image(channel, prefix + version)
                    if accepted:
                        self.accept(document)
                    else:
                        self.reject(document, "version|older")

    def test_published_bases_come_from_one_release(self):
        document = self.fixture.image()
        document["published_base"]["core"]["version"] = "testing-45.20261117.1"
        self.reject(document, "different releases")
        document = self.fixture.image()
        document["published_base"]["core"]["release_evidence_sha256"] = "e" * 64
        self.reject(document, "different releases")

    def test_image_candidate_version_must_match_its_line(self):
        document = self.fixture.image()
        self.reject(document | {"version_tag": "45.20261118.2"}, "channel line")
        self.reject(document | {"version_tag": "testing-45.20261118.3"}, "channel line")
        stable = self.fixture.image("stable")
        self.reject(stable | {"version_tag": "testing-45.20261118.2"}, "channel line")

    def test_version_order_is_numeric(self):
        order = pipeline.version_order
        self.assertEqual(order("testing-45.20261118"), (45, 20261118, 0))
        self.assertEqual(order("45.20261118.12"), (45, 20261118, 12))
        self.assertLess(order("45.20261118.9"), order("45.20261118.10"))
        self.assertLess(order("44.20261231.9"), order("45.20260101"))
        for value in ("45", "45.2026111", "x45.20261118", "45.20261118.01", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                order(value)

    def test_create_candidate_writes_release_kind(self):
        document = self.fixture.full()
        metadata = self.directory / "metadata.input"
        output = self.directory / "candidate.json"
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        fields = {k: v for k, v in document.items() if k != "artifacts"}
        for written in (
            fields,
            {k: v for k, v in fields.items() if k != "release_kind"},
        ):
            metadata.write_text(json.dumps(written))
            with (
                self.subTest(written=sorted(written)),
                mock.patch.dict(pipeline.os.environ, env),
                mock.patch.object(pipeline, "sign"),
            ):
                result = pipeline.create_candidate(
                    metadata, self.directory, output, Path("key")
                )
            self.assertEqual(json.loads(output.read_text())["release_kind"], "full")
            self.assertEqual(result["release_kind"], "full")
        for bad in (fields | {"release_kind": "other"}, fields | {"extra": 1}):
            metadata.write_text(json.dumps(bad))
            with (
                mock.patch.dict(pipeline.os.environ, env),
                mock.patch.object(pipeline, "sign") as sign,
                self.assertRaises(ValueError),
            ):
                pipeline.create_candidate(metadata, self.directory, output, Path("k"))
            sign.assert_not_called()


class ReceiptProfileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.fixture = Fixture(self.directory)
        log = self.directory / "check.log"
        log.write_text("observed")
        self.log = pipeline.digest(log)

    def receipts(self, candidate, names):
        return [
            {
                "name": name,
                "binding": pipeline.binding(candidate),
                "command": ["probe", name],
                "exit_code": 0,
                "started_at": "2026-11-18T10:00:00Z",
                "finished_at": "2026-11-18T10:01:00Z",
                "log": "check.log",
                "sha256": self.log,
            }
            for name in names
        ]

    def test_profiles(self):
        self.assertEqual(pipeline.checks("full"), pipeline.CHECKS)
        image = set(pipeline.checks("image"))
        self.assertEqual(
            image,
            set(pipeline.CHECKS) - {"sirius_install", "live_isolation"}
            | {"base_boot", "upgrade_from_published"},
        )
        self.assertEqual(pipeline.gates("full"), pipeline.GATES)
        self.assertNotIn("boot", pipeline.gates("image"))
        for kind in ("", "other", None):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                pipeline.checks(kind)

    def test_receipts_follow_the_candidate_kind(self):
        full = self.fixture.full()
        image = self.fixture.image()
        image_checks = pipeline.checks("image")
        pipeline.validate_receipts(
            self.receipts(full, pipeline.CHECKS), self.directory, full
        )
        pipeline.validate_receipts(
            self.receipts(image, image_checks), self.directory, image
        )
        for candidate, names in (
            (full, [n for n in pipeline.CHECKS if n != "live_isolation"]),
            (full, image_checks),
            (image, [n for n in image_checks if n != "base_boot"]),
            (image, [*image_checks, "sirius_install"]),
            (
                image,
                [n if n != "base_boot" else "sirius_install" for n in image_checks],
            ),
            (image, pipeline.CHECKS),
        ):
            with (
                self.subTest(kind=candidate["release_kind"], names=names),
                self.assertRaisesRegex(ValueError, "receipt"),
            ):
                pipeline.validate_receipts(
                    self.receipts(candidate, names), self.directory, candidate
                )

    def test_driver_records_only_the_candidates_checks(self):
        image = self.fixture.image()
        receipts = driver.Receipts(self.directory, image)
        self.assertEqual(receipts.checks, pipeline.checks("image"))
        with self.assertRaises(driver.CheckFailed):
            receipts.write("sirius_install", ["ssh"], driver.now(), "x")
        receipts.write("base_boot", ["ssh"], driver.now(), "observed")
        full = driver.Receipts(self.directory, self.fixture.full())
        with self.assertRaises(driver.CheckFailed):
            full.write("upgrade_from_published", ["ssh"], driver.now(), "x")

    def test_legacy_consumers_reject_unknown_kind(self):
        document = self.fixture.full() | {"release_kind": "partial"}
        for operation in (
            lambda: pipeline.binding(document),
            lambda: pipeline.validate_receipts([], self.directory, document),
            lambda: driver.Receipts(self.directory, document),
        ):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                operation()


def evidence(gates):
    digest = "sha256:" + "2" * 64
    return {
        "repository": "owner/repo",
        "candidate_digest": digest,
        "source": {
            "repository": "owner/repo",
            "ref": "refs/heads/main",
            "commit": "a" * 40,
            "run_id": 1,
        },
        "gates": {gate: True for gate in gates},
        "evidence": {
            gate: {
                "artifact": f"{gate}.json",
                "sha256": "f" * 64,
                "candidate_digest": digest,
            }
            for gate in gates
        },
    }


class GateProfileTests(unittest.TestCase):
    def test_policy_requires_the_kind_gate_set(self):
        full = policy.REQUIRED_GATES
        image = policy.required_gates("image")
        self.assertNotIn("boot", image)
        self.assertIn("installation", image)
        self.assertEqual(policy.validate_candidate(evidence(full)), [])
        self.assertEqual(
            policy.validate_candidate(evidence(image), release_kind="image"), []
        )
        self.assertTrue(policy.validate_candidate(evidence(image)))
        self.assertTrue(policy.validate_candidate(evidence(full), release_kind="image"))
        with self.assertRaises(ValueError):
            policy.validate_candidate(evidence(full), release_kind="other")

    def test_image_gates_never_record_a_boot_or_installer_gate(self):
        for path in ("boot/iso/screen-1.ppm", "scan/installer/x", "gates/boot.json"):
            with tempfile.TemporaryDirectory() as temp, self.subTest(path=path):
                directory = Path(temp)
                (directory / path).parent.mkdir(parents=True)
                (directory / path).write_text("x")
                env = {
                    "RELEASE_KIND": "image",
                    "SECURITY_FINDINGS_BYPASS": "false",
                    "QUALITY_RESULT": "success",
                    "SCAN_RESULT": "success",
                    "CORE": "core",
                    "WORKSTATION": "workstation",
                }
                with (
                    mock.patch.dict(publish.os.environ, env),
                    mock.patch.object(publish.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "boot or installer"),
                ):
                    publish.prepare_gates(directory)
                run.assert_not_called()
                self.assertFalse((directory / "gates/quality.json").exists())

    def test_image_gates_skip_boot_and_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for role in ("core", "workstation"):
                scan = directory / "scan" / role
                scan.mkdir(parents=True)
                files = {}
                for name in (
                    "sbom.spdx.json",
                    "vulnerabilities.json",
                    "provenance.json",
                ):
                    (scan / name).write_text(name)
                    files[name] = publish.sha256(scan / name)
                (scan / "scan-evidence.json").write_text(
                    json.dumps(
                        {
                            "security": {"gate": "success"},
                            "image": role,
                            "source_sha": "a" * 40,
                            "files": files,
                        }
                    )
                )
            env = {
                "RELEASE_KIND": "image",
                "SECURITY_FINDINGS_BYPASS": "false",
                "QUALITY_RESULT": "success",
                "BOOT_RESULT": "skipped",
                "SCAN_RESULT": "success",
                "CORE": "core",
                "WORKSTATION": "workstation",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_RUN_ID": "7",
            }
            with (
                mock.patch.dict(publish.os.environ, env),
                mock.patch.object(publish.subprocess, "run") as run,
            ):
                publish.prepare_gates(directory)
            verified = [call.args[0][-1] for call in run.call_args_list]
            self.assertEqual(verified, ["core", "workstation"])
            written = {p.stem for p in (directory / "gates").glob("*.json")}
            self.assertEqual(written, set(pipeline.gates("image")))
            quality = json.loads((directory / "gates/quality.json").read_text())
            self.assertEqual(set(quality["images"]), {"core", "workstation"})
            self.assertFalse(any("boot/" in name for name in quality["artifacts"]))

    def test_full_entry_points_refuse_image_candidates_before_writes(self):
        candidate = {"release_kind": "image", "channel": "testing"}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "publication"
            for operation in (
                lambda: publish.promote(
                    Path("c.json"), Path("e.json"), Path("k"), directory, "testing"
                ),
                lambda: publish.publish_downloads(Path("c.json"), directory, Path("k")),
            ):
                with (
                    self.subTest(operation=operation),
                    mock.patch.object(
                        publish, "verify_release", return_value=candidate
                    ),
                    mock.patch.object(publish.subprocess, "run") as run,
                    mock.patch.object(publish, "load_helper") as helper,
                    mock.patch.object(publish, "release_preflight") as preflight,
                    mock.patch.object(publish, "github_release") as release,
                    self.assertRaisesRegex(ValueError, "publish-image"),
                ):
                    operation()
                run.assert_not_called()
                helper.assert_not_called()
                preflight.assert_not_called()
                release.assert_not_called()
                self.assertFalse(directory.exists())


class BindingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.fixture = Fixture(self.directory)

    def other_base(self, image):
        other = copy.deepcopy(image)
        for base in other["published_base"].values():
            base["index_digest"] = "sha256:" + "9" * 64
        pipeline.validate_candidate(other, self.directory)
        return other

    def test_full_binding_keeps_its_pre_migration_fields(self):
        full = self.fixture.full()
        legacy = {k: v for k, v in full.items() if k != "release_kind"}
        legacy["run_id"] = 44376008169
        for document in (full, legacy):
            with self.subTest(kind="release_kind" in document):
                self.assertEqual(
                    pipeline.binding(document),
                    {
                        "repository": document["repository"],
                        "source_sha": document["source_sha"],
                        "images": document["images"],
                        "artifacts": document["artifacts"],
                        "source_run_id": document["run_id"],
                        "candidate_digest": document["images"]["workstation"].split(
                            "@", 1
                        )[1],
                    },
                )

    def test_image_binding_pins_kind_and_published_base(self):
        image = self.fixture.image()
        result = pipeline.binding(image)
        self.assertEqual(result["release_kind"], "image")
        self.assertEqual(result["published_base"], image["published_base"])
        self.assertNotEqual(result, pipeline.binding(self.other_base(image)))

    def test_receipts_and_validation_are_not_shared_across_published_bases(self):
        image = self.fixture.image()
        other = self.other_base(image)
        log = self.directory / "check.log"
        log.write_text("observed")
        receipts = ReceiptProfileTests.receipts(
            types.SimpleNamespace(log=pipeline.digest(log)),
            image,
            pipeline.checks("image"),
        )
        pipeline.validate_receipts(receipts, self.directory, image)
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            pipeline.validate_receipts(receipts, self.directory, other)
        validation = self.directory / "validation.json"
        validation.write_text(
            json.dumps(
                {
                    "version": 1,
                    "binding": pipeline.binding(image),
                    "runner_repository": "owner/repo",
                    "runner_ref": "refs/heads/main",
                    "runner_sha": "b" * 40,
                    "validation_run_id": 9,
                    "receipts": receipts,
                }
            )
        )
        with mock.patch.object(pipeline, "verify"):
            pipeline.validate_validation(validation, Path("k"), image)
            with self.assertRaisesRegex(ValueError, "validation candidate mismatch"):
                pipeline.validate_validation(validation, Path("k"), other)

    def test_release_evidence_is_not_shared_across_published_bases(self):
        image = self.fixture.image()
        other = self.other_base(image)
        full = self.fixture.full()
        evidence_path = self.directory / "release-evidence.json"

        def verify(candidate, evidence):
            evidence_path.write_text(json.dumps(evidence))
            promotion = mock.Mock()
            promotion.validate_candidate.return_value = []
            with (
                mock.patch.object(pipeline, "candidate", return_value=candidate),
                mock.patch.object(pipeline, "verify"),
                mock.patch.object(
                    publish,
                    "load_helper",
                    side_effect=lambda name: (
                        pipeline if name == "release_pipeline" else promotion
                    ),
                ),
            ):
                return publish.verify_release(
                    Path("candidate.json"), evidence_path, Path("k")
                )

        def assembled(candidate):
            return {
                "images": candidate["images"],
                "artifacts": candidate["artifacts"],
                **pipeline.kind_binding(candidate),
            }

        verify(image, assembled(image))
        for candidate, evidence in (
            (other, assembled(image)),
            (image, assembled(other)),
            (
                image,
                {k: v for k, v in assembled(image).items() if k != "published_base"},
            ),
            (image, {k: v for k, v in assembled(image).items() if k != "release_kind"}),
            (full, assembled(full) | {"published_base": image["published_base"]}),
            (full, assembled(full) | {"release_kind": "image"}),
        ):
            with (
                self.subTest(evidence=sorted(evidence)),
                self.assertRaisesRegex(ValueError, "does not match candidate"),
            ):
                verify(candidate, evidence)

    def test_prepare_results_uses_the_canonical_binding(self):
        image = self.fixture.image()
        for gate in pipeline.gates("image"):
            name = f"gates/{gate}.json"
            report = {
                "gate": gate,
                "conclusion": "success",
                "repository": image["repository"],
                "source_sha": image["source_sha"],
                "run_id": image["run_id"],
                "images": image["images"],
                "artifacts": {"gates/quality.json": "0" * 64},
            }
            (self.directory / name).write_text(json.dumps(report))
            image["artifacts"][name] = pipeline.digest(self.directory / name)
        with (
            mock.patch.object(pipeline, "candidate", return_value=image),
            mock.patch.object(pipeline, "checked_file"),
            mock.patch.object(publish, "load_helper", return_value=pipeline),
        ):
            publish.prepare_results(self.directory)
        results = json.loads((self.directory / "results.json").read_text())
        self.assertEqual(set(results), set(pipeline.gates("image")))
        for result in results.values():
            self.assertEqual(result["binding"], pipeline.binding(image))


class PromotionKindTests(unittest.TestCase):
    def evidence(self, gates, kind=None):
        document = evidence(gates) | {
            "repository": "owner/repo",
            "images": {
                role: "ghcr.io/owner/luminusos-candidates@sha256:" + "2" * 64
                for role in ("core", "workstation")
            },
        }
        if kind is not None:
            document["release_kind"] = kind
        return document

    def promote(self, document, **kind):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for item in document["evidence"].values():
                (root / item["artifact"]).write_bytes(b"gate")
                item["sha256"] = hashlib.sha256(b"gate").hexdigest()
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(document))
            signature = root / "evidence.json.sig"
            signature.write_text("sig")
            digest = "sha256:" + "2" * 64

            def command(argv, **_):
                return mock.Mock(stdout=digest if argv[0] == "skopeo" else "")

            with (
                mock.patch.dict(
                    promote_images.os.environ, {"GITHUB_REPOSITORY_OWNER": "owner"}
                ),
                mock.patch.object(promote_images, "inspect_version", return_value=None),
                mock.patch.object(
                    promote_images.subprocess, "run", side_effect=command
                ) as run,
            ):
                try:
                    promote_images.promote(
                        f"ghcr.io/owner/luminusos-candidates@{digest}",
                        digest,
                        [
                            "ghcr.io/owner/luminusos:testing-45.20261118.2",
                            "ghcr.io/owner/luminusos:testing-45",
                        ],
                        promote_images.CANDIDATE_KEY,
                        manifest,
                        signature,
                        "owner/repo",
                        "a" * 40,
                        "core",
                        **kind,
                    )
                finally:
                    self.calls = run.call_count

    def test_promotion_checks_the_signed_candidate_kind(self):
        full = policy.REQUIRED_GATES
        image = policy.required_gates("image")
        self.promote(self.evidence(full))
        self.assertGreater(self.calls, 0)
        self.promote(self.evidence(image, "image"), release_kind="image")
        self.assertGreater(self.calls, 0)
        for document, kind, message in (
            (self.evidence(full, "image"), "image", "exactly"),
            (self.evidence(image), "full", "boot"),
            (self.evidence(image, "image"), "full", "kind"),
            (self.evidence(full), "image", "kind"),
        ):
            with (
                self.subTest(gates=sorted(document["gates"]), kind=kind),
                self.assertRaisesRegex(ValueError, message),
            ):
                self.promote(document, release_kind=kind)
            self.assertEqual(self.calls, 0)


if __name__ == "__main__":
    unittest.main()
