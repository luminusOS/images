import copy
import hashlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from test_release_pipeline import core_oci_sample

MODULE = (
    Path(__file__).resolve().parents[1]
    / ".github/scripts/workflow/core_build_binding.py"
)
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("core_build_binding", MODULE)
    binding = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(binding)
else:
    binding = None


def archive_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    return stream.getvalue()


class CoreBuildBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.archive = Path(self.temporary.name) / "core.zip"
        self.files, self.manifest = core_oci_sample()
        self.policy = {
            "repository": "owner/repo",
            "repository_id": 456,
            "run_id": 123,
            "run_attempt": 2,
            "source_sha": "a" * 40,
            "workflow": ".github/workflows/publish.yml",
            "job_name": "Build candidate images / Build core image",
            "fedora": "45",
            "channel": "testing",
            "architecture": "x86_64",
            "base_digest": "sha256:" + "1" * 64,
            "policy_sha256": "2" * 64,
            "inputs_sha256": "3" * 64,
        }
        index = json.loads(self.files["index.json"])
        manifest = json.loads(self.files["blobs/sha256/" + self.manifest[7:]])
        config = json.loads(
            self.files["blobs/sha256/" + manifest["config"]["digest"][7:]]
        )
        config["config"] = {
            "Labels": {
                "org.luminusos.core.fedora": self.policy["fedora"],
                "org.luminusos.core.inputs-sha256": self.policy["inputs_sha256"],
            }
        }
        for value, descriptor in (
            (config, manifest["config"]),
            (manifest, index["manifests"][0]),
        ):
            raw = json.dumps(value).encode()
            checksum = hashlib.sha256(raw).hexdigest()
            self.files["blobs/sha256/" + checksum] = raw
            descriptor.update(digest="sha256:" + checksum, size=len(raw))
        self.manifest = index["manifests"][0]["digest"]
        self.files["index.json"] = json.dumps(index).encode()
        self.observations = {
            "run": {
                "id": 123,
                "run_attempt": 2,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "path": self.policy["workflow"],
                "repository": {"id": 456, "full_name": "owner/repo"},
                "head_repository": {"id": 456, "full_name": "owner/repo"},
                "status": "completed",
                "conclusion": "success",
                "event": "workflow_dispatch",
            },
            "jobs_pages": [
                {
                    "total_count": 1,
                    "jobs": [
                        {
                            "id": 90,
                            "run_id": 123,
                            "run_attempt": 2,
                            "head_sha": "a" * 40,
                            "name": self.policy["job_name"],
                            "status": "completed",
                            "conclusion": "success",
                            "steps": [
                                {
                                    "name": name,
                                    "number": number,
                                    "status": "completed",
                                    "conclusion": "success",
                                    "started_at": f"2026-11-11T20:10:{number * 10:02}Z",
                                    "completed_at": f"2026-11-11T20:10:{number * 10 + 5:02}Z",
                                }
                                for number, name in enumerate(
                                    (
                                        "Build core",
                                        "Export built core OCI layout",
                                        "Upload built core OCI layout",
                                    ),
                                    1,
                                )
                            ],
                        }
                    ],
                }
            ],
            "step_logs": [],
            "artifact": {
                "id": 10,
                "name": "core-oci",
                "expired": False,
                "workflow_run": {
                    "id": 123,
                    "repository_id": 456,
                    "head_repository_id": 456,
                    "head_sha": "a" * 40,
                    "head_branch": "main",
                },
            },
        }
        self.set_archive(archive_bytes(self.files))

    def set_archive(self, data):
        self.archive.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.observations["artifact"].update(
            size_in_bytes=len(data), digest="sha256:" + digest
        )
        self.observations["step_logs"] = [
            {
                "number": 3,
                "name": "Upload built core OCI layout",
                "log": (
                    f"2026-11-11T20:10:31.1Z SHA256 digest of uploaded artifact is {digest}\n"
                    "2026-11-11T20:10:32.1Z Artifact core-oci successfully finalized. Artifact ID 10\n"
                    "2026-11-11T20:10:32.2Z Artifact core-oci has been successfully uploaded! Final size is "
                    f"{len(data)} bytes. Artifact ID is 10\n"
                ),
            }
        ]

    @property
    def upload_log(self):
        return self.observations["step_logs"][0]["log"]

    @upload_log.setter
    def upload_log(self, value):
        self.observations["step_logs"][0]["log"] = value

    def add_other_upload(self, log):
        step = copy.deepcopy(self.observations["jobs_pages"][0]["jobs"][0]["steps"][-1])
        step.update(
            number=4,
            name="Upload core image archive",
            started_at="2026-11-11T20:10:34Z",
            completed_at="2026-11-11T20:10:45Z",
        )
        self.observations["jobs_pages"][0]["jobs"][0]["steps"].append(step)
        self.observations["step_logs"].append(
            {
                "number": 4,
                "name": step["name"],
                "log": log,
            }
        )

    def evaluate(self):
        self.assertIsNotNone(
            binding, "core output binding evaluator is not implemented"
        )
        return binding.evaluate_binding(self.policy, self.observations, self.archive)

    def test_observes_exact_bytes_without_authentication_or_production_claim(self):
        result = self.evaluate()
        self.assertEqual(result["core_digest"], self.manifest)
        self.assertEqual(result["artifact_id"], 10)
        self.assertEqual(result["run_attempt"], 2)
        for field in (
            "production_ready",
            "observations_authenticated",
            "runtime_verified",
        ):
            self.assertIs(result[field], False)
        self.assertIn("reviewed trusted acquisition adapter", result["limitation"])
        self.assertIn("provider step acquisition is unverified", result["limitation"])

    def test_rejects_mutated_authority_and_scalars(self):
        changes = [
            (("run", "id"), 124),
            (("run", "run_attempt"), 1),
            (("run", "run_attempt"), True),
            (("run", "head_sha"), "b" * 40),
            (("run", "path"), ".github/workflows/containers.yml"),
            (("run", "head_branch"), "release/45"),
            (("run", "conclusion"), "failure"),
            (("run", "status"), "in_progress"),
            (("run", "repository", "id"), True),
            (("run", "repository", "full_name"), "other/repo"),
            (("run", "head_repository", "id"), 457),
            (("artifact", "id"), 11),
            (("artifact", "id"), True),
            (("artifact", "name"), "previous-core-oci"),
            (("artifact", "expired"), True),
            (("artifact", "expired"), 0),
            (("artifact", "workflow_run", "id"), 124),
            (("artifact", "workflow_run", "head_sha"), "b" * 40),
            (("artifact", "workflow_run", "repository_id"), True),
            (("artifact", "workflow_run", "head_branch"), "other"),
            (("artifact", "size_in_bytes"), True),
            (("artifact", "size_in_bytes"), 1),
            (("artifact", "digest"), "sha256:" + "0" * 64),
            (("authenticated",), True),
            (("run", "authenticated"), True),
        ]
        original = copy.deepcopy(self.observations)
        for path, value in changes:
            with self.subTest(path=path, value=value):
                self.observations = copy.deepcopy(original)
                target = self.observations
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises((ValueError, OSError)):
                    self.evaluate()

    def test_policy_is_closed_and_testing_only(self):
        original = self.policy.copy()
        for field, value in (
            ("authenticated", True),
            ("channel", "stable"),
            ("run_id", True),
            ("run_attempt", 0),
            ("repository_id", "456"),
            ("job_name", ""),
            ("architecture", "aarch64"),
            ("inputs_sha256", "x"),
        ):
            with self.subTest(field=field):
                self.policy = original | {field: value}
                with self.assertRaises(ValueError):
                    self.evaluate()

    def test_requires_complete_unique_attempt_jobs_and_successful_ordered_steps(self):
        original = copy.deepcopy(self.observations)
        mutations = [
            lambda pages: pages[0].update(total_count=2),
            lambda pages: pages.append(copy.deepcopy(pages[0])),
            lambda pages: pages[0].update(total_count=True),
            lambda pages: pages[0]["jobs"][0].update(run_attempt=1),
            lambda pages: pages[0]["jobs"][0].update(run_id=124),
            lambda pages: pages[0]["jobs"][0].update(head_sha="b" * 40),
            lambda pages: pages[0]["jobs"][0].update(name="Build core image"),
            lambda pages: pages[0]["jobs"][0].update(conclusion="failure"),
            lambda pages: pages[0]["jobs"][0]["steps"].reverse(),
            lambda pages: pages[0]["jobs"][0]["steps"][1].update(number=True),
            lambda pages: pages[0]["jobs"][0]["steps"][1].update(
                completed_at="2026-11-11T20:10:40Z"
            ),
        ]
        for index in range(3):
            mutations.append(
                lambda pages, i=index: pages[0]["jobs"][0]["steps"][i].update(
                    conclusion="skipped"
                )
            )
        for mutate in mutations:
            self.observations = copy.deepcopy(original)
            mutate(self.observations["jobs_pages"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.evaluate()

    def test_complete_multiple_pages_are_accepted(self):
        other = copy.deepcopy(self.observations["jobs_pages"][0]["jobs"][0])
        other.update(id=91, name="Other job")
        self.observations["jobs_pages"][0]["total_count"] = 2
        self.observations["jobs_pages"].append({"total_count": 2, "jobs": [other]})
        self.assertEqual(self.evaluate()["job_id"], 90)

    def test_distinct_ids_cannot_duplicate_the_protected_job_name(self):
        other = copy.deepcopy(self.observations["jobs_pages"][0]["jobs"][0])
        other["id"] = 91
        self.observations["jobs_pages"][0]["total_count"] = 2
        self.observations["jobs_pages"][0]["jobs"].append(other)
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_core_labels_must_match_protected_fedora_and_input_hash(self):
        for field, value in (("fedora", "46"), ("inputs_sha256", "4" * 64)):
            original = self.policy[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.policy[field] = value
                self.evaluate()
            self.policy[field] = original

    def test_authority_claims_in_nested_observations_are_not_accepted(self):
        for record in (
            self.observations["artifact"],
            self.observations["jobs_pages"][0],
            self.observations["jobs_pages"][0]["jobs"][0],
            self.observations["jobs_pages"][0]["jobs"][0]["steps"][0],
            self.observations["step_logs"][0],
        ):
            record["observations_authenticated"] = True
            with self.assertRaises(ValueError):
                self.evaluate()
            del record["observations_authenticated"]

    def test_log_rejects_echo_duplicates_truncation_and_outside_upload_window(self):
        original = self.upload_log
        for log in (
            original.replace("20:10:31", "20:10:21"),
            original.replace("20:10:32", "20:10:36"),
            original.replace(" SHA256", " echo SHA256"),
            original + original.splitlines(keepends=True)[0],
            original + original.splitlines(keepends=True)[1],
            original.splitlines(keepends=True)[0],
            "2026-11-11T20:10:30Z ##[group]Run echo spoof\n" + original,
            "2026-11-11T20:10:30Z ##[group]Run echo spoof\n"
            + original
            + "2026-11-11T20:10:34Z ##[endgroup]\n",
            original.replace("Artifact ID is 10", "Artifact ID is 11"),
            original.replace("2026-11-11T20:10:31.1Z", "invalid"),
        ):
            with self.subTest(log=log), self.assertRaises(ValueError):
                self.upload_log = log
                self.evaluate()

    def test_other_upload_projection_does_not_invalidate_protected_upload(self):
        self.add_other_upload(
            self.upload_log.replace("core-oci", "core-image")
            .replace("20:10:31", "20:10:41")
            .replace("20:10:32", "20:10:42")
            .replace("Artifact ID 10", "Artifact ID 11")
            .replace("Artifact ID is 10", "Artifact ID is 11")
        )
        self.assertEqual(self.evaluate()["artifact_id"], 10)

    def test_other_projection_cannot_supply_or_override_protected_identity(self):
        original = self.upload_log
        self.add_other_upload(original)
        for protected in (
            "",
            "2026-11-11T20:10:31Z ordinary output\n",
            original.replace("Artifact ID 10", "Artifact ID 11"),
            original.replace(self.observations["artifact"]["digest"][7:], "0" * 64),
            original.replace("is 10", "is 11").replace("ID 10", "ID 11"),
        ):
            with self.subTest(protected=protected), self.assertRaises(ValueError):
                self.upload_log = protected
                self.evaluate()

    def test_step_log_projections_are_closed_unique_and_api_bound(self):
        original = copy.deepcopy(self.observations["step_logs"])
        mutations = [
            lambda logs: logs.append(copy.deepcopy(logs[0])),
            lambda logs: logs[0].update(number=2),
            lambda logs: logs[0].update(number=True),
            lambda logs: logs[0].update(name="Other upload"),
            lambda logs: logs[0].update(complete=True),
            lambda logs: logs[0].update(authenticated=True),
            lambda logs: logs[0].update(log=True),
            lambda logs: logs[0].pop("log"),
            lambda logs: logs.clear(),
        ]
        for mutate in mutations:
            self.observations["step_logs"] = copy.deepcopy(original)
            mutate(self.observations["step_logs"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.evaluate()

    def test_nonprotected_projection_name_must_also_match_api(self):
        self.add_other_upload("not used as upload evidence")
        self.observations["step_logs"][1]["name"] = "Invented step"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_benign_truncate_prose_and_balanced_parameter_group_are_allowed(self):
        self.upload_log = (
            "2026-11-11T20:10:30Z ##[group]Run actions/upload-artifact@pinned\n"
            "2026-11-11T20:10:30.01Z ordinary truncate option documentation\n"
            "2026-11-11T20:10:30.1Z ##[endgroup]\n"
        ) + self.upload_log
        self.assertEqual(self.evaluate()["artifact_id"], 10)

    def test_success_confirmation_is_mandatory(self):
        self.upload_log = "\n".join(self.upload_log.splitlines()[:2])
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_finalized_and_standalone_ids_must_agree_without_duplicate_forms(self):
        original = self.upload_log
        extra = "2026-11-11T20:10:32.15Z Artifact ID: 10\n"
        lines = original.splitlines(keepends=True)
        self.upload_log = "".join(lines[:2]) + extra + lines[2]
        self.assertEqual(self.evaluate()["artifact_id"], 10)
        for changed in (extra.replace("10\n", "11\n"), extra + extra):
            self.upload_log = "".join(lines[:2]) + changed + lines[2]
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.evaluate()

    def test_quantized_completion_accepts_fraction_but_excludes_next_second(self):
        steps = self.observations["jobs_pages"][0]["jobs"][0]["steps"]
        steps[-1]["completed_at"] = "2026-11-11T20:10:34Z"
        self.add_other_upload("adjacent step output without authority")
        original = self.upload_log
        for fraction in ("34.9", "34.999999999"):
            self.upload_log = original.replace("32.2", fraction)
            self.assertEqual(self.evaluate()["artifact_id"], 10)
        self.upload_log = original.replace("32.2", "35")
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_nanosecond_order_is_not_rounded_to_microseconds(self):
        self.assertGreater(
            binding.timestamp("2026-11-11T20:10:32.100000002Z"),
            binding.timestamp("2026-11-11T20:10:32.100000001Z"),
        )
        self.upload_log = self.upload_log.replace("32.1Z", "32.100000002Z").replace(
            "32.2Z", "32.100000001Z"
        )
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_shared_quantized_metadata_bucket_does_not_infer_step_overlap(self):
        steps = self.observations["jobs_pages"][0]["jobs"][0]["steps"]
        steps[1]["completed_at"] = "2026-11-11T20:10:30.999999999Z"
        steps[2]["started_at"] = "2026-11-11T20:10:30.9Z"
        self.upload_log = self.upload_log.replace("31.1Z", "30.000000000Z")
        self.assertEqual(self.evaluate()["artifact_id"], 10)

    def test_lower_start_bound_and_explicit_zero_fraction(self):
        original = self.upload_log
        self.upload_log = original.replace("31.1Z", "30.000000000Z")
        self.assertEqual(self.evaluate()["artifact_id"], 10)
        self.upload_log = original.replace("31.1Z", "29.999999999Z")
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_verified_archive_not_reopened_after_source_substitution(self):
        self.assertIsNotNone(
            binding, "core output binding evaluator is not implemented"
        )
        extract = binding.pipeline.extract_archive

        def swap(staged, output):
            self.archive.write_bytes(b"substituted after verified copy")
            return extract(staged, output)

        with mock.patch.object(binding.pipeline, "extract_archive", side_effect=swap):
            self.assertEqual(self.evaluate()["core_digest"], self.manifest)

    def test_archive_corruption_symlink_and_unsafe_oci_are_rejected(self):
        self.archive.write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            self.evaluate()
        self.set_archive(archive_bytes(self.files))
        target = self.archive.with_suffix(".actual")
        self.archive.rename(target)
        self.archive.symlink_to(target)
        with self.assertRaises(OSError):
            self.evaluate()
        self.archive.unlink()
        changed = self.files | {"blobs/sha256/" + self.manifest[7:]: b"corrupt"}
        self.set_archive(archive_bytes(changed))
        with self.assertRaises(ValueError):
            self.evaluate()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            entry = zipfile.ZipInfo("index.json")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "elsewhere")
        self.set_archive(buffer.getvalue())
        with self.assertRaises(ValueError):
            self.evaluate()
