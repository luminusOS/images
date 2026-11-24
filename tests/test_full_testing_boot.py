import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1] / ".github/workflows"
sys.path.insert(0, str(ROOT.parent / "scripts/workflow"))

import full_testing_boot as boot_lane
import validation_driver


def workflow(name):
    return yaml.load((ROOT / name).read_text(), Loader=yaml.BaseLoader)


class FullTestingBootTests(unittest.TestCase):
    def test_boot_creates_receipts_directory_for_validation_driver(self):
        sha = "a" * 40
        index = "sha256:" + "b" * 64
        manifest = "sha256:" + "c" * 64
        candidate = {
            "version": 1,
            "repository": "luminusOS/images",
            "run_id": 17,
            "source_sha": sha,
            "channel": "testing",
            "release_kind": "full",
            "images": {
                "workstation": f"ghcr.io/luminusos/luminusos-candidates@{index}"
            },
            "artifacts": {},
        }
        observations = {"platform_manifest_digest": manifest}
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "candidate").mkdir()
            (work / "candidate/candidate.json").write_text(json.dumps(candidate))
            environment = {
                "PATH": os.defpath,
                "HOME": directory,
                "RUNNER_TEMP": directory,
                "GITHUB_REPOSITORY": "luminusOS/images",
                "GITHUB_REPOSITORY_ID": "1118572971",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKFLOW_REF": f"luminusOS/images/{boot_lane.WORKFLOW}@refs/heads/main",
                "GITHUB_WORKFLOW_SHA": sha,
                "GITHUB_SHA": sha,
                "GITHUB_RUN_ID": "17",
                "GITHUB_RUN_ATTEMPT": "2",
            }

            def observe(_args, _candidate, _receipts, diagnostics, _work):
                self.assertEqual((work / "receipts").stat().st_mode & 0o777, 0o700)
                (diagnostics / "validation-boot-observation.json").write_text(
                    json.dumps(observations)
                )

            def run_driver(argv, **_kwargs):
                self.assertEqual(validation_driver.main(argv[2:]), 0)

            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(sys, "argv", ["full_testing_boot.py", "boot", directory]),
                patch.object(boot_lane.pipeline, "candidate", return_value=candidate),
                patch.object(
                    boot_lane, "verify_payload", return_value=(manifest, {}, ())
                ),
                patch.object(boot_lane.subprocess, "run", side_effect=run_driver),
                patch.object(validation_driver, "_validate", side_effect=observe),
            ):
                boot_lane.main()

            evidence = json.loads((work / "testing-boot-evidence.json").read_text())
            self.assertEqual(evidence["observations"], observations)
            self.assertEqual(evidence["scope"], boot_lane.SCOPE)

    def test_missing_candidate_artifact_explains_attempt_scoping(self):
        with (
            patch.object(
                boot_lane.pipeline,
                "download",
                side_effect=ValueError("expected exactly one artifact"),
            ),
            self.assertRaisesRegex(ValueError, "rerun all jobs"),
        ):
            boot_lane.download_candidate(17, 2, Path("unused"))

    def test_candidate_must_be_full_testing_current_and_unmarked(self):
        candidate = {
            "repository": "luminusOS/images",
            "run_id": 17,
            "source_sha": "a" * 40,
            "channel": "testing",
            "release_kind": "full",
            "artifacts": {},
        }
        boot_lane.require_candidate(candidate, 17, "a" * 40)
        for change in (
            {"release_kind": "image"},
            {"channel": "stable"},
            {"run_id": 18},
            {"source_sha": "b" * 40},
            {"artifacts": {"feature/profile.json": "c" * 64}},
        ):
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "expected a full testing candidate"),
            ):
                boot_lane.require_candidate(candidate | change, 17, "a" * 40)
        self.assertNotIn(boot_lane.WORKFLOW, boot_lane.pipeline.PRODUCER_WORKFLOWS)

    def test_full_testing_preparation_is_not_a_publication_producer(self):
        prepare = workflow("full-testing-boot.yml")["jobs"]["prepare"]
        self.assertEqual(prepare["uses"], "./.github/workflows/publish.yml")
        self.assertEqual(prepare["with"]["channel"], "testing")
        self.assertEqual(prepare["with"]["artifacts"], "full")
        self.assertEqual(prepare["with"]["isolated_feature_candidate"], "true")
        self.assertNotIn("candidate_run_id", prepare["with"])
        self.assertNotIn("validation_run_id", prepare["with"])
        boot = workflow("full-testing-boot.yml")["jobs"]["boot"]
        self.assertEqual(boot["environment"], "promotion-feature-snapshot-validation")
        self.assertEqual(set(boot["permissions"].values()), {"read"})
        uploads = [
            step["with"]
            for step in boot["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        ]
        self.assertEqual(
            [upload["name"] for upload in uploads],
            ["full-testing-boot-evidence-${{ github.run_attempt }}"],
        )
        self.assertTrue(uploads[0]["path"].endswith("/testing-boot-evidence.json"))
        for job in ("release-evidence", "release", "release-stable"):
            self.assertIn(
                "!inputs.isolated_feature_candidate",
                workflow("publish.yml")["jobs"][job]["if"],
            )
