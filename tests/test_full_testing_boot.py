import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1] / ".github/workflows"
sys.path.insert(0, str(ROOT.parent / "scripts/workflow"))

import full_testing_boot as boot_lane


def workflow(name):
    return yaml.load((ROOT / name).read_text(), Loader=yaml.BaseLoader)


class FullTestingBootTests(unittest.TestCase):
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
