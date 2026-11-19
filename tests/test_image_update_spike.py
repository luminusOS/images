import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
SPEC = importlib.util.spec_from_file_location(
    "image_update_spike", ROOT / ".github/scripts/workflow/image_update_spike.py"
)
spike = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(spike)
ARGS = [
    "--disk",
    "d",
    "--base-manifest",
    "m",
    "--candidate-layout",
    "l",
    "--output",
    "o",
]


class ImageUpdateSpikeTests(unittest.TestCase):
    def test_refuses_outside_main_dispatch(self):
        for env in (
            {
                "GITHUB_REF": "refs/heads/feature",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
            },
            {"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"},
        ):
            with (
                self.subTest(env=env),
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch.object(spike, "run") as run,
            ):
                self.assertEqual(spike.main(ARGS), 2)
                run.assert_not_called()

    def test_refuses_signing_credentials(self):
        env = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "CANDIDATE_COSIGN_PRIVATE_KEY": "x",
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(spike, "run") as run,
        ):
            self.assertEqual(spike.main(ARGS), 2)
            run.assert_not_called()

    def test_base_tag_comes_from_the_candidate_line(self):
        testing = {"channel": "testing", "fedora_version": "45"}
        stable = {"channel": "stable", "fedora_version": "45"}
        self.assertEqual(spike.base_tag(testing, ""), "testing-45")
        self.assertEqual(spike.base_tag(stable, ""), "45")
        self.assertEqual(
            spike.base_tag(testing, "testing-45.20261117.2"), "testing-45.20261117.2"
        )
        self.assertEqual(spike.base_tag(stable, "45.20261120.1"), "45.20261120.1")
        for candidate, version in (
            (stable, "testing-45.20261117.2"),
            (stable, "testing-45"),
            (testing, "45.20261120.1"),
            (testing, "testing-44.20261117"),
            (testing, "testing-45"),
            (testing, "testing-45.2026111"),
            ({"channel": "testing", "fedora_version": "4x"}, ""),
        ):
            with (
                self.subTest(candidate=candidate, version=version),
                self.assertRaises(ValueError),
            ):
                spike.base_tag(candidate, version)

    def test_workflow_has_no_environment_or_write_permissions(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/image-update-spike.yml").read_text()
        )
        job = workflow["jobs"]["spike"]
        self.assertNotIn("environment", job)
        self.assertEqual(
            job["permissions"],
            {"contents": "read", "actions": "read", "packages": "read"},
        )
        text = (ROOT / ".github/workflows/image-update-spike.yml").read_text()
        self.assertNotIn("secrets.CANDIDATE", text)
        self.assertNotIn("secrets.COSIGN", text)
        self.assertNotIn("record-validation", text)
        self.assertNotIn("inputs.base_tag", text)
        self.assertIn("image_update_spike.py base-tag", text)


if __name__ == "__main__":
    unittest.main()
