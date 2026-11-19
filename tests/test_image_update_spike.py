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


if __name__ == "__main__":
    unittest.main()
