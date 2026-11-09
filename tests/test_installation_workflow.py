import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
SPEC = importlib.util.spec_from_file_location(
    "validation_runner", ROOT / ".github/scripts/workflow/validation_runner.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def candidate():
    return {
        "version": 1,
        "run_id": 12,
        "repository": "org/repo",
        "source_sha": "a" * 40,
        "images": {
            "workstation": "ghcr.io/org/luminusos-workstation@sha256:" + "b" * 64,
            "core": "core",
            "installer": "installer",
        },
        "artifacts": {"iso": "c" * 64},
    }


def write_receipts(directory, document):
    binding = runner.release_pipeline.binding(document)
    for name in runner.release_pipeline.CHECKS:
        log = f"{name}.log"
        data = f"observed {name}\n".encode()
        (directory / log).write_bytes(data)
        receipt = {
            "name": name,
            "binding": binding,
            "command": ["real-probe", name],
            "exit_code": 0,
            "started_at": "2026-11-05T10:00:00Z",
            "finished_at": "2026-11-05T10:01:00Z",
            "log": log,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        (directory / f"{name}.json").write_text(json.dumps(receipt))


class RunnerTests(unittest.TestCase):
    def test_driver_is_fixed_and_untrusted_paths_rejected(self):
        self.assertEqual(
            str(runner.DRIVER), "/usr/local/libexec/luminusos/validate-candidate"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "driver"
            path.write_text("driver")
            path.chmod(0o777)
            with self.assertRaises(ValueError):
                runner.trusted_driver(path)
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                runner.trusted_driver(link)

    def test_unsafe_directory_and_run_id_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o777)
            with self.assertRaises(ValueError):
                runner.owned_directory(root)
            with self.assertRaises(ValueError):
                runner.run_validation(root, root, "12;id", "org/repo")

    def test_real_receipt_schema_checked_and_no_secrets_given_to_driver(self):
        document = candidate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.json").touch()

            def invoke(command, *, check, env):
                self.assertTrue(check)
                self.assertEqual(
                    command[1:3], ["--candidate", str(candidate_dir / "candidate.json")]
                )
                self.assertNotIn("COSIGN_PRIVATE_KEY", env)
                self.assertNotIn("GH_TOKEN", env)
                write_receipts(Path(command[-1]), document)
                return subprocess.CompletedProcess(command, 0)

            with (
                patch.object(
                    runner, "trusted_driver", return_value=Path("/trusted/driver")
                ),
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(runner.subprocess, "run", side_effect=invoke),
                patch.dict(
                    os.environ, {"GH_TOKEN": "secret", "COSIGN_PRIVATE_KEY": "secret"}
                ),
            ):
                receipts = runner.run_validation(candidate_dir, root, "12", "org/repo")
            self.assertEqual(
                len(list(receipts.glob("*.json"))), len(runner.release_pipeline.CHECKS)
            )
            self.assertFalse((receipts / "validation.json").exists())

    def test_driver_failure_and_wrong_binding_fail_without_success(self):
        document = candidate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.json").touch()
            with (
                patch.object(
                    runner, "trusted_driver", return_value=Path("/trusted/driver")
                ),
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(
                    runner.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "driver"),
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                runner.run_validation(candidate_dir, root, "12", "org/repo")
            with (
                patch.object(
                    runner, "trusted_driver", return_value=Path("/trusted/driver")
                ),
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(runner.subprocess, "run") as execute,
                self.assertRaises(ValueError),
            ):
                runner.run_validation(candidate_dir, root, "13", "org/repo")
            execute.assert_not_called()

    def test_invalid_receipt_or_log_rejects_before_signing(self):
        document = candidate()
        for failure in ("binding", "exit", "log"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate_dir = root / "candidate"
                candidate_dir.mkdir()
                (candidate_dir / "candidate.json").touch()

                def invoke(command, *, check, env, failure=failure):
                    receipts = Path(command[-1])
                    write_receipts(receipts, document)
                    path = next(receipts.glob("*.json"))
                    receipt = json.loads(path.read_text())
                    if failure == "binding":
                        receipt["binding"]["source_sha"] = "d" * 40
                        path.write_text(json.dumps(receipt))
                    elif failure == "exit":
                        receipt["exit_code"] = 1
                        path.write_text(json.dumps(receipt))
                    else:
                        (receipts / receipt["log"]).write_text("tampered")

                with (
                    patch.object(
                        runner, "trusted_driver", return_value=Path("/trusted/driver")
                    ),
                    patch.object(
                        runner.release_pipeline, "candidate", return_value=document
                    ),
                    patch.object(runner.subprocess, "run", side_effect=invoke),
                    self.assertRaises(ValueError),
                ):
                    runner.run_validation(candidate_dir, root, "12", "org/repo")

    def test_symlinked_outputs_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "log").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                runner.validate_output_tree(root)


class WorkflowTests(unittest.TestCase):
    def test_workflow_restricts_runner_environment_and_permissions(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/installation-validation.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertEqual(
            workflow["permissions"], {"contents": "read", "actions": "read"}
        )
        job = workflow["jobs"]["installation"]
        self.assertIn("refs/heads/main", job["if"])
        self.assertEqual(
            job["runs-on"], ["self-hosted", "linux", "x64", "luminusos-validation"]
        )
        self.assertEqual(job["environment"], "release-validation")
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
        steps = job["steps"]
        self.assertEqual(steps[0]["with"]["persist-credentials"], "false")
        self.assertIn("fetch-candidate", steps[3]["run"])
        self.assertIn("validation_runner.py", steps[4]["run"])
        self.assertIn("record-validation", steps[5]["run"])
        self.assertEqual(steps[6]["with"]["name"], "installation-validation")
        self.assertNotIn("COSIGN_PRIVATE_KEY", str(steps[4]))


if __name__ == "__main__":
    unittest.main()
