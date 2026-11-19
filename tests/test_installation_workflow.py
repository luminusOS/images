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
        "release_kind": "full",
        "run_id": 12,
        "repository": "org/repo",
        "channel": "testing",
        "fedora_version": "45",
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
    def setUp(self):
        patcher = patch.dict(os.environ, {"GITHUB_REF": "refs/heads/main"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_driver_is_the_reviewed_repository_script(self):
        self.assertEqual(
            runner.DRIVER, ROOT / ".github/scripts/workflow/validation_driver.py"
        )
        self.assertTrue(runner.DRIVER.is_file())

    def test_unsafe_directory_and_run_id_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o777)
            with self.assertRaises(ValueError):
                runner.owned_directory(root)
            with self.assertRaises(ValueError):
                runner.run_validation(root, root, "12;id", "org/repo", root)

    def test_real_receipt_schema_checked_and_no_secrets_given_to_driver(self):
        document = candidate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.json").touch()
            fixture = root / "fixture-base"
            fixture.mkdir()

            def invoke(command, *, check, env):
                self.assertTrue(check)
                self.assertEqual(command[:2], [sys.executable, str(runner.DRIVER)])
                self.assertEqual(
                    command[2:4], ["--candidate", str(candidate_dir / "candidate.json")]
                )
                self.assertEqual(command[-2:], ["--fixture-base", str(fixture)])
                self.assertNotIn("COSIGN_PRIVATE_KEY", env)
                self.assertNotIn("GH_TOKEN", env)
                write_receipts(Path(command[command.index("--receipts") + 1]), document)
                return subprocess.CompletedProcess(command, 0)

            with (
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(runner.subprocess, "run", side_effect=invoke),
                patch.dict(
                    os.environ,
                    {
                        "GH_TOKEN": "secret",
                        "COSIGN_PRIVATE_KEY": "secret",
                        "GITHUB_REF": "refs/heads/main",
                    },
                ),
            ):
                receipts = runner.run_validation(
                    candidate_dir, root, "12", "org/repo", fixture
                )
            self.assertEqual(
                len(list(receipts.glob("*.json"))), len(runner.release_pipeline.CHECKS)
            )
            self.assertFalse((receipts / "validation.json").exists())

    def test_candidates_are_validated_only_from_their_release_line(self):
        stable = candidate() | {"channel": "stable"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "candidate.json").touch()
            for document, ref in (
                (stable, "refs/heads/main"),
                (stable, "refs/heads/release/46"),
                (candidate(), "refs/heads/release/45"),
            ):
                with (
                    self.subTest(channel=document["channel"], ref=ref),
                    patch.object(
                        runner.release_pipeline, "candidate", return_value=document
                    ),
                    patch.object(runner.subprocess, "run") as driver,
                    patch.dict(os.environ, {"GITHUB_REF": ref}),
                    self.assertRaisesRegex(ValueError, "release line"),
                ):
                    runner.run_validation(root, root, "12", "org/repo", root)
                driver.assert_not_called()
        for ref, accepted in (
            ("refs/heads/main", True),
            ("refs/heads/release/45", True),
            ("refs/heads/feature", False),
            ("refs/heads/release/x", False),
        ):
            env = {
                "GITHUB_REF": ref,
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_TEMP": "/nonexistent",
                "CANDIDATE_RUN_ID": "12",
                "GITHUB_REPOSITORY": "org/repo",
                "FIXTURE_BASE": "/nonexistent",
            }
            with (
                self.subTest(ref=ref),
                patch.dict(os.environ, env),
                patch.object(runner, "run_validation", side_effect=RuntimeError) as run,
            ):
                with self.assertRaises(RuntimeError if accepted else ValueError):
                    runner.main()
                self.assertEqual(run.called, accepted)

    def test_driver_failure_and_wrong_binding_fail_without_success(self):
        document = candidate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.json").touch()
            fixture = root / "fixture-base"
            fixture.mkdir()
            with (
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
                runner.run_validation(candidate_dir, root, "12", "org/repo", fixture)
            with (
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(runner.subprocess, "run") as execute,
                self.assertRaises(ValueError),
            ):
                runner.run_validation(candidate_dir, root, "13", "org/repo", fixture)
            execute.assert_not_called()

    def test_invalid_receipt_or_log_rejects_before_signing(self):
        document = candidate()
        for failure in ("binding", "exit", "log"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate_dir = root / "candidate"
                candidate_dir.mkdir()
                (candidate_dir / "candidate.json").touch()
                fixture = root / "fixture-base"
                fixture.mkdir()

                def invoke(command, *, check, env, failure=failure):
                    receipts = Path(command[command.index("--receipts") + 1])
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
                        runner.release_pipeline, "candidate", return_value=document
                    ),
                    patch.object(runner.subprocess, "run", side_effect=invoke),
                    self.assertRaises(ValueError),
                ):
                    runner.run_validation(
                        candidate_dir, root, "12", "org/repo", fixture
                    )

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
        self.assertEqual(
            job["if"],
            "(github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/heads/release/')) && github.event_name == 'workflow_dispatch'",
        )
        self.assertEqual(job["runs-on"], "ubuntu-26.04")
        self.assertEqual(job["environment"], "candidate-staging")
        self.assertEqual(
            job["permissions"],
            {"contents": "read", "actions": "read", "packages": "read"},
        )
        steps = {step.get("name", step.get("uses")): step for step in job["steps"]}
        ordered = [step.get("name", step.get("uses")) for step in job["steps"]]
        self.assertEqual(job["steps"][0]["with"]["persist-credentials"], "false")
        fetch = steps["Fetch and verify candidate"]
        stage = steps["Stage the private workstation image as the update fixture base"]
        validate = steps["Run installation and trust validation"]
        record = steps["Record and sign observed validation"]
        self.assertLess(ordered.index(fetch["name"]), ordered.index(stage["name"]))
        self.assertLess(ordered.index(stage["name"]), ordered.index(validate["name"]))
        self.assertLess(ordered.index(validate["name"]), ordered.index(record["name"]))
        self.assertIn("fetch-candidate", fetch["run"])
        self.assertIn("shared/release/candidate.pub", fetch["run"])
        self.assertIn("rm -f", stage["run"])
        self.assertIn("--password-stdin", stage["run"])
        self.assertIn("validation_runner.py", validate["run"])
        for step in (validate, record):
            self.assertNotIn("GH_TOKEN", step.get("env", {}))
            self.assertNotIn("GITHUB_TOKEN", str(step))
        self.assertNotIn("COSIGN", str(validate))
        self.assertIn("record-validation", record["run"])
        self.assertIn("shared/release/candidate.pub", record["run"])
        self.assertEqual(
            record["env"]["CANDIDATE_COSIGN_PRIVATE_KEY"],
            "${{ secrets.CANDIDATE_COSIGN_PRIVATE_KEY }}",
        )
        self.assertNotIn("secrets.COSIGN_PRIVATE_KEY", str(job))
        self.assertEqual(runner.PUBLIC_KEY, Path("shared/release/candidate.pub"))
        uploads = [s for s in job["steps"] if "upload-artifact" in s.get("uses", "")]
        self.assertEqual(
            [u["with"]["name"] for u in uploads],
            ["installation-validation", "installation-validation-diagnostics"],
        )
        self.assertEqual(uploads[1]["if"], "${{ failure() || cancelled() }}")
        cleanup = steps["Remove the staged candidate image"]
        self.assertEqual(cleanup["if"], "${{ always() }}")
        self.assertIn('rm -rf "$RUNNER_TEMP/fixture-base"', cleanup["run"])
        self.assertLess(ordered.index(validate["name"]), ordered.index(cleanup["name"]))


if __name__ == "__main__":
    unittest.main()
