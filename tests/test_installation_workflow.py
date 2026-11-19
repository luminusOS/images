import hashlib
import importlib.util
import json
import os
import re
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


def image_candidate():
    return candidate() | {
        "release_kind": "image",
        "images": {
            "workstation": "ghcr.io/org/luminusos-candidates@sha256:" + "b" * 64,
            "core": "core",
        },
        "artifacts": {"gates/quality.json": "c" * 64},
        "published_base": {"workstation": {}, "core": {}},
    }


def write_receipts(directory, document):
    binding = runner.release_pipeline.binding(document)
    kind = runner.release_pipeline.release_kind(document)
    for name in runner.release_pipeline.checks(kind):
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

    def test_image_candidates_get_the_base_disk_and_candidate_mirror(self):
        document = image_candidate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.json").touch()
            fixture = root / "fixture-base"
            fixture.mkdir()
            seen = []

            def invoke(command, *, check, env):
                seen.append(command)
                write_receipts(Path(command[command.index("--receipts") + 1]), document)
                return subprocess.CompletedProcess(command, 0)

            with (
                patch.object(
                    runner.release_pipeline, "candidate", return_value=document
                ),
                patch.object(runner.subprocess, "run", side_effect=invoke),
            ):
                with self.assertRaises(OSError):
                    runner.run_validation(
                        candidate_dir, root, "12", "org/repo", fixture
                    )
                self.assertEqual(seen, [])
                (root / "base-disk").mkdir()
                disk = root / runner.BASE_DISK
                disk.write_bytes(b"qcow2")
                (root / runner.CANDIDATE_MIRROR).mkdir(mode=0o700)
                disk.chmod(0o666)
                with self.assertRaisesRegex(ValueError, "untrusted runner file"):
                    runner.run_validation(
                        candidate_dir, root, "12", "org/repo", fixture
                    )
                disk.chmod(0o644)
                receipts = runner.run_validation(
                    candidate_dir, root, "12", "org/repo", fixture
                )
            self.assertEqual(
                seen[0][-4:],
                [
                    "--disk",
                    str(disk),
                    "--candidate-mirror",
                    str(root / runner.CANDIDATE_MIRROR),
                ],
            )
            self.assertEqual(
                {p.stem for p in receipts.glob("*.json")},
                set(runner.release_pipeline.checks("image")),
            )

    def test_full_candidates_get_no_image_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / runner.CANDIDATE_MIRROR).mkdir()
            self.assertEqual(runner.kind_inputs(candidate(), root), [])

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


def load_workflow(name):
    return yaml.load(
        (ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader
    )


def image_only(step):
    return "release_kind == 'image'" in step.get("if", "")


def label(step):
    return step.get("name", step.get("uses"))


FULL_STEPS = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "Check Python version",
    "Free disk space",
    "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532",
    "Fetch and verify candidate",
    "Require the kind the disk job saw",
    "Enable KVM and vhost-vsock for the runner user",
    "Install VM and fixture tooling",
    "Stage the private workstation image as the update fixture base",
    "Run installation and trust validation",
    "Remove the staged candidate image",
    "Record and sign observed validation",
    "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "Upload failure diagnostics",
]


class KindWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow("installation-validation.yml")
        self.disk = self.workflow["jobs"]["disk"]
        self.installation = self.workflow["jobs"]["installation"]

    def steps(self, job):
        return {label(step): step for step in job["steps"]}

    def test_full_candidates_run_the_existing_installation_steps(self):
        full = [label(s) for s in self.installation["steps"] if not image_only(s)]
        self.assertEqual(full, FULL_STEPS)
        for step in self.disk["steps"]:
            if label(step) in (
                "Fetch and verify candidate",
                "Remove the disposable disk and builder cache",
            ) or step.get("uses", "").startswith(
                ("actions/checkout@", "sigstore/cosign-installer@")
            ):
                continue
            with self.subTest(step=label(step)):
                self.assertTrue(image_only(step))

    def test_installation_waits_for_the_disk_job_and_its_kind(self):
        self.assertEqual(self.installation["needs"], "disk")
        self.assertEqual(self.disk["if"], self.installation["if"])
        self.assertEqual(
            self.disk["outputs"]["release_kind"],
            "${{ steps.candidate.outputs.release_kind }}",
        )
        guard = self.steps(self.installation)["Require the kind the disk job saw"]
        self.assertEqual(
            guard["env"],
            {
                "RELEASE_KIND": "${{ steps.candidate.outputs.release_kind }}",
                "DISK_KIND": "${{ needs.disk.outputs.release_kind }}",
            },
        )
        for job in (self.disk, self.installation):
            fetch = self.steps(job)["Fetch and verify candidate"]
            self.assertEqual(fetch["id"], "candidate")

    def test_disk_is_built_on_the_runner_that_builds_release_qcow2(self):
        publish = load_workflow("publish.yml")["jobs"]
        self.assertEqual(self.disk["runs-on"], publish["qcow2"]["runs-on"])
        self.assertEqual(self.disk["runs-on"], "ubuntu-24.04")
        self.assertEqual(self.installation["runs-on"], "ubuntu-26.04")
        builds = [
            label(step)
            for job in self.workflow["jobs"].values()
            for step in job["steps"]
            if "ci-package.py qcow2" in step.get("run", "")
        ]
        self.assertEqual(builds, ["Build a disposable disk from the published base"])

    def test_disk_job_holds_no_signing_secret_or_write_permission(self):
        self.assertNotIn("environment", self.disk)
        self.assertEqual(
            self.disk["permissions"], {"contents": "read", "actions": "read"}
        )
        self.assertNotIn("COSIGN", str(self.disk))
        self.assertEqual(
            set(re.findall(r"secrets\.([A-Z_]+)", str(self.disk))), {"GITHUB_TOKEN"}
        )
        self.assertEqual(self.disk["steps"][0]["with"]["persist-credentials"], "false")

    def test_stale_base_fails_before_the_disk_is_built(self):
        ordered = [label(step) for step in self.disk["steps"]]
        check = "Re-resolve the published base pinned by the candidate"
        build = "Build a disposable disk from the published base"
        self.assertLess(
            ordered.index("Fetch and verify candidate"), ordered.index(check)
        )
        self.assertLess(ordered.index(check), ordered.index(build))
        steps = self.steps(self.disk)
        self.assertIn("validation_base.py", steps[check]["run"])
        self.assertEqual(steps[check]["id"], "base")
        self.assertEqual(
            steps[build]["env"]["WORKSTATION_IMAGE"],
            "${{ steps.base.outputs.workstation_image }}",
        )

    def test_disk_artifact_is_short_lived_and_reaches_the_runner_path(self):
        upload = self.steps(self.disk)["Upload the disposable disk"]
        download = self.steps(self.installation)["Download the disposable base disk"]
        self.assertEqual(upload["with"]["retention-days"], "1")
        self.assertEqual(upload["with"]["name"], download["with"]["name"])
        self.assertEqual(
            download["with"]["path"],
            "${{ runner.temp }}/" + str(runner.BASE_DISK.parent),
        )
        validation_base = importlib.util.module_from_spec(
            importlib.util.spec_from_file_location(
                "validation_base",
                ROOT / ".github/scripts/workflow/validation_base.py",
            )
        )
        validation_base.__spec__.loader.exec_module(validation_base)
        self.assertEqual(validation_base.DISK_NAME, runner.BASE_DISK.name)
        cleanup = self.steps(self.disk)["Remove the disposable disk and builder cache"]
        self.assertEqual(cleanup["if"], "${{ always() }}")
        self.assertIn(".osbuild-cache", cleanup["run"])
        self.assertIn(validation_base.DISK_NAME, cleanup["run"])

    def test_candidate_mirror_is_staged_where_the_runner_reads_it(self):
        stage = self.steps(self.installation)[
            "Stage the candidate index and signature for the upgrade"
        ]
        self.assertIn(f'mirror="$RUNNER_TEMP/{runner.CANDIDATE_MIRROR}"', stage["run"])
        self.assertIn("--all --preserve-digests", stage["run"])
        self.assertIn("oci:$mirror/layout:candidate", stage["run"])
        self.assertIn('> "$mirror/signatures.json"', stage["run"])
        self.assertIn("trap 'rm -rf \"$auth\"' EXIT", stage["run"])
        ordered = [label(step) for step in self.installation["steps"]]
        validate = ordered.index("Run installation and trust validation")
        self.assertLess(ordered.index(label(stage)), validate)
        self.assertLess(ordered.index("Download the disposable base disk"), validate)
        cleanup = self.steps(self.installation)[
            "Remove the base disk, candidate mirror and VM work files"
        ]
        self.assertGreater(ordered.index(label(cleanup)), validate)
        self.assertIn("always()", cleanup["if"])
        for path in ("base-disk", "candidate-mirror", "validation-vm"):
            self.assertIn(f'"$RUNNER_TEMP/{path}"', cleanup["run"])

    def test_no_expression_is_interpolated_into_a_script(self):
        for job_name, job in self.workflow["jobs"].items():
            for step in job["steps"]:
                with self.subTest(job=job_name, step=label(step)):
                    self.assertNotIn("${{", step.get("run", ""))

    def test_sudo_podman_passes_environment_values_explicitly(self):
        found = False
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            workflow = yaml.safe_load(path.read_text())
            for job in (workflow.get("jobs") or {}).values():
                for step in job.get("steps", []):
                    script = step.get("run", "")
                    if "sudo podman run" not in script:
                        continue
                    found = True
                    for name in re.findall(
                        r"-e\s+([A-Za-z_][A-Za-z0-9_]*)(?=[\s\\]|$)", script
                    ):
                        with self.subTest(workflow=path.name, variable=name):
                            self.fail(f"sudo drops the environment; pass {name}=value")
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
