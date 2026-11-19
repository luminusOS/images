import importlib.util
import io
import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/scripts/workflow"
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(WORKFLOW))

from test_release_kind import Fixture


def load(name):
    spec = importlib.util.spec_from_file_location(name, WORKFLOW / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load("release_pipeline")
sign_candidates = load("sign_candidates")
PUBLISH = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
JOBS = PUBLISH["jobs"]
FULL = "needs.inputs.outputs.release_kind == 'full'"
IMAGE = "needs.inputs.outputs.release_kind == 'image'"


def step(job, name):
    return next(s for s in JOBS[job]["steps"] if s.get("name") == name)


def run_script(script, env):
    """Run a workflow shell step with every external command recorded."""
    with tempfile.TemporaryDirectory() as temp:
        bin_dir = Path(temp) / "bin"
        bin_dir.mkdir()
        log = Path(temp) / "calls"
        for tool in ("docker", "python3", "cosign"):
            stub = bin_dir / tool
            stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> "{log}"\n')
            stub.chmod(0o755)
        subprocess.run(
            ["bash", "-e", "-c", script],
            check=True,
            env={"PATH": f"{bin_dir}:/usr/bin:/bin"} | env,
        )
        return log.read_text().splitlines() if log.exists() else []


def scan_outputs(calls):
    return [c.split("--output ")[1].split()[0] for c in calls]


class ArtifactsInputTests(unittest.TestCase):
    def test_dispatch_and_call_defaults(self):
        dispatch = PUBLISH["on"]["workflow_dispatch"]["inputs"]["artifacts"]
        self.assertEqual(dispatch["type"], "choice")
        self.assertEqual(dispatch["options"], ["auto", "image", "full"])
        self.assertEqual(dispatch["default"], "auto")
        call = PUBLISH["on"]["workflow_call"]["inputs"]["artifacts"]
        self.assertEqual(call, {"type": "string", "default": "full"})

    def test_inputs_job_resolves_the_kind_without_interpolating_inputs(self):
        job = JOBS["inputs"]
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertEqual(
            job["outputs"]["release_kind"], "${{ steps.kind.outputs.release_kind }}"
        )
        kind = step("inputs", "Resolve release kind")
        self.assertEqual(kind["id"], "kind")
        self.assertEqual(
            kind["env"],
            {
                "ARTIFACTS": "${{ inputs.artifacts }}",
                "CANDIDATE": "${{ inputs.candidate_run_id }}",
            },
        )
        self.assertEqual(
            kind["run"],
            "python3 .github/scripts/workflow/release_pipeline.py resolve-kind",
        )

    def test_resolve_kind(self):
        for artifacts, candidate, expected in (
            ("auto", "", "image"),
            ("image", "", "image"),
            ("full", "", "full"),
            ("auto", "123", ""),
            ("full", "123", ""),
            ("image", "123", ""),
        ):
            with self.subTest(artifacts=artifacts, candidate=candidate):
                self.assertEqual(
                    pipeline.requested_kind(
                        {"ARTIFACTS": artifacts, "CANDIDATE": candidate}
                    ),
                    expected,
                )
        for artifacts in ("", "Image", "iso", "all"):
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                pipeline.requested_kind({"ARTIFACTS": artifacts, "CANDIDATE": ""})

    def test_resolve_kind_cli_writes_the_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            with (
                mock.patch.dict(
                    pipeline.os.environ,
                    {
                        "ARTIFACTS": "auto",
                        "CANDIDATE": "",
                        "GITHUB_OUTPUT": str(output),
                    },
                ),
                mock.patch.object(
                    pipeline.sys, "argv", ["release_pipeline", "resolve-kind"]
                ),
                mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            ):
                self.assertEqual(pipeline.main(), 0)
            self.assertEqual(output.read_text(), "release_kind=image\n")

    def test_resume_kind_comes_from_the_signed_candidate(self):
        for requested, signed in (
            ("auto", "image"),
            ("auto", "full"),
            ("image", "image"),
            ("full", "full"),
        ):
            with self.subTest(requested=requested, signed=signed):
                pipeline.check_kind({"ARTIFACTS": requested, "SIGNED": signed})
        for requested, signed in (
            ("image", "full"),
            ("full", "image"),
            ("auto", ""),
            ("", "full"),
            ("auto", "partial"),
        ):
            with (
                self.subTest(requested=requested, signed=signed),
                self.assertRaises(ValueError),
            ):
                pipeline.check_kind({"ARTIFACTS": requested, "SIGNED": signed})
        steps = [s.get("name") for s in JOBS["release-evidence"]["steps"]]
        check = step(
            "release-evidence",
            "Check requested release kind against the signed candidate",
        )
        self.assertEqual(
            check["env"],
            {
                "ARTIFACTS": "${{ inputs.artifacts }}",
                "SIGNED": "${{ steps.candidate.outputs.release_kind }}",
            },
        )
        self.assertLess(
            steps.index("Fetch signed candidate from prior successful run"),
            steps.index(check["name"]),
        )
        self.assertLess(
            steps.index(check["name"]),
            steps.index("Fetch matching installation validation"),
        )


class ImageJobGraphTests(unittest.TestCase):
    def test_containers_skip_the_installer_and_sequence_image_versions(self):
        with_ = JOBS["containers"]["with"]
        self.assertEqual(with_["build_installer"], "${{ " + FULL + " }}")
        self.assertEqual(
            with_["build_sequence"], "${{ inputs.build_sequence || " + IMAGE + " }}"
        )
        self.assertIn("inputs", JOBS["containers"]["needs"])

    def test_disk_jobs_run_only_for_full(self):
        for name in ("iso", "qcow2"):
            with self.subTest(job=name):
                self.assertIn(FULL, JOBS[name]["if"])
                self.assertIn("inputs", JOBS[name]["needs"])
        boot = JOBS["boot-test"]
        self.assertEqual(boot["needs"], ["iso", "qcow2"])
        self.assertIn("needs.iso.result == 'success'", boot["if"])
        self.assertIn("needs.qcow2.result == 'success'", boot["if"])

    def test_prepare_candidate_accepts_skips_only_for_image(self):
        condition = JOBS["prepare-candidate"]["if"]
        self.assertIn(
            f"(({FULL} && needs.iso.result == 'success' && "
            "needs.qcow2.result == 'success' && "
            "needs.boot-test.result == 'success') || "
            f"({IMAGE} && needs.iso.result == 'skipped' && "
            "needs.qcow2.result == 'skipped' && "
            "needs.boot-test.result == 'skipped'))",
            condition,
        )
        for required in (
            "needs.quality.result == 'success'",
            "needs.publish-images.result == 'success'",
            "needs.scan-candidates.result == 'success'",
            "inputs.candidate_run_id == ''",
        ):
            self.assertIn(required, condition)
        self.assertIn("inputs", JOBS["prepare-candidate"]["needs"])

    def test_installer_and_disk_steps_are_full_only(self):
        downloads = {
            s["with"]["name"]: s.get("if")
            for s in JOBS["prepare-candidate"]["steps"]
            if "download-artifact" in s.get("uses", "")
        }
        self.assertEqual(
            downloads,
            {
                "workstation-iso": FULL,
                "workstation-qcow2": FULL,
                "candidate-scans": None,
                "boot-test": FULL,
            },
        )
        publish_downloads = {
            s["with"]["name"]: s.get("if")
            for s in JOBS["publish-images"]["steps"]
            if "download-artifact" in s.get("uses", "")
        }
        self.assertEqual(publish_downloads["installer-image"], FULL)
        self.assertIsNone(publish_downloads["core-image"])
        self.assertEqual(
            step("publish-images", "Load verified installer archive")["if"], FULL
        )

    def test_published_base_is_resolved_only_for_image_before_metadata(self):
        names = [s.get("name") for s in JOBS["prepare-candidate"]["steps"]]
        resolve = step("prepare-candidate", "Resolve the published base")
        self.assertEqual(resolve["if"], IMAGE)
        self.assertNotIn("${{", resolve["run"])
        self.assertEqual(
            resolve["env"]["FEDORA_VERSION"],
            "${{ needs.containers.outputs.fedora_version }}",
        )
        login = next(
            i
            for i, s in enumerate(JOBS["prepare-candidate"]["steps"])
            if "docker/login-action" in s.get("uses", "")
        )
        self.assertLess(login, names.index(resolve["name"]))
        self.assertLess(
            names.index(resolve["name"]), names.index("Create candidate metadata")
        )
        metadata = step("prepare-candidate", "Create candidate metadata")
        self.assertEqual(
            metadata["env"]["RELEASE_KIND"], "${{ needs.inputs.outputs.release_kind }}"
        )
        gates = step("prepare-candidate", "Bind real gate outcomes")
        self.assertEqual(
            gates["env"]["RELEASE_KIND"], "${{ needs.inputs.outputs.release_kind }}"
        )
        self.assertEqual(
            JOBS["prepare-candidate"]["permissions"],
            {"contents": "read", "packages": "read"},
        )

    def test_new_steps_never_interpolate_expressions_in_shell(self):
        for job in JOBS.values():
            for item in job.get("steps", []):
                script = item.get("run", "")
                with self.subTest(step=item.get("name")):
                    self.assertNotIn("${{ inputs.", script)
                    self.assertNotIn("${{ steps.", script)
                    self.assertNotIn("release_kind", script)
                    self.assertNotIn("artifacts", script.replace("candidate-scans", ""))


SHELL_ENV = {
    "GITHUB_REPOSITORY_OWNER": "Org",
    "GITHUB_RUN_ID": "7",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": "a" * 40,
    "CORE_IMAGE": "core:local",
    "WORKSTATION_IMAGE": "workstation:local",
    "INSTALLER_IMAGE": "installer:local",
    "CORE": "c@sha256:1",
    "WORKSTATION": "w@sha256:2",
    "INSTALLER": "i@sha256:3",
    "FEDORA": "45",
}


class ShellStepTests(unittest.TestCase):
    """The edited shell steps keep the full path and drop the installer for image."""

    def calls(self, job, name, kind):
        item = step(job, name) if name else None
        return run_script(item["run"], SHELL_ENV | {"RELEASE_KIND": kind})

    def test_push_tags_and_signs_the_kinds_images(self):
        stage = "ghcr.io/org/luminusos-candidates"
        full = self.calls("publish-images", "Push candidate images", "full")
        self.assertEqual(
            full,
            [
                f"docker tag core:local {stage}:core-candidate-7-1",
                f"docker tag workstation:local {stage}:workstation-candidate-7-1",
                f"docker tag installer:local {stage}:workstation-iso-candidate-7-1",
                (
                    "python3 .github/scripts/workflow/sign_candidates.py "
                    f"{stage}:core-candidate-7-1 {stage}:workstation-candidate-7-1 "
                    f"{stage}:workstation-iso-candidate-7-1"
                ),
            ],
        )
        image = self.calls("publish-images", "Push candidate images", "image")
        self.assertEqual(
            image,
            [c for c in full if "iso-candidate" not in c][:2]
            + [
                (
                    "python3 .github/scripts/workflow/sign_candidates.py "
                    f"{stage}:core-candidate-7-1 {stage}:workstation-candidate-7-1"
                )
            ],
        )

    def test_signature_verification_and_metadata_follow_the_kind(self):
        for name in ("Verify staged candidate signatures",):
            full = self.calls("scan-candidates", name, "full")
            image = self.calls("scan-candidates", name, "image")
            self.assertEqual(
                [c.split()[-1] for c in full],
                ["c@sha256:1", "w@sha256:2", "i@sha256:3"],
            )
            self.assertEqual(
                [c.split()[-1] for c in image], ["c@sha256:1", "w@sha256:2"]
            )
        full = self.calls("prepare-candidate", "Create candidate metadata", "full")
        image = self.calls("prepare-candidate", "Create candidate metadata", "image")
        self.assertEqual(
            shlex.split(full[0])[-3:], ["c@sha256:1", "w@sha256:2", "i@sha256:3"]
        )
        self.assertEqual(
            shlex.split(image[0])[-3:],
            ["candidate-metadata.json", "c@sha256:1", "w@sha256:2"],
        )

    def test_scans_drop_only_the_installer_for_image(self):
        for step_id, channel in (
            ("inspect-testing", "testing"),
            ("inspect-stable", "stable"),
        ):
            item = next(
                s for s in JOBS["scan-candidates"]["steps"] if s.get("id") == step_id
            )
            with self.subTest(channel=channel):
                self.assertEqual(
                    item["env"]["RELEASE_KIND"],
                    "${{ needs.inputs.outputs.release_kind }}",
                )
                full = run_script(item["run"], SHELL_ENV | {"RELEASE_KIND": "full"})
                image = run_script(item["run"], SHELL_ENV | {"RELEASE_KIND": "image"})
                outputs = scan_outputs
                self.assertEqual(
                    outputs(full), ["scan/core", "scan/workstation", "scan/installer"]
                )
                self.assertEqual(outputs(image), ["scan/core", "scan/workstation"])
                self.assertTrue(all(f"--channel {channel}" in c for c in full))


METADATA_ENV = {
    "GITHUB_REPOSITORY": "owner/repo",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_RUN_ID": "123",
    "CHANNEL": "testing",
    "VERSION_TAG": "testing-45.20261118.2",
    "BUILD_VERSION": "45.20261118.2",
    "FEDORA_VERSION": "45",
    "FEDORA_BOOTC_DIGEST": "sha256:" + "1" * 64,
}


class ImageMetadataTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.fixture = Fixture(self.directory)

    def metadata(self, kind, images, base=None):
        target = self.directory / "candidate-metadata.json"
        target.unlink(missing_ok=True)
        env = METADATA_ENV | {"RELEASE_KIND": kind}
        if base is not None:
            path = self.directory / "published-base.json"
            path.write_text(json.dumps(base))
            env["PUBLISHED_BASE"] = str(path)
        with (
            mock.patch.dict(sign_candidates.os.environ, env),
            mock.patch.object(
                sys, "argv", ["sign_candidates.py", "--metadata", str(target), *images]
            ),
            mock.patch.object(sign_candidates.subprocess, "run") as run,
            mock.patch.object(sign_candidates.sys, "stderr", new_callable=io.StringIO),
        ):
            code = sign_candidates.main()
        run.assert_not_called()
        return code, (json.loads(target.read_text()) if target.exists() else None)

    def test_full_metadata_is_unchanged(self):
        images = list(self.fixture.full()["images"].values())
        code, metadata = self.metadata("full", images)
        self.assertEqual(code, 0)
        self.assertEqual(set(metadata), pipeline.LEGACY_FIELDS - {"artifacts"})
        self.assertEqual(self.metadata("full", images[:2])[0], 1)

    def test_image_metadata_creates_a_valid_image_candidate(self):
        expected = self.fixture.image()
        images = list(expected["images"].values())
        code, metadata = self.metadata("image", images, expected["published_base"])
        self.assertEqual(code, 0)
        self.assertEqual(metadata["release_kind"], "image")
        self.assertEqual(set(metadata["images"]), {"core", "workstation"})
        self.assertEqual(metadata["published_base"], expected["published_base"])
        self.assertEqual(self.metadata("image", [*images, images[0]], {})[0], 1)
        self.assertEqual(self.metadata("other", images, {})[0], 1)
        self.assertEqual(self.metadata("image", images)[0], 1)
        self.metadata("image", images, expected["published_base"])
        output = self.directory / "candidate.json"
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline, "sign"),
        ):
            candidate = pipeline.create_candidate(
                self.directory / "candidate-metadata.json",
                self.directory,
                output,
                Path("key"),
            )
        self.assertEqual(pipeline.release_kind(candidate), "image")
        self.assertEqual(candidate["published_base"], expected["published_base"])
        self.assertTrue(
            all(
                not pipeline.installer_artifact(name) for name in candidate["artifacts"]
            )
        )

    def test_image_version_equal_to_the_base_is_rejected(self):
        expected = self.fixture.image()
        base = json.loads(json.dumps(expected["published_base"]))
        for item in base.values():
            item["version"] = "testing-45.20261118.2"
        self.metadata("image", list(expected["images"].values()), base)
        with (
            mock.patch.dict(
                pipeline.os.environ,
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "123",
                },
            ),
            mock.patch.object(pipeline, "sign") as sign,
            self.assertRaisesRegex(ValueError, "older"),
        ):
            pipeline.create_candidate(
                self.directory / "candidate-metadata.json",
                self.directory,
                self.directory / "candidate.json",
                Path("key"),
            )
        sign.assert_not_called()

    def test_full_metadata_cannot_carry_a_published_base(self):
        document = self.fixture.full()
        metadata = {k: v for k, v in document.items() if k != "artifacts"}
        metadata["published_base"] = self.fixture.image()["published_base"]
        path = self.directory / "metadata.json"
        path.write_text(json.dumps(metadata))
        with (
            mock.patch.dict(
                pipeline.os.environ,
                {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "123",
                },
            ),
            mock.patch.object(pipeline, "sign") as sign,
            self.assertRaisesRegex(ValueError, "metadata fields"),
        ):
            pipeline.create_candidate(
                path, self.directory, self.directory / "candidate.json", Path("k")
            )
        sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
