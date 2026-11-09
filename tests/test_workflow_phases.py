import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


class WorkflowPhasesTest(unittest.TestCase):
    def test_core_canonical_artifact_requires_a_successful_testing_build(self):
        core = workflow("containers.yml")["jobs"]["core"]
        steps = core["steps"]
        build = next(step for step in steps if step.get("id") == "build")
        export = next(step for step in steps if step.get("id") == "export-core-oci")
        upload = next(step for step in steps if step.get("id") == "upload-core-oci")
        self.assertEqual(core["if"], "inputs.channel != 'stable'")
        self.assertEqual(
            export["if"],
            "inputs.channel == 'testing' && steps.select.outputs.reused != 'true' && steps.build.outcome == 'success'",
        )
        self.assertEqual(upload["if"], "steps.export-core-oci.outcome == 'success'")
        self.assertLess(steps.index(build), steps.index(export))
        self.assertLess(steps.index(export), steps.index(upload))
        self.assertEqual(build["with"]["load"], True)
        self.assertEqual(build["with"]["push"], False)
        self.assertEqual(build["with"]["platforms"], "linux/amd64")
        self.assertEqual(export["env"]["IMAGE"], build["with"]["tags"])
        self.assertEqual(
            upload["uses"],
            "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
        )
        self.assertEqual(
            upload["with"],
            {
                "name": "core-oci",
                "path": "core-oci/",
                "compression-level": 0,
                "if-no-files-found": "error",
            },
        )
        for step in (build, export, upload):
            self.assertNotIn("continue-on-error", step)
        self.assertEqual(core["permissions"], {"contents": "read", "packages": "read"})

    def test_core_canonical_export_has_tools_and_the_build_daemon(self):
        steps = workflow("containers.yml")["jobs"]["core"]["steps"]
        setup = next(
            step
            for step in steps
            if "docker/setup-docker-action@" in step.get("uses", "")
        )
        tools = next(
            step for step in steps if "apt-get install -y skopeo" in step.get("run", "")
        )
        export = next(step for step in steps if step.get("id") == "export-core-oci")
        self.assertIs(setup["with"]["set-host"], True)
        self.assertNotIn("if", tools)
        self.assertLess(steps.index(setup), steps.index(export))
        self.assertLess(steps.index(tools), steps.index(export))
        self.assertEqual(
            export["run"],
            'python3 .github/scripts/workflow/oci_layout.py export --image "$IMAGE" --layout core-oci --ref core --docker-host "${DOCKER_HOST:?Docker setup did not expose its socket}"',
        )

    def test_core_built_oci_outputs_are_separate_and_require_uploaded_artifact(self):
        data = workflow("containers.yml")
        core = data["jobs"]["core"]
        call = data.get("on", data.get(True))["workflow_call"]["outputs"]
        for name, source in (
            ("manifest_digest", "steps.export-core-oci.outputs.manifest_digest"),
            ("skopeo_version", "steps.export-core-oci.outputs.skopeo_version"),
            ("artifact_id", "steps.upload-core-oci.outputs.artifact-id"),
        ):
            self.assertEqual(
                core["outputs"][f"built_oci_{name}"],
                "${{ steps.upload-core-oci.outcome == 'success' && "
                + source
                + " || '' }}",
            )
            self.assertEqual(
                call[f"core_built_oci_{name}"]["value"],
                "${{ jobs.core.outputs.built_oci_" + name + " }}",
            )
        self.assertEqual(
            core["outputs"]["digest"], "${{ steps.select.outputs.digest }}"
        )
        self.assertEqual(
            call["core_digest"]["value"], "${{ jobs.core.outputs.digest }}"
        )
        self.assertEqual(
            core["outputs"]["image_id"], "${{ steps.save.outputs.image_id }}"
        )
        self.assertTrue(
            any(
                step.get("with", {}).get("name") == "core-image"
                for step in core["steps"]
            )
        )

    def test_security_bypass_is_manual_auto_testing_only_and_cron_is_false(self):
        auto = workflow("auto-testing.yml")
        triggers = auto.get("on", auto.get(True))
        self.assertEqual(
            triggers["workflow_dispatch"]["inputs"]["security_findings_bypass"][
                "default"
            ],
            False,
        )
        self.assertEqual(
            auto["jobs"]["prepare"]["with"]["security_findings_bypass"],
            "${{ github.event_name == 'workflow_dispatch' && inputs.security_findings_bypass || false }}",
        )
        publish = workflow("publish.yml")
        self.assertNotIn(
            "security_findings_bypass", publish["on"]["workflow_dispatch"]["inputs"]
        )
        self.assertEqual(
            publish["on"]["workflow_call"]["inputs"]["security_findings_bypass"],
            {"type": "boolean", "default": False},
        )
        self.assertEqual(
            publish["env"]["SECURITY_FINDINGS_BYPASS"],
            "${{ inputs.security_findings_bypass || false }}",
        )
        authorization = publish["jobs"]["inputs"]["steps"]
        self.assertIn("validate-bypass", authorization[1]["run"])
        for job in ("containers", "stable-source", "release"):
            self.assertIn("inputs", publish["jobs"][job]["needs"])

    def test_bypass_blocks_candidate_and_promotion_even_when_scans_succeed(self):
        jobs = workflow("publish.yml")["jobs"]
        for name in ("prepare-candidate", "stable-source", "release"):
            with self.subTest(job=name):
                self.assertIn("!inputs.security_findings_bypass", jobs[name]["if"])
        for name in ("publish-images", "iso", "qcow2"):
            self.assertNotIn("!inputs.security_findings_bypass", jobs[name]["if"])

    def test_workflow_names_describe_the_build_responsibility(self):
        self.assertEqual(
            workflow("containers.yml")["name"], "Image Build Orchestration"
        )
        self.assertEqual(
            workflow("build-containers.yml")["name"], "Image Build Validation"
        )
        self.assertEqual(workflow("publish.yml")["name"], "Image Publication")
        jobs = workflow("containers.yml")["jobs"]
        self.assertEqual(jobs["core"]["name"], "Build core image")
        self.assertEqual(jobs["workstation"]["name"], "Build workstation image")
        self.assertEqual(jobs["installer"]["name"], "Build installer image")
        validation = workflow("build-containers.yml")
        self.assertEqual(
            validation["jobs"]["build-containers"]["name"], "Validate image builds"
        )

    def test_container_editions_keep_explicit_build_dependency_chain(self):
        jobs = workflow("containers.yml")["jobs"]
        assert jobs["core"]["needs"] == ["metadata"]
        assert "core" in jobs["workstation"]["needs"]
        assert "workstation" in jobs["installer"]["needs"]
        assert "installer" not in jobs["workstation"]["needs"]

    def test_installer_is_a_separate_reusable_workflow_with_declared_contract(self):
        installer = workflow("installer.yml")
        call = installer.get("on", installer.get(True))["workflow_call"]
        inputs = call["inputs"]
        self.assertTrue(
            {
                "channel",
                "fedora_version",
                "sirius_version",
                "sirius_rpm_version",
                "sirius_sha256",
                "build_version",
                "workstation_image",
                "image_namespace",
                "target_tag",
                "workstation_iso_image",
            }.issubset(inputs)
        )
        self.assertTrue(
            all(
                inputs[name]["required"] is True
                for name in (
                    "channel",
                    "fedora_version",
                    "sirius_version",
                    "sirius_rpm_version",
                    "sirius_sha256",
                    "build_version",
                    "workstation_image",
                    "image_namespace",
                    "target_tag",
                    "workstation_iso_image",
                )
            )
        )
        for name in (
            "workstation_digest",
            "workstation_archive_sha256",
            "workstation_image_id",
        ):
            self.assertEqual(inputs[name]["default"], "")
        self.assertEqual(
            call["outputs"]["image_id"]["value"],
            "${{ jobs.build.outputs.image_id }}",
        )
        self.assertEqual(
            call["outputs"]["archive_sha256"]["value"],
            "${{ jobs.build.outputs.archive_sha256 }}",
        )

    def test_installer_caller_forwards_metadata_and_testing_archive_evidence(self):
        jobs = workflow("containers.yml")["jobs"]
        installer = jobs["installer"]
        self.assertEqual(installer["uses"], "./.github/workflows/installer.yml")
        self.assertEqual(installer["needs"], ["metadata", "workstation"])
        self.assertIn("always()", installer["if"])
        self.assertIn("needs.metadata.result == 'success'", installer["if"])
        self.assertIn("needs.workstation.result == 'success'", installer["if"])
        for name in (
            "channel",
            "fedora_version",
            "sirius_version",
            "sirius_rpm_version",
            "sirius_sha256",
            "build_version",
            "workstation_image",
            "image_namespace",
            "target_tag",
            "workstation_iso_image",
        ):
            self.assertIn(name, installer["with"])
        self.assertEqual(
            installer["with"]["workstation_archive_sha256"],
            "${{ needs.workstation.outputs.archive_sha256 }}",
        )
        self.assertEqual(
            installer["with"]["workstation_image_id"],
            "${{ needs.workstation.outputs.image_id }}",
        )
        self.assertEqual(
            jobs["installer"]["permissions"],
            {"contents": "read", "packages": "read"},
        )

    def test_dispatch_inputs_and_candidate_autodetection(self):
        publish = workflow("publish.yml")
        inputs = publish["on"]["workflow_dispatch"]["inputs"]
        assert len(inputs) <= 10
        assert {"sirius_version", "sirius_sha256"} <= inputs.keys()
        assert "candidate_workflow" not in inputs
        assert "testing_workflow" not in inputs
        for job in ("stable-source", "release"):
            fetch = next(
                step["run"]
                for step in publish["jobs"][job]["steps"]
                if "fetch-candidate" in step.get("run", "")
            )
            assert "--workflow" not in fetch

    def test_prepare_and_resume_are_disjoint(self):
        jobs = workflow("publish.yml")["jobs"]
        assert "inputs.candidate_run_id == ''" in jobs["containers"]["if"]
        assert "inputs.candidate_run_id == ''" in jobs["prepare-candidate"]["if"]
        assert "inputs.candidate_run_id != ''" in jobs["release"]["if"]
        assert "inputs.validation_run_id != ''" in jobs["release"]["if"]
        assert "containers" not in jobs["release"]["needs"]
        prepare_commands = "\n".join(
            step.get("run", "") for step in jobs["prepare-candidate"]["steps"]
        )
        assert prepare_commands.count("prepare-gates") == 1
        assert (
            prepare_commands.index("prepare-gates")
            < prepare_commands.index("create-candidate")
            < prepare_commands.index("prepare-results")
        )
        commands = "\n".join(step.get("run", "") for step in jobs["release"]["steps"])
        assert "fetch-candidate" in commands
        assert "fetch-validation" in commands
        assert "prepare-results" in commands
        assert "assemble-evidence" in commands
        assert commands.index("fetch-validation") < commands.index("assemble-evidence")
        assert commands.index("assemble-evidence") < commands.index(" promote ")
        assert commands.index(" promote ") < commands.index(" publish ")
        assert "--output candidate" in commands
        assert "--output dist/release-evidence.json" in commands
        assert "--candidate candidate/candidate.json" in commands
        assert "--evidence dist/release-evidence.json" in commands
        assert '--channel "$CHANNEL"' in commands
        assert "--directory dist" in commands

    def test_stable_preparation_uses_approved_payload(self):
        jobs = workflow("publish.yml")["jobs"]
        assert jobs["stable-installer"]["needs"] == ["stable-source"]
        assert (
            "needs.stable-source.outputs.workstation_digest"
            in jobs["stable-installer"]["with"]["workstation_digest"]
        )
        assert (
            "needs.stable-source.outputs.workstation"
            in jobs["qcow2"]["steps"][-2]["env"]["WORKSTATION_IMAGE"]
        )
        metadata = next(
            step
            for step in jobs["prepare-candidate"]["steps"]
            if step.get("name") == "Create candidate metadata"
        )
        assert (
            "needs.stable-source.outputs.build_version"
            in metadata["env"]["VERSION_TAG"]
        )
        commands = "\n".join(
            step.get("run", "") for step in jobs["stable-source"]["steps"]
        )
        assert (
            commands.index("fetch-candidate")
            < commands.index("fetch-validation")
            < commands.index("prepare-results")
            < commands.index("assemble-evidence")
            < commands.index("verify-release")
            < commands.index("verify-source")
        )

    def test_scheduled_preparation_reuses_publish(self):
        auto = workflow("auto-testing.yml")
        prepare = auto["jobs"]["prepare"]
        assert prepare["uses"] == "./.github/workflows/publish.yml"
        assert prepare["with"]["force_core"] is True
        assert prepare["with"]["build_sequence"] is True
        assert "concurrency" not in auto
