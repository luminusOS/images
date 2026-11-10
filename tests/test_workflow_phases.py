import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


class WorkflowPhasesTest(unittest.TestCase):
    def test_installer_validation_requires_explicit_boolean_manual_opt_in(self):
        validation = workflow("build-containers.yml")
        triggers = validation.get("on", validation.get(True))
        self.assertEqual(set(triggers), {"push", "pull_request", "workflow_dispatch"})
        inputs = triggers["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"fedora_version", "build_installer"})
        self.assertEqual(
            inputs["build_installer"],
            {
                "description": "Build the installer image (validation only, nothing is published)",
                "type": "boolean",
                "required": False,
                "default": False,
            },
        )
        caller = validation["jobs"]["build-containers"]
        self.assertEqual(
            caller["with"]["build_installer"],
            "${{ github.event_name == 'workflow_dispatch' && inputs.build_installer == true }}",
        )
        self.assertIs(caller["with"]["publish"], False)
        self.assertEqual(caller["with"]["builder_mode"], "local")

    def test_artifact_read_permissions_cover_only_approved_jobs_and_callers(self):
        containers = workflow("containers.yml")
        installer = workflow("installer.yml")
        validation = workflow("build-containers.yml")
        publication = workflow("publish.yml")
        read_only = {"contents": "read", "packages": "read", "actions": "read"}
        for name, job in (
            ("workstation", containers["jobs"]["workstation"]),
            ("installer", containers["jobs"]["installer"]),
            ("installer-build", installer["jobs"]["build"]),
            ("build-containers", validation["jobs"]["build-containers"]),
            ("containers", publication["jobs"]["containers"]),
            ("stable-installer", publication["jobs"]["stable-installer"]),
        ):
            with self.subTest(job=name):
                self.assertEqual(job["permissions"], read_only)
                self.assertNotIn("secrets", job)
                self.assertNotIn("GH_TOKEN", job.get("env", {}))
                for step in job.get("steps", []):
                    if (name, step.get("id")) in (
                        ("workstation", "fetch-core-oci"),
                        ("installer-build", "fetch-workstation-payload"),
                    ):
                        self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
                    else:
                        self.assertNotIn("GH_TOKEN", step.get("env", {}))
                if name in ("build-containers", "containers", "stable-installer"):
                    self.assertEqual(job["uses"], "./.github/workflows/containers.yml")

        for data, expected in (
            (containers, {"workstation", "installer"}),
            (installer, {"build"}),
            (validation, {"build-containers"}),
            (
                publication,
                {"containers", "stable-installer", "stable-source", "release"},
            ),
        ):
            self.assertEqual(
                {
                    name
                    for name, job in data["jobs"].items()
                    if "actions" in job.get("permissions", {})
                },
                expected,
            )
        self.assertNotIn("permissions", containers)
        self.assertNotIn("permissions", installer)
        self.assertNotIn("permissions", validation)
        self.assertEqual(publication["permissions"], {"contents": "read"})
        self.assertEqual(
            containers["jobs"]["core"]["permissions"],
            {"contents": "read", "packages": "read"},
        )
        self.assertNotIn("GH_TOKEN", installer.get("env", {}))
        self.assertNotIn("github.token", str(installer.get("env", {})))
        self.assertNotIn("github.token", str(installer["jobs"]["build"].get("env", {})))
        for step in installer["jobs"]["build"]["steps"]:
            if step.get("id") != "fetch-workstation-payload":
                self.assertNotIn("github.token", str(step))
                self.assertNotIn("GH_TOKEN", step.get("env", {}))
        self.assertNotIn("secrets.GITHUB_TOKEN", str(installer))
        auto = workflow("auto-testing.yml")["jobs"]["prepare"]
        self.assertEqual(auto["uses"], "./.github/workflows/publish.yml")
        self.assertEqual(
            auto["permissions"],
            {"contents": "write", "packages": "write", "actions": "read"},
        )
        self.assertNotIn("GH_TOKEN", containers.get("env", {}))
        for name, job in containers["jobs"].items():
            self.assertNotIn("GH_TOKEN", job.get("env", {}))
            self.assertNotIn("github.token", str(job.get("env", {})))
            for step in job.get("steps", []):
                if (name, step.get("id")) != ("workstation", "fetch-core-oci"):
                    self.assertNotIn("GH_TOKEN", step.get("env", {}))
                    self.assertNotIn("github.token", str(step))
                    self.assertNotIn("secrets.GITHUB_TOKEN", str(step))

    def test_workstation_consumes_canonical_core_only_for_testing_built_core(self):
        jobs = workflow("containers.yml")["jobs"]
        canonical = "inputs.channel == 'testing' && needs.core.outputs.reused != 'true'"
        legacy = "inputs.channel != 'testing' || needs.core.outputs.reused == 'true'"
        self.assertEqual(
            jobs["core"]["outputs"]["reused"], "${{ steps.select.outputs.reused }}"
        )
        self.assertEqual(jobs["workstation"]["if"], "inputs.channel != 'stable'")
        steps = jobs["workstation"]["steps"]
        fetch = next(step for step in steps if step.get("id") == "fetch-core-oci")
        self.assertEqual(fetch["if"], canonical)
        self.assertEqual(
            fetch["env"],
            {
                "GH_TOKEN": "${{ github.token }}",
                "EXPECTED_DIGEST": "${{ needs.core.outputs.built_oci_manifest_digest }}",
            },
        )
        self.assertEqual(
            fetch["run"],
            'python3 .github/scripts/workflow/oci_layout.py fetch-core --repository "$GITHUB_REPOSITORY" '
            '--run-id "$GITHUB_RUN_ID" --layout "$RUNNER_TEMP/core-oci" --expected-digest "$EXPECTED_DIGEST"',
        )
        download = next(
            step for step in steps if step.get("with", {}).get("name") == "core-image"
        )
        load = next(step for step in steps if step.get("name") == "Load core image")
        for step in (download, load):
            self.assertEqual(step["if"], legacy)
        build = next(step for step in steps if step.get("id") == "build")
        self.assertEqual(
            build["with"]["build-contexts"],
            "${{ "
            + canonical
            + " && format('luminusos-core-context.invalid/core=oci-layout://{0}/core-oci@{1}', runner.temp, needs.core.outputs.built_oci_manifest_digest) || '' }}",
        )
        self.assertEqual(
            build["with"]["build-args"].splitlines()[0],
            "core_image=${{ "
            + canonical
            + " && 'luminusos-core-context.invalid/core' || needs.metadata.outputs.core_image }}",
        )
        self.assertLess(steps.index(fetch), steps.index(build))
        self.assertNotIn("continue-on-error", fetch)
        self.assertNotIn("always()", build.get("if", ""))
        self.assertFalse(
            any(step.get("with", {}).get("name") == "core-oci" for step in steps)
        )
        setup = next(
            step
            for step in steps
            if "docker/setup-buildx-action@" in step.get("uses", "")
        )
        self.assertEqual(setup["with"]["driver"], "docker")

    def test_workstation_ancestry_gates_canonical_upload(self):
        steps = workflow("containers.yml")["jobs"]["workstation"]["steps"]
        ancestry = next(
            step for step in steps if step.get("id") == "check-core-ancestry"
        )
        export = next(
            step for step in steps if step.get("id") == "export-workstation-oci"
        )
        upload = next(
            step for step in steps if step.get("id") == "upload-workstation-oci"
        )
        self.assertEqual(
            ancestry["if"],
            "inputs.channel == 'testing' && needs.core.outputs.reused != 'true' && steps.export-workstation-oci.outcome == 'success'",
        )
        self.assertEqual(
            ancestry["env"],
            {
                "CORE_DIGEST": "${{ needs.core.outputs.built_oci_manifest_digest }}",
                "WORKSTATION_DIGEST": "${{ steps.export-workstation-oci.outputs.manifest_digest }}",
            },
        )
        self.assertEqual(
            ancestry["run"],
            'python3 .github/scripts/workflow/oci_layout.py ancestry --core-layout "$RUNNER_TEMP/core-oci" '
            '--layout workstation-oci --core-digest "$CORE_DIGEST" --expected-digest "$WORKSTATION_DIGEST"',
        )
        self.assertEqual(
            upload["if"],
            "success() && steps.export-workstation-oci.outcome == 'success' && (needs.core.outputs.reused == 'true' || steps.check-core-ancestry.outcome == 'success')",
        )
        self.assertLess(steps.index(export), steps.index(ancestry))
        self.assertLess(steps.index(ancestry), steps.index(upload))
        self.assertNotIn("continue-on-error", ancestry)

    def test_workstation_and_installer_export_in_their_build_daemon(self):
        for role, filename, job_name in (
            ("workstation", "containers.yml", "workstation"),
            ("installer", "installer.yml", "build"),
        ):
            with self.subTest(role=role):
                job = workflow(filename)["jobs"][job_name]
                steps = job["steps"]
                build = next(step for step in steps if step.get("id") == "build")
                export = next(
                    step for step in steps if step.get("id") == f"export-{role}-oci"
                )
                upload = next(
                    step for step in steps if step.get("id") == f"upload-{role}-oci"
                )
                setup = next(
                    step
                    for step in steps
                    if "docker/setup-docker-action@" in step.get("uses", "")
                )
                tools = next(
                    step
                    for step in steps
                    if "apt-get install -y skopeo" in step.get("run", "")
                )
                self.assertIs(setup["with"]["set-host"], True)
                self.assertNotIn("if", tools)
                self.assertEqual(build["with"]["platforms"], "linux/amd64")
                self.assertIs(build["with"]["load"], True)
                self.assertIs(build["with"]["push"], False)
                self.assertEqual(export["env"]["IMAGE"], build["with"]["tags"])
                self.assertEqual(
                    export["if"],
                    "inputs.channel == 'testing' && steps.build.outcome == 'success'",
                )
                self.assertEqual(
                    export["run"],
                    'python3 .github/scripts/workflow/oci_layout.py export --image "$IMAGE" '
                    f"--layout {role}-oci --ref {role} "
                    '--docker-host "${DOCKER_HOST:?Docker setup did not expose its socket}"',
                )
                self.assertEqual(
                    upload["if"],
                    "success() && steps.export-workstation-oci.outcome == 'success' && (needs.core.outputs.reused == 'true' || steps.check-core-ancestry.outcome == 'success')"
                    if role == "workstation"
                    else f"steps.export-{role}-oci.outcome == 'success'",
                )
                self.assertEqual(
                    upload["uses"],
                    "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
                )
                self.assertEqual(
                    upload["with"],
                    {
                        "name": f"{role}-oci",
                        "path": f"{role}-oci/",
                        "compression-level": 0,
                        "if-no-files-found": "error",
                    },
                )
                for prerequisite in (setup, tools, build):
                    self.assertLess(steps.index(prerequisite), steps.index(export))
                self.assertLess(steps.index(export), steps.index(upload))
                for step in (build, export, upload):
                    self.assertNotIn("continue-on-error", step)
                self.assertEqual(
                    job["permissions"],
                    {"contents": "read", "packages": "read", "actions": "read"},
                )

    def test_workstation_and_installer_oci_outputs_require_successful_upload(self):
        containers = workflow("containers.yml")
        installer = workflow("installer.yml")
        outer = containers.get("on", containers.get(True))["workflow_call"]["outputs"]
        inner = installer.get("on", installer.get(True))["workflow_call"]["outputs"]
        for role, job in (
            ("workstation", containers["jobs"]["workstation"]),
            ("installer", installer["jobs"]["build"]),
        ):
            for name, source in (
                ("manifest_digest", f"steps.export-{role}-oci.outputs.manifest_digest"),
                ("skopeo_version", f"steps.export-{role}-oci.outputs.skopeo_version"),
                ("artifact_id", f"steps.upload-{role}-oci.outputs.artifact-id"),
            ):
                with self.subTest(role=role, output=name):
                    self.assertEqual(
                        job["outputs"][f"built_oci_{name}"],
                        "${{ steps.upload-"
                        + role
                        + "-oci.outcome == 'success' && "
                        + source
                        + " || '' }}",
                    )
                    self.assertEqual(
                        outer[f"{role}_built_oci_{name}"]["value"],
                        "${{ jobs." + role + ".outputs.built_oci_" + name + " }}",
                    )
                    if role == "installer":
                        self.assertEqual(
                            inner[f"built_oci_{name}"]["value"],
                            "${{ jobs.build.outputs.built_oci_" + name + " }}",
                        )

    def test_new_oci_artifacts_preserve_legacy_archives_and_installer_selection(self):
        containers = workflow("containers.yml")
        caller = containers["jobs"]["installer"]
        self.assertEqual(caller["uses"], "./.github/workflows/installer.yml")
        self.assertEqual(caller["needs"], ["metadata", "workstation"])
        self.assertEqual(
            caller["if"],
            "always() && inputs.build_installer && needs.metadata.result == 'success' && (inputs.channel == 'stable' || needs.workstation.result == 'success')",
        )
        self.assertEqual(caller["with"]["channel"], "${{ inputs.channel }}")
        installer = workflow("installer.yml")
        channel = installer.get("on", installer.get(True))["workflow_call"]["inputs"][
            "channel"
        ]
        self.assertEqual(channel, {"type": "string", "required": True})
        self.assertEqual(
            containers["jobs"]["workstation"]["if"], "inputs.channel != 'stable'"
        )
        for role, job in (
            ("workstation", containers["jobs"]["workstation"]),
            ("installer", installer["jobs"]["build"]),
        ):
            with self.subTest(role=role):
                self.assertEqual(
                    job["outputs"]["image_id"], "${{ steps.save.outputs.image_id }}"
                )
                self.assertEqual(
                    job["outputs"]["archive_sha256"],
                    "${{ steps.save.outputs.archive_sha256 }}",
                )
                save = next(step for step in job["steps"] if step.get("id") == "save")
                self.assertEqual(
                    save["run"],
                    "python3 .github/scripts/workflow/image_archive.py save",
                )
                self.assertEqual(save["env"]["ARCHIVE"], f"{role}-image.tar")
                self.assertTrue(
                    any(
                        step.get("with", {}).get("name") == f"{role}-image"
                        for step in job["steps"]
                    )
                )

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
            {"contents": "read", "packages": "read", "actions": "read"},
        )

    def test_testing_installer_payload_uses_only_authenticated_canonical_workstation(
        self,
    ):
        caller = workflow("containers.yml")["jobs"]["installer"]
        installer = workflow("installer.yml")
        inputs = installer.get("on", installer.get(True))["workflow_call"]["inputs"]
        self.assertEqual(
            inputs["workstation_built_oci_manifest_digest"],
            {"type": "string", "default": ""},
        )
        self.assertEqual(
            caller["with"]["workstation_built_oci_manifest_digest"],
            "${{ needs.workstation.outputs.built_oci_manifest_digest }}",
        )
        self.assertEqual(
            caller["with"]["workstation_digest"], "${{ inputs.workstation_digest }}"
        )
        steps = installer["jobs"]["build"]["steps"]
        fetch = next(
            step for step in steps if step.get("id") == "fetch-workstation-payload"
        )
        self.assertEqual(fetch["if"], "inputs.channel == 'testing'")
        self.assertEqual(
            fetch["env"],
            {
                "GH_TOKEN": "${{ github.token }}",
                "EXPECTED_DIGEST": "${{ inputs.workstation_built_oci_manifest_digest }}",
            },
        )
        self.assertEqual(
            fetch["run"],
            'mkdir -p .test\npython3 .github/scripts/workflow/oci_layout.py fetch-payload --repository "$GITHUB_REPOSITORY" --run-id "$GITHUB_RUN_ID" --layout .test/payload.oci --expected-digest "$EXPECTED_DIGEST"\n',
        )
        export = next(
            step for step in steps if step.get("name") == "Export installer payload"
        )
        self.assertEqual(export["if"], "inputs.channel == 'stable'")
        self.assertEqual(
            export["run"],
            "python3 .github/scripts/workflow/installer_payload.py export",
        )
        self.assertEqual(
            export["env"]["WORKSTATION_DIGEST"], "${{ inputs.workstation_digest }}"
        )
        load = next(
            step for step in steps if step.get("name") == "Load workstation image"
        )
        build = next(step for step in steps if step.get("id") == "build")
        self.assertLess(steps.index(fetch), steps.index(load))
        self.assertLess(steps.index(fetch), steps.index(build))
        self.assertNotIn("continue-on-error", fetch)
        self.assertNotIn("always()", build.get("if", ""))

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
