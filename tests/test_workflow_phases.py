import copy
import hashlib
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


def reusable_permission_errors(workflows, entrypoint):
    levels = {"none": 0, "read": 1, "write": 2}
    errors = []

    def visit(filename, ceiling=None):
        data = workflows[filename]
        for name, job in data["jobs"].items():
            requested = job.get("permissions", data.get("permissions", ceiling or {}))
            if ceiling is not None:
                for permission, level in requested.items():
                    if levels[level] > levels[ceiling.get(permission, "none")]:
                        errors.append((filename, name, permission, level))
            uses = job.get("uses", "")
            if uses.startswith("./.github/workflows/"):
                effective = (
                    requested
                    if ceiling is None
                    else {
                        permission: level
                        for permission, level in requested.items()
                        if levels[level] <= levels[ceiling.get(permission, "none")]
                    }
                )
                visit(uses.rsplit("/", 1)[1], effective)

    visit(entrypoint)
    return errors


class WorkflowPhasesTest(unittest.TestCase):
    def test_phase_inputs_bind_each_channel_to_its_line_before_any_job(self):
        step = next(
            step
            for step in workflow("publish.yml")["jobs"]["inputs"]["steps"]
            if step.get("name") == "Validate phase inputs"
        )
        self.assertEqual(
            step["run"],
            "python3 .github/scripts/workflow/release_pipeline.py check-phase",
        )
        command = [sys.executable, *shlex.split(step["run"])[1:]]
        for ref, channel, candidate, validation, expected in (
            ("refs/heads/main", "stable", "", "", 1),
            ("refs/heads/main", "testing", "", "", 0),
            ("refs/heads/main", "testing", "123", "456", 0),
            ("refs/heads/release/45", "testing", "", "", 1),
            ("refs/heads/main", "testing", "123", "", 1),
            ("refs/heads/main", "testing", "", "456", 1),
            ("refs/heads/main", "testing", "abc", "def", 1),
            ("refs/heads/main", "testing", "0", "456", 1),
            ("refs/heads/main", "testing", "١", "456", 1),
        ):
            with self.subTest(
                ref=ref, channel=channel, candidate=candidate, validation=validation
            ):
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env={
                        **os.environ,
                        "GITHUB_REF": ref,
                        "CHANNEL": channel,
                        "CANDIDATE": candidate,
                        "VALIDATION": validation,
                        "FEDORA": "",
                    },
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_public_writers_require_successful_inputs_and_inert_probe_is_separate(self):
        jobs = workflow("publish.yml")["jobs"]

        def guarded(name):
            if name == "inputs":
                return True
            job = jobs[name]
            if any(
                function in job.get("if", "")
                for function in ("always()", "failure()", "cancelled()", "success()")
            ):
                return False
            dependencies = job.get("needs", [])
            if isinstance(dependencies, str):
                dependencies = [dependencies]
            return any(guarded(dependency) for dependency in dependencies)

        writers = {
            name
            for name, job in jobs.items()
            if "write" in job.get("permissions", {}).values()
        }
        self.assertEqual(writers, {"publish-images", "release", "release-stable"})
        for name in writers:
            with self.subTest(job=name):
                self.assertTrue(guarded(name))
        self.assertNotIn("needs", jobs["r2-producer-probe"])
        self.assertIn("inputs.inert_r2_probe == true", jobs["r2-producer-probe"]["if"])
        self.assertEqual(
            jobs["inputs"]["if"],
            "${{ !(github.event_name == 'workflow_dispatch' && inputs.inert_r2_probe == true) }}",
        )
        for name in ("iso", "qcow2", "prepare-candidate"):
            self.assertIn("always()", jobs[name]["if"])
            self.assertIn("needs.", jobs[name]["if"])
            self.assertIn(".result == 'success'", jobs[name]["if"])

    def test_legacy_call_graph_respects_permission_ceiling_before_conditions(self):
        workflows = {
            path.name: workflow(path.name)
            for path in (ROOT / ".github/workflows").glob("*.yml")
        }
        for caller in ("build-containers.yml", "publish.yml", "auto-testing.yml"):
            with self.subTest(caller=caller):
                self.assertEqual(reusable_permission_errors(workflows, caller), [])

    def test_permission_ceiling_rejects_guarded_false_nested_attester(self):
        workflows = {
            path.name: workflow(path.name)
            for path in (ROOT / ".github/workflows").glob("*.yml")
        }
        attester = copy.deepcopy(
            workflows["private-core-producer.yml"]["jobs"]["private-core-attest"]
        )
        attester["if"] = "${{ false }}"
        workflows["containers.yml"]["jobs"]["private-core-attest"] = attester
        for caller in ("build-containers.yml", "publish.yml", "auto-testing.yml"):
            with self.subTest(caller=caller):
                self.assertEqual(
                    reusable_permission_errors(workflows, caller),
                    [
                        ("containers.yml", "private-core-attest", "id-token", "write"),
                        (
                            "containers.yml",
                            "private-core-attest",
                            "attestations",
                            "write",
                        ),
                    ],
                )

    def assert_container_token_scope(self, containers, private=False):
        approved = (
            {("private-core-attest", None, "Check actual private producer object")}
            if private
            else {
                (
                    "workstation",
                    "fetch-core-oci",
                    "Fetch verified canonical core OCI layout",
                ),
            }
        )
        self.assertNotIn("GH_TOKEN", containers.get("env", {}))
        self.assertNotIn("github.token", str(containers.get("env", {})))
        seen = []
        for name, job in containers["jobs"].items():
            self.assertNotIn("GH_TOKEN", job.get("env", {}))
            self.assertNotIn("github.token", str(job.get("env", {})))
            for step in job.get("steps", []):
                key = (name, step.get("id"), step.get("name"))
                remaining = copy.deepcopy(step)
                if key in approved:
                    seen.append(key)
                    self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
                    del remaining["env"]["GH_TOKEN"]
                self.assertNotIn("GH_TOKEN", str(remaining), key)
                self.assertNotIn("github.token", str(remaining), key)
                self.assertNotIn("secrets.GITHUB_TOKEN", str(step), key)
        self.assertCountEqual(seen, approved)

    def test_container_token_scope_rejects_mutations(self):
        originals = {
            False: workflow("containers.yml"),
            True: workflow("private-core-producer.yml"),
        }
        for private, original in originals.items():
            self.assert_container_token_scope(original, private)
        for job_name, step_name in (
            ("core", "Build core"),
            ("private-core", "Build and export private core"),
            ("private-core-attest", "Validate independent operator policy"),
        ):
            with self.subTest(job=job_name, step=step_name):
                private = job_name.startswith("private-core")
                mutated = copy.deepcopy(originals[private])
                step = next(
                    s
                    for s in mutated["jobs"][job_name]["steps"]
                    if s.get("name") == step_name
                )
                step.setdefault("env", {})["GH_TOKEN"] = "${{ github.token }}"
                with self.assertRaises(AssertionError):
                    self.assert_container_token_scope(mutated, private)
        mutated = copy.deepcopy(originals[True])
        mutated["jobs"]["private-core-extra"] = {
            "steps": [{"env": {"GH_TOKEN": "${{ github.token }}"}}]
        }
        with self.assertRaises(AssertionError):
            self.assert_container_token_scope(mutated, True)

    def test_separation_retains_exact_legacy_conditions(self):
        data = workflow("containers.yml")
        triggers = data.get("on", data.get(True))
        self.assertNotIn("private_core_handoff", triggers["workflow_call"]["inputs"])
        for name in ("metadata", "core", "workstation"):
            with self.subTest(job=name):
                self.assertNotIn("if", data["jobs"][name])
        self.assertEqual(
            data["jobs"]["installer"]["if"],
            "always() && inputs.build_installer && needs.metadata.result == 'success' && needs.workstation.result == 'success'",
        )

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
                if name in ("build-containers", "containers"):
                    self.assertEqual(job["uses"], "./.github/workflows/containers.yml")

        for data, expected in (
            (containers, {"workstation", "installer"}),
            (installer, {"build"}),
            (validation, {"build-containers"}),
            (
                publication,
                {
                    "containers",
                    "release-evidence",
                    "release",
                    "release-stable",
                },
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
        private = workflow("private-core-producer.yml")
        self.assertEqual(
            private["jobs"]["private-core"]["permissions"], {"contents": "read"}
        )
        self.assertEqual(
            private["jobs"]["private-core-attest"]["permissions"],
            {
                "contents": "read",
                "actions": "read",
                "id-token": "write",
                "attestations": "write",
            },
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
        self.assert_container_token_scope(containers)

    def test_workstation_consumes_canonical_core_only_for_testing_built_core(self):
        jobs = workflow("containers.yml")["jobs"]
        canonical = "needs.core.outputs.reused != 'true'"
        legacy = "needs.core.outputs.reused == 'true'"
        self.assertEqual(
            jobs["core"]["outputs"]["reused"], "${{ steps.select.outputs.reused }}"
        )
        self.assertNotIn("if", jobs["workstation"])
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
            "needs.core.outputs.reused != 'true' && steps.export-workstation-oci.outcome == 'success'",
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
                    "steps.build.outcome == 'success'",
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
            "always() && inputs.build_installer && needs.metadata.result == 'success' && needs.workstation.result == 'success'",
        )
        self.assertNotIn("channel", caller["with"])
        installer = workflow("installer.yml")
        self.assertNotIn(
            "channel",
            installer.get("on", installer.get(True))["workflow_call"]["inputs"],
        )
        self.assertNotIn("if", containers["jobs"]["workstation"])
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
        self.assertNotIn("if", core)
        self.assertEqual(
            export["if"],
            "steps.select.outputs.reused != 'true' && steps.build.outcome == 'success'",
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
        for job in ("containers", "release"):
            self.assertIn("inputs", publish["jobs"][job]["needs"])

    def test_bypass_blocks_candidate_and_promotion_even_when_scans_succeed(self):
        jobs = workflow("publish.yml")["jobs"]
        for name in ("publish-images", "prepare-candidate", "release"):
            with self.subTest(job=name):
                self.assertIn("!inputs.security_findings_bypass", jobs[name]["if"])
        for name in ("iso", "qcow2"):
            with self.subTest(job=name):
                self.assertIn("publish-images", jobs[name]["needs"])
                self.assertIn(
                    "needs.publish-images.result == 'success'", jobs[name]["if"]
                )
        self.assertIn("iso", jobs["boot-test"]["needs"])
        self.assertIn("qcow2", jobs["boot-test"]["needs"])

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
                "fedora_version",
                "sirius_version",
                "sirius_rpm_version",
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
                    "fedora_version",
                    "sirius_version",
                    "sirius_rpm_version",
                    "build_version",
                    "workstation_image",
                    "image_namespace",
                    "target_tag",
                    "workstation_iso_image",
                )
            )
        )
        self.assertNotIn("channel", inputs)
        self.assertNotIn("workstation_digest", inputs)
        for name in (
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
            "fedora_version",
            "sirius_version",
            "sirius_rpm_version",
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
        self.assertNotIn("workstation_digest", caller["with"])
        steps = installer["jobs"]["build"]["steps"]
        fetch = next(
            step for step in steps if step.get("id") == "fetch-workstation-payload"
        )
        self.assertNotIn("if", fetch)
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
        self.assertFalse(
            any(step.get("name") == "Export installer payload" for step in steps)
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
        assert "sirius_version" in inputs
        assert "candidate_workflow" not in inputs
        assert "testing_workflow" not in inputs
        for job in ("release-evidence", "release"):
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
        evidence_commands = "\n".join(
            step.get("run", "") for step in jobs["release-evidence"]["steps"]
        )
        assert "fetch-candidate" in commands
        assert "fetch-validation" in evidence_commands
        assert "prepare-results" in evidence_commands
        assert "assemble-evidence" in evidence_commands
        assert evidence_commands.index("fetch-validation") < evidence_commands.index(
            "assemble-evidence"
        )
        assert "release-evidence" in jobs["release"]["needs"]
        assert commands.index(" promote ") < commands.index(" publish ")
        assert "--output candidate" in commands
        assert "--output dist/release-evidence.json" in evidence_commands
        assert "--candidate candidate/candidate.json" in commands
        assert "--evidence dist/release-evidence.json" in commands
        assert '--channel "$CHANNEL"' in commands
        assert "--directory dist" in commands

    def test_stable_candidates_are_built_on_their_release_line(self):
        publish = workflow("publish.yml")
        jobs = publish["jobs"]
        for legacy in ("stable-source", "stable-installer", "publish-stable-installer"):
            self.assertNotIn(legacy, jobs)
        for name in ("promote_version", "testing_run_id", "testing_validation_run_id"):
            self.assertNotIn(name, publish["on"]["workflow_dispatch"]["inputs"])
            self.assertNotIn(name, publish["on"]["workflow_call"]["inputs"])
        line = (
            "((inputs.channel == 'testing' && github.ref == 'refs/heads/main') || "
            "(inputs.channel == 'stable' && startsWith(github.ref, 'refs/heads/release/')))"
        )
        for name in ("containers", "publish-images", "prepare-candidate"):
            with self.subTest(job=name):
                self.assertIn(line, jobs[name]["if"])
                self.assertNotIn("github.ref == 'refs/heads/main' &&", jobs[name]["if"])
        self.assertIs(jobs["containers"]["with"]["build_installer"], True)
        self.assertEqual(jobs["containers"]["with"]["channel"], "${{ inputs.channel }}")
        self.assertIn(line, jobs["release-evidence"]["if"])
        steps = {step.get("id"): step for step in jobs["scan-candidates"]["steps"]}
        self.assertEqual(steps["inspect-testing"]["if"], "inputs.channel == 'testing'")
        self.assertEqual(steps["inspect-stable"]["if"], "inputs.channel == 'stable'")
        stable = steps["inspect-stable"]["run"]
        self.assertEqual(stable.count("--channel stable"), 3)
        self.assertNotIn("testing", stable)
        self.assertEqual(stable.count(" || status=1"), 3)
        self.assertTrue(stable.rstrip().endswith('exit "$status"'))
        policies = ROOT / "shared/release/exceptions"
        for name in (
            "core-core_payload-stable-45.json",
            "workstation-workstation_payload-stable-45.json",
            "workstation-installer_live-stable-45.json",
        ):
            with self.subTest(policy=name):
                digest = hashlib.sha256((policies / name).read_bytes()).hexdigest()
                self.assertIn(
                    f"--exceptions shared/release/exceptions/{name} "
                    f"--policy-sha256 {digest}",
                    stable,
                )

    def test_stable_promotion_waits_for_the_protected_environment(self):
        jobs = workflow("publish.yml")["jobs"]
        stable = jobs["release-stable"]
        self.assertEqual(stable["environment"], "stable")
        self.assertIn("inputs.channel == 'stable'", stable["if"])
        self.assertIn("startsWith(github.ref, 'refs/heads/release/')", stable["if"])
        self.assertIn("!inputs.security_findings_bypass", stable["if"])
        self.assertIn("release-evidence", stable["needs"])
        self.assertIn("inputs.channel == 'testing'", jobs["release"]["if"])
        self.assertNotIn("environment", jobs["release"])
        official = (
            "secrets.COSIGN_PRIVATE_KEY",
            "secrets.R2_ACCESS_KEY_ID",
            "secrets.R2_SECRET_ACCESS_KEY",
            "secrets.SF_",
        )
        for name, job in jobs.items():
            if any(secret in str(job) for secret in official):
                with self.subTest(job=name):
                    self.assertIn(name, ("release", "release-stable"))
        names = [step.get("name") for step in stable["steps"]]
        recheck = names.index("Recheck the summary shown before approval")
        self.assertLess(recheck, names.index("Verify and promote immutable images"))
        step = stable["steps"][recheck]
        self.assertEqual(
            step["env"]["APPROVED_SUMMARY"],
            "${{ needs.release-evidence.outputs.summary_sha256 }}",
        )
        self.assertIn('--expect-sha256 "$APPROVED_SUMMARY"', step["run"])
        evidence = jobs["release-evidence"]
        self.assertEqual(
            evidence["outputs"]["summary_sha256"],
            "${{ steps.approval.outputs.summary_sha256 }}",
        )
        shown = next(s for s in evidence["steps"] if s.get("id") == "approval")
        self.assertEqual(shown["if"], "inputs.channel == 'stable'")
        self.assertIn("approval-summary", shown["run"])
        self.assertNotIn("--expect-sha256", shown["run"])
        promote = next(
            s
            for s in stable["steps"]
            if s.get("name") == "Verify and promote immutable images"
        )
        self.assertEqual(promote["env"]["CHANNEL"], "${{ inputs.channel }}")

    def test_scheduled_preparation_reuses_publish(self):
        auto = workflow("auto-testing.yml")
        prepare = auto["jobs"]["prepare"]
        assert prepare["uses"] == "./.github/workflows/publish.yml"
        assert prepare["with"]["force_core"] is True
        assert prepare["with"]["build_sequence"] is True
        assert "concurrency" not in auto
