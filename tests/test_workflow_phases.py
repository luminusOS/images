import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


class WorkflowPhasesTest(unittest.TestCase):
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
