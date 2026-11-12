import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/private-core-handoff.yml"
PRODUCER = "8dbe8cd5f9c099010c013c9155f60285ee1bd339"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


class PrivateCoreHandoffTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load(WORKFLOW.read_text())
        self.jobs = self.workflow["jobs"]
        self.reader = self.jobs["consumer"]
        self.bootstrap = self.reader["steps"][0]
        self.policy = {
            "repository": "luminusOS/images",
            "repository_id": "1118572971",
            "producer_sha": PRODUCER,
            "source_sha": "a" * 40,
            "caller_ref": "refs/heads/main",
            "caller_workflow": ".github/workflows/private-core-handoff.yml",
            "fedora": "45",
            "base_digest": "sha256:" + "b" * 64,
            "actions_sha256": hashlib.sha256(
                (
                    CHECKOUT
                    + "\nactions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6\n"
                ).encode()
            ).hexdigest(),
        }
        self.context = {
            "repository": self.policy["repository"],
            "repository_id": self.policy["repository_id"],
            "sha": self.policy["source_sha"],
            "ref": self.policy["caller_ref"],
            "workflow_ref": "luminusOS/images/"
            + self.policy["caller_workflow"]
            + "@"
            + self.policy["caller_ref"],
            "event_name": "workflow_dispatch",
            "run_id": "123",
            "run_attempt": "1",
        }

    def bootstrap_run(self, policy=None, context=None, runner="github-hosted"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            environment = Path(directory) / "environment"
            env = {
                "PATH": os.environ["PATH"],
                "CORE_HANDOFF_POLICY": json.dumps(
                    self.policy if policy is None else policy
                ),
                "CORE_HANDOFF_CONTEXT": json.dumps(
                    self.context if context is None else context
                ),
                "CORE_RUNNER_ENVIRONMENT": runner,
                "ACTION_CLOSURE": self.bootstrap["env"]["ACTION_CLOSURE"],
                "GITHUB_ENV": str(environment),
                "GITHUB_OUTPUT": str(output),
            }
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-c", self.bootstrap["run"]],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            return result, environment.read_text() if environment.exists() else ""

    def test_manual_only_and_no_source_override(self):
        self.assertEqual(
            self.workflow.get("on", self.workflow.get(True)), {"workflow_dispatch": {}}
        )
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_quality_checks_actual_source_before_producer(self):
        quality = self.jobs["quality"]
        self.assertEqual(
            quality["uses"], f"luminusOS/images/.github/workflows/ci.yml@{PRODUCER}"
        )
        self.assertEqual(quality["with"], {"checkout_ref": "${{ github.sha }}"})
        producer = self.jobs["producer"]
        self.assertEqual(producer["needs"], ["quality"])
        self.assertEqual(
            producer["uses"],
            f"luminusOS/images/.github/workflows/private-core-producer.yml@{PRODUCER}",
        )
        self.assertEqual(
            producer["with"],
            {
                "private_core_handoff": True,
                "channel": "testing",
                "publish": False,
                "build_installer": False,
            },
        )
        self.assertEqual(
            producer["permissions"],
            {
                "contents": "read",
                "actions": "read",
                "id-token": "write",
                "attestations": "write",
            },
        )
        self.assert_producer_secret_contract(self.workflow)

    def assert_producer_secret_contract(self, workflow):
        self.assertEqual(
            workflow["jobs"]["producer"].get("secrets"),
            {
                "CORE_R2_WRITER_ACCESS_KEY_ID": "${{ secrets.CORE_R2_WRITER_ACCESS_KEY_ID }}",
                "CORE_R2_WRITER_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_WRITER_SECRET_ACCESS_KEY }}",
                "CORE_R2_READER_ACCESS_KEY_ID": "${{ secrets.CORE_R2_READER_ACCESS_KEY_ID }}",
                "CORE_R2_READER_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_READER_SECRET_ACCESS_KEY }}",
            },
        )

    def test_producer_secret_contract_rejects_missing_extra_and_inherited_secrets(self):
        self.assert_producer_secret_contract(self.workflow)
        original = self.jobs["producer"]["secrets"]
        mutations = [None, "inherit", dict(original, UNEXPECTED_SECRET="value")]
        for name in original:
            missing = dict(original)
            del missing[name]
            mutations.append(missing)
            mutations.append(dict(original, **{name: "${{ secrets.OTHER_SECRET }}"}))
        for secrets in mutations:
            with self.subTest(secrets=secrets):
                mutated = copy.deepcopy(self.workflow)
                if secrets is None:
                    del mutated["jobs"]["producer"]["secrets"]
                else:
                    mutated["jobs"]["producer"]["secrets"] = secrets
                with self.assertRaises(AssertionError):
                    self.assert_producer_secret_contract(mutated)

    def assert_producer_pins(self, workflow):
        jobs = workflow["jobs"]
        self.assertEqual(
            jobs["quality"]["uses"],
            f"luminusOS/images/.github/workflows/ci.yml@{PRODUCER}",
        )
        self.assertEqual(
            jobs["producer"]["uses"],
            f"luminusOS/images/.github/workflows/private-core-producer.yml@{PRODUCER}",
        )
        steps = jobs["consumer"]["steps"]
        self.assertIn(f"producer = '{PRODUCER}'", steps[0]["run"])
        self.assertEqual(steps[1]["with"]["ref"], PRODUCER)
        self.assertEqual(
            steps[2]["run"],
            f'test "$(git -C trusted-tooling rev-parse HEAD)" = {PRODUCER}',
        )

    def test_all_producer_pins_match_and_reject_individual_pin_drift(self):
        self.assert_producer_pins(self.workflow)
        text = WORKFLOW.read_text()
        parts = text.split(PRODUCER)
        self.assertEqual(len(parts), 6)
        for index in range(5):
            with self.subTest(pin=index):
                mutated = PRODUCER.join(parts[: index + 1])
                mutated += "f6631960b38fed0f6d176175b8592145326c3bd2"
                mutated += PRODUCER.join(parts[index + 1 :])
                with self.assertRaises(AssertionError):
                    self.assert_producer_pins(yaml.safe_load(mutated))

    def test_reader_is_fresh_read_only_and_checks_only_reviewed_tooling(self):
        self.assertEqual(self.reader["needs"], ["quality", "producer"])
        self.assertEqual(self.reader["environment"], "core-candidate-reader")
        self.assertEqual(
            self.reader["permissions"], {"contents": "read", "actions": "read"}
        )
        checkouts = [s for s in self.reader["steps"] if s.get("uses") == CHECKOUT]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(
            checkouts[0]["with"],
            {
                "repository": "luminusOS/images",
                "ref": PRODUCER,
                "path": "trusted-tooling",
                "persist-credentials": False,
            },
        )
        self.assertEqual(
            self.reader["env"]["CORE_HANDOFF_POLICY"], "${{ vars.CORE_HANDOFF_POLICY }}"
        )
        self.assertNotIn("CORE_HANDOFF_JOB", self.bootstrap.get("env", {}))
        self.assertNotIn("workflow_sha", self.bootstrap["run"])

    def test_bootstrap_binds_producer_without_claiming_caller_is_producer(self):
        result, environment = self.bootstrap_run()
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(environment.removeprefix("CORE_HANDOFF_CONTEXT="))
        self.assertEqual(context["sha"], self.policy["source_sha"])
        self.assertEqual(context["producer_sha"], PRODUCER)
        self.assertEqual(
            context["producer_ref"],
            f"luminusOS/images/.github/workflows/private-core-producer.yml@{PRODUCER}",
        )

    def test_bootstrap_rejects_policy_mutations_before_checkout(self):
        mutations = {
            "producer_sha": "c" * 40,
            "source_sha": "c" * 40,
            "caller_ref": "refs/heads/unapproved",
            "caller_workflow": ".github/workflows/other.yml",
            "repository": "attacker/images",
            "repository_id": "12",
            "fedora": "44",
            "base_digest": "latest",
            "actions_sha256": "d" * 64,
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                policy = dict(self.policy, **{key: value})
                result, environment = self.bootstrap_run(policy=policy)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(environment, "")
        for policy in ({}, dict(self.policy, extra="value"), None):
            with self.subTest(policy=policy):
                result, environment = self.bootstrap_run(
                    policy={} if policy is None else policy
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(environment, "")

    def test_bootstrap_rejects_untrusted_execution_context(self):
        for key, value in {
            "sha": "c" * 40,
            "ref": "refs/heads/unapproved",
            "workflow_ref": "attacker/images/other.yml@refs/heads/main",
            "event_name": "pull_request",
            "run_id": "0",
            "run_attempt": "1\nX=y",
        }.items():
            with self.subTest(key=key):
                context = copy.deepcopy(self.context)
                context[key] = value
                result, environment = self.bootstrap_run(context=context)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(environment, "")
        result, environment = self.bootstrap_run(runner="self-hosted")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(environment, "")

    def test_reader_acquires_real_outputs_and_limits_credentials_to_command(self):
        steps = self.reader["steps"]
        credential_steps = [s for s in steps if "R2_ACCESS_KEY_ID" in s.get("env", {})]
        self.assertEqual(len(credential_steps), 1)
        acquire = credential_steps[0]
        self.assertIn("core_build_acquisition.py acquire --output", acquire["run"])
        self.assertEqual(acquire["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(
            acquire["env"]["R2_ACCESS_KEY_ID"],
            "${{ secrets.CORE_R2_READER_ACCESS_KEY_ID }}",
        )
        facts = acquire["env"]["CORE_HANDOFF_FACTS"]
        for key in (
            "archive_sha256",
            "archive_size",
            "manifest_digest",
            "object_key",
            "policy_sha256",
        ):
            output = "key" if key == "object_key" else key
            self.assertIn(
                f"toJSON(needs.producer.outputs.private_core_{output})", facts
            )
        self.assertFalse(any("R2_" in key for key in self.reader["env"]))
        self.assertIn("trap ", acquire["run"])
        for forbidden in (
            "upload-artifact",
            "actions/cache",
            "docker ",
            "podman ",
            "secrets: inherit",
            "packages: write",
            "contents: write",
        ):
            self.assertNotIn(forbidden, WORKFLOW.read_text())

    def test_reader_cleans_private_workspace_on_success_and_failure(self):
        acquire = self.reader["steps"][-1]
        for exit_code in (0, 1):
            with (
                self.subTest(exit_code=exit_code),
                tempfile.TemporaryDirectory() as root,
            ):
                directory = Path(root)
                tooling = directory / "trusted-tooling/.github/scripts/workflow"
                tooling.mkdir(parents=True)
                (tooling / "core_build_acquisition.py").write_text(
                    "import pathlib, sys\n"
                    "output = pathlib.Path(sys.argv[-1])\n"
                    "output.mkdir()\n"
                    "(output / 'core-oci.zip').write_bytes(b'private test bytes')\n"
                    f"raise SystemExit({exit_code})\n"
                )
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-e", "-c", acquire["run"]],
                    cwd=directory,
                    env={"PATH": os.environ["PATH"], "RUNNER_TEMP": root},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertFalse((directory / "private-core-consumer").exists())


if __name__ == "__main__":
    unittest.main()
