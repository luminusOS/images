import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / f".github/scripts/workflow/{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


chain = load("stable_chain")
detect = load("stable_detect")

REPO = "luminusOS/images"
LINES = {"45"}


def run(**overrides):
    value = {
        "id": 100,
        "path": ".github/workflows/auto-stable.yml",
        "conclusion": "success",
        "head_branch": "release/45",
        "event": "workflow_dispatch",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
    }
    value.update(overrides)
    return value


class FakeGitHub:
    def __init__(self, artifacts=("release-candidate",), newer=(), tags=()):
        self.artifacts = list(artifacts)
        self.newer = list(newer)
        self.tags = set(tags)
        self.dispatched = []
        self.superseded_query = None

    def candidate_version(self, run_id):
        return "45.20261118.1"

    def tag_exists(self, tag):
        return tag in self.tags

    def artifact_names(self, run_id):
        return self.artifacts if run_id == 100 else []

    def candidate_runs_after(self, run_id, workflow, branch):
        self.superseded_query = (workflow, branch)
        return [r for r in self.newer if r > run_id]

    def dispatch(self, workflow, inputs, ref):
        self.dispatched.append((workflow, inputs, ref))
        return 200 + len(self.dispatched) - 1


def advance(github, overrides=None, validation="success", gate="waiting"):
    return chain.advance(
        run(**(overrides or {})),
        REPO,
        LINES,
        github,
        wait_for=lambda _g, run_id, *, deadline: validation,
        wait_for_gate=lambda _g, run_id, *, deadline: gate,
    )


class StableChainTests(unittest.TestCase):
    def test_candidate_is_validated_then_stops_at_the_approval_gate(self):
        github = FakeGitHub()
        self.assertEqual(advance(github), 201)
        self.assertEqual(
            github.dispatched,
            [
                (
                    "installation-validation.yml",
                    {"candidate_run_id": "100"},
                    "release/45",
                ),
                (
                    "publish.yml",
                    {
                        "channel": "stable",
                        "candidate_run_id": "100",
                        "validation_run_id": "200",
                    },
                    "release/45",
                ),
            ],
        )
        self.assertEqual(github.superseded_query, ("auto-stable.yml", "release/45"))

    def test_untrusted_runs_and_inactive_lines_dispatch_nothing(self):
        for overrides in (
            {"conclusion": "failure"},
            {"head_branch": "main"},
            {"head_branch": "release/44"},
            {"head_branch": "release/45x"},
            {"head_branch": "release/045"},
            {"event": "schedule"},
            {"event": "pull_request"},
            {"event": "workflow_run"},
            {"head_repository": {"full_name": "fork/images"}},
            {"repository": {"full_name": "other/images"}},
            {"path": ".github/workflows/auto-testing.yml"},
        ):
            github = FakeGitHub()
            with self.subTest(overrides=overrides):
                self.assertIsNone(advance(github, overrides))
                self.assertEqual(github.dispatched, [])

    def test_runs_without_a_candidate_dispatch_nothing(self):
        github = FakeGitHub(artifacts=())
        self.assertIsNone(advance(github))
        self.assertEqual(github.dispatched, [])

    def test_released_version_is_skipped_before_and_after_validation(self):
        github = FakeGitHub(tags={"45.20261118.1"})
        self.assertIsNone(advance(github))
        self.assertEqual(github.dispatched, [])
        github = FakeGitHub(tags={"testing-45.20261118.1"})
        self.assertEqual(advance(github), 201)

        class TakenDuringValidation(FakeGitHub):
            def tag_exists(self, tag):
                return len(self.dispatched) > 0

        github = TakenDuringValidation()
        self.assertIsNone(advance(github))
        self.assertEqual(
            [w for w, _, _ in github.dispatched], ["installation-validation.yml"]
        )

    def test_failed_validation_or_superseded_candidate_never_requests_approval(self):
        github = FakeGitHub()
        with self.assertRaisesRegex(ValueError, "validation run 200"):
            advance(github, validation="failure")
        self.assertEqual(len(github.dispatched), 1)
        github = FakeGitHub(newer=[150])
        self.assertIsNone(advance(github))
        self.assertEqual(len(github.dispatched), 1)

    def test_publication_that_never_reaches_the_gate_fails(self):
        for state in ("failure", "success", "cancelled"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                advance(FakeGitHub(), gate=state)

    def test_gate_wait_stops_at_waiting_and_honours_the_deadline(self):
        states = iter(
            [
                subprocess.CalledProcessError(1, "gh"),
                {"status": "in_progress"},
                {"status": "waiting"},
            ]
        )

        class Polled:
            def run(self, run_id):
                state = next(states)
                if isinstance(state, Exception):
                    raise state
                return state

        sleeps = []
        self.assertEqual(
            chain.wait_for_approval(
                Polled(), 1, deadline=10, sleep=sleeps.append, clock=lambda: 0
            ),
            "waiting",
        )
        self.assertEqual(len(sleeps), 2)

        class Done:
            def run(self, run_id):
                return {"status": "completed", "conclusion": "failure"}

        self.assertEqual(
            chain.wait_for_approval(Done(), 1, deadline=10, clock=lambda: 0),
            "failure",
        )
        with self.assertRaisesRegex(ValueError, "approval gate"):
            chain.wait_for_approval(Done(), 1, deadline=0, clock=lambda: 1)

    def test_line_is_prepared_then_carried_to_the_gate_on_one_deadline(self):
        class Line(FakeGitHub):
            def dispatch(self, workflow, inputs, ref):
                self.dispatched.append((workflow, inputs, ref))
                if workflow == "auto-stable.yml":
                    return 100
                return 200 + len(self.dispatched)

            def run(self, run_id):
                return run(id=run_id)

        deadlines = []

        def wait_for(_g, run_id, *, deadline):
            deadlines.append(deadline)
            return "success"

        def gate(_g, run_id, *, deadline):
            deadlines.append(deadline)
            return "waiting"

        github = Line()
        clock = iter(range(0, 1000, 7))
        publication = chain.run_line(
            "45",
            LINES,
            REPO,
            github,
            77,
            wait_for=wait_for,
            wait_for_gate=gate,
            clock=lambda: next(clock),
        )
        self.assertEqual(
            [d[0] for d in github.dispatched],
            ["auto-stable.yml", "installation-validation.yml", "publish.yml"],
        )
        self.assertEqual(
            github.dispatched[0],
            ("auto-stable.yml", {"orchestrator_run_id": "77"}, "release/45"),
        )
        self.assertEqual(publication, 203)
        self.assertEqual(len(deadlines), 3)
        self.assertEqual(len(set(deadlines)), 1)

    def test_failed_or_inactive_line_never_validates(self):
        github = FakeGitHub()
        with self.assertRaisesRegex(ValueError, "not an active"):
            chain.run_line("46", LINES, REPO, github, 77)
        self.assertEqual(github.dispatched, [])
        with self.assertRaisesRegex(ValueError, "ended with failure"):
            chain.run_line(
                "45",
                LINES,
                REPO,
                github,
                77,
                wait_for=lambda _g, run_id, *, deadline: "failure",
            )
        self.assertEqual([d[0] for d in github.dispatched], ["auto-stable.yml"])

    def test_cli_lists_lines_and_runs_one_line(self):
        env = {"GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "77"}
        with (
            mock.patch.dict(chain.os.environ, env),
            mock.patch.object(chain, "run_line") as line,
            mock.patch.object(chain.sys, "stderr"),
            mock.patch("builtins.print") as printed,
        ):
            self.assertEqual(chain.main(["lines"]), 0)
            printed.assert_called_with('["45"]')
            self.assertEqual(chain.main(["line", "45"]), 0)
            self.assertEqual(line.call_args.args[0], "45")
            self.assertEqual(line.call_args.args[4], 77)
            line.side_effect = ValueError("validation run 9 ended with failure")
            self.assertEqual(chain.main(["line", "45"]), 1)
            for argv in (["line"], ["advance", "[1]"], []):
                with self.subTest(argv=argv):
                    self.assertEqual(chain.main(argv), 1)

    def test_stable_lines_come_from_the_release_config(self):
        self.assertEqual(chain.stable_lines(ROOT / "config/releases.env"), {"45"})


class DetectTests(unittest.TestCase):
    LIVE = "sha256:" + "a" * 64

    def test_changed_base_builds_and_unchanged_released_base_does_not(self):
        self.assertTrue(detect.decide(self.LIVE, "", "", False, []))
        self.assertTrue(
            detect.decide(self.LIVE, "sha256:" + "b" * 64, "45.1.1", True, [])
        )
        self.assertFalse(detect.decide(self.LIVE, self.LIVE, "45.1.1", True, []))
        self.assertTrue(detect.decide(self.LIVE, self.LIVE, "45.1.1", False, []))

    def test_nothing_is_built_while_a_stable_run_is_in_flight(self):
        self.assertFalse(detect.decide(self.LIVE, "", "", False, [7]))

    def test_invalid_live_digest_fails(self):
        for live in ("", "latest", "sha256:abc"):
            with self.subTest(live=live), self.assertRaises(ValueError):
                detect.decide(live, "", "", False, [])

    def test_only_a_missing_image_counts_as_never_built(self):
        def result(code, stdout="", stderr=""):
            return mock.Mock(returncode=code, stdout=stdout, stderr=stderr)

        labels = {
            "Labels": {
                "org.opencontainers.image.base.digest": self.LIVE,
                "org.opencontainers.image.version": "45.20261118.1",
            }
        }
        with mock.patch.object(
            detect.subprocess, "run", return_value=result(0, json.dumps(labels))
        ):
            self.assertEqual(detect.published("x"), (self.LIVE, "45.20261118.1"))
        with mock.patch.object(
            detect.subprocess, "run", return_value=result(1, stderr="manifest unknown")
        ):
            self.assertEqual(detect.published("x"), ("", ""))
        with (
            mock.patch.object(
                detect.subprocess, "run", return_value=result(1, stderr="unauthorized")
            ),
            self.assertRaises(ValueError),
        ):
            detect.published("x")

    def test_in_flight_covers_every_phase_up_to_the_approval_gate(self):
        queries = []
        ids = {
            ("publish.yml", "release/45"): [5],
            ("installation-validation.yml", "release/45"): [4],
            ("auto-stable.yml", "release/45"): [9, 6],
            ("auto-stable.yml", "main"): [8, 3],
        }

        def gh(path):
            queries.append(path)
            workflow = path.split("/")[2]
            branch = re.search(r"branch=([^&]+)", path).group(1)
            active = [
                {"id": i, "status": detect.ACTIVE[i % len(detect.ACTIVE)]}
                for i in ids[(workflow, branch)]
            ]
            done = [{"id": 1000 + len(queries), "status": "completed"}]
            return {"workflow_runs": active + done}

        with mock.patch.object(detect, "gh", side_effect=gh):
            self.assertEqual(detect.in_flight("release/45", {9, 8}), [3, 4, 5, 6])
        self.assertEqual(len(queries), len(ids))
        self.assertFalse(any("status=" in q for q in queries))

    def test_released_needs_the_exact_tag(self):
        with mock.patch.object(
            detect, "gh", return_value=[{"ref": "refs/tags/45.20261118.10"}]
        ):
            self.assertFalse(detect.released("45.20261118.1"))
        with mock.patch.object(
            detect, "gh", return_value=[{"ref": "refs/tags/45.20261118.1"}]
        ):
            self.assertTrue(detect.released("45.20261118.1"))
        self.assertFalse(detect.released(""))

    def test_lines_must_be_numbers(self):
        self.assertEqual(detect.parse_lines('STABLE_LINES="45 46"\n'), {"45", "46"})
        for config in ('STABLE_LINES="45;x"\n', "", 'STABLE_LINES="04"\n'):
            with self.subTest(config=config), self.assertRaises(ValueError):
                detect.parse_lines(config)


def workflow(name):
    text = (ROOT / ".github/workflows" / name).read_text()
    return text, yaml.load(text, Loader=yaml.BaseLoader)


class StableWorkflowTests(unittest.TestCase):
    def test_detector_dispatches_lines_from_main_and_builds_only_on_a_line(self):
        text, auto = workflow("auto-stable.yml")
        self.assertEqual(auto["name"], "Auto Stable")
        self.assertEqual(set(auto["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(auto["permissions"], {"contents": "read"})
        self.assertEqual(auto["jobs"]["lines"]["if"], "github.ref == 'refs/heads/main'")
        quality = auto["jobs"]["quality"]
        self.assertIn("startsWith(github.ref, 'refs/heads/release/')", quality["if"])
        self.assertIn("github.event_name == 'workflow_dispatch'", quality["if"])
        self.assertEqual(auto["jobs"]["check"]["needs"], ["quality"])
        prepare = auto["jobs"]["prepare"]
        self.assertEqual(prepare["uses"], "./.github/workflows/publish.yml")
        self.assertEqual(prepare["with"]["channel"], "stable")
        self.assertEqual(
            prepare["with"]["detected_base_digest"],
            "${{ needs.check.outputs.fedora_bootc_digest }}",
        )
        self.assertNotIn("security_findings_bypass", prepare["with"])
        self.assertEqual(
            set(re.findall(r"secrets\.([A-Z_]+)", text)),
            {
                "GITHUB_TOKEN",
                "CANDIDATE_COSIGN_PRIVATE_KEY",
                "CANDIDATE_COSIGN_PASSWORD",
            },
        )

    def test_main_run_carries_each_line_in_its_own_job(self):
        _, auto = workflow("auto-stable.yml")
        self.assertEqual(auto["jobs"]["lines"]["permissions"], {"contents": "read"})
        job = auto["jobs"]["line"]
        self.assertEqual(job["needs"], ["lines"])
        self.assertEqual(job["permissions"], {"actions": "write", "contents": "read"})
        self.assertNotIn("environment", job)
        self.assertEqual(job["timeout-minutes"], "360")
        self.assertEqual(job["strategy"]["fail-fast"], "false")
        self.assertEqual(
            job["strategy"]["matrix"]["line"],
            "${{ fromJSON(needs.lines.outputs.lines) }}",
        )
        self.assertEqual(job["steps"][0]["with"]["persist-credentials"], "false")
        self.assertIn('stable_chain.py line "$LINE"', job["steps"][1]["run"])
        self.assertEqual(
            auto["jobs"]["check"]["steps"][1]["env"]["ORCHESTRATOR_RUN_ID"],
            "${{ inputs.orchestrator_run_id }}",
        )
        self.assertFalse((ROOT / ".github/workflows/stable-release-chain.yml").exists())

    def test_each_channel_and_line_has_its_own_publication_group(self):
        _, publish = workflow("publish.yml")
        self.assertIn(
            "format('luminus-release-{0}-{1}-{2}', github.repository,"
            " inputs.channel, github.ref_name)",
            publish["concurrency"]["group"],
        )
        self.assertEqual(publish["concurrency"]["cancel-in-progress"], "false")

    def test_publication_does_not_require_the_official_key_from_callers(self):
        _, publish = workflow("publish.yml")
        secrets = publish["on"]["workflow_call"]["secrets"]
        self.assertEqual(secrets["COSIGN_PRIVATE_KEY"]["required"], "false")


if __name__ == "__main__":
    unittest.main()
