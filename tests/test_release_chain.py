import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_chain", ROOT / ".github/scripts/workflow/release_chain.py"
)
chain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = chain
SPEC.loader.exec_module(chain)

REPO = "luminusOS/images"
AUTO = ".github/workflows/auto-testing.yml"


def run(**overrides):
    value = {
        "id": 100,
        "path": AUTO,
        "conclusion": "success",
        "head_branch": "main",
        "event": "schedule",
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

    def candidate_version(self, run_id):
        return "45.20261117.1"

    def tag_exists(self, tag):
        return tag in self.tags

    def artifact_names(self, run_id):
        return self.artifacts if run_id == 100 else []

    def candidate_runs_after(self, run_id):
        return [r for r in self.newer if r > run_id]

    def dispatch(self, workflow, inputs):
        self.dispatched.append((workflow, inputs))
        return 200 + len(self.dispatched) - 1


def finished(conclusion, publication="success"):
    return lambda _github, run_id, *, deadline: (
        conclusion if run_id == 200 else publication
    )


class ChainTests(unittest.TestCase):
    def test_candidate_is_validated_then_published_with_both_run_ids(self):
        github = FakeGitHub()
        waited = []

        def wait_for(_github, run_id, *, deadline):
            waited.append(run_id)
            return "success"

        publication = chain.advance(run(), REPO, github, wait_for=wait_for)
        self.assertEqual(waited, [200, 201])
        self.assertEqual(publication, 201)
        self.assertEqual(
            github.dispatched,
            [
                ("installation-validation.yml", {"candidate_run_id": "100"}),
                (
                    "publish.yml",
                    {
                        "channel": "testing",
                        "candidate_run_id": "100",
                        "validation_run_id": "200",
                    },
                ),
            ],
        )

    def test_runs_without_a_candidate_dispatch_nothing(self):
        for artifacts in ((), ("boot-test", "workstation-iso")):
            github = FakeGitHub(artifacts=artifacts)
            chain.advance(run(), REPO, github, wait_for=finished("success"))
            self.assertEqual(github.dispatched, [])

    def test_untrusted_or_failed_runs_dispatch_nothing(self):
        for overrides in (
            {"conclusion": "failure"},
            {"head_branch": "feature"},
            {"event": "pull_request"},
            {"event": "workflow_run"},
            {"head_repository": {"full_name": "fork/images"}},
            {"repository": {"full_name": "other/images"}},
            {"path": ".github/workflows/ci.yml"},
        ):
            github = FakeGitHub()
            with self.subTest(overrides=overrides):
                chain.advance(
                    run(**overrides), REPO, github, wait_for=finished("success")
                )
                self.assertEqual(github.dispatched, [])

    def test_failed_validation_never_publishes(self):
        for conclusion in ("failure", "cancelled", "timed_out", None):
            github = FakeGitHub()
            with self.subTest(conclusion=conclusion), self.assertRaises(ValueError):
                chain.advance(run(), REPO, github, wait_for=finished(conclusion))
            self.assertEqual(
                [w for w, _ in github.dispatched], ["installation-validation.yml"]
            )

    def test_superseded_candidate_is_not_published(self):
        github = FakeGitHub(newer=[150])
        self.assertIsNone(
            chain.advance(run(), REPO, github, wait_for=finished("success"))
        )
        self.assertEqual(
            [w for w, _ in github.dispatched], ["installation-validation.yml"]
        )

    def test_failed_publication_fails_the_chain(self):
        for conclusion in ("failure", "cancelled"):
            github = FakeGitHub()
            with (
                self.subTest(conclusion=conclusion),
                self.assertRaisesRegex(ValueError, "publication"),
            ):
                chain.advance(
                    run(), REPO, github, wait_for=finished("success", conclusion)
                )

    def test_validation_timeout_points_to_the_manual_resume(self):
        def late(_github, run_id, *, deadline):
            raise ValueError(f"run {run_id} did not finish in time")

        with self.assertRaisesRegex(
            ValueError, "candidate_run_id=100 -f validation_run_id=200"
        ):
            chain.advance(run(), REPO, FakeGitHub(), wait_for=late)

    def test_workflow_path_may_carry_a_ref_suffix(self):
        for path in (AUTO, f"{AUTO}@main", f"{AUTO}@refs/heads/main"):
            github = FakeGitHub()
            with self.subTest(path=path):
                chain.advance(
                    run(path=path), REPO, github, wait_for=finished("success")
                )
                self.assertEqual(len(github.dispatched), 2)
        for path in (f"fork/images/{AUTO}@main", f"{AUTO}x", f"x{AUTO}@main"):
            github = FakeGitHub()
            with self.subTest(path=path):
                chain.advance(
                    run(path=path), REPO, github, wait_for=finished("success")
                )
                self.assertEqual(github.dispatched, [])

    def test_wait_survives_transient_api_errors(self):
        error = chain.subprocess.CalledProcessError(1, ["gh"])
        answers = iter(
            [
                error,
                {"status": "in_progress"},
                error,
                {"status": "completed", "conclusion": "success"},
            ]
        )

        def fetch(_id):
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer

        clock = iter(range(0, 10000, 60)).__next__
        self.assertEqual(
            chain.wait(
                mock.Mock(run=fetch),
                7,
                deadline=1000,
                sleep=lambda _s: None,
                clock=clock,
            ),
            "success",
        )

    def test_wait_polls_until_completed_and_honours_the_deadline(self):
        states = iter(
            [
                {"status": "queued"},
                {"status": "in_progress"},
                {"status": "completed", "conclusion": "success"},
            ]
        )
        github = mock.Mock(run=lambda _id: next(states))
        sleeps = []
        clock = iter(range(0, 10000, 60)).__next__
        self.assertEqual(
            chain.wait(github, 7, deadline=1000, sleep=sleeps.append, clock=clock),
            "success",
        )
        self.assertEqual(len(sleeps), 2)
        stuck = mock.Mock(run=lambda _id: {"status": "in_progress"})
        with self.assertRaisesRegex(ValueError, "did not finish"):
            chain.wait(
                stuck,
                7,
                deadline=300,
                sleep=lambda _s: None,
                clock=iter(range(0, 10000, 60)).__next__,
            )

    def test_dispatch_asks_for_the_run_id_and_rejects_a_missing_one(self):
        github = chain.GitHub(REPO)
        response = mock.Mock(stdout='{"workflow_run_id": 44085208080}')
        with mock.patch.object(
            chain.subprocess, "run", return_value=response
        ) as execute:
            run_id = github.dispatch(
                "publish.yml", {"channel": "testing", "candidate_run_id": "1"}
            )
        self.assertEqual(run_id, 44085208080)
        argv = execute.call_args.args[0]
        self.assertEqual(
            argv[-1], f"repos/{REPO}/actions/workflows/publish.yml/dispatches"
        )
        for item in (
            "ref=main",
            "return_run_details=true",
            "inputs[channel]=testing",
            "inputs[candidate_run_id]=1",
        ):
            self.assertIn(item, argv)
        self.assertTrue(execute.call_args.kwargs["check"])
        with (
            mock.patch.object(
                chain.subprocess, "run", return_value=mock.Mock(stdout="{}")
            ),
            self.assertRaisesRegex(ValueError, "no run"),
        ):
            github.dispatch("publish.yml", {})


class VersionCollisionTests(unittest.TestCase):
    def test_candidate_whose_version_tag_exists_is_skipped_before_validation(self):
        github = FakeGitHub(tags={"testing-45.20261117.1"})
        self.assertIsNone(
            chain.advance(run(), REPO, github, wait_for=finished("success"))
        )
        self.assertEqual(github.dispatched, [])

    def test_other_versions_do_not_skip_the_candidate(self):
        github = FakeGitHub(tags={"testing-45.20261117.2", "testing-46.20261117.1"})
        self.assertEqual(
            chain.advance(run(), REPO, github, wait_for=finished("success")), 201
        )

    def test_version_taken_during_validation_skips_publication(self):
        github = FakeGitHub()
        github.tag_exists = lambda tag: bool(github.dispatched)
        self.assertIsNone(
            chain.advance(run(), REPO, github, wait_for=finished("success"))
        )
        self.assertEqual(
            [w for w, _ in github.dispatched], ["installation-validation.yml"]
        )

    def test_candidate_version_comes_from_the_scanned_image_label(self):
        github = chain.GitHub(REPO)

        def download(argv, **_kwargs):
            directory = Path(argv[argv.index("--dir") + 1])
            (directory / "core").mkdir()
            (directory / "core/vulnerabilities.json").write_text(json.dumps(scan))

        for version, expected in (
            ("45.20261117.2", "45.20261117.2"),
            ("45.20261117", None),
            ("45.20261117.2/../x", None),
            (None, None),
        ):
            labels = (
                {} if version is None else {"org.opencontainers.image.version": version}
            )
            scan = {"source": {"target": {"labels": labels}}}
            with (
                self.subTest(version=version),
                mock.patch.object(chain.subprocess, "run", side_effect=download),
            ):
                if expected:
                    self.assertEqual(github.candidate_version(100), expected)
                else:
                    with self.assertRaises(ValueError):
                        github.candidate_version(100)

    def test_missing_or_broken_scan_is_a_chain_error(self):
        github = chain.GitHub(REPO)
        for content in (None, "not json"):

            def download(argv, content=content, **_kwargs):
                if content is not None:
                    directory = Path(argv[argv.index("--dir") + 1])
                    (directory / "core").mkdir()
                    (directory / "core/vulnerabilities.json").write_text(content)

            with (
                self.subTest(content=content),
                mock.patch.object(chain.subprocess, "run", side_effect=download),
                self.assertRaisesRegex(ValueError, "candidate-scans"),
            ):
                github.candidate_version(100)

    def test_tag_check_requires_the_exact_ref(self):
        github = chain.GitHub(REPO)
        refs = [{"ref": "refs/tags/testing-45.20261117.10"}]
        github.api = lambda path, *_a: refs
        self.assertFalse(github.tag_exists("testing-45.20261117.1"))
        refs.append({"ref": "refs/tags/testing-45.20261117.1"})
        self.assertTrue(github.tag_exists("testing-45.20261117.1"))


class SupersessionTests(unittest.TestCase):
    def github(self, pages, candidates):
        github = chain.GitHub(REPO)
        calls = []

        def api(path, *_args):
            calls.append(path)
            if "/artifacts" in path:
                run_id = int(path.split("/runs/")[1].split("/")[0])
                names = ["release-candidate"] if run_id in candidates else []
                return {"artifacts": [{"name": n, "expired": False} for n in names]}
            page = int(path.rsplit("page=", 1)[1])
            workflow = path.split("/workflows/")[1].split("/")[0]
            runs = pages.get(workflow, [])
            return {
                "workflow_runs": [
                    {"id": i} for i in (runs[page - 1] if page <= len(runs) else [])
                ]
            }

        github.api = api
        return github, calls

    def test_pages_until_runs_are_older_than_the_candidate(self):
        pages = {
            "auto-testing.yml": [list(range(300, 200, -1)), [199, 150, 99]],
            "publish.yml": [[500]],
        }
        github, calls = self.github(pages, {150, 500})
        self.assertEqual(github.candidate_runs_after(100), [150])
        self.assertFalse(any("publish.yml" in c for c in calls))
        self.assertTrue(any("page=2" in c for c in calls))
        self.assertFalse(any("page=3" in c for c in calls))

    def test_older_runs_alone_mean_no_newer_candidate(self):
        github, _ = self.github({"auto-testing.yml": [[99, 50]]}, {99})
        self.assertEqual(github.candidate_runs_after(100), [])

    def test_unbounded_history_fails_closed(self):
        endless = [
            list(range(10_000 - p * 100, 9_900 - p * 100, -1)) for p in range(50)
        ]
        github, _ = self.github({"auto-testing.yml": endless}, set())
        with self.assertRaisesRegex(ValueError, "newer candidates"):
            github.candidate_runs_after(1)


class WorkflowTests(unittest.TestCase):
    def test_chain_follows_auto_testing_with_minimal_permissions(self):
        text = (ROOT / ".github/workflows/testing-release-chain.yml").read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        trigger = workflow["on"]["workflow_run"]
        self.assertEqual(trigger["workflows"], ["Auto Testing"])
        self.assertEqual(trigger["types"], ["completed"])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
        self.assertIn("workflow_run.id", workflow["concurrency"]["group"])
        job = workflow["jobs"]["advance"]
        self.assertEqual(job["permissions"], {"actions": "write", "contents": "read"})
        self.assertIn("workflow_run.conclusion == 'success'", job["if"])
        self.assertIn("head_branch == 'main'", job["if"])
        self.assertNotIn("environment", job)
        self.assertEqual(set(re.findall(r"secrets\.([A-Z_]+)", text)), {"GITHUB_TOKEN"})
        self.assertEqual(job["steps"][0]["with"]["persist-credentials"], "false")

    def test_names_match_the_chained_workflows(self):
        for path, name in (
            (".github/workflows/auto-testing.yml", "Auto Testing"),
            (
                ".github/workflows/installation-validation.yml",
                "Installation Validation",
            ),
        ):
            self.assertEqual(yaml.safe_load((ROOT / path).read_text())["name"], name)


if __name__ == "__main__":
    unittest.main()
