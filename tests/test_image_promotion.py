import copy
import importlib.util
import json
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

from test_release_kind import Fixture


def load(name):
    spec = importlib.util.spec_from_file_location(name, WORKFLOW / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publish = load("release_publish")
promote_images = load("promote_images")
CANDIDATE_KEY = ROOT / "shared/release/candidate.pub"
REAL_HELPER = publish.load_helper
EDITIONS = {"core": "luminusos", "workstation": "luminusos-workstation"}
FORBIDDEN = ("rsync", "ssh-keyscan", "ssh-keygen", "aws", "python3")


class FakeBase:
    """The published_base helper as the line looks at publication time."""

    EDITIONS = EDITIONS

    def __init__(self, candidate):
        self.pinned = copy.deepcopy(candidate["published_base"])
        self.resolved = copy.deepcopy(self.pinned)
        version = self.pinned["core"]["version"]
        self.newest = (version, {}, self.pinned["core"]["release_evidence_sha256"])
        self.tags = {e: b["index_digest"] for e, b in self.pinned.items()}
        self.calls = 0

    def resolve(self, repository, channel, fedora):
        self.calls += 1
        if isinstance(self.resolved, Exception):
            raise self.resolved
        return self.resolved

    def release_evidence(self, repository, channel, fedora):
        return self.newest

    def line_tag(self, channel, fedora):
        return ("testing-" if channel == "testing" else "") + fedora

    def image_repository(self, repository, edition):
        return "ghcr.io/owner/" + self.EDITIONS[edition]

    def line_digest(self, repository_ref, line):
        edition = next(
            e for e, n in self.EDITIONS.items() if repository_ref.endswith("/" + n)
        )
        return self.tags[edition]


class Publication:
    def __init__(self, test, channel="testing"):
        temp = tempfile.TemporaryDirectory()
        test.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.source = root / "candidate"
        self.source.mkdir()
        self.dist = root / "dist"
        self.candidate = Fixture(self.source).image(channel)
        (self.source / "candidate.json").write_text(json.dumps(self.candidate))
        (self.source / "candidate.json.sig").write_text("candidate signature")
        (self.dist / "evidence/installation").mkdir(parents=True)
        (self.dist / "release-evidence.json").write_text(
            json.dumps({"images": self.candidate["images"], "release_kind": "image"})
        )
        (self.dist / "release-evidence.json.sig").write_text("evidence signature")
        (self.dist / "evidence/installation/validation.json").write_text("{}")
        (self.dist / "evidence/installation/validation.json.sig").write_text("sig")
        (self.dist / "evidence/installation/base_boot.log").write_text("booted")
        self.base = FakeBase(self.candidate)
        self.promoted = []
        self.calls = []
        self.release = None
        self.draft = False
        self.events = []

    def helper(self, name):
        if name == "published_base":
            return self.base
        if name == "promote_images":
            return mock.Mock(
                promote=self.promote, public_repository=promote_images.public_repository
            )
        return REAL_HELPER(name)

    def promote(self, image, digest, destinations, *args, release_kind):
        self.events.append("promote")
        self.promoted.append((args[-1], release_kind, destinations))

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] in FORBIDDEN:
            raise AssertionError(f"image publication ran {argv}")
        if argv[:2] == ["cosign", "sign-blob"]:
            Path(argv[argv.index("--output-signature") + 1]).write_text("official")
        if argv[:2] == ["skopeo", "inspect"]:
            return mock.Mock(stdout=argv[-1].split("@", 1)[1])
        if argv[:3] == ["gh", "release", "view"]:
            if self.release is None:
                raise subprocess.CalledProcessError(1, argv, stderr="release not found")
            view = {
                "isDraft": self.draft,
                "isPrerelease": self.candidate["channel"] == "testing",
                "targetCommitish": self.candidate["source_sha"],
                "name": f"LuminusOS {self.candidate['build_version']}",
                "assets": [{"name": n} for n in self.release],
            }
            return mock.Mock(stdout=json.dumps(view))
        if argv[:3] == ["gh", "release", "download"]:
            return mock.Mock(stdout=self.release[argv[argv.index("--pattern") + 1]])
        if argv[:3] == ["gh", "release", "edit"]:
            self.events.append("edit")
            self.draft = False
            return mock.Mock(stdout="")
        if argv[:3] in (["gh", "release", "create"], ["gh", "release", "upload"]):
            self.events.append(argv[2])
            uploaded = {
                Path(a).name: Path(a).read_bytes() for a in argv if Path(a).is_file()
            }
            self.release = (self.release or {}) | {
                n: v for n, v in uploaded.items() if n in publish.RELEASE_ASSETS
            }
            self.notes = (
                Path(argv[argv.index("--notes-file") + 1]).read_text()
                if "--notes-file" in argv
                else None
            )
        return mock.Mock(stdout="")

    def publish(self):
        recheck = publish.recheck_published_base

        def tracked(candidate):
            self.events.append("recheck")
            return recheck(candidate)

        with (
            mock.patch.dict(
                publish.os.environ,
                {"GITHUB_REPOSITORY_OWNER": "owner", "COSIGN_PRIVATE_KEY": "fixture"},
            ),
            mock.patch.object(publish, "verify_release", return_value=self.candidate),
            mock.patch.object(publish, "load_helper", side_effect=self.helper),
            mock.patch.object(publish.subprocess, "run", side_effect=self.run),
            mock.patch.object(
                publish, "release_configuration", return_value={"LATEST_RELEASE": "45"}
            ),
            mock.patch.object(publish, "check_fedora_ga") as ga,
            mock.patch.object(publish, "recheck_published_base", side_effect=tracked),
            mock.patch.object(
                publish.urllib.request,
                "urlopen",
                side_effect=AssertionError("download site contacted"),
            ),
        ):
            publish.publish_image(
                self.source / "candidate.json",
                self.dist / "release-evidence.json",
                CANDIDATE_KEY,
                self.dist,
                self.candidate["channel"],
            )
            self.ga = ga

    def writes(self):
        return [e for e in self.events if e in ("promote", "create", "upload", "edit")]


class ImagePromotionTests(unittest.TestCase):
    def test_image_release_promotes_oci_tags_and_publishes_evidence_only(self):
        run = Publication(self)
        run.publish()
        self.assertEqual([r for r, _, _ in run.promoted], ["core", "workstation"])
        self.assertTrue(all(kind == "image" for _, kind, _ in run.promoted))
        tags = [tag for _, _, destinations in run.promoted for tag in destinations]
        self.assertEqual(
            tags,
            [
                "ghcr.io/owner/luminusos:testing-45.20261118.2",
                "ghcr.io/owner/luminusos:testing-45",
                "ghcr.io/owner/luminusos:testing",
                "ghcr.io/owner/luminusos-workstation:testing-45.20261118.2",
                "ghcr.io/owner/luminusos-workstation:testing-45",
                "ghcr.io/owner/luminusos-workstation:testing",
            ],
        )
        self.assertFalse(any("-iso" in tag or "installer" in tag for tag in tags))
        self.assertEqual(run.events.index("recheck"), 0)
        self.assertEqual(set(run.release), set(publish.RELEASE_ASSETS))
        create = next(c for c in run.calls if c[:3] == ["gh", "release", "create"])
        self.assertIn("--prerelease", create)
        self.assertNotIn("Downloads", run.notes)
        self.assertNotIn(".iso", run.notes)
        self.assertNotIn(".qcow2", run.notes)
        bundle = publish.bundle_content(run.release["evidence.tar.gz"])
        self.assertIn("release-evidence.json", bundle)
        self.assertIn("candidate.json", bundle)
        self.assertIn("evidence/installation/base_boot.log", bundle)
        self.assertIn("scan/core/scan-evidence.json", bundle)
        self.assertFalse(
            any(
                name.endswith((".iso", ".qcow2", ".ppm")) or name.startswith("boot/")
                for name in bundle
            )
        )
        sums = run.release["SHA256SUMS"].decode()
        self.assertIn("release-evidence.json", sums)
        self.assertNotIn(".iso", sums)
        signing = next(c for c in run.calls if c[:2] == ["cosign", "sign-blob"])
        self.assertIn("env://COSIGN_PRIVATE_KEY", signing)
        self.assertFalse(any(c[0] in FORBIDDEN for c in run.calls))
        run.ga.assert_not_called()

    def test_stale_base_fails_before_any_public_write(self):
        newer = Publication(self)
        newer.base.resolved = copy.deepcopy(newer.base.pinned)
        for item in newer.base.resolved.values():
            item["version"] = "testing-45.20261118.3"
        newer.base.newest = ("testing-45.20261118.3", {}, "e" * 64)
        moved = Publication(self)
        moved.base.resolved = ValueError("tag is not the image of the release")
        moved.base.tags["workstation"] = "sha256:" + "7" * 64
        broken = Publication(self)
        broken.base.resolved = subprocess.CalledProcessError(1, ["gh"])
        broken.base.release_evidence = mock.Mock(side_effect=ValueError("no release"))
        for run in (newer, moved, broken):
            with (
                self.subTest(run=run),
                self.assertRaisesRegex(ValueError, "stale image candidate"),
            ):
                run.publish()
            self.assertEqual(run.writes(), [])
            self.assertIsNone(run.release)

    def test_conflicting_release_fails_before_any_write(self):
        run = Publication(self)
        run.release = {"SHA256SUMS": b"other contents\n"}
        with self.assertRaisesRegex(ValueError, "already exists with other contents"):
            run.publish()
        self.assertEqual(run.writes(), [])
        self.assertEqual(run.base.calls, 0)

    def test_identical_retry_after_partial_or_complete_publication(self):
        run = Publication(self)
        run.publish()
        first = dict(run.release)
        candidate_digests = {
            e: run.candidate["images"][e].split("@", 1)[1] for e in FakeBase.EDITIONS
        }
        run.base.resolved = ValueError("line tags now serve the candidate")
        run.base.tags = dict(candidate_digests)
        run.base.newest = ("testing-45.20261118.2", {}, "f" * 64)
        run.events.clear()
        run.publish()
        self.assertEqual(run.release, first)
        self.assertNotIn("create", run.events)
        self.assertNotIn("upload", run.events)
        partial = Publication(self)
        partial.base.resolved = ValueError("line tags now serve the candidate")
        partial.base.tags = {"core": candidate_digests["core"]} | {
            "workstation": partial.base.pinned["workstation"]["index_digest"]
        }
        partial.publish()
        self.assertEqual(set(partial.release), set(publish.RELEASE_ASSETS))

    def test_retry_publishes_the_draft_an_interrupted_create_left(self):
        run = Publication(self)
        run.publish()
        complete = dict(run.release)
        run.base.resolved = ValueError("line tags now serve the candidate")
        run.base.tags = {
            e: run.candidate["images"][e].split("@", 1)[1] for e in EDITIONS
        }
        run.release = {"SHA256SUMS": complete["SHA256SUMS"]}
        run.draft = True
        run.events.clear()
        run.publish()
        self.assertEqual(run.writes(), ["promote", "promote", "upload", "edit"])
        self.assertFalse(run.draft)
        self.assertEqual(set(run.release), set(publish.RELEASE_ASSETS))
        edit = next(c for c in run.calls if c[:3] == ["gh", "release", "edit"])
        self.assertIn("--prerelease=true", edit)

    def test_draft_with_other_contents_fails_before_any_write(self):
        run = Publication(self)
        run.release = {"SHA256SUMS": b"other contents\n"}
        run.draft = True
        with self.assertRaisesRegex(ValueError, "already exists with other contents"):
            run.publish()
        self.assertEqual(run.writes(), [])

    def test_own_release_must_hold_every_line_tag(self):
        run = Publication(self)
        run.base.resolved = ValueError("line tags moved")
        run.base.newest = ("testing-45.20261118.2", {}, "f" * 64)
        with self.assertRaisesRegex(ValueError, "stale image candidate"):
            run.publish()
        self.assertEqual(run.writes(), [])

    def test_stable_rechecks_the_base_after_approval_and_before_writes(self):
        run = Publication(self, "stable")
        run.publish()
        run.ga.assert_called_once_with("45")
        self.assertEqual(run.events[0], "recheck")
        create = next(c for c in run.calls if c[:3] == ["gh", "release", "create"])
        self.assertNotIn("--prerelease", create)
        tags = [tag for _, _, destinations in run.promoted for tag in destinations]
        self.assertIn("ghcr.io/owner/luminusos:45.20261118.2", tags)
        self.assertIn("ghcr.io/owner/luminusos-workstation:latest", tags)
        self.assertFalse(any("testing" in tag for tag in tags))
        stale = Publication(self, "stable")
        stale.base.resolved = ValueError("newer stable release")
        stale.base.newest = ("45.20261119.1", {}, "e" * 64)
        with self.assertRaisesRegex(ValueError, "stale image candidate"):
            stale.publish()
        self.assertEqual(stale.writes(), [])

    def test_publish_image_refuses_full_candidates(self):
        candidate = {"release_kind": "full", "channel": "testing"}
        with (
            mock.patch.object(publish, "verify_release", return_value=candidate),
            mock.patch.object(publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "full candidates"),
        ):
            publish.publish_image(
                Path("c"), Path("e"), Path("k"), Path("dist"), "testing"
            )
        run.assert_not_called()


class FullPublicationTests(unittest.TestCase):
    def test_full_downloads_still_go_to_sourceforge_and_r2(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        candidate = Fixture(Path(temp.name)).full()
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "ssh-keygen":
                return mock.Mock(
                    stdout="256 SHA256:209BDmH3jsRyO9UeGPPgLWPSegKmYCBIya0nR/AWWCY h\n"
                )
            return mock.Mock(stdout="")

        with (
            mock.patch.dict(
                publish.os.environ, {"SF_USER": "builder", "SF_SSH_KEY": "fixture"}
            ),
            mock.patch.object(publish, "verify_release", return_value=candidate),
            mock.patch.object(publish, "release_artifacts", return_value=[]),
            mock.patch.object(publish, "verify_staged_distribution"),
            mock.patch.object(publish, "release_preflight", return_value={}),
            mock.patch.object(
                publish, "release_configuration", return_value={"LATEST_RELEASE": "45"}
            ),
            mock.patch.object(publish, "github_release") as release,
            mock.patch.object(publish.subprocess, "run", side_effect=run),
        ):
            publish.publish_downloads(Path("c"), Path("dist"), Path("k"))
        self.assertTrue(any(c[0] == "rsync" for c in calls))
        r2 = next(
            c for c in calls if c[:2] == ["python3", ".github/scripts/publish-r2.py"]
        )
        self.assertIn("--require-evidence", r2)
        release.assert_called_once()


class ReleaseJobTests(unittest.TestCase):
    def test_release_jobs_split_by_signed_kind(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())[
            "jobs"
        ]
        self.assertEqual(
            jobs["release-evidence"]["outputs"]["release_kind"],
            "${{ steps.candidate.outputs.release_kind }}",
        )
        full = "needs.release-evidence.outputs.release_kind == 'full'"
        image = "needs.release-evidence.outputs.release_kind == 'image'"
        for name, group in (("release", "testing"), ("release-stable", "stable")):
            with self.subTest(job=name):
                job = jobs[name]
                self.assertIn("release-evidence", job["needs"])
                self.assertEqual(
                    job["concurrency"]["group"],
                    f"image-publication-${{{{ github.repository }}}}-{group}",
                )
                steps = {s.get("name"): s for s in job["steps"]}
                self.assertEqual(
                    steps["Verify and promote immutable images"]["if"], full
                )
                self.assertEqual(
                    steps["Publish verified downloads and release"]["if"], full
                )
                step = steps["Promote images and publish the evidence release"]
                self.assertEqual(step["if"], image)
                self.assertEqual(
                    set(step["env"]),
                    {"GH_TOKEN", "COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD", "CHANNEL"},
                )
                self.assertNotIn("${{", step["run"])
                self.assertIn(" publish-image ", step["run"])
                self.assertIn("--directory dist", step["run"])
                names = [s.get("name") for s in job["steps"]]
                if name == "release-stable":
                    self.assertEqual(job["environment"], "stable")
                    self.assertLess(
                        names.index("Recheck the summary shown before approval"),
                        names.index(step["name"]),
                    )


class ReleaseNotesTests(unittest.TestCase):
    def test_full_notes_keep_the_download_table(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = Fixture(root)
            disk = root / "luminusos-workstation-testing-45.20261118.2.iso"
            disk.write_bytes(b"iso")
            notes = root / "notes.md"
            publish.release_notes(
                notes, fixture.full(), "testing-45.20261118.2", [disk]
            )
            self.assertIn("## Downloads", notes.read_text())
            publish.release_notes(notes, fixture.image(), "testing-45.20261118.2", [])
            self.assertNotIn("Downloads", notes.read_text())
            self.assertIn("bootc upgrade", notes.read_text())


if __name__ == "__main__":
    unittest.main()
