import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_publish_approval", ROOT / ".github/scripts/workflow/release_publish.py"
)
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)

NOW = datetime(2026, 11, 20, tzinfo=UTC)
BASE = "sha256:" + "b" * 64
ROLES = {
    "core": ("core", "core_payload", "1"),
    "workstation": ("workstation", "workstation_payload", "2"),
    "installer": ("workstation", "installer_live", "3"),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ApprovalSummaryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "checkout"
        self.directory = Path(temp.name) / "candidate"
        release = self.root / "shared/release"
        (release / "exceptions").mkdir(parents=True)
        self.base_risk = release / "base-trust-risk-stable.json"
        self.base_risk.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "fedora-bootc-upstream-signature-risk",
                    "repository": "quay.io/fedora/fedora-bootc",
                    "fedora_version": "45",
                    "owner": "owner",
                    "accepted_at": "2026-11-17T00:00:00Z",
                    "expires_at": "2026-12-17T00:00:00Z",
                    "reason": "unsigned upstream",
                    "mitigations": ["digest pin"],
                }
            )
        )
        self.exclusion = release / "flatpak-scan-risk-stable.json"
        self.exclusion.write_bytes(b'{"kind": "flatpak"}\n')
        exception = {
            "advisory": "CVE-2019-14899",
            "package": "linux-kernel",
            "package_version": "any",
            "classification": "accepted_risk",
            "owner": "owner",
            "expires_at": "2026-12-17T00:00:00Z",
            "issued_at": "2026-11-17T00:00:00Z",
        }
        self.candidate = {
            "repository": "owner/repo",
            "source_sha": "a" * 40,
            "run_id": 7,
            "channel": "stable",
            "version_tag": "45.20261120.1",
            "build_version": "45.20261120.1",
            "fedora_version": "45",
            "fedora_bootc_digest": BASE,
            "images": {},
            "artifacts": {},
        }
        for role, (edition, scope, digit) in ROLES.items():
            policy = release / "exceptions" / f"{edition}-{scope}-stable-45.json"
            policy.write_text(json.dumps({"scope": scope}))
            digest = "sha256:" + digit * 64
            self.candidate["images"][role] = (
                f"ghcr.io/owner/luminusos-candidates@{digest}"
            )
            scan = {
                "digest": digest.split(":", 1)[1],
                "policy_sha256": sha(policy.read_bytes()),
                "security": {
                    "gate": "success",
                    "decision": "accepted_risk" if role == "core" else "clean",
                    "policy_sha256": sha(policy.read_bytes()),
                    "scope": {
                        "edition": edition,
                        "component_scope": scope,
                        "channel": "stable",
                        "fedora": "45",
                    },
                    "exception_summary": [exception] if role == "core" else [],
                },
                "scan": {
                    "decision": "accepted_risk",
                    **(
                        {
                            "exclusions": [
                                {
                                    "path": "/var/lib/flatpak",
                                    "record_sha256": sha(self.exclusion.read_bytes()),
                                    "expires_at": "2026-12-17T00:00:00Z",
                                }
                            ]
                        }
                        if role != "core"
                        else {}
                    ),
                },
            }
            self.write_scan(role, scan)

    def write_scan(self, role, scan):
        path = self.directory / "scan" / role / "scan-evidence.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(scan))
        self.candidate["artifacts"][f"scan/{role}/scan-evidence.json"] = sha(
            path.read_bytes()
        )

    def scan(self, role):
        return json.loads(
            (self.directory / "scan" / role / "scan-evidence.json").read_text()
        )

    def summary(self, now=NOW, candidate=None):
        return publish.approval_summary(
            candidate or self.candidate, self.directory, self.root, now
        )

    def test_summary_lists_identity_policy_and_accepted_risks(self):
        summary = self.summary()
        self.assertEqual(summary["candidate"]["images"], self.candidate["images"])
        self.assertEqual(summary["candidate"]["source_sha"], "a" * 40)
        self.assertEqual(summary["candidate"]["fedora_bootc_digest"], BASE)
        self.assertEqual(summary["roles"]["core"]["decision"], "accepted_risk")
        self.assertEqual(
            summary["roles"]["core"]["exceptions"],
            [
                {
                    "advisory": "CVE-2019-14899",
                    "package": "linux-kernel",
                    "package_version": "any",
                    "classification": "accepted_risk",
                    "owner": "owner",
                    "expires_at": "2026-12-17T00:00:00Z",
                }
            ],
        )
        self.assertEqual(summary["roles"]["workstation"]["exceptions"], [])
        self.assertEqual(
            summary["roles"]["workstation"]["exclusions"][0]["path"],
            "/var/lib/flatpak",
        )
        self.assertEqual(summary["base_risk"]["expires_at"], "2026-12-17T00:00:00Z")
        later = self.summary(now=datetime(2026, 12, 1, tzinfo=UTC))
        self.assertEqual(publish.summary_digest(summary), publish.summary_digest(later))

    def test_expired_exception_exclusion_or_base_risk_blocks(self):
        for when in (
            datetime(2026, 12, 17, tzinfo=UTC),
            datetime(2027, 1, 1, tzinfo=UTC),
        ):
            with self.subTest(now=when), self.assertRaisesRegex(ValueError, "expire"):
                self.summary(now=when)
        scan = self.scan("core")
        scan["security"]["exception_summary"][0]["expires_at"] = "2026-11-19T00:00:00Z"
        self.write_scan("core", scan)
        with self.assertRaisesRegex(ValueError, "expire"):
            self.summary()

    def test_base_risk_record_must_be_in_force_and_cover_the_base(self):
        record = json.loads(self.base_risk.read_text())
        for change in (
            {
                "expires_at": "2026-11-19T00:00:00Z",
                "accepted_at": "2026-11-01T00:00:00Z",
            },
            {"fedora_version": "46"},
            {"repository": "quay.io/other/fedora-bootc"},
        ):
            self.base_risk.write_text(json.dumps(record | change))
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "base risk"),
            ):
                self.summary()

    def test_missing_base_risk_record_is_a_clean_refusal(self):
        self.base_risk.unlink()
        with self.assertRaisesRegex(ValueError, "base risk record"):
            self.summary()

    def test_policy_changed_on_the_branch_blocks(self):
        policy = (
            self.root / "shared/release/exceptions/core-core_payload-stable-45.json"
        )
        policy.write_text(json.dumps({"scope": "changed"}))
        with self.assertRaisesRegex(ValueError, "policy"):
            self.summary()

    def test_changed_exclusion_record_blocks(self):
        self.exclusion.write_bytes(b'{"kind": "changed"}\n')
        with self.assertRaisesRegex(ValueError, "exclusion"):
            self.summary()

    def test_scan_must_be_the_candidates_stable_gate(self):
        mutations = (
            ("digest", lambda s: s.update(digest="f" * 64)),
            ("gate", lambda s: s["security"].update(gate="bypassed")),
            ("channel", lambda s: s["security"]["scope"].update(channel="testing")),
            ("scope", lambda s: s["security"]["scope"].update(fedora="46")),
            ("hash", lambda s: s["security"].update(policy_sha256="0" * 64)),
        )
        for name, mutate in mutations:
            original = self.scan("installer")
            scan = copy.deepcopy(original)
            mutate(scan)
            self.write_scan("installer", scan)
            with self.subTest(name), self.assertRaises(ValueError):
                self.summary()
            self.write_scan("installer", original)
        self.summary()

    def test_unsigned_scan_evidence_or_testing_candidate_is_refused(self):
        tampered = self.scan("core")
        tampered["security"]["exception_summary"] = []
        path = self.directory / "scan/core/scan-evidence.json"
        path.write_text(json.dumps(tampered))
        with self.assertRaisesRegex(ValueError, "signed"):
            self.summary()
        with self.assertRaisesRegex(ValueError, "stable"):
            self.summary(candidate=self.candidate | {"channel": "testing"})

    def test_records_are_read_from_the_current_branch_tip(self):
        def archive(root):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as tar:
                tar.add(root / "shared/release", arcname="shared/release")
            return buffer.getvalue()

        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["git", "archive"]:
                return mock.Mock(stdout=archive(self.root))
            return mock.Mock(stdout=b"")

        with (
            mock.patch.object(publish.subprocess, "run", side_effect=run),
            publish.branch_records("refs/heads/release/45") as root,
        ):
            approved = publish.approval_summary(
                self.candidate, self.directory, root, NOW
            )
        self.assertEqual(
            calls[0],
            ["git", "fetch", "--quiet", "--depth=1", "origin", "refs/heads/release/45"],
        )
        self.assertEqual(calls[1][:3], ["git", "archive", "--format=tar"])
        self.assertEqual(calls[1][-2:], ["FETCH_HEAD", "shared/release"])
        self.assertEqual(
            publish.summary_digest(approved), publish.summary_digest(self.summary())
        )
        policy = (
            self.root / "shared/release/exceptions/core-core_payload-stable-45.json"
        )
        policy.write_text(json.dumps({"scope": "revoked"}))
        with (
            mock.patch.object(publish.subprocess, "run", side_effect=run),
            publish.branch_records("refs/heads/release/45") as root,
            self.assertRaisesRegex(ValueError, "policy"),
        ):
            publish.approval_summary(self.candidate, self.directory, root, NOW)
        for ref in ("main", "refs/heads/release/x", "refs/tags/45"):
            with (
                self.subTest(ref=ref),
                self.assertRaises(ValueError),
                publish.branch_records(ref),
            ):
                pass

    def test_cli_publishes_summary_and_refuses_a_divergent_resume(self):
        output = self.directory / "approval.json"
        step = self.directory / "step.md"
        github_output = self.directory / "github-output"

        def run(*extra):
            argv = [
                "release_publish",
                "approval-summary",
                "--candidate",
                str(self.directory / "candidate.json"),
                "--evidence",
                str(self.directory / "release-evidence.json"),
                "--public-key",
                "shared/release/candidate.pub",
                "--output",
                str(output),
                "--policy-ref",
                "refs/heads/release/45",
                *extra,
            ]
            env = {
                "GITHUB_STEP_SUMMARY": str(step),
                "GITHUB_OUTPUT": str(github_output),
            }
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(publish.os.environ, env),
                mock.patch.object(
                    publish, "verify_release", return_value=self.candidate
                ),
                mock.patch.object(
                    publish,
                    "branch_records",
                    side_effect=lambda ref: contextlib.nullcontext(self.root),
                ),
                mock.patch.object(publish, "utc_now", return_value=NOW),
                mock.patch.object(sys, "stdout", new_callable=io.StringIO),
            ):
                publish.main()

        run()
        digest = publish.summary_digest(json.loads(output.read_text()))
        self.assertIn(f"summary_sha256={digest}", github_output.read_text())
        self.assertIn("CVE-2019-14899", step.read_text())
        self.assertIn("45.20261120.1", step.read_text())
        run("--expect-sha256", digest)
        with self.assertRaisesRegex(ValueError, "summary"):
            run("--expect-sha256", "0" * 64)
        with self.assertRaisesRegex(ValueError, "no approval summary digest"):
            run("--expect-sha256", "")


if __name__ == "__main__":
    unittest.main()


class StableReleaseVerificationTests(unittest.TestCase):
    def test_stable_evidence_and_version_must_belong_to_the_release_line(self):
        evidence = {
            "images": {"workstation": "x@sha256:" + "1" * 64},
            "artifacts": {"gates/boot.json": "x"},
        }
        candidate = {
            "channel": "stable",
            "fedora_version": "45",
            "repository": "owner/repo",
            "source_sha": "a" * 40,
            "build_version": "45.20261120.1",
            **evidence,
        }
        pipeline = mock.Mock()
        pipeline.kind_binding.return_value = {}
        pipeline.release_kind.return_value = "full"
        pipeline.release_ref.side_effect = lambda channel, fedora: (
            f"refs/heads/release/{fedora}"
        )
        promotion = mock.Mock()
        promotion.validate_candidate.return_value = []

        def helper(name):
            return pipeline if name == "release_pipeline" else promotion

        for version_tag, accepted in (
            ("45.20261120.1", True),
            ("testing-45.20261120.1", False),
        ):
            pipeline.candidate.return_value = candidate | {"version_tag": version_tag}
            with (
                self.subTest(version_tag=version_tag),
                mock.patch.object(publish, "load_helper", side_effect=helper),
                mock.patch.object(publish, "sha256", return_value="x"),
                mock.patch.object(
                    publish.json, "loads", side_effect=[evidence, {"artifacts": {}}]
                ),
                mock.patch.object(Path, "read_text", return_value="{}"),
            ):
                if accepted:
                    publish.verify_release(Path("c.json"), Path("e.json"), Path("k"))
                else:
                    with self.assertRaisesRegex(ValueError, "version tag"):
                        publish.verify_release(
                            Path("c.json"), Path("e.json"), Path("k")
                        )
            self.assertEqual(
                promotion.validate_candidate.call_args.kwargs["expected_ref"],
                "refs/heads/release/45",
            )


class GitHubReleaseTests(unittest.TestCase):
    ASSETS = ("SHA256SUMS", "SHA256SUMS.sig", "evidence.tar.gz")

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.files = {}
        for name in (*self.ASSETS, "notes.md"):
            path = self.directory / name
            path.write_bytes(name.encode())
            self.files[name] = path
        source = self.directory / "evidence"
        source.mkdir()
        (source / "release-evidence.json").write_text("{}")
        publish.evidence_bundle(source, [], self.files["evidence.tar.gz"])
        self.bundle = self.files["evidence.tar.gz"].read_bytes()
        verify = mock.patch.object(publish, "verify_blob")
        verify.start()
        self.addCleanup(verify.stop)

    def gh(self, release, calls):
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ["gh", "release", "view"]:
                if release is None:
                    raise publish.subprocess.CalledProcessError(
                        1, "gh", stderr="release not found"
                    )
                view = {
                    "isDraft": release.get("draft", False),
                    "isPrerelease": release["prerelease"],
                    "targetCommitish": release.get("target", "a" * 40),
                    "name": release.get("name", "LuminusOS 45"),
                    "assets": [{"name": name} for name in release["assets"]],
                }
                return mock.Mock(stdout=json.dumps(view))
            if argv[:3] == ["gh", "release", "download"]:
                return mock.Mock(
                    stdout=release["assets"][argv[argv.index("--pattern") + 1]]
                )
            return mock.Mock(stdout="")

        return run

    def release(self, channel, release):
        calls = []
        with mock.patch.object(
            publish.subprocess, "run", side_effect=self.gh(release, calls)
        ):
            publish.github_release(
                self.files, "45.20261120.1", "a" * 40, "LuminusOS 45", channel
            )
        return calls

    def test_stable_is_a_full_release_and_testing_a_prerelease(self):
        for channel, prerelease in (("stable", False), ("testing", True)):
            with self.subTest(channel=channel):
                calls = self.release(channel, None)
                create = next(c for c in calls if c[:3] == ["gh", "release", "create"])
                self.assertEqual("--prerelease" in create, prerelease)
                self.assertIn("a" * 40, create)
                for name in self.ASSETS:
                    self.assertIn(str(self.files[name]), create)

    def test_rerun_completes_a_partial_release_without_overwriting(self):
        partial = {"prerelease": False, "assets": {"SHA256SUMS": b"SHA256SUMS"}}
        calls = self.release("stable", partial)
        self.assertFalse(any(c[:3] == ["gh", "release", "create"] for c in calls))
        upload = next(c for c in calls if c[:3] == ["gh", "release", "upload"])
        self.assertEqual(
            upload,
            [
                "gh",
                "release",
                "upload",
                "45.20261120.1",
                str(self.files["SHA256SUMS.sig"]),
                str(self.files["evidence.tar.gz"]),
            ],
        )
        complete = {
            "prerelease": False,
            "assets": {
                "SHA256SUMS": b"SHA256SUMS",
                "SHA256SUMS.sig": b"any valid signature",
                "evidence.tar.gz": self.bundle,
            },
        }
        calls = self.release("stable", complete)
        self.assertFalse(
            any(
                c[:3] in (["gh", "release", "create"], ["gh", "release", "upload"])
                for c in calls
            )
        )

    def writes(self, calls):
        return [
            c[2]
            for c in calls
            if c[:3]
            in (
                ["gh", "release", "create"],
                ["gh", "release", "upload"],
                ["gh", "release", "edit"],
            )
        ]

    def test_interrupted_create_leaves_a_draft_that_a_retry_publishes(self):
        for channel in ("stable", "testing"):
            with self.subTest(channel=channel):
                draft = {
                    "draft": True,
                    "prerelease": channel == "testing",
                    "assets": {"SHA256SUMS": b"SHA256SUMS"},
                }
                calls = self.release(channel, draft)
                self.assertEqual(self.writes(calls), ["upload", "edit"])
                edit = next(c for c in calls if c[:3] == ["gh", "release", "edit"])
                self.assertEqual(
                    edit,
                    [
                        "gh",
                        "release",
                        "edit",
                        "45.20261120.1",
                        "--draft=false",
                        f"--prerelease={str(channel == 'testing').lower()}",
                    ],
                )

    def test_complete_draft_is_published_and_published_release_left_alone(self):
        assets = {
            "SHA256SUMS": b"SHA256SUMS",
            "SHA256SUMS.sig": b"any valid signature",
            "evidence.tar.gz": self.bundle,
        }
        calls = self.release(
            "stable", {"draft": True, "prerelease": False, "assets": assets}
        )
        self.assertEqual(self.writes(calls), ["edit"])
        calls = self.release(
            "stable", {"draft": False, "prerelease": False, "assets": assets}
        )
        self.assertEqual(self.writes(calls), [])

    def test_draft_with_other_contents_or_identity_is_refused_before_writes(self):
        for draft in (
            {"draft": True, "prerelease": False, "assets": {"SHA256SUMS": b"other"}},
            {"draft": True, "prerelease": True, "assets": {}},
            {"draft": True, "prerelease": False, "assets": {"x.iso": b"x"}},
            {"draft": True, "prerelease": False, "assets": {}, "target": "b" * 40},
            {"draft": True, "prerelease": False, "assets": {}, "name": "Other"},
            {"draft": None, "prerelease": False, "assets": {}},
            {"draft": False, "prerelease": False, "assets": {}, "target": "b" * 40},
        ):
            calls = []
            with (
                self.subTest(draft=draft),
                mock.patch.object(
                    publish.subprocess, "run", side_effect=self.gh(draft, calls)
                ),
                self.assertRaisesRegex(ValueError, "already exists"),
            ):
                publish.github_release(
                    self.files, "45.20261120.1", "a" * 40, "LuminusOS 45", "stable"
                )
            self.assertEqual(self.writes(calls), [])

    def test_retry_accepts_new_valid_signatures_over_the_same_content(self):
        def bundle(signature, content="{}"):
            source = self.directory / f"bundle-{signature}"
            source.mkdir()
            (source / "release-evidence.json").write_text(content)
            (source / "release-evidence.json.sig").write_text(signature)
            target = source / "out.tar.gz"
            publish.evidence_bundle(source, [target], target)
            return target.read_bytes()

        self.files["evidence.tar.gz"].write_bytes(bundle("new"))
        self.files["SHA256SUMS.sig"].write_text("new signature")
        published = {
            "prerelease": False,
            "assets": {
                "SHA256SUMS": b"SHA256SUMS",
                "SHA256SUMS.sig": b"old signature",
                "evidence.tar.gz": bundle("old"),
            },
        }
        calls = []
        with (
            mock.patch.object(
                publish.subprocess, "run", side_effect=self.gh(published, calls)
            ),
            mock.patch.object(publish, "verify_blob") as verify,
        ):
            self.assertEqual(
                publish.check_release(self.files, "45.20261120.1", "stable"), []
            )
        self.assertEqual(verify.call_count, 2)
        changed = published | {
            "assets": published["assets"] | {"SHA256SUMS.sig": b"forged"}
        }
        with (
            mock.patch.object(
                publish.subprocess, "run", side_effect=self.gh(changed, [])
            ),
            mock.patch.object(
                publish, "verify_blob", side_effect=ValueError("bad signature")
            ),
            self.assertRaises(ValueError),
        ):
            publish.check_release(self.files, "45.20261120.1", "stable")
        self.assertEqual(
            publish.bundle_content(bundle("a")), publish.bundle_content(bundle("b"))
        )
        self.assertNotEqual(
            publish.bundle_content(bundle("c")),
            publish.bundle_content(bundle("d", '{"x": 1}')),
        )

    def test_bundle_signatures_must_all_be_present_and_valid(self):
        def bundle(names):
            source = Path(tempfile.mkdtemp(dir=self.directory))
            (source / "candidate.json").write_text("{}")
            (source / "SHA256SUMS").write_text("sums")
            for name in names:
                (source / name).write_text("sig")
            target = Path(tempfile.mkdtemp(dir=self.directory)) / "b.tar.gz"
            publish.evidence_bundle(source, [], target)
            return target

        both = ("candidate.json.sig", "SHA256SUMS.sig")
        self.files["evidence.tar.gz"] = bundle(both)
        published = {"prerelease": False, "assets": {}}

        def check(asset, verify=None):
            published["assets"] = {"evidence.tar.gz": asset.read_bytes()}
            calls = []
            with (
                mock.patch.object(
                    publish.subprocess, "run", side_effect=self.gh(published, calls)
                ),
                mock.patch.object(publish, "verify_blob", side_effect=verify) as blob,
            ):
                publish.check_release(self.files, "45.20261120.1", "stable")
            return blob

        blob = check(bundle(both))
        keys = sorted(
            (Path(call.args[0]).name, str(call.args[2])) for call in blob.call_args_list
        )
        self.assertEqual(
            keys,
            [
                ("SHA256SUMS", publish.OFFICIAL_KEY),
                ("candidate.json", publish.CANDIDATE_KEY),
            ],
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            check(bundle(("SHA256SUMS.sig",)))
        with self.assertRaisesRegex(ValueError, "already exists"):
            check(
                bundle(both),
                verify=publish.subprocess.CalledProcessError(1, "cosign"),
            )

    def test_only_a_missing_release_counts_as_absent(self):
        def failing(stderr):
            def run(argv, **kwargs):
                raise publish.subprocess.CalledProcessError(1, argv, stderr=stderr)

            return run

        with mock.patch.object(
            publish.subprocess, "run", side_effect=failing("release not found\n")
        ):
            self.assertIsNone(publish.existing_release("45.20261120.1"))
        for stderr in (
            "HTTP 401: Bad credentials",
            "error connecting to api.github.com",
        ):
            with (
                self.subTest(stderr=stderr),
                mock.patch.object(
                    publish.subprocess, "run", side_effect=failing(stderr)
                ),
                self.assertRaises(publish.subprocess.CalledProcessError),
            ):
                publish.existing_release("45.20261120.1")

    def test_conflicting_release_is_refused_before_any_write(self):
        for release in (
            {"prerelease": True, "assets": {}},
            {"prerelease": False, "assets": {"SHA256SUMS": b"other"}},
            {"prerelease": False, "assets": {"evidence.tar.gz": b"other"}},
            {"prerelease": False, "assets": {"unexpected.iso": b"x"}},
        ):
            calls = []
            with (
                self.subTest(release=release),
                mock.patch.object(
                    publish.subprocess, "run", side_effect=self.gh(release, calls)
                ),
                self.assertRaisesRegex(ValueError, "already exists"),
            ):
                publish.check_release(self.files, "45.20261120.1", "stable")
            self.assertFalse(
                any(
                    c[:3] in (["gh", "release", "create"], ["gh", "release", "upload"])
                    for c in calls
                )
            )

    def test_published_downloads_with_other_contents_are_refused(self):
        def opener(body):
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = body
            return response

        url = "https://download.luminusos.org/stable/45.20261120.1/SHA256SUMS"
        with mock.patch.object(publish.urllib.request, "urlopen") as urlopen:
            urlopen.return_value = opener(b"SHA256SUMS")
            publish.check_downloads(self.files["SHA256SUMS"], "stable", "45.20261120.1")
            request = urlopen.call_args.args[0]
            self.assertEqual(request.full_url, url)
            self.assertFalse(
                request.get_header("User-agent", "Python-urllib").startswith(
                    "Python-urllib"
                )
            )
            urlopen.return_value = opener(b"other")
            with self.assertRaisesRegex(ValueError, "already"):
                publish.check_downloads(
                    self.files["SHA256SUMS"], "stable", "45.20261120.1"
                )
            urlopen.side_effect = publish.urllib.error.HTTPError(url, 404, "", {}, None)
            publish.check_downloads(self.files["SHA256SUMS"], "stable", "45.20261120.1")
            urlopen.side_effect = publish.urllib.error.HTTPError(url, 500, "", {}, None)
            with self.assertRaises(publish.urllib.error.HTTPError):
                publish.check_downloads(
                    self.files["SHA256SUMS"], "stable", "45.20261120.1"
                )

    def test_conflicts_stop_publication_before_downloads_move(self):
        candidate = {
            "channel": "stable",
            "build_version": "45.20261120.1",
            "source_sha": "a" * 40,
        }
        for conflict in ("check_release", "check_downloads"):
            with (
                self.subTest(conflict=conflict),
                mock.patch.object(publish, "verify_release", return_value=candidate),
                mock.patch.object(publish, "release_artifacts", return_value=[]),
                mock.patch.object(publish, "verify_staged_distribution"),
                mock.patch.object(publish, "check_release"),
                mock.patch.object(publish, "check_downloads"),
                mock.patch.object(
                    publish, conflict, side_effect=ValueError("already exists")
                ),
                mock.patch.object(publish.subprocess, "run") as run,
                mock.patch.dict(
                    publish.os.environ, {"SF_USER": "user", "SF_SSH_KEY": "k"}
                ),
                self.assertRaisesRegex(ValueError, "already exists"),
            ):
                publish.publish_downloads(Path("c.json"), self.directory, Path("k"))
            run.assert_not_called()

    def test_conflicts_stop_promotion_before_image_tags_move(self):
        candidate = {
            "channel": "stable",
            "build_version": "45.20261120.1",
            "fedora_version": "45",
            "images": {},
        }
        promotion = mock.Mock()
        with (
            mock.patch.object(publish, "verify_release", return_value=candidate),
            mock.patch.object(publish, "release_artifacts", return_value=[]),
            mock.patch.object(publish, "verify_staged_distribution"),
            mock.patch.object(publish, "release_notes"),
            mock.patch.object(publish, "evidence_bundle"),
            mock.patch.object(publish, "check_downloads"),
            mock.patch.object(
                publish, "check_release", side_effect=ValueError("already exists")
            ),
            mock.patch.object(publish, "load_helper", return_value=promotion),
            mock.patch.object(publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "already exists"),
        ):
            (self.directory / "SHA256SUMS").write_text("sums")
            publish.promote(Path("c"), Path("e"), Path("k"), self.directory)
        run.assert_not_called()
        promotion.promote.assert_not_called()

    def test_evidence_bundle_is_reproducible(self):
        source = self.directory / "dist"
        (source / "scan").mkdir(parents=True)
        (source / "scan/report.json").write_text("{}")
        (source / "SHA256SUMS").write_text("sums")
        first = self.directory / "first.tar.gz"
        second = self.directory / "second.tar.gz"
        publish.evidence_bundle(source, [], first)
        (source / "scan/report.json").touch()
        publish.evidence_bundle(source, [], second)
        self.assertEqual(first.read_bytes(), second.read_bytes())


PROMOTE_SPEC = importlib.util.spec_from_file_location(
    "promote_images_approval", ROOT / ".github/scripts/workflow/promote_images.py"
)
promote_images = importlib.util.module_from_spec(PROMOTE_SPEC)
PROMOTE_SPEC.loader.exec_module(promote_images)


class ChannelDestinationTests(unittest.TestCase):
    def destinations(self, channel):
        candidate = {
            "repository": "owner/repo",
            "source_sha": "a" * 40,
            "channel": channel,
            "fedora_version": "45",
            "build_version": "45.20261120.1",
            "version_tag": ("testing-" if channel == "testing" else "")
            + "45.20261120.1",
            "images": {
                role: f"ghcr.io/owner/luminusos-candidates@sha256:{digit * 64}"
                for role, digit in (
                    ("core", "1"),
                    ("workstation", "2"),
                    ("installer", "3"),
                )
            },
        }
        seen = {}

        def record(image, digest, destinations, *args, release_kind):
            self.assertEqual(release_kind, "full")
            role = args[-1]
            seen[role] = promote_images.destination_tags(
                promote_images.public_repository(role, "owner/repo"),
                destinations,
                role,
            )

        promotion = mock.Mock(
            promote=record,
            public_repository=promote_images.public_repository,
            release_kind=lambda _: "full",
        )
        with (
            mock.patch.dict(publish.os.environ, {"GITHUB_REPOSITORY_OWNER": "owner"}),
            mock.patch.object(publish, "verify_release", return_value=candidate),
            mock.patch.object(publish, "release_artifacts"),
            mock.patch.object(publish, "verify_staged_distribution"),
            mock.patch.object(publish, "stage"),
            mock.patch.object(publish, "release_preflight"),
            mock.patch.object(publish, "check_fedora_ga"),
            mock.patch.object(
                publish, "release_configuration", return_value={"LATEST_RELEASE": "45"}
            ),
            mock.patch.object(publish, "load_helper", return_value=promotion),
            mock.patch.object(
                publish.subprocess,
                "run",
                side_effect=lambda argv, **kw: mock.Mock(
                    stdout=argv[-1].split("@", 1)[1] if argv[0] == "skopeo" else ""
                ),
            ),
        ):
            publish.promote(
                Path("c"), Path("e"), Path("k"), Path(tempfile.gettempdir())
            )
        return seen

    def test_each_channel_promotes_to_its_own_tags(self):
        self.assertEqual(
            self.destinations("stable"),
            {
                "core": ["45.20261120.1", "45", "latest"],
                "workstation": ["45.20261120.1", "45", "latest"],
                "installer": ["45.20261120.1-iso", "45-iso"],
            },
        )
        self.assertEqual(
            self.destinations("testing")["core"],
            ["testing-45.20261120.1", "testing-45", "testing"],
        )

    def test_destinations_never_mix_channels(self):
        repository = "ghcr.io/owner/luminusos"
        for tags in (
            ["testing-45.20261120.1", "45"],
            ["45.20261120.1", "testing"],
            ["45.20261120.1", "testing-45"],
            ["testing-45.20261120.1", "latest"],
            ["45.20261120.1-iso", "45"],
            ["45.20261120.1", "45.20261120.2"],
        ):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                promote_images.destination_tags(
                    repository, [f"{repository}:{tag}" for tag in tags], "core"
                )
        with self.assertRaises(ValueError):
            promote_images.destination_tags(
                "ghcr.io/owner/luminusos-workstation",
                ["ghcr.io/owner/luminusos-workstation:45.20261120.1-iso", "x:latest"],
                "installer",
            )
