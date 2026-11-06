import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "publish_r2", ROOT / ".github/scripts/publish-r2.py"
)
publish_r2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish_r2)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        self.version = "testing-45.20261031"
        for fmt in ("iso", "qcow2"):
            (self.dist / f"luminusos-workstation-{self.version}.{fmt}").write_bytes(
                fmt.encode()
            )

    def test_promotion_and_prune_after_verified_downloads(self):
        calls = []
        manifests = []

        def fake(args, **kwargs):
            calls.append(args)
            if args[:3] == ["aws", "s3", "cp"] and args[4].endswith("/latest.json"):
                manifests.append(json.loads(Path(args[3]).read_text()))
            if args[:3] == ["aws", "s3", "ls"]:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=" PRE testing-45.20261030/\n PRE ../../bad/\n PRE testing-45.20261031/\n",
                )
            return subprocess.CompletedProcess(args, 0)

        def download(url):
            calls.append(["curl", url])
            return hashlib.sha256(url.rsplit(".", 1)[-1].encode()).hexdigest()

        with (
            patch.object(publish_r2.subprocess, "run", side_effect=fake),
            patch.object(publish_r2, "download_digest", side_effect=download),
        ):
            publish_r2.publish(
                "testing", self.version, self.dist, "bucket", "https://example.invalid"
            )
        removals = [call for call in calls if call[:3] == ["aws", "s3", "rm"]]
        self.assertEqual(len(removals), 1)
        self.assertEqual(removals[0][3], "s3://bucket/testing/testing-45.20261030/")
        self.assertEqual(manifests[0]["version"], self.version)
        self.assertTrue(
            manifests[0]["assets"]["iso"].startswith(
                "https://download.luminusos.org/testing/"
            )
        )
        self.assertTrue(manifests[0]["assets"]["qcow2"].endswith(".qcow2"))
        self.assertGreater(
            calls.index(removals[0]),
            max(i for i, call in enumerate(calls) if call[0] == "curl"),
        )

    def test_corrupt_download_never_updates_index_or_prunes(self):
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0)

        with (
            patch.object(publish_r2.subprocess, "run", side_effect=fake),
            patch.object(publish_r2, "download_digest", return_value="corrupt"),
            self.assertRaises(ValueError),
        ):
            publish_r2.publish(
                "testing", self.version, self.dist, "bucket", "https://example.invalid"
            )
        self.assertFalse(
            any(
                "latest.json" in " ".join(call) or call[:3] == ["aws", "s3", "rm"]
                for call in calls
            )
        )

    def test_invalid_inputs_cannot_call_aws(self):
        with patch.object(publish_r2.subprocess, "run") as run:
            for channel, version, bucket in (
                ("testing", "../bad", "bucket"),
                ("stable", "testing-45.20261031", "bucket"),
                ("testing", self.version, "../bucket"),
            ):
                with (
                    self.subTest(channel=channel, version=version, bucket=bucket),
                    self.assertRaises(ValueError),
                ):
                    publish_r2.publish(
                        channel, version, self.dist, bucket, "https://example.invalid"
                    )
            run.assert_not_called()

    def test_upload_or_download_failure_never_promotes_or_prunes(self):
        for failure in ("qcow2-upload", "download"):
            calls = []

            def fake(args, *, calls=calls, failure=failure, **kwargs):
                calls.append(args)
                if (
                    failure == "qcow2-upload"
                    and args[:3] == ["aws", "s3", "cp"]
                    and args[3].endswith(".qcow2")
                ):
                    raise subprocess.CalledProcessError(1, args)
                return subprocess.CompletedProcess(args, 0)

            def download(url, *, failure=failure):
                if failure == "download":
                    raise subprocess.CalledProcessError(22, ["curl", url])
                return hashlib.sha256(url.rsplit(".", 1)[-1].encode()).hexdigest()

            with (
                self.subTest(failure=failure),
                patch.object(publish_r2.subprocess, "run", side_effect=fake),
                patch.object(publish_r2, "download_digest", side_effect=download),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                publish_r2.publish(
                    "testing",
                    self.version,
                    self.dist,
                    "bucket",
                    "https://example.invalid",
                )
            self.assertFalse(
                any(
                    "latest.json" in " ".join(call) or call[:3] == ["aws", "s3", "rm"]
                    for call in calls
                )
            )

    def test_required_evidence_uploads_and_is_publicly_verified_before_pruning(self):
        evidence = self.dist / "image" / "sbom.spdx.json"
        evidence.parent.mkdir()
        evidence.write_text('{"packages":[]}')
        (self.dist / "image" / "provenance.json").write_text("{}")
        (self.dist / "release-evidence.json").write_text("{}")
        entries = {}
        for path in self.dist.rglob("*"):
            if path.is_file() and not path.name.endswith(".sig"):
                entries[path.relative_to(self.dist).as_posix()] = publish_r2.sha256(
                    path
                )
        (self.dist / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items()))
        )
        (self.dist / "SHA256SUMS.sig").write_text("detached")
        calls = []
        latest = []

        def fake(args, **kwargs):
            calls.append(args)
            if args[:3] == ["aws", "s3", "cp"] and args[4].endswith("latest.json"):
                latest.append(json.loads(Path(args[3]).read_text()))
            if args[:3] == ["aws", "s3", "ls"]:
                return subprocess.CompletedProcess(
                    args, 0, stdout=" PRE testing-45.20261030/\n"
                )
            return subprocess.CompletedProcess(args, 0)

        def download(url):
            calls.append(["curl", url])
            relative = url.split(f"/{self.version}/", 1)[1]
            return publish_r2.sha256(self.dist / relative)

        with (
            patch.object(publish_r2.subprocess, "run", side_effect=fake),
            patch.object(publish_r2, "download_digest", side_effect=download),
        ):
            publish_r2.publish(
                "testing",
                self.version,
                self.dist,
                "bucket",
                "https://example.invalid",
                True,
            )
        self.assertIn("image/sbom.spdx.json", latest[0]["evidence"])
        self.assertEqual(
            latest[0]["assets"]["iso"].rsplit("/", 1)[-1],
            f"luminusos-workstation-{self.version}.iso",
        )
        verify = next(call for call in calls if call[0] == "cosign")
        self.assertIn("verify-blob", verify)
        self.assertLess(
            calls.index(verify),
            next(i for i, call in enumerate(calls) if call[0:3] == ["aws", "s3", "cp"]),
        )
        self.assertGreater(
            calls.index(
                next(call for call in calls if call[:3] == ["aws", "s3", "rm"])
            ),
            max(i for i, call in enumerate(calls) if call[0] == "curl"),
        )

    def test_required_evidence_rejects_manifest_mismatch_before_upload(self):
        (self.dist / "SHA256SUMS").write_text("0" * 64 + "  unknown.json\n")
        (self.dist / "SHA256SUMS.sig").write_text("signature")
        with (
            patch.object(publish_r2.subprocess, "run") as run,
            self.assertRaises(ValueError),
        ):
            publish_r2.publish(
                "testing",
                self.version,
                self.dist,
                "bucket",
                "https://example.invalid",
                True,
            )
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
