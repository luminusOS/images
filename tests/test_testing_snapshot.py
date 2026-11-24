import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / ".github/scripts/workflow")
)

import testing_snapshot as snapshot


class TestingSnapshotTests(unittest.TestCase):
    def test_verify_cli_retrieves_both_run_records_and_rejects_another_repository_id(
        self,
    ):
        repo = {"id": snapshot.REPOSITORY_ID, "full_name": snapshot.REPOSITORY}
        run = {
            "repository": repo,
            "head_repository": repo,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "head_sha": "a" * 40,
        }
        runs = {
            123: run | {"id": 123, "path": snapshot.WORKFLOW},
            789: run | {"id": 789, "path": snapshot.VALIDATION_WORKFLOW},
        }

        def github(command, **kwargs):
            run_id = int(command[-1].rsplit("/", 1)[1])
            self.assertEqual(
                command,
                ["gh", "api", f"repos/{snapshot.REPOSITORY}/actions/runs/{run_id}"],
            )
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps(runs[run_id])
            )

        argv = [
            "testing_snapshot.py",
            "verify-feature-boot",
            "123",
            "789",
            "candidate",
            "snapshot",
            "feature-boot.json",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch.object(snapshot.pipeline.subprocess, "run", side_effect=github),
            patch.object(
                snapshot.pipeline, "verify", side_effect=ValueError("unsigned fixture")
            ) as signature,
            patch.object(snapshot, "read_candidate"),
            tempfile.TemporaryDirectory() as directory,
        ):
            statement = Path(directory) / "feature-boot.json"
            statement.touch()
            argv[-1] = str(statement)
            runs[789] = runs[789] | {"head_repository": repo | {"id": 1}}
            with self.assertRaisesRegex(ValueError, "canonical isolated main dispatch"):
                snapshot.main()
            signature.assert_not_called()
            runs[789] = runs[789] | {"head_repository": repo}
            with self.assertRaisesRegex(ValueError, "unsigned fixture"):
                snapshot.main()
            signature.assert_called_once_with(
                statement, snapshot.pipeline.CANDIDATE_PUBLIC_KEY
            )

    def test_records_only_validated_guest_observations_and_pins_both_attempts(self):
        version = "45.20261118.2"
        manifest, raw = "sha256:" + "a" * 64, "b" * 64
        candidate = {
            "run_id": 123,
            "source_sha": "c" * 40,
            "build_version": version,
            "images": {
                "workstation": "ghcr.io/luminusos/luminusos-candidates@sha256:"
                + "d" * 64
            },
        }
        observation = {
            "before_boot_id": "00000000-0000-0000-0000-000000000001",
            "after_boot_id": "00000000-0000-0000-0000-000000000002",
            "platform_manifest_digest": manifest,
            "raw_sha256": raw,
            "fetched": [
                f"/{version}/release.json.gpg",
                f"/{version}/luminusos-dummy_{version}.raw.xz",
            ],
            "discovered_features": ["dummy"],
            "selinux": "Enforcing",
            "service": "active",
            "merge": "provisioned",
        }
        environment = {
            "GITHUB_RUN_ID": "789",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_WORKFLOW_SHA": "a" * 40,
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, environment),
            patch.object(snapshot, "read_candidate", return_value=candidate),
            patch.object(snapshot, "verify", return_value=manifest),
            patch.object(snapshot.pipeline, "sign") as sign,
        ):
            root = Path(directory)
            observations = root / "diagnostics/feature-observation.json"
            observations.parent.mkdir()
            (root / "release.json").write_text(
                json.dumps({"features": {"dummy": {"raw_sha256": raw}}})
            )
            key = "candidates/123/2/snapshot.tar"
            observations.write_text(json.dumps(observation | {"selinux": "Permissive"}))
            with self.assertRaises(ValueError):
                snapshot.record(root, root, root, key)
            sign.assert_not_called()
            observations.write_text(json.dumps(observation))
            statement = snapshot.record(root, root, root, key)
            sign.assert_called_once_with(
                statement, snapshot.pipeline.CANDIDATE_PUBLIC_KEY, tlog_upload=False
            )
            receipt = json.loads(statement.read_text())
            self.assertEqual(receipt["candidate"]["run_attempt"], 2)
            self.assertEqual(receipt["validator"]["run_attempt"], 3)
            self.assertEqual(receipt["observations"], observation)
            self.assertEqual(
                receipt["scope"], "isolated-testing; not promotion evidence"
            )
            repo = {"id": snapshot.REPOSITORY_ID, "full_name": snapshot.REPOSITORY}
            run = {
                "repository": repo,
                "head_repository": repo,
                "head_branch": "main",
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
            }
            producer = run | {
                "id": 123,
                "run_attempt": 2,
                "path": snapshot.WORKFLOW,
                "head_sha": "c" * 40,
            }
            validator = run | {
                "id": 789,
                "run_attempt": 3,
                "path": ".github/workflows/installation-validation.yml",
                "head_sha": "a" * 40,
            }
            with patch.object(snapshot.pipeline, "verify"):
                snapshot.verify_receipt(statement, root, root, producer, validator)
                for mismatch in (
                    {"run_attempt": 4},
                    {"head_sha": "b" * 40},
                    {"event": "schedule"},
                    {"head_branch": "release/45"},
                    {"path": snapshot.WORKFLOW},
                    {"conclusion": "failure"},
                ):
                    with self.subTest(mismatch=mismatch), self.assertRaises(ValueError):
                        snapshot.verify_receipt(
                            statement, root, root, producer, validator | mismatch
                        )
                with self.assertRaises(ValueError):
                    snapshot.verify_receipt(
                        statement, root, root, producer | {"run_attempt": 3}, validator
                    )
                (root / "release.json").write_text(
                    (root / "release.json").read_text() + "\n"
                )
                with self.assertRaises(ValueError):
                    snapshot.verify_receipt(statement, root, root, producer, validator)

    def test_isolated_reader_pins_a_key_outside_the_shared_image_overlay(self):
        self.assertNotEqual(snapshot.STAGING_KEYRING, snapshot.feature.SNAPSHOT_KEYRING)
        self.assertGreater(snapshot.STAGING_KEYRING.stat().st_size, 0)
        self.assertNotIn("files", snapshot.STAGING_KEYRING.parts)

    def test_only_complete_verified_download_is_exposed_to_boot_job(self):
        version = "45.20261118.2"
        key = "candidates/123/2/snapshot.tar"
        for case in ("signed", "truncated", "bad-signature"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "boot-input"

                def download(
                    operation,
                    requested_key,
                    flag,
                    byte_range,
                    output_path,
                    *,
                    case=case,
                ):
                    self.assertEqual((operation, requested_key), ("get-object", key))
                    self.assertEqual(
                        (flag, byte_range),
                        ("--range", f"bytes=0-{snapshot.MAX_ARCHIVE}"),
                    )
                    with tarfile.open(output_path, "w") as archive:
                        for name in snapshot.members(version):
                            member = tarfile.TarInfo(name)
                            member.size = 1
                            archive.addfile(member, io.BytesIO(b"x"))
                    size = Path(output_path).stat().st_size
                    total = size + 1 if case == "truncated" else size
                    return json.dumps({"ContentRange": f"bytes 0-{size - 1}/{total}"})

                with (
                    patch.object(
                        snapshot,
                        "read_candidate",
                        return_value={"build_version": version},
                    ),
                    patch.object(snapshot, "aws", side_effect=download),
                    patch.object(
                        snapshot,
                        "verify",
                        side_effect=ValueError("bad signature")
                        if case == "bad-signature"
                        else None,
                    ),
                ):
                    if case == "signed":
                        snapshot.download(root / "candidate", output, key)
                        self.assertEqual(
                            {path.name for path in output.iterdir()},
                            set(snapshot.members(version)),
                        )
                    else:
                        with self.assertRaises(ValueError):
                            snapshot.download(root / "candidate", output, key)
                        self.assertFalse(output.exists())

    def test_only_isolated_manual_main_run_can_supply_snapshot(self):
        run = {
            "id": 123,
            "run_attempt": 2,
            "repository": {"full_name": "luminusOS/images", "id": 1118572971},
            "head_repository": {"full_name": "luminusOS/images", "id": 1118572971},
            "path": ".github/workflows/testing-feature-candidate.yml",
            "head_branch": "main",
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
        }
        self.assertEqual(snapshot.snapshot_key(run), "candidates/123/2/snapshot.tar")
        for field, value in (
            ("run_attempt", True),
            ("event", "schedule"),
            ("head_branch", "release/45"),
            ("path", ".github/workflows/auto-testing.yml"),
            ("conclusion", "failure"),
            ("head_repository", {"full_name": "fork/images", "id": 2}),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                snapshot.snapshot_key(run | {field: value})
        with self.assertRaisesRegex(ValueError, "untrusted workflow"):
            snapshot.pipeline.authorize_run(
                run, "luminusOS/images", 123, snapshot.pipeline.PRODUCER_WORKFLOWS
            )

    def test_only_exact_regular_snapshot_members_are_extracted(self):
        cases = ("valid", "traversal", "duplicate", "link", "oversized", "missing")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "snapshot.tar"
                names = sorted(snapshot.members("45.20261118.2"))
                selected = names[:-1] if case == "missing" else names
                if case in {"traversal", "duplicate"}:
                    selected = selected + [
                        "../outside" if case == "traversal" else names[0]
                    ]
                with tarfile.open(archive, "w") as stream:
                    for position, name in enumerate(selected):
                        entry = tarfile.TarInfo(name)
                        entry.size = 1
                        if position == 0 and case == "link":
                            entry.type = tarfile.SYMTYPE
                            entry.linkname = "../outside"
                            entry.size = 0
                        stream.addfile(entry, io.BytesIO(b"x"))
                output = root / "private"
                if case == "oversized":
                    with archive.open("ab") as stream:
                        stream.truncate(snapshot.MAX_ARCHIVE + 1)
                if case == "valid":
                    snapshot.extract(archive, output, "45.20261118.2")
                    self.assertEqual({p.name for p in output.iterdir()}, set(names))
                    self.assertTrue(
                        all(p.read_bytes() == b"x" for p in output.iterdir())
                    )
                else:
                    with self.assertRaises(ValueError):
                        snapshot.extract(archive, output, "45.20261118.2")
                    self.assertFalse(output.exists())
