import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "release_pipeline",
    Path(__file__).resolve().parents[1]
    / ".github/scripts/workflow/release_pipeline.py",
)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


def sample(tmp_path):
    artifact = tmp_path / "disk.qcow2"
    artifact.write_bytes(b"disk")
    key = tmp_path / "key.pub"
    key.write_text("key")
    path = tmp_path / "candidate.json"
    document = {
        "version": 1,
        "repository": "owner/repo",
        "source_sha": "a" * 40,
        "run_id": 123,
        "channel": "testing",
        "version_tag": "testing-42",
        "build_version": "42",
        "fedora_version": "42",
        "fedora_bootc_digest": "sha256:" + "1" * 64,
        "images": {
            name: f"ghcr.io/owner/{image}@sha256:" + str(index) * 64
            for index, (name, image) in enumerate(
                (
                    ("core", "luminusos"),
                    ("workstation", "luminusos-workstation"),
                    ("installer", "luminusos-workstation"),
                ),
                1,
            )
        },
        "artifacts": {"disk.qcow2": pipeline.digest(artifact)},
    }
    path.write_text(json.dumps(document))
    (tmp_path / "candidate.json.sig").write_text("signature")
    return path, key, document


def run_document():
    return {
        "id": 123,
        "repository": {"full_name": "owner/repo"},
        "head_repository": {"full_name": "owner/repo"},
        "path": ".github/workflows/publish.yml",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
    }


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp_path = Path(self.directory.name)
        self.sample = sample(self.tmp_path)

    def test_fetch_candidate_cli_workflow_authorization(self):
        path, key, _ = self.sample
        run = run_document()
        run["path"] = ".github/workflows/auto-testing.yml"
        output = self.tmp_path / "download"
        args = [
            "release_pipeline",
            "fetch-candidate",
            "--repository",
            "owner/repo",
            "--run-id",
            "123",
            "--output",
            str(output),
            "--public-key",
            str(key),
        ]

        def download(repository, run_id, name, directory):
            self.assertEqual(
                (repository, run_id, name), ("owner/repo", 123, "release-candidate")
            )
            directory.mkdir(exist_ok=True)
            for filename in ("candidate.json", "candidate.json.sig", "disk.qcow2"):
                (directory / filename).write_bytes(
                    (path.parent / filename).read_bytes()
                )

        def command(argv, **kwargs):
            return mock.Mock(stdout=json.dumps(run) if argv[0] == "gh" else "")

        with (
            mock.patch.object(pipeline.sys, "argv", args),
            mock.patch.object(pipeline.subprocess, "run", side_effect=command),
            mock.patch.object(pipeline, "download", side_effect=download),
            mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            mock.patch.dict(pipeline.os.environ, {"GITHUB_OUTPUT": ""}),
        ):
            self.assertEqual(pipeline.main(), 0)
        for field, value, extra in (
            ("path", ".github/workflows/unknown.yml", []),
            ("head_repository", {"full_name": "fork/repo"}, []),
            (
                "path",
                ".github/workflows/auto-testing.yml",
                ["--workflow", ".github/workflows/publish.yml"],
            ),
        ):
            with self.subTest(field=field, extra=extra):
                changed = run_document()
                changed[field] = value
                run = changed
                with (
                    mock.patch.object(pipeline.sys, "argv", args + extra),
                    mock.patch.object(pipeline.subprocess, "run", side_effect=command),
                    mock.patch.object(pipeline, "download") as fetch,
                    mock.patch.object(pipeline.sys, "stderr", new_callable=io.StringIO),
                ):
                    self.assertEqual(pipeline.main(), 1)
                    fetch.assert_not_called()

    def test_record_and_assemble_cli_success_and_missing_gate(self):
        path, key, candidate = self.sample
        receipts = self.tmp_path / "receipts"
        receipts.mkdir()
        log = receipts / "install.log"
        log.write_text("trusted executor observation")
        for name in pipeline.CHECKS:
            receipt = {
                "name": name,
                "command": ["checked"],
                "exit_code": 0,
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:01:00Z",
                "log": "install.log",
                "sha256": pipeline.digest(log),
                "binding": pipeline.binding(candidate),
            }
            (receipts / f"{name}.json").write_text(json.dumps(receipt))
        validation = receipts / "validation.json"
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "b" * 40,
            "GITHUB_RUN_ID": "456",
        }

        def command(argv, **kwargs):
            if argv[:2] == ["cosign", "sign-blob"]:
                Path(argv[argv.index("--output-signature") + 1]).write_text("signature")
            return mock.Mock(stdout="")

        record = [
            "release_pipeline",
            "record-validation",
            "--candidate",
            str(path),
            "--receipts",
            str(receipts),
            "--output",
            str(validation),
            "--public-key",
            str(key),
        ]
        results = self.tmp_path / "results.json"
        evidence_log = self.tmp_path / "quality.log"
        evidence_log.write_text("trusted job result")
        gates = {
            gate: {
                "conclusion": "success",
                "binding": pipeline.binding(candidate),
                "artifact": evidence_log.name,
                "sha256": pipeline.digest(evidence_log),
            }
            for gate in pipeline.GATES
        }
        results.write_text(json.dumps(gates))
        evidence = self.tmp_path / "release" / "evidence.json"
        assemble = [
            "release_pipeline",
            "assemble-evidence",
            "--candidate",
            str(path),
            "--validation",
            str(validation),
            "--results",
            str(results),
            "--output",
            str(evidence),
            "--public-key",
            str(key),
        ]
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline.subprocess, "run", side_effect=command),
            mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            mock.patch.object(pipeline.sys, "stderr", new_callable=io.StringIO),
        ):
            with mock.patch.object(pipeline.sys, "argv", record):
                self.assertEqual(pipeline.main(), 0)
            self.assertEqual(json.loads(validation.read_text())["runner_sha"], "b" * 40)
            with mock.patch.object(pipeline.sys, "argv", assemble):
                self.assertEqual(pipeline.main(), 0)
                result = json.loads(evidence.read_text())
                self.assertEqual(result["source"]["commit"], "a" * 40)
                self.assertTrue(all(result["gates"].values()))
                self.assertTrue(
                    (
                        evidence.parent / "evidence/installation/validation.json.sig"
                    ).is_file()
                )
                evidence.unlink()
                del gates["quality"]
                results.write_text(json.dumps(gates))
                self.assertEqual(pipeline.main(), 1)
                self.assertFalse(evidence.exists())

    def test_candidate_signature_and_artifact_tampering(self):
        sample = self.sample
        path, key, document = sample
        with mock.patch.object(pipeline.subprocess, "run") as run:
            assert pipeline.candidate(path, key) == document
            assert run.call_args.args[0][:2] == ["cosign", "verify-blob"]
            (path.parent / "disk.qcow2").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                pipeline.candidate(path, key)
            run.side_effect = subprocess.CalledProcessError(1, "cosign")
            with self.assertRaises(subprocess.CalledProcessError):
                pipeline.candidate(path, key)

    def test_zip_traversal(self):
        tmp_path = self.tmp_path
        for filename in ["../escape", "/absolute", "dir/../../escape", "dir\\escape"]:
            with self.subTest(filename=filename):
                archive = tmp_path / "a.zip"
                with zipfile.ZipFile(archive, "w") as z:
                    z.writestr(filename, "data")
                with self.assertRaises(ValueError):
                    pipeline.extract_archive(archive, tmp_path / "out")

    def test_zip_symlink_and_duplicate(self):
        tmp_path = self.tmp_path
        archive = tmp_path / "a.zip"
        entry = zipfile.ZipInfo("link")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(entry, "target")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            pipeline.extract_archive(archive, tmp_path / "out")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("x", "1")
            with self.assertWarns(UserWarning):
                z.writestr("x", "2")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pipeline.extract_archive(archive, tmp_path / "out2")

    def test_zip_limits_and_disk_space(self):
        tmp_path = self.tmp_path
        archive = tmp_path / "a.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("large.qcow2", b"0" * 128)
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_FILE_BYTES": "127"}),
            self.assertRaisesRegex(ValueError, "too large"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_TOTAL_BYTES": "127"}),
            self.assertRaisesRegex(ValueError, "too large"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.object(
                pipeline.shutil, "disk_usage", return_value=mock.Mock(free=127)
            ),
            self.assertRaisesRegex(ValueError, "disk"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.dict(
                pipeline.os.environ,
                {"RELEASE_MAX_FILE_BYTES": str(pipeline.MAX_FILE + 1)},
            ),
            self.assertRaisesRegex(ValueError, "invalid"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")

    def test_download_streams_authenticated_gh_artifact(self):
        tmp_path = self.tmp_path
        archive = tmp_path / "input.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("candidate.json", "data")
        data = archive.read_bytes()
        result = mock.Mock(
            stdout=json.dumps(
                [
                    {
                        "artifacts": [
                            {
                                "name": "release-candidate",
                                "id": 10,
                                "expired": False,
                                "size_in_bytes": len(data),
                            }
                        ]
                    }
                ]
            )
        )
        process = mock.MagicMock()
        process.stdout = io.BytesIO(data)
        process.wait.return_value = 0
        process.__enter__.return_value = process
        with (
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            mock.patch.object(
                pipeline.subprocess, "Popen", return_value=process
            ) as popen,
        ):
            pipeline.download("owner/repo", 123, "release-candidate", tmp_path / "out")
        assert (tmp_path / "out/candidate.json").read_text() == "data"
        assert popen.call_args.args[0] == [
            "gh",
            "api",
            "repos/owner/repo/actions/artifacts/10/zip",
        ]
        assert popen.call_args.kwargs["stdout"] == subprocess.PIPE

    def test_download_stops_stream_exceeding_limit(self):
        tmp_path = self.tmp_path
        result = mock.Mock(
            stdout=json.dumps(
                [
                    {
                        "artifacts": [
                            {"name": "release-candidate", "id": 10, "size_in_bytes": 1}
                        ]
                    }
                ]
            )
        )
        process = mock.MagicMock()
        process.stdout = io.BytesIO(b"excessive")
        process.__enter__.return_value = process
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_TOTAL_BYTES": "4"}),
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            mock.patch.object(pipeline.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(ValueError, "archive too large"),
        ):
            pipeline.download("owner/repo", 123, "release-candidate", tmp_path / "out")
        process.kill.assert_called_once()

    def test_reject_untrusted_run(self):
        for field, value in [
            ("id", 124),
            ("repository", {"full_name": "other/repo"}),
            ("path", ".github/workflows/evil.yml"),
            ("head_branch", "feature"),
            ("conclusion", "cancelled"),
            ("event", "pull_request"),
        ]:
            with self.subTest(field=field):
                run = run_document()
                run[field] = value
                with (
                    mock.patch.object(
                        pipeline.subprocess,
                        "run",
                        return_value=mock.Mock(stdout=json.dumps(run)),
                    ),
                    self.assertRaises(ValueError),
                ):
                    pipeline.run_info(
                        "owner/repo", 123, {".github/workflows/publish.yml"}
                    )

    def test_receipts_bind_original_candidate_and_logs(self):
        sample = self.sample
        path, key, document = sample
        log = path.parent / "install.log"
        log.write_text("trusted executor observation")
        receipts = [
            {
                "name": name,
                "command": ["test-command"],
                "exit_code": 0,
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:01:00Z",
                "log": "install.log",
                "sha256": pipeline.digest(log),
                "binding": pipeline.binding(document),
            }
            for name in pipeline.CHECKS
        ]
        with mock.patch.object(pipeline.subprocess, "run"):
            assert pipeline.candidate(path, key)["source_sha"] == "a" * 40
            pipeline.validate_receipts(receipts, path.parent, document)
            receipts[0]["binding"] = dict(receipts[0]["binding"], source_run_id=124)
            with self.assertRaisesRegex(ValueError, "binding"):
                pipeline.validate_receipts(receipts, path.parent, document)
            receipts[0]["binding"] = pipeline.binding(document)
            log.write_text("tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                pipeline.validate_receipts(receipts, path.parent, document)

    def test_create_candidate_hashes_artifacts_and_signs(self):
        tmp_path = self.tmp_path
        sample = self.sample
        path, key, document = sample
        metadata = tmp_path / "metadata.input"
        metadata.write_text(
            json.dumps({k: v for k, v in document.items() if k != "artifacts"})
        )
        nested = tmp_path / "nested"
        nested.mkdir()
        (nested / "notes.txt").write_text("evidence")
        (nested / "qemu.ppm").write_bytes(b"ppm screenshot")
        (nested / "qemu.png").write_bytes(b"png screenshot")
        (nested / "ignored.bin").write_bytes(b"ignored")
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline, "sign") as sign,
        ):
            result = pipeline.create_candidate(metadata, tmp_path, path, key)
        assert result["artifacts"] == {
            "disk.qcow2": pipeline.digest(tmp_path / "disk.qcow2"),
            "nested/notes.txt": pipeline.digest(nested / "notes.txt"),
            "nested/qemu.ppm": pipeline.digest(nested / "qemu.ppm"),
            "nested/qemu.png": pipeline.digest(nested / "qemu.png"),
        }
        assert json.loads(path.read_text()) == result
        sign.assert_called_once_with(path, key)
        for filename in ("qemu.ppm", "qemu.png"):
            with self.subTest(screenshot=filename):
                screenshot = nested / filename
                original = screenshot.read_bytes()
                screenshot.write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    pipeline.validate_candidate(result, tmp_path)
                screenshot.write_bytes(original)

    def test_create_candidate_rejects_wrong_context(self):
        tmp_path = self.tmp_path
        sample = self.sample
        for field, value in [
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_REF", "refs/heads/branch"),
            ("GITHUB_SHA", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("GITHUB_RUN_ID", "124"),
        ]:
            with self.subTest(field=field):
                path, key, document = sample
                metadata = tmp_path / "metadata.input"
                metadata.write_text(
                    json.dumps({k: v for k, v in document.items() if k != "artifacts"})
                )
                env = {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "123",
                    field: value,
                }
                with (
                    mock.patch.dict(pipeline.os.environ, env),
                    mock.patch.object(pipeline, "sign") as sign,
                    self.assertRaises(ValueError),
                ):
                    pipeline.create_candidate(metadata, tmp_path, path, key)
                sign.assert_not_called()

    def test_create_candidate_rejects_symlinks(self):
        tmp_path = self.tmp_path
        sample = self.sample
        path, key, document = sample
        metadata = tmp_path / "metadata.input"
        metadata.write_text(
            json.dumps({k: v for k, v in document.items() if k != "artifacts"})
        )
        (tmp_path / "link.txt").symlink_to(tmp_path / "disk.qcow2")
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline, "sign") as sign,
            self.assertRaisesRegex(ValueError, "symlink"),
        ):
            pipeline.create_candidate(metadata, tmp_path, path, key)
        sign.assert_not_called()
