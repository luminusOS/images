import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from test_release_pipeline import core_oci_sample

MODULE = (
    Path(__file__).resolve().parents[1]
    / ".github/scripts/workflow/core_build_acquisition.py"
)
if MODULE.exists():
    spec = importlib.util.spec_from_file_location("core_build_acquisition", MODULE)
    acquisition = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acquisition)
else:
    acquisition = None

BASE = "repos/luminusOS/images/actions/"
SOURCE = "a" * 40
JOB_NAME = "Validate image builds / Build core image"


class Fixture:
    def __init__(self):
        self.calls = []
        self.counts = {}
        self.after = {}
        self.files, self.digest = core_oci_sample()
        repo = {"id": 1118572971, "full_name": "luminusOS/images"}
        self.run = {
            "id": 12,
            "run_attempt": 1,
            "head_sha": SOURCE,
            "head_branch": "pr-branch",
            "path": ".github/workflows/build-containers.yml",
            "repository": repo,
            "head_repository": repo.copy(),
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request",
        }
        self.steps = [
            {
                "number": n,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": f"2026-11-11T20:10:{n * 10:02}Z",
                "completed_at": f"2026-11-11T20:10:{n * 10 + 5:02}Z",
            }
            for n, name in enumerate(
                (
                    "Build core",
                    "Export built core OCI layout",
                    "Upload built core OCI layout",
                ),
                1,
            )
        ]
        self.job = {
            "id": 90,
            "run_id": 12,
            "run_attempt": 1,
            "head_sha": SOURCE,
            "name": JOB_NAME,
            "status": "completed",
            "conclusion": "success",
            "steps": self.steps,
        }
        self.pages = [{"total_count": 1, "jobs": [self.job]}]
        self.artifact = {
            "id": 10,
            "name": "core-oci",
            "expired": False,
            "expires_at": "2099-01-01T00:00:00Z",
            "workflow_run": {
                "id": 12,
                "repository_id": 1118572971,
                "head_repository_id": 1118572971,
                "head_sha": SOURCE,
                "head_branch": "pr-branch",
            },
        }
        self.export = (
            "\ufeff2026-11-11T20:10:20.1Z ##[group]Run export\n"
            "2026-11-11T20:10:20.2Z \x1b[36;1mexport command\x1b[0m\n"
            "2026-11-11T20:10:20.3Z ##[endgroup]\n"
            "2026-11-11T20:10:21.1Z "
            + json.dumps(
                {
                    "manifest_digest": self.digest,
                    "skopeo_version": "skopeo version 1.21.0-dev",
                }
            )
            + "\n"
        ).encode()
        self.repack()

    def repack(self, entries=None):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, raw in self.files.items() if entries is None else entries:
                archive.writestr(name, raw)
        self.archive = stream.getvalue()
        self.artifact.update(
            size_in_bytes=len(self.archive),
            digest="sha256:" + hashlib.sha256(self.archive).hexdigest(),
        )
        self.upload = (
            "\ufeff2026-11-11T20:10:31.1Z SHA256 digest of uploaded artifact zip is "
            + self.artifact["digest"][7:]
            + "\n"
            "2026-11-11T20:10:31.2Z Artifact core-oci successfully finalized. Artifact ID 10\n"
            f"2026-11-11T20:10:32.1Z Artifact core-oci has been successfully uploaded! Final size is {len(self.archive)} bytes. Artifact ID is 10\n"
        ).encode()

    def stream(self, endpoint, limit, deadline):
        self.calls.append(endpoint)
        self.counts[endpoint] = self.counts.get(endpoint, 0) + 1
        if self.counts[endpoint] > 1 and endpoint in self.after:
            value = self.after[endpoint]
        elif endpoint == BASE + "runs/12":
            value = self.run
        elif endpoint.startswith(BASE + "runs/12/attempts/1/jobs?per_page=100&page="):
            page = int(endpoint.rsplit("=", 1)[1])
            value = (
                self.pages[page - 1]
                if page <= len(self.pages)
                else {"total_count": 1, "jobs": []}
            )
        elif endpoint == BASE + "artifacts/10":
            value = self.artifact
        elif endpoint == BASE + "artifacts/10/zip":
            value = self.archive
        elif endpoint == BASE + f"jobs/90/steps/{self.steps[1]['number']}/logs":
            value = self.export
        elif endpoint == BASE + f"jobs/90/steps/{self.steps[2]['number']}/logs":
            value = self.upload
        else:
            raise AssertionError("unexpected endpoint: " + endpoint)
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        for offset in range(0, len(raw), 127):
            yield raw[offset : offset + 127]


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / "acquired"
        self.fixture = Fixture()
        self.failure_index = 0

    def acquire(self, **pins):
        self.assertIsNotNone(
            acquisition, "local acquisition adapter is not implemented"
        )
        policy = acquisition.Policy(
            **(
                {
                    "run_id": 12,
                    "run_attempt": 1,
                    "job_id": 90,
                    "source_sha": SOURCE,
                    "artifact_id": 10,
                    "workflow": ".github/workflows/build-containers.yml",
                    "job_name": JOB_NAME,
                }
                | pins
            )
        )
        return acquisition.acquire(policy, self.output, transport=self.fixture)

    def rejected(self):
        with self.assertRaises((ValueError, OSError, TimeoutError, zipfile.BadZipFile)):
            self.acquire()
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            self.assertFalse((self.output / "core-build.json").exists())
            self.assertFalse((self.output / "acquisition.json").exists())
        self.failure_index += 1
        self.output = Path(self.tmp.name) / f"failure-{self.failure_index}"

    def test_small_actual_oci_archive_passes_without_authority(self):
        result = self.acquire()
        self.assertEqual(result["kind"], "local-core-acquisition")
        self.assertEqual(result["core_digest"], self.fixture.digest)
        self.assertTrue(result["archive_bytes_verified"])
        for flag in (
            "production_ready",
            "observations_authenticated",
            "runtime_verified",
        ):
            self.assertIs(result[flag], False)
        self.assertEqual(
            result["step_logs"][0]["raw_sha256"],
            hashlib.sha256(self.fixture.export).hexdigest(),
        )
        self.assertTrue((self.output / "layout/index.json").is_file())
        self.assertFalse((self.output / "core-build.json").exists())

    def test_exact_metadata_identity_types_and_step_success(self):
        mutations = [
            ("run", "id", 13),
            ("run", "run_attempt", True),
            ("run", "head_sha", "b" * 40),
            ("run", "path", ".github/workflows/other.yml"),
            ("run", "conclusion", "failure"),
            ("job", "id", True),
            ("job", "run_id", 13),
            ("job", "run_attempt", 2),
            ("job", "head_sha", "b" * 40),
            ("job", "name", "Other job"),
            ("job", "status", "in_progress"),
            ("artifact", "id", True),
            ("artifact", "name", "core-image"),
            ("artifact", "expired", True),
            ("artifact", "expired", 0),
            ("artifact", "expires_at", "2000-01-01T00:00:00Z"),
            ("artifact", "size_in_bytes", True),
            ("artifact", "digest", "sha256:" + "A" * 64),
        ]
        for target, key, value in mutations:
            with self.subTest(target=target, key=key):
                self.fixture = Fixture()
                getattr(self.fixture, target)[key] = value
                self.rejected()
        for field in ("repository", "head_repository"):
            for key, value in [("id", True), ("full_name", "attacker/images")]:
                self.fixture = Fixture()
                self.fixture.run[field][key] = value
                self.rejected()
        for key, value in [
            ("id", 13),
            ("repository_id", 1),
            ("head_repository_id", True),
            ("head_sha", "b" * 40),
            ("head_branch", "other"),
        ]:
            self.fixture = Fixture()
            self.fixture.artifact["workflow_run"][key] = value
            self.rejected()
        for key, value in [
            ("number", True),
            ("name", "other"),
            ("conclusion", "skipped"),
            ("completed_at", "not-a-time"),
        ]:
            self.fixture = Fixture()
            self.fixture.steps[1][key] = value
            self.rejected()

    def test_policy_cannot_enable_authority_or_inject_endpoint(self):
        for pins in (
            {"run_id": True},
            {"artifact_id": "../other"},
            {"job_id": 91},
            {"source_sha": "x"},
            {"workflow": "https://evil.invalid"},
            {"run_attempt": 2},
        ):
            with (
                self.subTest(pins=pins),
                self.assertRaises((ValueError, AssertionError)),
            ):
                self.acquire(**pins)
            self.failure_index += 1
            self.output = Path(self.tmp.name) / f"failure-{self.failure_index}"
        with self.assertRaises(TypeError):
            self.acquire(production_ready=True)

    def test_pagination_rejects_duplicates_ambiguity_and_incomplete_pages(self):
        for kind in ("duplicate", "ambiguous", "missing", "steps", "count"):
            self.fixture = Fixture()
            if kind in ("duplicate", "ambiguous"):
                other = copy.deepcopy(self.fixture.job)
                if kind == "ambiguous":
                    other["id"] += 1
                self.fixture.pages[0] = {
                    "total_count": 2,
                    "jobs": [self.fixture.job, other],
                }
            elif kind == "missing":
                self.fixture.pages[0]["total_count"] = 101
            elif kind == "steps":
                self.fixture.steps.append(copy.deepcopy(self.fixture.steps[-1]))
            else:
                self.fixture.pages[0]["total_count"] = True
            with self.subTest(kind=kind):
                self.rejected()

    def test_complete_pagination_and_metadata_refresh(self):
        others = [
            dict(self.fixture.job, id=100 + n, name=f"other {n}") for n in range(100)
        ]
        self.fixture.pages = [
            {"total_count": 101, "jobs": others},
            {"total_count": 101, "jobs": [self.fixture.job]},
        ]
        self.acquire()
        self.assertEqual(
            self.fixture.calls.count(
                BASE + "runs/12/attempts/1/jobs?per_page=100&page=2"
            ),
            2,
        )

    def test_step_numbers_are_selected_from_api_not_fixture_constants(self):
        for step, number in zip(self.fixture.steps, (9, 10, 11), strict=True):
            step["number"] = number
        result = self.acquire()
        self.assertEqual([item["number"] for item in result["step_logs"]], [10, 11])
        self.assertIn(BASE + "jobs/90/steps/11/logs", self.fixture.calls)

    def test_default_acquisition_uses_its_own_transport(self):
        with mock.patch.object(
            acquisition, "GhTransport", return_value=self.fixture
        ) as transport:
            policy = acquisition.Policy(
                12,
                1,
                90,
                SOURCE,
                10,
                ".github/workflows/build-containers.yml",
                JOB_NAME,
            )
            result = acquisition.acquire(policy, self.output)
        transport.assert_called_once_with()
        self.assertFalse(result["observations_authenticated"])

    def test_pagination_total_cannot_change_and_duplicate_ids_cross_pages_fail(self):
        for total, identity in [(102, 90), (101, 100)]:
            self.fixture = Fixture()
            others = [
                dict(self.fixture.job, id=100 + n, name=f"other {n}")
                for n in range(100)
            ]
            selected = dict(self.fixture.job, id=identity)
            self.fixture.pages = [
                {"total_count": 101, "jobs": others},
                {"total_count": total, "jobs": [selected]},
            ]
            self.rejected()

    def test_after_job_steps_cannot_change(self):
        changed = copy.deepcopy(self.fixture.pages[0])
        changed["jobs"][0]["steps"][2]["number"] = 4
        self.fixture.after[BASE + "runs/12/attempts/1/jobs?per_page=100&page=1"] = (
            changed
        )
        self.rejected()

    def test_private_destination_and_symlink_parent(self):
        self.acquire()
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        alternate = Path(self.tmp.name) / "linked"
        alternate.symlink_to(self.output, target_is_directory=True)
        self.output = alternate / "nested"
        with self.assertRaises(OSError):
            self.acquire()
        self.assertFalse(self.output.exists())

    def test_failure_restores_prior_alarm_handler(self):
        import signal

        handler = signal.getsignal(signal.SIGALRM)
        self.fixture.archive = b"bad"
        self.rejected()
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_changed_metadata_after_download_is_rejected(self):
        for endpoint, original, key, value in [
            ("artifacts/10", self.fixture.artifact, "expired", True),
            ("artifacts/10", self.fixture.artifact, "digest", "sha256:" + "0" * 64),
            ("runs/12", self.fixture.run, "head_sha", "b" * 40),
        ]:
            self.fixture = Fixture()
            self.fixture.after[BASE + endpoint] = dict(original, **{key: value})
            self.rejected()

    def test_upload_rejects_echo_conflicts_truncation_controls_and_bad_encoding(self):
        original = self.fixture.upload
        bad = [
            b"\xef\xbb\xbf" + original,
            original.replace(b"SHA256", b"echo SHA256"),
            original + original.lstrip(b"\xef\xbb\xbf"),
            original.splitlines(keepends=True)[0],
            original.replace(b"ID is 10", b"ID is 11"),
            original + b"\xff",
            original.replace(b"SHA256", b"\x1b[0mSHA256"),
            original + b"\x00",
            original.replace(b"2026-11-11T20:10:31.1Z", b"20:10:31Z"),
            original.replace(b"2026-11-11T20:10:31.1Z", b"2026-11-11T20:10:21.1Z"),
            original.replace(
                b"SHA256", b"##[group]echo\n2026-11-11T20:10:31.1Z SHA256"
            ),
        ]
        for raw in bad:
            with self.subTest(case=bad.index(raw)):
                self.fixture = Fixture()
                self.fixture.upload = raw
                self.rejected()

    def test_export_requires_unique_complete_ungrouped_json_and_narrow_sgr(self):
        original = self.fixture.export
        for raw in [
            original.replace(
                self.fixture.digest.encode(), ("sha256:" + "0" * 64).encode()
            ),
            original + original.splitlines(keepends=True)[-1],
            original.replace(b'{"manifest_digest"', b'echo {"manifest_digest"'),
            original.replace(b"##[endgroup]", b"command"),
            original.replace(b"\x1b[36;1m", b"\x1b[2J"),
            original.rsplit(b"\n", 2)[0] + b"\n",
        ]:
            self.fixture = Fixture()
            self.fixture.export = raw
            self.rejected()

    def test_bounded_raw_logs_and_zip_bytes(self):
        self.assertIsNotNone(
            acquisition, "local acquisition adapter is not implemented"
        )
        with mock.patch.object(acquisition, "MAX_LOG", 100):
            self.rejected()
        for raw in [
            self.fixture.archive[:-1],
            self.fixture.archive + b"x",
            b"x" * len(self.fixture.archive),
        ]:
            self.fixture = Fixture()
            self.fixture.archive = raw
            self.rejected()

    def test_corrupt_blob_fails_even_with_matching_zip_hash(self):
        blob = next(name for name in self.fixture.files if name.startswith("blobs/"))
        self.fixture.files[blob] += b"corrupt"
        self.fixture.repack()
        self.rejected()

    def test_zip_preflight_rejects_unsafe_colliding_and_special_members(self):
        special = zipfile.ZipInfo("evil")
        special.create_system = 3
        special.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = [
            [("../evil", b"x")],
            [("/evil", b"x")],
            [("a//b", b"x")],
            [("a/./b", b"x")],
            [("a\\b", b"x")],
            [("a", b"x"), ("a/b", b"x")],
            [("a", b"x"), ("a/", b"")],
            [(special, b"target")],
        ]
        for entries in cases:
            with self.subTest(case=cases.index(entries)):
                self.fixture = Fixture()
                self.fixture.repack(entries)
                self.rejected()

    def test_zip_member_expansion_and_disk_caps(self):
        self.assertIsNotNone(
            acquisition, "local acquisition adapter is not implemented"
        )
        for constant, value in [
            ("MAX_MEMBERS", 1),
            ("MAX_EXPANDED", 1),
            ("DISK_BUDGET", 1),
        ]:
            with (
                self.subTest(constant=constant),
                mock.patch.object(acquisition, constant, value),
            ):
                self.rejected()

    def test_zip_path_depth_is_bounded_before_extraction(self):
        self.fixture.files["/".join(["nested"] * 17) + "/extra"] = b"x"
        self.fixture.repack()
        self.rejected()

    def test_encrypted_zip_is_rejected_before_extraction(self):
        raw = bytearray(self.fixture.archive)
        raw[raw.index(b"PK\x03\x04") + 6] |= 1
        raw[raw.index(b"PK\x01\x02") + 8] |= 1
        old = self.fixture.artifact["digest"][7:]
        digest = hashlib.sha256(raw).hexdigest()
        self.fixture.archive = bytes(raw)
        self.fixture.artifact["digest"] = "sha256:" + digest
        self.fixture.upload = self.fixture.upload.replace(old.encode(), digest.encode())
        self.rejected()

    def test_exact_duplicate_member_is_rejected(self):
        entries = list(self.fixture.files.items()) + [
            ("index.json", self.fixture.files["index.json"])
        ]
        with self.assertWarns(UserWarning):
            self.fixture.repack(entries)
        self.rejected()

    def test_injected_transport_cannot_ignore_deadline_or_claim_authority(self):
        with (
            mock.patch.object(acquisition.time, "monotonic", return_value=1),
            self.assertRaisesRegex(ValueError, "deadline"),
        ):
            acquisition.receive(self.fixture, "runs/12", 1024, 0)

    def test_existing_destination_is_never_overwritten_or_cleaned(self):
        self.output.mkdir()
        sentinel = self.output / "archive.zip.part"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.acquire()
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_transport_failure_retains_private_partial_without_success(self):
        self.assertIsNotNone(
            acquisition, "local acquisition adapter is not implemented"
        )

        def failing(endpoint, limit, deadline):
            if endpoint.endswith("/zip"):
                yield b"partial"
                raise TimeoutError("bounded transport timeout")
            yield from Fixture.stream(self.fixture, endpoint, limit, deadline)

        self.fixture.stream = failing
        retained = self.output
        self.rejected()
        self.assertEqual((retained / "archive.zip.part").read_bytes(), b"partial")

    def test_round1_ancestor_rename_between_parent_validation_and_creation(self):
        parent = Path(self.tmp.name) / "parent"
        parent.mkdir(mode=0o700)
        self.output = parent / "acquired"
        moved = Path(self.tmp.name) / "moved-parent"
        mkdir = os.mkdir
        fired = False

        def replace_parent(path, *args, **kwargs):
            nonlocal fired
            if Path(path).name == "acquired" and not fired:
                fired = True
                parent.rename(moved)
                mkdir(parent, 0o700)
                (parent / "sentinel").write_bytes(b"victim")
            return mkdir(path, *args, **kwargs)

        with mock.patch.object(acquisition.os, "mkdir", side_effect=replace_parent):
            result = self.acquire()
        self.assertTrue(result["archive_bytes_verified"])
        self.assertEqual(list(parent.iterdir()), [parent / "sentinel"])
        self.assertEqual((parent / "sentinel").read_bytes(), b"victim")
        self.assertTrue((moved / "acquired/layout/index.json").is_file())

    def test_round1_output_rename_before_download_never_writes_replacement(self):
        moved = Path(self.tmp.name) / "moved-output"
        stream = self.fixture.stream
        fired = False

        def replace_output(endpoint, limit, deadline):
            nonlocal fired
            if endpoint.endswith("/steps/3/logs") and not fired:
                fired = True
                self.output.rename(moved)
                self.output.mkdir(mode=0o700)
                (self.output / "sentinel").write_bytes(b"victim")
            yield from stream(endpoint, limit, deadline)

        self.fixture.stream = replace_output
        result = self.acquire()
        self.assertFalse(result["production_ready"])
        self.assertEqual(list(self.output.iterdir()), [self.output / "sentinel"])
        self.assertEqual((self.output / "sentinel").read_bytes(), b"victim")
        self.assertTrue((moved / "layout/index.json").is_file())

    def test_round1_output_rename_during_extraction_stays_on_open_descriptors(self):
        moved = Path(self.tmp.name) / "moved-extraction"
        opened = zipfile.ZipFile.open
        fired = False

        def replace_output(archive, *args, **kwargs):
            nonlocal fired
            if not fired:
                fired = True
                self.output.rename(moved)
                (self.output / "layout/blobs/sha256").mkdir(parents=True)
                (self.output / "sentinel").write_bytes(b"victim")
            return opened(archive, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "open", replace_output):
            result = self.acquire()
        self.assertTrue(result["oci_layout_verified"])
        self.assertEqual(
            [
                p.relative_to(self.output).as_posix()
                for p in self.output.rglob("*")
                if p.is_file()
            ],
            ["sentinel"],
        )
        self.assertTrue((moved / "layout/index.json").is_file())

    def test_round1_failed_acquisition_never_recursively_deletes(self):
        self.fixture.archive = b"partial"
        with mock.patch.object(shutil, "rmtree", wraps=shutil.rmtree) as removed:
            with self.assertRaises(ValueError):
                self.acquire()
            removed.assert_not_called()
        self.assertEqual((self.output / "archive.zip.part").read_bytes(), b"partial")
        self.assertFalse((self.output / "core-build.json").exists())

    def test_round1_parent_writable_by_other_users_is_not_adopted(self):
        parent = Path(self.tmp.name) / "shared-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        self.output = parent / "acquired"
        with self.assertRaisesRegex(ValueError, "private.*parent"):
            self.acquire()
        self.assertFalse(self.output.exists())

    def test_round1_symlink_substitution_before_initial_open_is_rejected(self):
        victim = Path(self.tmp.name) / "victim"
        victim.mkdir(mode=0o700)
        (victim / "sentinel").write_bytes(b"victim")
        moved = Path(self.tmp.name) / "original-created-directory"
        mkdir = os.mkdir
        fired = False

        def substitute(path, *args, **kwargs):
            nonlocal fired
            result = mkdir(path, *args, **kwargs)
            if Path(path).name == "acquired" and not fired:
                fired = True
                self.output.rename(moved)
                self.output.symlink_to(victim, target_is_directory=True)
            return result

        with (
            mock.patch.object(acquisition.os, "mkdir", side_effect=substitute),
            self.assertRaises(OSError),
        ):
            self.acquire()
        self.assertEqual(list(victim.iterdir()), [victim / "sentinel"])
        self.assertEqual((victim / "sentinel").read_bytes(), b"victim")
        self.assertFalse(list(moved.iterdir()))

    def test_round1_crc_failure_retains_partials_without_success(self):
        raw = bytearray(self.fixture.archive)
        raw[raw.index(b"core payload")] ^= 1
        old = self.fixture.artifact["digest"][7:]
        digest = hashlib.sha256(raw).hexdigest()
        self.fixture.archive = bytes(raw)
        self.fixture.artifact["digest"] = "sha256:" + digest
        self.fixture.upload = self.fixture.upload.replace(old.encode(), digest.encode())
        with self.assertRaises(zipfile.BadZipFile):
            self.acquire()
        self.assertTrue((self.output / "archive.verified.zip").is_file())
        self.assertFalse((self.output / "core-build.json").exists())

    def test_round1_file_creation_is_exclusive_nofollow_and_private(self):
        opened = os.open
        calls = []

        def observe(path, flags, mode=0o777, *, dir_fd=None):
            if path == "archive.zip.part":
                calls.append((flags, mode, dir_fd))
            return opened(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(acquisition.os, "open", side_effect=observe):
            self.acquire()
        self.assertEqual(len(calls), 1)
        flags, mode, parent = calls[0]
        required = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        self.assertEqual(flags & required, required)
        self.assertEqual(mode, 0o600)
        self.assertIs(type(parent), int)
        self.assertEqual(
            stat.S_IMODE((self.output / "archive.verified.zip").stat().st_mode), 0o600
        )

    def test_round1_replacement_survives_transport_failure(self):
        moved = Path(self.tmp.name) / "retained-failed-output"
        stream = self.fixture.stream

        def fail_after_rename(endpoint, limit, deadline):
            if endpoint.endswith("/zip"):
                self.output.rename(moved)
                self.output.mkdir(mode=0o700)
                (self.output / "sentinel").write_bytes(b"victim")
                yield b"partial"
                raise TimeoutError("transport deadline exceeded")
            yield from stream(endpoint, limit, deadline)

        self.fixture.stream = fail_after_rename
        with self.assertRaises(TimeoutError):
            self.acquire()
        self.assertEqual(list(self.output.iterdir()), [self.output / "sentinel"])
        self.assertEqual((self.output / "sentinel").read_bytes(), b"victim")
        self.assertEqual((moved / "archive.zip.part").read_bytes(), b"partial")

    def test_clarification_root_owned_trusted_parent_is_allowed(self):
        parent = self.output.parent.stat()
        fstat = os.fstat

        def root_owner(descriptor):
            info = fstat(descriptor)
            if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
                values = list(info)
                values[4] = 0
                return os.stat_result(values)
            return info

        with mock.patch.object(acquisition.os, "fstat", side_effect=root_owner):
            result = self.acquire()
        self.assertFalse(result["production_ready"])

    def test_clarification_created_output_ownership_and_privacy_are_verified(self):
        fstat = os.fstat
        for kind in ("owner", "permissions"):
            with self.subTest(kind=kind):
                self.output = Path(self.tmp.name) / f"created-{kind}"
                self.fixture = Fixture()

                def invalid_output(descriptor, kind=kind):
                    info = fstat(descriptor)
                    if self.output.exists():
                        target = self.output.stat()
                        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                            values = list(info)
                            if kind == "owner":
                                values[4] = os.geteuid() + 1
                            else:
                                values[0] = stat.S_IFDIR | 0o755
                            return os.stat_result(values)
                    return info

                with (
                    mock.patch.object(
                        acquisition.os, "fstat", side_effect=invalid_output
                    ),
                    self.assertRaisesRegex(
                        ValueError, "private owned output directory"
                    ),
                ):
                    self.acquire()
                self.assertFalse(self.fixture.calls)


class GhTransportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            acquisition, "local acquisition adapter is not implemented"
        )

    def child(self, code):
        original = subprocess.Popen
        children = []

        def spawn(args, **kwargs):
            child = original(["/usr/bin/python3", "-c", code], **kwargs)
            children.append(child)
            return child

        return mock.patch.object(
            acquisition.subprocess, "Popen", side_effect=spawn
        ), children

    def test_fixed_host_safe_environment_and_raw_stream(self):
        patch, children = self.child("import sys; sys.stdout.buffer.write(b'raw')")
        with (
            patch as spawn,
            mock.patch.dict(
                os.environ,
                {"GH_DEBUG": "api", "GH_HOST": "evil.invalid", "GH_REPO": "evil/repo"},
            ),
        ):
            raw = b"".join(
                acquisition.GhTransport().stream(
                    BASE + "artifacts/10", 10, time.monotonic() + 3
                )
            )
        self.assertEqual(raw, b"raw")
        args, kwargs = spawn.call_args
        self.assertIn("--hostname", args[0])
        self.assertEqual(args[0][args[0].index("--hostname") + 1], "github.com")
        self.assertNotIn("GH_DEBUG", kwargs["env"])
        self.assertNotIn("GH_HOST", kwargs["env"])
        self.assertNotIn("GH_REPO", kwargs["env"])
        self.assertIsNotNone(children[0].returncode)

    def test_timeout_excess_and_error_are_sanitized_and_reaped(self):
        for code, cap, seconds in [
            ("import time; time.sleep(30)", 10, 0.02),
            ("print('oversized output')", 1, 3),
            ("import sys; sys.stderr.write('SECRET signedURL'); sys.exit(1)", 10, 3),
        ]:
            patch, children = self.child(code)
            with patch, self.assertRaises((ValueError, TimeoutError)) as caught:
                list(
                    acquisition.GhTransport().stream(
                        BASE + "artifacts/10", cap, time.monotonic() + seconds
                    )
                )
            self.assertNotIn("SECRET", str(caught.exception))
            self.assertIsNotNone(children[0].returncode)

    def test_transport_rejects_generic_and_cross_repository_urls(self):
        for endpoint in (
            "https://evil.invalid",
            "repos/evil/images/actions/artifacts/10",
            BASE + "artifacts/10?token=x",
            BASE + "../other",
        ):
            with self.assertRaises(ValueError):
                list(
                    acquisition.GhTransport().stream(endpoint, 10, time.monotonic() + 1)
                )


class PrivateHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.fixture = Fixture()
        self.policy = {
            "repository": "luminusOS/images",
            "repository_id": "1118572971",
            "producer_sha": "b" * 40,
            "source_sha": SOURCE,
            "caller_ref": "refs/heads/main",
            "caller_workflow": ".github/workflows/build-containers.yml",
            "fedora": "45",
            "base_digest": "sha256:" + "c" * 64,
            "actions_sha256": hashlib.sha256(
                b"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                b"actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6\n"
            ).hexdigest(),
        }
        self.context = {
            "repository": "luminusOS/images",
            "repository_id": "1118572971",
            "sha": SOURCE,
            "ref": "refs/heads/main",
            "event_name": "workflow_dispatch",
            "workflow_ref": "luminusOS/images/.github/workflows/build-containers.yml@refs/heads/main",
            "producer_ref": "luminusOS/images/.github/workflows/containers.yml@"
            + "b" * 40,
            "producer_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "runner_environment": "github-hosted",
        }
        self.fixture.files["core-handoff-policy.json"] = json.dumps(
            dict(self.policy, run_id="12", run_attempt="1"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.fixture.repack()
        self.facts = {
            "policy_sha256": hashlib.sha256(
                json.dumps(self.policy, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "archive_sha256": hashlib.sha256(self.fixture.archive).hexdigest(),
            "archive_size": str(len(self.fixture.archive)),
            "manifest_digest": self.fixture.digest,
            "object_key": f"core-candidates/1118572971/12/1/{SOURCE}/core-oci.zip",
        }

    def checked(self):
        return acquisition.private_policy(self.policy, self.context)

    def test_independent_policy_binds_producer_source_and_recipe(self):
        policy = self.checked()
        self.assertEqual(acquisition.private_key(policy), self.facts["object_key"])
        for key in self.policy:
            changed = dict(self.policy, **{key: "wrong"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                acquisition.private_policy(changed, self.context)
        for key in self.context:
            if key in ("run_id", "run_attempt"):
                value = "../1"
            else:
                value = "wrong"
            with self.subTest(context=key), self.assertRaises(ValueError):
                acquisition.private_policy(
                    self.policy, dict(self.context, **{key: value})
                )
        for event in ("pull_request", "pull_request_target", "push", "schedule"):
            with self.assertRaises(ValueError):
                acquisition.private_policy(
                    self.policy, dict(self.context, event_name=event)
                )
        with self.assertRaises(ValueError):
            acquisition.private_policy({}, self.context)

    def download(self, facts=None, payload=None):
        class Reader:
            def stream(reader, key, limit, deadline):
                self.assertEqual(key, self.facts["object_key"])
                yield self.fixture.archive if payload is None else payload

        return acquisition.private_download(
            self.checked(),
            facts or self.facts,
            self.parent / "received",
            transport=Reader(),
        )

    def test_actual_private_archive_is_checked_before_attesting(self):
        result = self.download()
        self.assertEqual(result["manifest_digest"], self.fixture.digest)
        self.assertEqual(stat.S_IMODE((self.parent / "received").stat().st_mode), 0o700)
        self.assertEqual(
            (self.parent / "received/core-oci.zip").read_bytes(), self.fixture.archive
        )

    def test_valid_but_different_base_policy_cannot_claim_the_producer_archive(self):
        changed = dict(self.policy, base_digest="sha256:" + "d" * 64)
        policy = acquisition.private_policy(changed, self.context)
        with self.assertRaisesRegex(ValueError, "policy"):
            acquisition.private_facts(policy, self.facts)

    def test_forged_policy_output_cannot_replace_archive_embedded_producer_policy(self):
        policy = acquisition.private_policy(
            dict(self.policy, base_digest="sha256:" + "d" * 64), self.context
        )
        facts = dict(
            self.facts, policy_sha256=acquisition.private_policy_sha256(policy)
        )
        with (
            mock.patch.object(
                acquisition.R2Transport,
                "stream",
                return_value=(chunk for chunk in [self.fixture.archive]),
            ),
            self.assertRaisesRegex(ValueError, "policy"),
        ):
            acquisition.private_download(policy, facts, self.parent / "forged-policy")

    def test_archive_digest_size_manifest_and_key_are_not_candidate_authority(self):
        for field, value in (
            ("archive_sha256", "0" * 64),
            ("archive_size", "1"),
            ("manifest_digest", "sha256:" + "0" * 64),
            ("object_key", "../core-oci.zip"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.download(dict(self.facts, **{field: value}))
            if (self.parent / "received").exists():
                shutil.rmtree(self.parent / "received")
        with self.assertRaises(ValueError):
            self.download(payload=self.fixture.archive[:-1])

    def test_oci_corruption_cannot_be_attested_even_with_correct_archive_hash(self):
        self.fixture.files["blobs/sha256/" + self.fixture.digest[7:]] = b"broken"
        self.fixture.repack()
        self.facts.update(
            archive_sha256=hashlib.sha256(self.fixture.archive).hexdigest(),
            archive_size=str(len(self.fixture.archive)),
        )
        with self.assertRaises(ValueError):
            self.download()

    def test_native_verifier_uses_standard_identity_constraints_and_exact_attempt(self):
        calls = []
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "core-oci.zip",
                    "digest": {"sha256": self.facts["archive_sha256"]},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "runDetails": {
                    "metadata": {
                        "invocationId": "https://github.com/luminusOS/images/actions/runs/12/attempts/1"
                    }
                }
            },
        }

        def command(argv):
            calls.append(argv)
            return json.dumps(
                [{"verificationResult": {"statement": statement}}]
            ).encode()

        policy = self.checked()
        acquisition.verify_native(
            policy, self.parent / "core-oci.zip", self.facts, command=command
        )
        argv = calls[0]
        for flag, value in (
            ("--repo", "luminusOS/images"),
            ("--signer-digest", "b" * 40),
            ("--source-digest", SOURCE),
            ("--source-ref", "refs/heads/main"),
            ("--format", "json"),
            ("--signer-workflow", "luminusOS/images/.github/workflows/containers.yml"),
        ):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--deny-self-hosted-runners", argv)
        for target, key, value in (
            (statement, "predicateType", "other"),
            (statement["subject"][0]["digest"], "sha256", "0" * 64),
            (
                statement["predicate"]["runDetails"]["metadata"],
                "invocationId",
                "https://github.com/luminusOS/images/actions/runs/12/attempts/2",
            ),
        ):
            old = target[key]
            target[key] = value
            with self.assertRaises(ValueError):
                acquisition.verify_native(
                    policy, self.parent / "core-oci.zip", self.facts, command=command
                )
            target[key] = old

    def test_workflow_private_route_has_no_legacy_byte_or_host_source_path(self):
        import yaml

        root = MODULE.parents[3]
        workflow = yaml.safe_load(
            (root / ".github/workflows/containers.yml").read_text()
        )
        jobs = workflow["jobs"]
        for name in ("metadata", "core", "workstation", "installer"):
            self.assertIn("!inputs.private_core_handoff", jobs[name]["if"])
        build, attest = jobs["private-core"], jobs["private-core-attest"]
        self.assertEqual(build["environment"], "core-candidate-writer")
        self.assertEqual(attest["environment"], "core-candidate-reader")
        self.assertNotIn("id-token", build["permissions"])
        self.assertEqual(attest["permissions"]["id-token"], "write")
        self.assertNotIn("packages", attest["permissions"])
        for job in (build, attest):
            self.assertIn("workflow_dispatch", job["if"])
            self.assertEqual(
                job["steps"][0]["name"], "Validate independent operator policy"
            )
            for step in job["steps"]:
                self.assertNotIn("secrets: inherit", json.dumps(step))
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
        text = json.dumps([build, attest])
        for forbidden in (
            "upload-artifact",
            "cache-to",
            "cache-from",
            "sign_candidates",
            "docker push",
            "source/.github/scripts",
        ):
            self.assertNotIn(forbidden, text)
        native = next(
            s
            for s in attest["steps"]
            if s.get("uses", "").startswith("actions/attest@")
        )
        self.assertIn("core-oci.zip", native["with"]["subject-path"])
        self.assertNotIn("subject-digest", native["with"])
        self.assertIs(native["with"]["push-to-registry"], False)

    def test_pack_uses_actual_oci_bytes_and_roundtrips_private_download(self):
        layout = self.parent / "exported"
        layout.mkdir(mode=0o700)
        for name, raw in self.fixture.files.items():
            if name == "core-handoff-policy.json":
                continue
            target = layout / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        self.facts = acquisition.private_pack(
            self.checked(), layout, self.parent / "packed"
        )
        self.fixture.archive = (self.parent / "packed/core-oci.zip").read_bytes()
        self.assertEqual(
            self.facts["archive_sha256"],
            hashlib.sha256(self.fixture.archive).hexdigest(),
        )
        self.assertEqual(self.download()["manifest_digest"], self.fixture.digest)

    def test_private_zip_retains_accepted_traversal_and_symlink_defenses(self):
        self.fixture.repack([("../escape", b"not code")])
        self.facts.update(
            archive_sha256=hashlib.sha256(self.fixture.archive).hexdigest(),
            archive_size=str(len(self.fixture.archive)),
        )
        with self.assertRaises(ValueError):
            self.download()
        self.assertFalse((self.parent / "escape").exists())

    def attempt_fixture(self):
        run = dict(
            self.fixture.run,
            path=self.policy["caller_workflow"],
            head_branch="main",
            event="workflow_dispatch",
        )
        jobs = [
            dict(self.fixture.job, id=90 + n, name="Caller / " + name)
            for n, name in enumerate(
                ("Private core producer", "Private core attestation")
            )
        ]

        def command(argv):
            if argv[-1].endswith("/jobs?per_page=100&page=1"):
                return json.dumps({"total_count": len(jobs), "jobs": jobs}).encode()
            self.assertTrue(argv[-1].endswith("/runs/12/attempts/1"))
            return json.dumps(run).encode()

        return run, jobs, command

    def test_authenticated_api_rejects_wrong_attempt_run_source_repo_and_job_outcome(
        self,
    ):
        run, jobs, command = self.attempt_fixture()
        acquisition.private_attempt(self.checked(), command=command)
        for target, key, value in (
            (run, "id", 13),
            (run, "run_attempt", 2),
            (run, "head_sha", "d" * 40),
            (run, "event", "pull_request"),
            (run, "head_branch", "other"),
            (run, "conclusion", "failure"),
            (run["repository"], "id", 4),
            (jobs[0], "conclusion", "skipped"),
            (jobs[1], "conclusion", "failure"),
            (jobs[0], "run_attempt", 2),
            (jobs[1], "head_sha", "d" * 40),
        ):
            old = target[key]
            target[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                acquisition.private_attempt(self.checked(), command=command)
            target[key] = old
        jobs.append(dict(jobs[0], id=99))
        with self.assertRaises(ValueError):
            acquisition.private_attempt(self.checked(), command=command)

    def test_consumer_in_active_run_requires_completed_producer_and_attester(self):
        run, jobs, command = self.attempt_fixture()
        run.update(status="in_progress", conclusion=None)
        acquisition.private_attempt(self.checked(), command=command)
        jobs[1].update(status="in_progress", conclusion=None)
        with self.assertRaises(ValueError):
            acquisition.private_attempt(self.checked(), command=command)
        acquisition.private_attempt(self.checked(), completed=False, command=command)

    def test_precheckout_bootstraps_match_policy_and_reject_before_any_action(self):
        import yaml

        workflow = yaml.safe_load(
            (MODULE.parents[3] / ".github/workflows/containers.yml").read_text()
        )
        for job_name in ("private-core", "private-core-attest"):
            step = workflow["jobs"][job_name]["steps"][0]
            code = step["run"].split("\n", 1)[1].rsplit("\nPY", 1)[0]
            env = {
                "PATH": os.environ["PATH"],
                **step["env"],
                "CORE_HANDOFF_POLICY": json.dumps(self.policy),
                "CORE_HANDOFF_CONTEXT": json.dumps(self.context),
                "CORE_HANDOFF_JOB": json.dumps(
                    {
                        "workflow_sha": self.context["producer_sha"],
                        "workflow_ref": self.context["producer_ref"],
                    }
                ),
                "CORE_RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_ENV": str(self.parent / "github-env"),
                "GITHUB_OUTPUT": str(self.parent / "github-output"),
            }
            passed = subprocess.run(
                ["python3", "-c", code], env=env, capture_output=True, check=False
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)
            for key in self.policy:
                failed = subprocess.run(
                    ["python3", "-c", code],
                    env=dict(
                        env,
                        CORE_HANDOFF_POLICY=json.dumps(
                            dict(self.policy, **{key: "wrong"})
                        ),
                    ),
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(failed.returncode, 0, key)

    def test_writer_only_enters_transport_after_builder_shutdown(self):
        import yaml

        workflow = yaml.safe_load(
            (MODULE.parents[3] / ".github/workflows/containers.yml").read_text()
        )
        job = workflow["jobs"]["private-core"]
        self.assertNotIn("R2_", json.dumps(job.get("env", {})))
        steps = job["steps"]
        writer = [i for i, step in enumerate(steps) if "WRITER" in json.dumps(step)]
        self.assertEqual(writer, [len(steps) - 1])
        self.assertIn("systemctl stop docker.service docker.socket", steps[-2]["run"])
        self.assertNotIn("continue-on-error", steps[-2])
        self.assertNotIn("READER", json.dumps(job))
        self.assertNotIn("WRITER", json.dumps(workflow["jobs"]["private-core-attest"]))
        self.assertIs(
            workflow[True]["workflow_call"]["inputs"]["private_core_handoff"][
                "default"
            ],
            False,
        )

    def test_new_command_withholds_credentials_and_reaps_failed_verifier(self):
        patch, children = GhTransportTests.child(
            self, "import sys; sys.stderr.write('SECRET'); sys.exit(1)"
        )
        with patch, self.assertRaises(ValueError) as caught:
            acquisition.bounded_command(["gh", "attestation", "verify", "archive"])
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertIsNotNone(children[0].returncode)
        patch, children = GhTransportTests.child(self, "print('output')")
        with (
            patch as spawn,
            mock.patch.dict(
                os.environ, {"GH_DEBUG": "api", "R2_SECRET_ACCESS_KEY": "SECRET"}
            ),
        ):
            self.assertEqual(
                acquisition.bounded_command(["gh", "api", "endpoint"]), b"output\n"
            )
        self.assertNotIn("GH_DEBUG", spawn.call_args.kwargs["env"])
        self.assertNotIn("R2_SECRET_ACCESS_KEY", spawn.call_args.kwargs["env"])

    def test_native_command_failure_cannot_become_authenticated_handoff(self):
        def failed(argv):
            raise ValueError("SECRET from verifier stderr")

        with self.assertRaisesRegex(
            ValueError, "Native gh verification failed"
        ) as caught:
            acquisition.verify_native(
                self.checked(), self.parent / "core-oci.zip", self.facts, command=failed
            )
        self.assertNotIn("SECRET", str(caught.exception))
        with (
            mock.patch.object(acquisition, "private_attempt", return_value=({}, [])),
            mock.patch.object(
                acquisition.R2Transport,
                "stream",
                return_value=(chunk for chunk in [self.fixture.archive]),
            ),
            mock.patch.object(
                acquisition,
                "verify_native",
                side_effect=ValueError("wrong native identity"),
            ),
            self.assertRaisesRegex(ValueError, "wrong native identity"),
        ):
            acquisition.acquire_private(
                self.checked(), self.facts, self.parent / "rejected"
            )

    def test_separate_authenticated_result_never_grants_release_or_vm_authority(self):
        with (
            mock.patch.object(
                acquisition, "private_attempt", return_value=({}, [])
            ) as api,
            mock.patch.object(
                acquisition.R2Transport,
                "stream",
                return_value=(chunk for chunk in [self.fixture.archive]),
            ),
            mock.patch.object(acquisition, "verify_native") as verify,
        ):
            result = acquisition.acquire_private(
                self.checked(), self.facts, self.parent / "handoff"
            )
        self.assertEqual(api.call_count, 2)
        verify.assert_called_once()
        self.assertEqual(result["kind"], "authenticated-private-core-handoff")
        for field in ("production_ready", "runtime_verified", "release_authorized"):
            self.assertIs(result[field], False)

    def test_new_command_limits_output_and_time_without_leaking_stderr(self):
        patch, children = GhTransportTests.child(
            self, "print('oversized SECRET output')"
        )
        with (
            patch,
            mock.patch.object(acquisition, "MAX_JSON", 1),
            self.assertRaises(ValueError) as caught,
        ):
            acquisition.bounded_command(["gh", "attestation", "verify", "archive"])
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertIsNotNone(children[0].returncode)
        patch, children = GhTransportTests.child(self, "import time; time.sleep(30)")
        with (
            patch,
            mock.patch.object(acquisition.time, "monotonic", side_effect=[0, 181]),
            self.assertRaises(ValueError),
        ):
            acquisition.bounded_command(["gh", "attestation", "verify", "archive"])
        self.assertIsNotNone(children[0].returncode)

    def test_build_only_runs_trusted_host_command_without_credentials_or_entitlements(
        self,
    ):
        source = self.parent / "source"
        recipe = source / "editions/core/Containerfile"
        recipe.parent.mkdir(parents=True)
        recipe.write_text("FROM scratch\n")
        tooling_file = (
            self.parent
            / "trusted-tooling/.github/scripts/workflow/core_build_acquisition.py"
        )
        env = {
            "GITHUB_WORKSPACE": str(self.parent),
            "CORE_HANDOFF_POLICY": json.dumps(self.policy),
            "CORE_HANDOFF_CONTEXT": json.dumps(self.context),
        }
        argv = [
            "core_build_acquisition.py",
            "build",
            "--output",
            str(self.parent / "layout"),
        ]
        with (
            mock.patch.dict(os.environ, env),
            mock.patch.object(acquisition, "__file__", str(tooling_file)),
            mock.patch.object(acquisition.sys, "argv", argv),
            mock.patch.object(
                acquisition, "bounded_command", return_value=SOURCE.encode()
            ),
            mock.patch.object(acquisition.subprocess, "run") as run,
            mock.patch.object(acquisition.oci, "export_layout") as export,
        ):
            self.assertEqual(acquisition.private_main(), 0)
            args, kwargs = run.call_args
            self.assertEqual(args[0][:3], ["docker", "buildx", "build"])
            self.assertEqual(args[0][-1], str(source))
            self.assertIn(
                "base=quay.io/fedora/fedora-bootc:45@" + self.policy["base_digest"],
                args[0],
            )
            for forbidden in (
                "--allow",
                "--secret",
                "--ssh",
                "--push",
                "--cache-to",
                "--cache-from",
                "--privileged",
            ):
                self.assertNotIn(forbidden, args[0])
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            export.assert_called_once()
            run.reset_mock()
            with mock.patch.dict(
                os.environ, {"R2_SECRET_ACCESS_KEY": "must-not-enter-build"}
            ):
                self.assertEqual(acquisition.private_main(), 1)
                run.assert_not_called()

    def test_r2_absolute_deadline_interrupts_blocking_transaction(self):
        for stage in ("endheaders", "getresponse", "read", "send"):
            with self.subTest(stage=stage):
                connection = mock.Mock()
                response = connection.getresponse.return_value
                response.status = 200
                response.getheader.return_value = self.facts["archive_size"]
                response.read.side_effect = [self.fixture.archive, b""]
                progress = []

                def trickle(
                    *args, progress=progress, stage=stage, response=response, **kwargs
                ):
                    until = time.monotonic() + 0.35
                    while time.monotonic() < until:
                        time.sleep(0.005)
                        progress.append(b"x")
                    return self.fixture.archive if stage == "read" else response

                target = response if stage == "read" else connection
                getattr(target, stage).side_effect = trickle
                handler = signal.getsignal(signal.SIGALRM)
                started = time.monotonic()
                with (
                    mock.patch.dict(
                        os.environ,
                        {
                            "R2_ACCESS_KEY_ID": "a" * 32,
                            "R2_SECRET_ACCESS_KEY": "b" * 64,
                        },
                    ),
                    mock.patch.object(
                        acquisition.http.client,
                        "HTTPSConnection",
                        return_value=connection,
                    ),
                    mock.patch.object(
                        acquisition, "R2_TRANSACTION_SECONDS", 0.1, create=True
                    ),
                    self.assertRaisesRegex(
                        TimeoutError, "^R2 transaction deadline exceeded$"
                    ),
                ):
                    if stage == "send":
                        acquisition.R2Transport().upload(
                            self.facts["object_key"],
                            io.BytesIO(self.fixture.archive),
                            self.facts,
                        )
                    else:
                        list(
                            acquisition.R2Transport().stream(
                                self.facts["object_key"],
                                len(self.fixture.archive),
                                started + 0.1,
                            )
                        )
                self.assertLess(time.monotonic() - started, 0.3)
                self.assertTrue(progress)
                connection.close.assert_called_once()
                self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_r2_deadline_interrupts_connection_construction(self):
        def blocked_connection(*args, **kwargs):
            time.sleep(0.35)
            return mock.Mock()

        handler = signal.getsignal(signal.SIGALRM)
        with (
            mock.patch.dict(
                os.environ,
                {
                    "R2_ACCESS_KEY_ID": "a" * 32,
                    "R2_SECRET_ACCESS_KEY": "b" * 64,
                },
            ),
            mock.patch.object(
                acquisition.http.client,
                "HTTPSConnection",
                side_effect=blocked_connection,
            ),
            self.assertRaisesRegex(TimeoutError, "^R2 transaction deadline exceeded$"),
        ):
            list(
                acquisition.R2Transport().stream(
                    self.facts["object_key"],
                    len(self.fixture.archive),
                    time.monotonic() + 0.1,
                )
            )
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_r2_rejects_expired_deadline_before_connection_or_upload(self):
        with (
            mock.patch.dict(
                os.environ,
                {
                    "R2_ACCESS_KEY_ID": "a" * 32,
                    "R2_SECRET_ACCESS_KEY": "b" * 64,
                },
            ),
            mock.patch.object(acquisition.http.client, "HTTPSConnection") as connect,
        ):
            for method in ("GET", "PUT"):
                with self.subTest(method=method):
                    source = mock.Mock()
                    request = acquisition.R2Transport().request(
                        method,
                        self.facts["object_key"],
                        self.facts["archive_sha256"],
                        source=source,
                        deadline=time.monotonic() - 1,
                    )
                    with self.assertRaisesRegex(
                        TimeoutError, "^R2 transaction deadline exceeded$"
                    ):
                        next(request)
                    source.read.assert_not_called()
            connect.assert_not_called()

    def test_r2_rejects_active_or_nested_alarm_without_clobbering(self):
        handler = signal.getsignal(signal.SIGALRM)
        signal.setitimer(signal.ITIMER_REAL, 10, 10)
        try:
            with (
                self.assertRaisesRegex(ValueError, "unoccupied main-thread timer"),
                acquisition.r2_deadline(time.monotonic() + 1),
            ):
                self.fail("active alarm accepted")
            remaining, interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(remaining, 9)
            self.assertEqual(interval, 10)
            self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        with acquisition.r2_deadline(time.monotonic() + 10):
            active_handler = signal.getsignal(signal.SIGALRM)
            with (
                self.assertRaisesRegex(ValueError, "unoccupied main-thread timer"),
                acquisition.r2_deadline(time.monotonic() + 1),
            ):
                self.fail("nested alarm accepted")
            self.assertEqual(signal.getsignal(signal.SIGALRM), active_handler)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 9)
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_r2_rejects_worker_thread_without_changing_main_timer(self):
        failures = []

        def worker():
            try:
                with acquisition.r2_deadline(time.monotonic() + 1):
                    failures.append("worker accepted")
            except ValueError as error:
                failures.append(str(error))

        handler = signal.getsignal(signal.SIGALRM)
        thread = acquisition.threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            failures, ["R2 transaction requires an unoccupied main-thread timer"]
        )
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_r2_fixed_endpoint_conditional_put_and_private_get_no_redirect(self):
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.return_value = self.facts["archive_size"]
        response.read.side_effect = [self.fixture.archive, b""]
        with (
            mock.patch.dict(
                os.environ,
                {"R2_ACCESS_KEY_ID": "a" * 32, "R2_SECRET_ACCESS_KEY": "b" * 64},
            ),
            mock.patch.object(
                acquisition.http.client, "HTTPSConnection", return_value=connection
            ) as connect,
        ):
            reader = acquisition.R2Transport()
            self.assertEqual(
                b"".join(
                    reader.stream(
                        self.facts["object_key"],
                        len(self.fixture.archive),
                        time.monotonic() + 3,
                    )
                ),
                self.fixture.archive,
            )
            connect.assert_called_with(acquisition.R2_HOST, timeout=30)
            connection.putrequest.assert_called_with(
                "GET",
                "/luminus-images-staging/" + self.facts["object_key"],
                skip_host=True,
                skip_accept_encoding=True,
            )
            reader.upload(
                self.facts["object_key"], io.BytesIO(self.fixture.archive), self.facts
            )
            connection.putheader.assert_any_call("if-none-match", "*")
            connection.send.assert_called_with(self.fixture.archive)
            response.status = 302
            with self.assertRaisesRegex(ValueError, "response withheld"):
                list(
                    reader.stream(
                        self.facts["object_key"],
                        len(self.fixture.archive),
                        time.monotonic() + 3,
                    )
                )
            for key in (
                "../archive",
                "https://evil.invalid/archive",
                self.facts["object_key"] + "?token=x",
            ):
                with self.assertRaises(ValueError):
                    list(reader.stream(key, 1, time.monotonic() + 3))
        self.assertTrue(connection.close.called)


if __name__ == "__main__":
    unittest.main()
