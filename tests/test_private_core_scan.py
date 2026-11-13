import copy
import hashlib
import importlib.util
import io
import json
import os
import signal
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from test_core_build_acquisition import acquisition
from test_release_pipeline import core_oci_sample

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".github/scripts/workflow/private_core_scan.py"
)
spec = importlib.util.spec_from_file_location("private_core_scan_test", SCRIPT)
caller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(caller)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class PrivateCallerTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            guard = mock.patch(
                target,
                side_effect=AssertionError("unexpected native/network operation"),
            )
            guard.start()
            self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix="private-core-caller-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        self.policy = self.root / "policy.json"
        self.policy.write_bytes(
            b'{\n  "evidence_class": "runtime",\n  "exceptions": [],\n  "kind": "policy",\n  "schema_version": 2\n}\n'
        )
        self.bundle_root = self.root / "bundle"
        self.bundle_root.mkdir(mode=0o700)
        self.files, self.manifest_digest = core_oci_sample()
        manifest = json.loads(self.files["blobs/sha256/" + self.manifest_digest[7:]])
        self.config_digest = manifest["config"]["digest"]
        self.diff_ids = json.loads(
            self.files["blobs/sha256/" + self.config_digest[7:]]
        )["rootfs"]["diff_ids"]
        tools = {
            name: self.store(name, b"synthetic executable", executable=True)
            for name in ("syft", "grype", "bwrap", "prlimit")
        }
        for name, (version, archive) in caller.TOOL_ARCHIVES.items():
            tools[name].update(version=version, archive_sha256=archive)
        database = {
            "cache_path": "db",
            "installed": self.store(
                "db/6/vulnerability.db", b"synthetic DB, never executed"
            ),
            "import_metadata": self.store("db/6/import.json", b"{}\n"),
            "archive": {
                "url": "https://toolbox-data.anchore.io/grype/databases/v6/synthetic-only.tar.zst",
                "sha256": "c" * 64,
                "size_bytes": 100,
            },
            "schemaVersion": "v6.0.3",
            "built": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        preparation = {
            "kind": "prepared-grype-database",
            "schema_version": 1,
            **{k: v for k, v in database.items() if k != "cache_path"},
        }
        database["preparation_receipt"] = self.store(
            "preparation.json", json.dumps(preparation).encode()
        )
        self.bundle = {
            "kind": "private-core-scan-bundle",
            "schema_version": 1,
            "tools": tools,
            "runtime_files": [
                {
                    **self.store("loader", b"synthetic runtime"),
                    "destination": "/lib64/ld-linux-x86-64.so.2",
                }
            ],
            "database": database,
        }
        self.bundle_path = self.bundle_root / "bundle.json"
        approved = {
            "repository": "luminusOS/images",
            "repository_id": "1118572971",
            "producer_sha": "b" * 40,
            "source_sha": "a" * 40,
            "caller_ref": "refs/heads/main",
            "caller_workflow": ".github/workflows/private-core-handoff.yml",
            "fedora": "45",
            "base_digest": "sha256:" + "d" * 64,
            "actions_sha256": acquisition.PRIVATE_ACTIONS_SHA256,
        }
        context = {
            "repository": "luminusOS/images",
            "repository_id": "1118572971",
            "sha": "a" * 40,
            "ref": approved["caller_ref"],
            "workflow_ref": "luminusOS/images/.github/workflows/private-core-handoff.yml@refs/heads/main",
            "producer_sha": "b" * 40,
            "producer_ref": acquisition.PRIVATE_WORKFLOW + "@" + "b" * 40,
            "event_name": "workflow_dispatch",
            "runner_environment": "github-hosted",
            "run_id": "12",
            "run_attempt": "1",
        }
        self.expected = acquisition.private_policy(approved, context)
        self.archive = b"synthetic acquired archive"
        facts = {
            "archive_sha256": digest(self.archive),
            "archive_size": str(len(self.archive)),
            "manifest_digest": self.manifest_digest,
            "object_key": acquisition.private_key(self.expected),
            "policy_sha256": acquisition.private_policy_sha256(self.expected),
        }
        self.invocation = {
            "kind": "private-core-scan-invocation",
            "schema_version": 1,
            "trusted_root": str(SCRIPT.parents[3]),
            "source_checkout": str(self.root / "source"),
            "scope": dict(caller.SCOPE),
            "policy": {"path": str(self.policy), "sha256": caller.POLICY_SHA256},
            "bundle": {"path": str(self.bundle_path), "sha256": ""},
            "acquisition": {"policy": approved, "context": context, "facts": facts},
            "logical_image": "ghcr.io/luminusos/luminusos@" + self.manifest_digest,
            "layout_max_bytes": 1024**2,
        }
        self.path = self.root / "invocation.json"
        self.events = []
        self.receipt_change = None
        self.acquire_result_change = None
        self.scan_change = None
        self.executor_error = None
        self.native_matches = []
        self.native_result_change = None
        self.secrets = {
            "GH_TOKEN": "SECRET-GH",
            "R2_ACCESS_KEY_ID": "SECRET-ID",
            "R2_SECRET_ACCESS_KEY": "SECRET-R2",
            "HTTPS_PROXY": "SECRET-PROXY",
            "PYTHONPATH": "untrusted-source",
        }

    def store(self, name, raw, executable=False):
        path = self.bundle_root / name
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o555 if executable else 0o444)
        return {"path": name, "sha256": digest(raw), "size_bytes": len(raw)}

    def write_inputs(self):
        if self.bundle_path.exists():
            self.bundle_path.chmod(0o600)
        self.bundle_path.write_text(json.dumps(self.bundle))
        self.bundle_path.chmod(0o444)
        self.invocation["bundle"]["sha256"] = digest(self.bundle_path.read_bytes())
        self.path.write_text(json.dumps(self.invocation))
        return digest(self.path.read_bytes())

    def execute(self, argv, *, env, work, seconds, check):
        self.events.append((argv, env))
        check()
        if self.executor_error:
            raise self.executor_error
        if "acquire" in argv:
            destination = self.work / "acquisition"
            destination.mkdir(mode=0o700)
            (destination / "core-oci.zip").write_bytes(self.archive)
            for name, raw in self.files.items():
                path = destination / "layout" / name
                path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                path.write_bytes(raw)
            summary = {
                "kind": "authenticated-private-core-handoff",
                **self.expected,
                **self.invocation["acquisition"]["facts"],
                "production_ready": False,
                "runtime_verified": False,
                "release_authorized": False,
            }
            receipt = {
                "schema_version": 1,
                **summary,
                "layout": {
                    "path": "layout",
                    "manifest_digest": self.manifest_digest,
                    "config_digest": self.config_digest,
                    "diff_ids": self.diff_ids,
                    "os": "linux",
                    "architecture": "amd64",
                    "reference": "core",
                },
                "verification": dict(caller.VERIFICATION),
            }
            if self.receipt_change:
                self.receipt_change(receipt)
            raw = json.dumps(receipt).encode()
            marker = destination / "acquisition-receipt.json"
            marker.write_bytes(raw)
            marker.chmod(0o600)
            result = {
                **summary,
                "acquisition_receipt": {
                    "path": marker.name,
                    "sha256": digest(raw),
                    "size_bytes": len(raw),
                },
            }
            if self.acquire_result_change:
                self.acquire_result_change(result)
            return json.dumps(result).encode()
        self.assertIn("--scan-child", argv)
        self.assertFalse((self.work / "auth-home").exists())
        config = self.work / "scan-input.json"
        with (
            mock.patch.object(
                caller._libraries()[1].local_oci_scan,
                "scan",
                side_effect=self.native_scan,
            ),
            mock.patch.object(caller, "_inspect", wraps=caller._inspect) as inspected,
            mock.patch.dict(os.environ, env, clear=True),
        ):
            result = caller.scan_child(config, digest(config.read_bytes()))
        image, output, source_sha, policy = inspected.call_args.args
        kwargs = inspected.call_args.kwargs
        self.assertEqual(image, self.invocation["logical_image"])
        self.assertEqual(output, self.work / "reports")
        self.assertEqual(source_sha, "a" * 40)
        self.assertEqual(policy, self.policy)
        self.assertEqual({k: kwargs[k] for k in caller.SCOPE}, caller.SCOPE)
        self.assertEqual(kwargs["expected_policy_sha256"], caller.POLICY_SHA256)
        if self.scan_change:
            self.scan_change(result)
        check()
        return json.dumps(result).encode()

    def native_scan(self, local, output, *, now=None):
        self.assertEqual(local.db_cache, self.bundle_root / "db")
        self.assertEqual(local.diff_ids, tuple(self.diff_ids))
        self.assertEqual(local.private_binding.producer_run_id, 12)
        output.mkdir(mode=0o700, exist_ok=True)
        (output / "sbom.spdx.json").write_text(
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
        )
        (output / "vulnerabilities.json").write_text(
            json.dumps({"matches": self.native_matches})
        )
        result = {
            "tools": {"syft": "synthetic test only", "grype": "synthetic test only"},
            "private_binding": local.private_binding._asdict(),
            "manifest_digest": local.manifest_digest,
            "config_digest": local.config_digest,
            "diff_ids": list(local.diff_ids),
            "database": {
                "installed_sha256": local.db_sha256,
                "installed_size_bytes": local.db_size,
                "import_metadata_sha256": local.import_sha256,
                "archive_sha256": local.db_archive_sha256,
                "preparation_receipt_sha256": local.preparation_receipt.sha256,
                "status": {
                    "valid": True,
                    "built": self.bundle["database"]["built"],
                    "schemaVersion": "v6.0.3",
                    "path": "/db/6/vulnerability.db",
                },
            },
        }
        if self.native_result_change:
            self.native_result_change(result)
        return result

    def run_cli(self):
        expected_hash = self.write_inputs()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.dict(os.environ, self.secrets, clear=True),
            mock.patch.object(caller, "_verify_tooling"),
            mock.patch.object(caller, "_execute", side_effect=self.execute),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = caller.main(
                [
                    "--invocation",
                    str(self.path),
                    "--expected-invocation-sha256",
                    expected_hash,
                    "--work-root",
                    str(self.work),
                ]
            )
        self.assertNotIn("SECRET", stderr.getvalue())
        return code, stdout.getvalue()

    def test_cli_two_children_exact_scope_policy_and_false_authority_after_cleanup(
        self,
    ):
        code, raw = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.events), 2)
        result = json.loads(raw)
        self.assertEqual(result["vulnerability_gate"], "success")
        for key in ("production_ready", "runtime_verified", "release_authorized"):
            self.assertIs(result[key], False)
        self.assertEqual(result["upstream_signature"], "blocked")
        self.assertFalse(self.work.exists())
        self.assertTrue((self.bundle_root / "db/6/vulnerability.db").exists())
        acquire, scan = self.events
        self.assertEqual(acquire[0][:2], [caller.PYTHON, "-I"])
        self.assertEqual(scan[0][:2], [caller.PYTHON, "-I"])
        self.assertIn("pycache_prefix=" + str(SCRIPT), scan[0])
        self.assertEqual(caller.sys.pycache_prefix, str(SCRIPT))
        for key in ("GH_TOKEN", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"):
            self.assertEqual(acquire[1][key], self.secrets[key])
            self.assertNotIn(key, scan[1])
        self.assertNotIn("HTTPS_PROXY", acquire[1])
        self.assertNotIn("PYTHONPATH", acquire[1])
        self.assertEqual(set(scan[1]), {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"})

    def test_preflight_scope_policy_and_bypass_before_any_child(self):
        for change in (
            lambda: self.invocation["scope"].update(channel="stable"),
            lambda: self.invocation["policy"].update(sha256="f" * 64),
            lambda: self.secrets.update(SECURITY_FINDINGS_BYPASS="true"),
        ):
            with self.subTest(change=change):
                original = copy.deepcopy(self.invocation)
                change()
                self.assertEqual(self.run_cli(), (1, ""))
                self.assertEqual(self.events, [])
                self.assertFalse(self.work.exists())
                self.invocation = original
                self.secrets.pop("SECURITY_FINDINGS_BYPASS", None)

    def test_static_scanners_accept_empty_runtime_inventory(self):
        self.bundle["runtime_files"] = []
        (self.bundle_root / "loader").unlink()
        self.write_inputs()
        bundle = caller._bundle(self.invocation["bundle"])
        self.assertEqual(bundle["runtime"], ())

    def test_missing_hash_and_substituted_bundle_rejected(self):
        self.write_inputs()
        with mock.patch.object(caller, "_execute") as command:
            for expected in ("0" * 64, "", "bad"):
                self.assertEqual(
                    caller.main(
                        [
                            "--invocation",
                            str(self.path),
                            "--expected-invocation-sha256",
                            expected,
                            "--work-root",
                            str(self.work),
                        ]
                    ),
                    1,
                )
        command.assert_not_called()

    def test_bundle_identity_paths_and_writability_fail_before_children(self):
        mutations = [
            lambda: self.bundle["tools"]["syft"].update(sha256="f" * 64),
            lambda: self.bundle["tools"]["grype"].update(version="999"),
            lambda: self.bundle["database"]["installed"].update(size_bytes=99),
            lambda: self.bundle["runtime_files"][0].update(path="../outside"),
            lambda: self.bundle["tools"]["bwrap"].update(path="syft"),
            lambda: self.bundle["database"].update(built="2020-01-01T00:00:00Z"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                old = copy.deepcopy(self.bundle)
                mutate()
                self.assertEqual(self.run_cli(), (1, ""))
                self.assertEqual(self.events, [])
                self.bundle = old
        (self.bundle_root / "syft").chmod(0o755)
        self.assertEqual(self.run_cli(), (1, ""))

    def test_receipt_substitution_gates_and_false_flags_rejected(self):
        for field, value in (
            ("producer_sha", "c" * 40),
            ("source_sha", "c" * 40),
            ("run_attempt", "2"),
            ("archive_sha256", "c" * 64),
            ("production_ready", True),
            ("schema_version", True),
        ):
            with self.subTest(field=field):
                self.receipt_change = lambda receipt, field=field, value=value: (
                    receipt.update({field: value})
                )
                self.assertEqual(self.run_cli(), (1, ""))
                self.assertFalse(self.work.exists())
        for field, value in (
            ("path", "../layout"),
            ("config_digest", "sha256:" + "e" * 64),
            ("diff_ids", ["sha256:" + "e" * 64]),
        ):
            with self.subTest(field=field):
                self.receipt_change = lambda receipt, field=field, value=value: receipt[
                    "layout"
                ].update({field: value})
                self.assertEqual(self.run_cli(), (1, ""))
        self.receipt_change = lambda receipt: receipt["verification"].update(
            attempt="not_run"
        )
        self.assertEqual(self.run_cli(), (1, ""))

    def test_descriptor_substitution_rejected_and_stale_workspace_not_deleted(self):
        for field, value in (
            ("path", "other.json"),
            ("sha256", "e" * 64),
            ("size_bytes", 1),
        ):
            self.acquire_result_change = lambda result, field=field, value=value: (
                result["acquisition_receipt"].update({field: value})
            )
            self.assertEqual(self.run_cli(), (1, ""))
        self.work.mkdir(mode=0o700)
        sentinel = self.work / "stale"
        sentinel.write_text("retain")
        self.assertEqual(self.run_cli(), (1, ""))
        self.assertEqual(sentinel.read_text(), "retain")

    def test_failure_interruption_and_cleanup_failure_never_print_success(self):
        for error in (
            ValueError("SECRET native failure"),
            InterruptedError("interrupted"),
            KeyboardInterrupt(),
        ):
            self.executor_error = error
            self.assertEqual(self.run_cli(), (1, ""))
            self.assertFalse(self.work.exists())
        self.executor_error = None
        with mock.patch.object(
            caller.shutil, "rmtree", side_effect=OSError("refuse cleanup")
        ):
            self.assertEqual(self.run_cli(), (1, ""))
        self.assertTrue(self.work.exists())

    def test_resource_admission_precedes_children_and_fast_growth_rejected(self):
        self.invocation["layout_max_bytes"] = caller.TOTAL_LIMIT
        self.assertEqual(self.run_cli(), (1, ""))
        self.assertEqual(self.events, [])
        self.invocation["layout_max_bytes"] = 1024**2
        old_execute = self.execute

        def overrun(*args, **kwargs):
            result = old_execute(*args, **kwargs)
            with (self.work / "oversize").open("wb") as stream:
                stream.truncate(caller.TOTAL_LIMIT)
            kwargs["check"]()
            return result

        with mock.patch.object(self, "execute", side_effect=overrun):
            self.assertEqual(self.run_cli(), (1, ""))
        self.assertFalse(self.work.exists())

    def test_scan_gate_cannot_be_bypassed_or_grant_authority(self):
        for change in (
            lambda result: result.update(vulnerability_gate="bypassed"),
            lambda result: result.update(release_authorized=True),
        ):
            self.scan_change = change
            self.assertEqual(self.run_cli(), (1, ""))

    def test_existing_evaluator_rejects_high_critical_unknown_without_exceptions(self):
        for severity in ("High", "Critical", "Unknown", "Medium"):
            with self.subTest(severity=severity):
                self.native_matches = [
                    {
                        "vulnerability": {"id": "SYNTHETIC-ONLY", "severity": severity},
                        "artifact": {
                            "name": "synthetic-package",
                            "version": "0",
                            "type": "rpm",
                        },
                    }
                ]
                code, raw = self.run_cli()
                self.assertEqual(code, 0 if severity == "Medium" else 1)
                if severity != "Medium":
                    self.assertEqual(raw, "")
                self.assertFalse(self.work.exists())

    def test_native_database_status_must_match_authenticated_preparation(self):
        for change in (
            lambda result: result["database"]["status"].update(
                built="2020-01-01T00:00:00Z"
            ),
            lambda result: result["database"].update(installed_sha256="f" * 64),
        ):
            self.native_result_change = change
            self.assertEqual(self.run_cli(), (1, ""))
            self.assertFalse(self.work.exists())

    def test_bundle_hash_missing_input_symlink_and_overlap_are_fail_closed(self):
        self.write_inputs()
        for descriptor in (
            {"path": str(self.bundle_path), "sha256": "f" * 64},
            {"path": str(self.bundle_path), "sha256": ""},
            {"path": str(self.root / "missing/bundle.json"), "sha256": "f" * 64},
        ):
            with self.assertRaises((ValueError, OSError)):
                caller._bundle(descriptor)
        loader = self.bundle_root / "loader"
        loader.unlink()
        loader.symlink_to(self.policy)
        self.assertEqual(self.run_cli(), (1, ""))
        self.assertTrue(self.policy.exists())
        loader.unlink()
        self.store("loader", b"synthetic runtime")
        self.work = self.bundle_root / "work"
        self.assertEqual(self.run_cli(), (1, ""))
        self.assertTrue(self.bundle_path.exists())

    def test_cleanup_refuses_changed_root_without_deleting_foreign_directory(self):
        moved = self.root / "moved"
        with (
            self.assertRaisesRegex(ValueError, "changed workspace"),
            caller._workspace(self.work),
        ):
            self.work.rename(moved)
            self.work.mkdir(mode=0o700)
            (self.work / "foreign").write_text("retain")
        self.assertTrue(moved.exists())
        self.assertEqual((self.work / "foreign").read_text(), "retain")

    def test_cli_normalizes_and_restores_umask_for_owned_lifecycle(self):
        expected = self.write_inputs()
        previous = os.umask(0o777)
        try:
            with mock.patch.object(self, "write_inputs", return_value=expected):
                code, _ = self.run_cli()
            observed = os.umask(0o777)
            self.assertEqual(observed, 0o777)
        finally:
            os.umask(previous)
        self.assertEqual(code, 0)
        self.assertFalse(self.work.exists())

    def test_internal_child_rejects_secrets_before_reading_configuration(self):
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "SECRET"}, clear=True),
            self.assertRaisesRegex(ValueError, "unauthorized environment"),
        ):
            caller.scan_child(self.work / "scan-input.json", "a" * 64)

    def test_tooling_verification_rejects_revision_and_dirty_checkout(self):
        for replies in ([b"wrong\n"], [b"b" * 40 + b"\n", b" M source\n"]):
            with (
                mock.patch.object(caller, "_execute", side_effect=replies),
                self.assertRaises(ValueError),
            ):
                caller._verify_tooling(
                    SCRIPT.parents[3], "b" * 40, self.work, lambda: None
                )

    def test_tooling_verification_compares_source_bytes_not_only_git_status(self):
        tree = (
            "100644 blob "
            + "a" * 40
            + "\t.github/scripts/workflow/private_core_scan.py\n"
        ).encode()
        with (
            mock.patch.object(
                caller,
                "_execute",
                side_effect=[b"b" * 40 + b"\n", b"", tree, b"c" * 40 + b"\n"],
            ),
            self.assertRaisesRegex(ValueError, "bytes differ"),
        ):
            caller._verify_tooling(SCRIPT.parents[3], "b" * 40, self.work, lambda: None)

    def test_receipt_ordered_diffids_cannot_be_reordered_without_decompression(self):
        manifest = json.loads(self.files["blobs/sha256/" + self.manifest_digest[7:]])
        config = json.loads(self.files["blobs/sha256/" + self.config_digest[7:]])
        payload = b"synthetic second layer"
        layer_digest = "sha256:" + digest(payload)
        self.files["blobs/sha256/" + layer_digest[7:]] = payload
        manifest["layers"].append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": len(payload),
            }
        )
        config["rootfs"]["diff_ids"].append(layer_digest)
        raw = json.dumps(config).encode()
        self.config_digest = "sha256:" + digest(raw)
        self.files["blobs/sha256/" + self.config_digest[7:]] = raw
        manifest["config"].update(digest=self.config_digest, size=len(raw))
        raw = json.dumps(manifest).encode()
        self.manifest_digest = "sha256:" + digest(raw)
        self.files["blobs/sha256/" + self.manifest_digest[7:]] = raw
        index = json.loads(self.files["index.json"])
        index["manifests"][0].update(digest=self.manifest_digest, size=len(raw))
        self.files["index.json"] = json.dumps(index).encode()
        self.diff_ids = config["rootfs"]["diff_ids"]
        self.invocation["acquisition"]["facts"]["manifest_digest"] = (
            self.manifest_digest
        )
        self.invocation["logical_image"] = (
            "ghcr.io/luminusos/luminusos@" + self.manifest_digest
        )
        self.receipt_change = lambda receipt: receipt["layout"].update(
            diff_ids=list(reversed(self.diff_ids))
        )
        with mock.patch.object(
            caller._libraries()[0].oci, "verify_diff_ids"
        ) as decompression:
            self.assertEqual(self.run_cli(), (1, ""))
        decompression.assert_not_called()

    def test_executor_fast_oversize_is_rejected_and_logs_removed(self):
        self.work.mkdir(mode=0o700)
        child = mock.Mock(pid=12345)
        child.poll.return_value = 0
        child.wait.return_value = 0

        def launch(*args, **kwargs):
            os.ftruncate(kwargs["stdout"].fileno(), caller.JSON_LIMIT + 1)
            return child

        with (
            mock.patch.object(caller.subprocess, "Popen", side_effect=launch),
            mock.patch.object(caller.os, "killpg"),
            self.assertRaisesRegex(ValueError, "output exceeded"),
        ):
            caller._execute(
                ["trusted"], env={}, work=self.work, seconds=1, check=lambda: None
            )
        self.assertEqual(list(self.work.iterdir()), [])

    def test_executor_hard_kills_even_when_graceful_wait_fails(self):
        self.work.mkdir(mode=0o700)
        child = mock.Mock(pid=12345)
        child.poll.return_value = None
        child.wait.side_effect = [OSError("wait failed"), 0]
        with (
            mock.patch.object(caller.subprocess, "Popen", return_value=child),
            mock.patch.object(caller.os, "killpg") as kill,
            self.assertRaises(OSError),
        ):
            caller._execute(
                ["trusted"],
                env={},
                work=self.work,
                seconds=1,
                check=mock.Mock(side_effect=ValueError("stop")),
            )
        self.assertIn(mock.call(12345, signal.SIGKILL), kill.call_args_list)

    def test_executor_fast_exit_limits_close_fds_groups_and_deadline(self):
        self.work.mkdir(mode=0o700)
        child = mock.Mock(pid=12345)
        child.poll.return_value = 0
        child.wait.return_value = 0
        checked = []
        with (
            mock.patch.object(caller.subprocess, "Popen", return_value=child) as popen,
            mock.patch.object(caller.os, "killpg") as kill,
        ):
            self.assertEqual(
                caller._execute(
                    ["trusted"],
                    env={"LANG": "C"},
                    work=self.work,
                    seconds=1,
                    check=lambda: checked.append(True),
                ),
                b"",
            )
        self.assertTrue(checked)
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertNotIn("pass_fds", popen.call_args.kwargs)
        kill.assert_called_with(12345, signal.SIGKILL)
        child.poll.return_value = None
        with (
            mock.patch.object(caller.subprocess, "Popen", return_value=child),
            mock.patch.object(caller.os, "killpg"),
            mock.patch.object(caller.time, "monotonic", side_effect=[0, 2]),
            self.assertRaises(ValueError),
        ):
            caller._execute(
                ["trusted"], env={}, work=self.work, seconds=1, check=lambda: None
            )


if __name__ == "__main__":
    unittest.main()
