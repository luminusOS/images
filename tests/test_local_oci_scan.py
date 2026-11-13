import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).parents[1] / ".github/scripts/workflow/local_oci_scan.py"
SPEC = importlib.util.spec_from_file_location("local_oci_scan", SCRIPT)
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)


def encoded(value):
    return json.dumps(value).encode()


class LocalScanTests(unittest.TestCase):
    def test_direct_failure_invalidates_prior_managed_outputs(self):
        output = self.root / "output"
        for failure in ("validation", "scanner", "unexpected"):
            for name in (
                "sbom.spdx.json",
                "vulnerabilities.json",
                "scan-evidence.json",
                "provenance.json",
            ):
                (output / name).write_bytes(b"old successful result")
            value = (
                self.input._replace(db_sha256="f" * 64)
                if failure == "validation"
                else self.input
            )
            error = (
                RuntimeError("unexpected executor failure")
                if failure == "unexpected"
                else OSError("scanner denied")
            )
            with (
                self.subTest(failure=failure),
                patch.object(local, "execute", side_effect=error),
                self.assertRaises((ValueError, OSError, RuntimeError)),
            ):
                local.scan(value, output, now=self.now)
            self.assertEqual(list(output.iterdir()), [])

    def test_direct_rejected_output_relationships_preserve_all_bytes(self):
        output = self.root / "output"
        receipt = output / "provenance.json"
        receipt.write_bytes(b"protected preparation receipt")
        value = self.input._replace(
            preparation_receipt=local.TrustedFile(receipt, local.sha256(receipt))
        )
        with patch.object(local, "execute") as execute, self.assertRaises(ValueError):
            local.scan(value, output, now=self.now)
        execute.assert_not_called()
        self.assertEqual(receipt.read_bytes(), b"protected preparation receipt")

    def test_second_publication_failure_invalidates_pair(self):
        output = self.root / "output"
        replace = os.replace

        def fail_second(source, destination, **kwargs):
            if Path(destination).name == "vulnerabilities.json":
                raise OSError("second publication failed")
            return replace(source, destination, **kwargs)

        with (
            patch.object(local, "execute", side_effect=self.executor),
            patch.object(local.os, "replace", side_effect=fail_second) as publish,
            self.assertRaises(OSError),
        ):
            local.scan(self.input, output, now=self.now)
        self.assertEqual(publish.call_count, 2)
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(list(self.input.scratch.iterdir()), [])

    def test_second_staging_write_failure_cleans_private_exclusive_stages(self):
        output = self.root / "output"
        opened = []
        open_file = os.open

        def fail_second(path, flags, *args, **kwargs):
            if flags & os.O_CREAT and Path(path).parent.parent == output:
                opened.append((path, flags, args[0]))
                if Path(path).name == "vulnerabilities.json":
                    raise OSError("second staging write failed")
            return open_file(path, flags, *args, **kwargs)

        with (
            patch.object(local, "execute", side_effect=self.executor),
            patch.object(local.os, "open", side_effect=fail_second),
            self.assertRaises(OSError),
        ):
            local.scan(self.input, output, now=self.now)
        self.assertEqual(len(opened), 2)
        for path, flags, mode in opened:
            self.assertEqual(Path(path).parent.parent, output)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_EXCL)
            self.assertEqual(mode, 0o600)
        self.assertEqual(list(output.iterdir()), [])
        self.assertEqual(list(self.input.scratch.iterdir()), [])

    def test_publication_does_not_truncate_hardlinked_trusted_tool(self):
        output = self.root / "output"
        destination = output / "sbom.spdx.json"
        self.input.syft.path.chmod(0o700)
        os.link(self.input.syft.path, destination)
        with patch.object(local, "execute", side_effect=self.executor):
            local.scan(self.input, output, now=self.now)
        self.assertEqual(local.sha256(self.input.syft.path), self.input.syft.sha256)
        self.assertNotEqual(
            destination.stat().st_ino, self.input.syft.path.stat().st_ino
        )
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_failed_cleanup_keeps_original_error_and_invalidates_success_first(self):
        output = self.root / "output"
        original = RuntimeError("unexpected executor failure")
        unlink = Path.unlink

        def execute(argv, work):
            for name in (
                "sbom.spdx.json",
                "vulnerabilities.json",
                "scan-evidence.json",
                "provenance.json",
            ):
                (output / name).write_bytes(b"partial result")
            raise original

        def denied(path, *args, **kwargs):
            if path == output / "sbom.spdx.json" and path.exists():
                raise PermissionError("cannot clean report")
            return unlink(path, *args, **kwargs)

        with (
            patch.object(local, "execute", side_effect=execute),
            patch.object(Path, "unlink", new=denied),
            self.assertRaises(RuntimeError) as raised,
        ):
            local.scan(self.input, output, now=self.now)
        self.assertIs(raised.exception, original)
        self.assertTrue(
            any("cleanup" in note for note in getattr(original, "__notes__", []))
        )
        for name in ("vulnerabilities.json", "scan-evidence.json", "provenance.json"):
            self.assertFalse((output / name).exists())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        for name in ("layout", "db", "output", "scratch", "tools"):
            (self.root / name).mkdir(mode=0o700)
        self.layout = self.root / "layout"
        self.now = datetime(2026, 11, 12, 12, tzinfo=UTC)
        layer_bytes = io.BytesIO()
        with tarfile.open(fileobj=layer_bytes, mode="w") as archive:
            content = b"synthetic fixture, not executed"
            member = tarfile.TarInfo("usr/share/proof.txt")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        self.layer = layer_bytes.getvalue()
        layer = self.blob(self.layer, "application/vnd.oci.image.layer.v1.tar")
        self.diff = layer["digest"]
        self.config = encoded(
            {
                "architecture": "amd64",
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": [self.diff]},
            }
        )
        config = self.blob(self.config, local.oci.CONFIG)
        self.manifest = encoded(
            {
                "schemaVersion": 2,
                "mediaType": local.oci.MANIFEST,
                "config": config,
                "layers": [layer],
            }
        )
        descriptor = self.blob(self.manifest, local.oci.MANIFEST)
        descriptor["annotations"] = {local.oci.REF: "core"}
        (self.layout / "index.json").write_bytes(
            encoded({"schemaVersion": 2, "manifests": [descriptor]})
        )
        (self.layout / "oci-layout").write_bytes(
            encoded({"imageLayoutVersion": "1.0.0"})
        )
        self.manifest_digest = descriptor["digest"]
        self.config_digest = config["digest"]
        self.tools = []
        for name in ("syft", "grype", "bwrap", "prlimit", "libc.so"):
            path = self.root / "tools" / name
            path.write_bytes(name.encode())
            path.chmod(0o500)
            self.tools.append(local.TrustedFile(path, local.sha256(path)))
        db = self.root / "db/6"
        db.mkdir()
        (db / "vulnerability.db").write_bytes(b"installed hydrated database")
        (db / "import.json").write_bytes(b'{"source":"manual import"}')
        receipt = self.root / "preparation.json"
        receipt.write_bytes(b"caller-approved preparation receipt")
        self.input = local.LocalOCIInput(
            layout=self.layout,
            manifest_digest=self.manifest_digest,
            config_digest=self.config_digest,
            diff_ids=(self.diff,),
            syft=self.tools[0],
            grype=self.tools[1],
            bwrap=self.tools[2],
            prlimit=self.tools[3],
            runtime_files=(),
            db_cache=self.root / "db",
            db_sha256=local.sha256(db / "vulnerability.db"),
            db_size=(db / "vulnerability.db").stat().st_size,
            import_sha256=local.sha256(db / "import.json"),
            preparation_receipt=local.TrustedFile(receipt, local.sha256(receipt)),
            db_archive_sha256="a" * 64,
            scratch=self.root / "scratch",
            private_binding=local.PrivateBinding(
                local.sha256(receipt), "owner/images", 123, 1, "c" * 64
            ),
            handoff_receipt=local.TrustedFile(receipt, local.sha256(receipt)),
        )

    def blob(self, raw, media):
        digest = hashlib.sha256(raw).hexdigest()
        target = self.layout / "blobs/sha256" / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return {"digest": "sha256:" + digest, "size": len(raw), "mediaType": media}

    def db_status(self, age=0):
        return {
            "valid": True,
            "schemaVersion": "v6.1.10",
            "built": (self.now - timedelta(seconds=age))
            .isoformat()
            .replace("+00:00", "Z"),
            "path": "/db/6/vulnerability.db",
        }

    def reports(self):
        sbom = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "root",
                }
            ],
            "packages": [
                {
                    "SPDXID": "root",
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": self.manifest_digest[7:],
                        }
                    ],
                }
            ],
        }
        scan = {
            "matches": [],
            "descriptor": {"db": {"status": self.db_status()}},
            "source": {
                "type": "image",
                "target": {
                    "imageID": self.config_digest,
                    "manifestDigest": self.manifest_digest,
                    "architecture": "",
                    "os": "",
                    "layers": [{"digest": self.diff}],
                    "manifest": base64.b64encode(self.manifest).decode(),
                    "config": base64.b64encode(self.config).decode(),
                },
            },
        }
        return sbom, scan

    def executor(self, argv, work):
        command = argv[len(argv) - argv[::-1].index("--") :]
        if "version" in command:
            return (
                "Version: " + ("1.34.2" if command[0] == "/tools/syft" else "0.101.1")
            ).encode()
        if "status" in command:
            return encoded(self.db_status())
        sbom, scan = self.reports()
        name = command[command.index("--file") + 1].split("/")[-1]
        (work / "reports" / name).write_bytes(
            encoded(sbom if command[0] == "/tools/syft" else scan)
        )
        return b""

    def test_native_scan_contract_and_cleanup(self):
        with patch.object(local, "execute", side_effect=self.executor) as execute:
            result = local.scan(self.input, self.root / "output", now=self.now)
        self.assertEqual(result["private_binding"]["producer_run_attempt"], 1)
        self.assertEqual(result["database"]["installed_sha256"], self.input.db_sha256)
        self.assertEqual(list(self.input.scratch.iterdir()), [])
        argv = execute.call_args_list[0].args[0]
        self.assertIn("--unshare-net", argv)
        self.assertIn("--clearenv", argv)
        self.assertNotIn("--tmpfs", argv)
        self.assertNotIn(str(Path.home()), argv)
        self.assertIn("oci-dir:/layout", execute.call_args_list[3].args[0])

    def test_db_boundaries_and_native_errors(self):
        for age in (-300, 432000):
            local.check_db_status(self.db_status(age), self.now)
        for age in (-301, 432001):
            with self.subTest(age=age), self.assertRaises(ValueError):
                local.check_db_status(self.db_status(age), self.now)
        for changes in (
            {"valid": False},
            {"error": "bad"},
            {"schemaVersion": "v5.0.0"},
            {"built": "2026-11-12T12:00:00+00:00"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                local.check_db_status(self.db_status() | changes, self.now)

    def test_wrong_version_or_hash_blocks_local_execution(self):
        for output in (b"Version: 0.0.0", b"x" * 4097):
            with (
                self.subTest(output_size=len(output)),
                patch.object(local, "execute", return_value=output) as run,
                self.assertRaises(ValueError),
            ):
                local.scan(self.input, self.root / "output", now=self.now)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(list(self.input.scratch.iterdir()), [])
        wrong = self.input._replace(
            preparation_receipt=self.input.preparation_receipt._replace(sha256="f" * 64)
        )
        with patch.object(local, "execute") as run, self.assertRaises(ValueError):
            local.scan(wrong, self.root / "output", now=self.now)
        run.assert_not_called()

    def test_report_bindings_reject_mismatches_not_any_package_checksum(self):
        for kind in (
            "root",
            "checksum",
            "document",
            "config",
            "diffid",
            "platform",
            "raw",
            "db",
        ):
            sbom, scan = self.reports()
            if kind == "root":
                sbom["relationships"] = []
            elif kind == "checksum":
                sbom["packages"][0]["checksums"].append(
                    {"algorithm": "SHA256", "checksumValue": "f" * 64}
                )
            elif kind == "document":
                del sbom["SPDXID"]
            elif kind == "config":
                scan["source"]["target"]["imageID"] = "sha256:" + "d" * 64
            elif kind == "diffid":
                scan["source"]["target"]["layers"] = []
            elif kind == "platform":
                scan["source"]["target"]["os"] = "windows"
            elif kind == "raw":
                scan["source"]["target"]["config"] = base64.b64encode(b"{}").decode()
            else:
                scan["descriptor"]["db"]["status"]["valid"] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                local.check_reports(self.input, sbom, scan, self.now)

    def test_layout_and_db_mutation_fail_closed(self):
        with patch.object(local, "execute", side_effect=self.executor):
            bad = self.input._replace(diff_ids=("sha256:" + "e" * 64,))
            with self.assertRaises(ValueError):
                local.scan(bad, self.root / "output", now=self.now)
        index = json.loads((self.layout / "index.json").read_bytes())
        index["manifests"] *= 2
        (self.layout / "index.json").write_bytes(encoded(index))
        with patch.object(local, "execute") as execute, self.assertRaises(ValueError):
            local.scan(self.input, self.root / "output", now=self.now)
        execute.assert_not_called()

    def test_mutation_and_sandbox_failure_cleanup(self):
        for mutate in (False, True):

            def run(argv, work, mutate=mutate):
                if not mutate:
                    raise OSError("bwrap denied")
                result = self.executor(argv, work)
                if "oci-dir:/layout" in argv:
                    (self.input.db_cache / "6/import.json").write_bytes(b"changed")
                return result

            with (
                self.subTest(mutate=mutate),
                patch.object(local, "execute", side_effect=run),
                self.assertRaises((ValueError, OSError)),
            ):
                local.scan(self.input, self.root / "output", now=self.now)
            self.assertEqual(list(self.input.scratch.iterdir()), [])

    def test_fast_exit_output_and_deadline_checked_before_read(self):
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                tempfile.TemporaryDirectory(dir=self.input.scratch) as work,
            ):
                work = Path(work)

                def start(*args, overflow=overflow, **kwargs):
                    kwargs["stdout"].write(
                        b"x" * (local.OUTPUT_LIMIT + 1 if overflow else 1)
                    )
                    kwargs["stdout"].flush()
                    return Mock(
                        pid=12345, poll=Mock(return_value=0), wait=Mock(return_value=0)
                    )

                with (
                    patch.object(local.subprocess, "Popen", side_effect=start),
                    patch.object(
                        local.time,
                        "monotonic",
                        side_effect=[0, 0 if overflow else local.WALL_SECONDS + 1],
                    ),
                    patch.object(local.os, "killpg") as kill,
                    patch.object(
                        Path, "read_bytes", side_effect=AssertionError("unbounded read")
                    ),
                    self.assertRaises(ValueError),
                ):
                    local.execute(["/trusted/bwrap"], work)
                kill.assert_called_once()

    def test_executor_sanitizes_host_environment_and_group_lifetime(self):
        with (
            tempfile.TemporaryDirectory(dir=self.input.scratch) as work,
            patch.object(local.subprocess, "Popen") as start,
            patch.object(local.os, "killpg") as kill,
        ):
            start.return_value.pid = 12345
            start.return_value.poll.return_value = 0
            start.return_value.wait.return_value = 0
            local.execute(["/trusted/bwrap"], Path(work))
            self.assertEqual(
                start.call_args.kwargs["env"], {"LANG": "C", "LC_ALL": "C"}
            )
            self.assertEqual(start.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertTrue(start.call_args.kwargs["close_fds"])
            self.assertTrue(start.call_args.kwargs["start_new_session"])
            kill.assert_called_once()

    def test_running_deadline_and_nonzero_exit_kill_group(self):
        for timed_out in (True, False):
            with (
                self.subTest(timed_out=timed_out),
                tempfile.TemporaryDirectory(dir=self.input.scratch) as work,
                patch.object(local.subprocess, "Popen") as start,
                patch.object(local.os, "killpg") as kill,
                patch.object(
                    local.time,
                    "monotonic",
                    side_effect=[0, local.WALL_SECONDS + 1 if timed_out else 0],
                ),
            ):
                start.return_value.pid = 12345
                start.return_value.poll.return_value = None if timed_out else 1
                start.return_value.wait.return_value = 1
                with self.assertRaises(ValueError):
                    local.execute(["/trusted/prlimit"], Path(work))
                kill.assert_called_once()
                self.assertFalse((Path(work) / "stdout").exists())

    def test_fast_exit_report_disk_and_file_count_checked(self):
        with (
            tempfile.TemporaryDirectory(dir=self.input.scratch) as work,
            patch.object(local.subprocess, "Popen") as start,
            patch.object(local.os, "killpg"),
        ):
            work = Path(work)
            (work / "reports").mkdir()
            with (work / "reports/oversize").open("wb") as stream:
                stream.truncate(local.WORK_LIMIT + 1)
            start.return_value.pid = 12345
            start.return_value.poll.return_value = 0
            with self.assertRaises(ValueError):
                local.execute(["/trusted/prlimit"], work)

    def test_final_db_freshness_and_input_mutations_are_not_silent(self):
        original = (self.input.db_cache / "6/import.json").read_bytes()
        for failure in ("stale_end", "import", "tool", "layout"):
            status_calls = 0

            def run(argv, work, failure=failure):
                nonlocal status_calls
                result = self.executor(argv, work)
                if "status" in argv:
                    status_calls += 1
                    if status_calls == 2 and failure == "stale_end":
                        return encoded(self.db_status(432001))
                if "oci-dir:/layout" in argv:
                    if failure == "import":
                        (self.input.db_cache / "6/import.json").write_bytes(b"changed")
                    elif failure == "tool":
                        self.input.syft.path.chmod(0o700)
                        self.input.syft.path.write_bytes(b"tampered")
                    elif failure == "layout":
                        (self.layout / "oci-layout").write_bytes(b"changed")
                return result

            with (
                self.subTest(failure=failure),
                patch.object(local, "execute", side_effect=run),
                self.assertRaises(ValueError),
            ):
                local.scan(self.input, self.root / "output", now=self.now)
            (self.input.db_cache / "6/import.json").write_bytes(original)
            self.input.syft.path.chmod(0o700)
            self.input.syft.path.write_bytes(b"syft")
            self.input.syft.path.chmod(0o500)
            (self.layout / "oci-layout").write_bytes(
                encoded({"imageLayoutVersion": "1.0.0"})
            )
            self.assertFalse((self.root / "output/sbom.spdx.json").exists())
            self.assertEqual(list(self.input.scratch.iterdir()), [])

    def test_runtime_aliases_readonly_binds_and_single_diffid_pass(self):
        runtime = local.RuntimeFile(self.tools[4], "/lib64/ld-linux-x86-64.so.2")
        value = self.input._replace(runtime_files=(runtime,))
        with (
            patch.object(local, "execute", side_effect=self.executor) as execute,
            patch.object(
                local.oci, "verify_diff_ids", wraps=local.oci.verify_diff_ids
            ) as verify,
        ):
            local.scan(value, self.root / "output", now=self.now)
        verify.assert_called_once()
        argv = execute.call_args.args[0]
        self.assertIn("--as=3221225472:3221225472", argv)
        self.assertEqual(argv[argv.index(str(self.tools[4].path)) - 1], "--ro-bind")
        for path in (value.layout, value.db_cache):
            self.assertEqual(argv[argv.index(str(path)) - 1], "--ro-bind")
        self.assertEqual(argv[argv.index("--remount-ro") + 1], "/dev")
        remounts = {argv[i + 1] for i, arg in enumerate(argv) if arg == "--remount-ro"}
        self.assertIn("/", remounts)
        for destination in ("/home/auth", "/", "/lib64/../../secret"):
            invalid = value._replace(
                runtime_files=(runtime._replace(destination=destination),)
            )
            with (
                self.subTest(destination=destination),
                patch.object(local, "execute") as run,
                self.assertRaises(ValueError),
            ):
                local.scan(invalid, self.root / "output", now=self.now)
            run.assert_not_called()
