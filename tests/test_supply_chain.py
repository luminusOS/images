import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / ".github/scripts/workflow/supply_chain.py"
SPEC = importlib.util.spec_from_file_location("supply_chain", SCRIPT)
supply_chain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supply_chain)


def local_input_paths(output):
    root = output.parent / "scan-inputs"
    trusted = supply_chain.local_oci_scan.TrustedFile(root / "trusted", "a" * 64)
    return SimpleNamespace(
        manifest_digest="sha256:" + "a" * 64,
        layout=root / "layout",
        db_cache=root / "db",
        scratch=root / "scratch",
        syft=trusted,
        grype=trusted,
        bwrap=trusted,
        prlimit=trusted,
        preparation_receipt=trusted,
        handoff_receipt=trusted,
        runtime_files=(),
    )


class SupplyChainTests(unittest.TestCase):
    def test_output_relationship_preflight_precedes_every_cleanup(self):
        local = supply_chain.local_oci_scan
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "output"
            output.mkdir(mode=0o700)
            trusted = local.TrustedFile(root / "trusted", "a" * 64)
            baseline = SimpleNamespace(
                layout=root / "layout",
                db_cache=root / "db",
                scratch=root / "scratch",
                syft=trusted,
                grype=trusted,
                bwrap=trusted,
                prlimit=trusted,
                preparation_receipt=trusted,
                handoff_receipt=trusted,
                runtime_files=(),
            )
            for field in (
                "layout",
                "db_cache",
                "scratch",
                "syft",
                "grype",
                "bwrap",
                "prlimit",
                "preparation_receipt",
                "handoff_receipt",
                "runtime_files",
                "exceptions",
            ):
                for name in (
                    "provenance.json",
                    "scan-evidence.json",
                    "sbom.spdx.json",
                    "vulnerabilities.json",
                ):
                    (output / name).write_bytes(b"protected input and previous output")
                managed = output / "provenance.json"
                args = vars(baseline).copy()
                exceptions = None
                if field in ("layout", "db_cache", "scratch"):
                    args[field] = output
                elif field == "exceptions":
                    exceptions = managed
                elif field == "runtime_files":
                    args[field] = (
                        local.RuntimeFile(
                            local.TrustedFile(managed, "b" * 64), "/lib64/libproof.so"
                        ),
                    )
                else:
                    args[field] = local.TrustedFile(managed, "b" * 64)
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                with (
                    self.subTest(field=field),
                    patch.object(local, "scan") as scan,
                    self.assertRaises(supply_chain.SupplyChainError),
                ):
                    supply_chain.inspect_image(
                        "invalid logical subject",
                        output,
                        "b" * 40,
                        exceptions,
                        expected_syft_version="1.34.2",
                        expected_grype_version="0.101.1",
                        local_input=SimpleNamespace(**args),
                    )
                scan.assert_not_called()
                self.assertEqual(
                    {p.name: p.read_bytes() for p in output.iterdir()}, before
                )

    def test_private_seam_requires_reviewed_policy_and_rejects_bypass_first(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            evidence = output / "scan-evidence.json"
            for bypass in ("false", "true"):
                evidence.write_text("stale previous success")
                with (
                    patch.dict(
                        "os.environ", {"SECURITY_FINDINGS_BYPASS": bypass}, clear=True
                    ),
                    patch.object(supply_chain, "_run") as run,
                    self.assertRaises(supply_chain.SupplyChainError),
                ):
                    supply_chain.inspect_image(
                        "repo@sha256:" + "a" * 64,
                        output,
                        "b" * 40,
                        expected_syft_version="1.34.2",
                        expected_grype_version="0.101.1",
                        local_input=local_input_paths(output),
                    )
                run.assert_not_called()
                self.assertFalse(evidence.exists())

    def test_private_seam_reuses_evaluator_and_separates_policy_identities(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            policy = Path(temp) / "reviewed-unit-fixture.json"
            policy.write_text(
                json.dumps(
                    {
                        "kind": "policy",
                        "schema_version": 2,
                        "evidence_class": "runtime",
                        "exceptions": [],
                    }
                )
            )
            policy_hash = hashlib.sha256(policy.read_bytes()).hexdigest()
            binding = {"handoff_policy_sha256": "d" * 64, "receipt_sha256": "e" * 64}

            def scan(local_input, destination, **kwargs):
                (destination / "sbom.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
                )
                (destination / "vulnerabilities.json").write_text(
                    json.dumps({"matches": []})
                )
                return {
                    "tools": {"syft": "Version: 1.34.2", "grype": "Version: 0.101.1"},
                    "private_binding": binding,
                }

            with (
                patch.dict("os.environ", {}, clear=True),
                patch.object(supply_chain.local_oci_scan, "scan", side_effect=scan),
                patch.object(supply_chain, "_run") as public_run,
            ):
                manifest = supply_chain.inspect_image(
                    "repo@sha256:" + "a" * 64,
                    output,
                    "b" * 40,
                    policy,
                    expected_syft_version="1.34.2",
                    expected_grype_version="0.101.1",
                    edition="core",
                    component_scope="core_payload",
                    channel="testing",
                    fedora="45",
                    expected_policy_sha256=policy_hash,
                    local_input=local_input_paths(output),
                )
            public_run.assert_not_called()
            value = json.loads(manifest.read_text())
            self.assertEqual(value["policy_sha256"], policy_hash)
            self.assertEqual(value["local_input"]["private_binding"], binding)
            self.assertEqual(value["image"], "repo@sha256:" + "a" * 64)
            self.assertEqual(value["security"]["gate"], "success")

    def test_private_policy_scope_hash_and_findings_fail_without_stale_success(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            policy = Path(temp) / "synthetic-unit-policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "kind": "policy",
                        "schema_version": 2,
                        "evidence_class": "runtime",
                        "exceptions": [],
                    }
                )
            )
            expected = hashlib.sha256(policy.read_bytes()).hexdigest()
            args = {
                "expected_syft_version": "1.34.2",
                "expected_grype_version": "0.101.1",
                "edition": "core",
                "component_scope": "core_payload",
                "channel": "testing",
                "fedora": "45",
                "expected_policy_sha256": expected,
                "local_input": local_input_paths(output),
            }
            for changes in (
                {"expected_policy_sha256": "f" * 64},
                {"component_scope": "installer_live"},
                {"expected_syft_version": "1.2.3"},
            ):
                (output / "scan-evidence.json").write_text("old success")
                with (
                    self.subTest(changes=changes),
                    patch.dict("os.environ", {}, clear=True),
                    patch.object(supply_chain.local_oci_scan, "scan") as scan,
                    self.assertRaises(supply_chain.SupplyChainError),
                ):
                    supply_chain.inspect_image(
                        "repo@sha256:" + "a" * 64,
                        output,
                        "b" * 40,
                        policy,
                        **(args | changes),
                    )
                scan.assert_not_called()
                self.assertFalse((output / "scan-evidence.json").exists())

            def vulnerable(value, destination, **kwargs):
                (destination / "sbom.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
                )
                (destination / "vulnerabilities.json").write_text(
                    json.dumps(
                        {
                            "matches": [
                                {
                                    "vulnerability": {
                                        "id": "CVE-2026-1234",
                                        "severity": "Critical",
                                    },
                                    "artifact": {"name": "pkg", "version": "1"},
                                }
                            ]
                        }
                    )
                )
                return {
                    "tools": {"syft": "Version: 1.34.2", "grype": "Version: 0.101.1"}
                }

            with (
                patch.dict("os.environ", {}, clear=True),
                patch.object(
                    supply_chain.local_oci_scan, "scan", side_effect=vulnerable
                ),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                supply_chain.inspect_image(
                    "repo@sha256:" + "a" * 64, output, "b" * 40, policy, **args
                )
            self.assertFalse((output / "scan-evidence.json").exists())
            self.assertFalse((output / "vulnerabilities.json").exists())

    def bypass_environment(self):
        return {
            "SECURITY_FINDINGS_BYPASS": "true",
            "GITHUB_REPOSITORY": "owner/images",
            "GITHUB_WORKFLOW_REF": "owner/images/.github/workflows/auto-testing.yml@refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "operator",
            "GITHUB_RUN_ID": "123",
            "GITHUB_SERVER_URL": "https://github.com",
            "BYPASS_CHANNEL": "testing",
        }

    def test_bypass_requires_exact_manual_fresh_auto_testing_context(self):
        with patch.dict("os.environ", self.bypass_environment(), clear=True):
            self.assertTrue(supply_chain.authorize_bypass())
        cases = {
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REF": "refs/heads/topic",
            "GITHUB_WORKFLOW_REF": "owner/images/.github/workflows/publish.yml@refs/heads/main",
            "GITHUB_REPOSITORY": "other/images",
            "BYPASS_CHANNEL": "stable",
            "BYPASS_CANDIDATE": "1",
            "BYPASS_VALIDATION": "2",
            "BYPASS_TESTING": "3",
            "BYPASS_TESTING_VALIDATION": "4",
            "BYPASS_VERSION": "45.20260101",
        }
        for field, value in cases.items():
            with (
                self.subTest(field=field),
                patch.dict(
                    "os.environ", self.bypass_environment() | {field: value}, clear=True
                ),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                supply_chain.authorize_bypass()

    def test_default_and_explicit_false_are_strict(self):
        for environment in (
            {},
            {"SECURITY_FINDINGS_BYPASS": "false", "GITHUB_EVENT_NAME": "schedule"},
        ):
            with patch.dict("os.environ", environment, clear=True):
                self.assertFalse(supply_chain.authorize_bypass())

    def test_bypass_audits_clean_and_vulnerable_scans(self):
        for severity in (None, "High", "Critical", "Unknown"):
            with (
                self.subTest(severity=severity),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary)
                summary = output / "summary.md"
                matches = (
                    []
                    if severity is None
                    else [
                        {
                            "vulnerability": {
                                "id": "CVE-2026-1234",
                                "severity": severity,
                            },
                            "artifact": {"name": "pkg", "version": "1.0"},
                        }
                    ]
                )

                def run(argv, matches=matches, **kwargs):
                    if argv[1] == "version":
                        return subprocess.CompletedProcess(
                            argv, 0, "Version: 1.2.3", ""
                        )
                    payload = (
                        {"spdxVersion": "SPDX-2.3", "packages": []}
                        if argv[0] == "syft"
                        else {"matches": matches}
                    )
                    Path(argv[argv.index("--file") + 1]).write_text(json.dumps(payload))
                    return subprocess.CompletedProcess(argv, 0, "", "")

                with (
                    patch.dict(
                        "os.environ",
                        self.bypass_environment()
                        | {"GITHUB_STEP_SUMMARY": str(summary)},
                        clear=True,
                    ),
                    patch.object(supply_chain.subprocess, "run", side_effect=run),
                ):
                    manifest = supply_chain.inspect_image(
                        "repo@sha256:" + "a" * 64,
                        output,
                        "b" * 40,
                        expected_syft_version="1.2.3",
                        expected_grype_version="1.2.3",
                    )
                audit = json.loads(manifest.read_text())["security"]
                self.assertEqual(audit["gate"], "bypassed")
                self.assertEqual(audit["actor"], "operator")
                self.assertEqual(audit["run_id"], "123")
                self.assertEqual(len(audit["findings"]), int(severity is not None))
                self.assertEqual(
                    json.loads((output / "provenance.json").read_text())["predicate"][
                        "security"
                    ],
                    audit,
                )
                self.assertIn("NOT eligible for promotion", summary.read_text())

    def test_rejects_tag(self):
        with self.assertRaises(supply_chain.SupplyChainError):
            supply_chain._digest_image("registry.example/image:latest")

    def test_bypass_does_not_relax_invalid_scanner_evidence(self):
        cases = [
            "not JSON",
            {"matches": {}},
            {"matches": [None]},
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2026-1234", "severity": "Severe"},
                        "artifact": {"name": "pkg", "version": "1"},
                    }
                ]
            },
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2026-1234", "severity": []},
                        "artifact": {"name": "pkg", "version": "1"},
                    }
                ]
            },
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2026-1234", "severity": "High"},
                        "artifact": {"name": "pkg"},
                    }
                ]
            },
        ]
        for fix in ([], "invalid", {"versions": "1.0"}, {"versions": [None]}):
            cases.append(
                {
                    "matches": [
                        {
                            "vulnerability": {
                                "id": "CVE-2026-1234",
                                "severity": "High",
                                "fix": fix,
                            },
                            "artifact": {"name": "pkg", "version": "1"},
                        }
                    ]
                }
            )
        for payload in cases:
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as temporary,
            ):

                def run(argv, payload=payload, **kwargs):
                    if argv[1] == "version":
                        return subprocess.CompletedProcess(
                            argv, 0, "Version: 1.2.3", ""
                        )
                    value = (
                        {"spdxVersion": "SPDX-2.3", "packages": []}
                        if argv[0] == "syft"
                        else payload
                    )
                    Path(argv[argv.index("--file") + 1]).write_text(
                        value if isinstance(value, str) else json.dumps(value)
                    )
                    return subprocess.CompletedProcess(argv, 0, "", "")

                with (
                    patch.dict("os.environ", self.bypass_environment(), clear=True),
                    patch.object(supply_chain.subprocess, "run", side_effect=run),
                    self.assertRaises(supply_chain.SupplyChainError),
                ):
                    supply_chain.inspect_image(
                        "repo@sha256:" + "a" * 64,
                        Path(temporary),
                        "b" * 40,
                        expected_syft_version="1.2.3",
                        expected_grype_version="1.2.3",
                    )
                self.assertFalse((Path(temporary) / "scan-evidence.json").exists())

    def test_bypass_does_not_relax_command_failures_or_digest(self):
        with (
            patch.dict("os.environ", self.bypass_environment(), clear=True),
            tempfile.TemporaryDirectory() as temporary,
        ):
            for image, error in (
                ("repo:tag", None),
                ("repo@sha256:" + "a" * 64, subprocess.CalledProcessError(1, "grype")),
            ):
                with (
                    self.subTest(image=image),
                    patch.object(supply_chain.subprocess, "run", side_effect=error),
                    self.assertRaises(supply_chain.SupplyChainError),
                ):
                    supply_chain.inspect_image(
                        image,
                        Path(temporary),
                        "b" * 40,
                        expected_syft_version="1.2.3",
                        expected_grype_version="1.2.3",
                    )

    def test_bypass_scanner_execution_failures_remain_fatal(self):
        for failed_tool in ("syft", "grype"):
            with (
                self.subTest(tool=failed_tool),
                tempfile.TemporaryDirectory() as temporary,
            ):

                def run(argv, failed_tool=failed_tool, **kwargs):
                    if argv[1] == "version":
                        return subprocess.CompletedProcess(
                            argv, 0, "Version: 1.2.3", ""
                        )
                    if argv[0] == failed_tool:
                        raise subprocess.CalledProcessError(1, argv)
                    Path(argv[argv.index("--file") + 1]).write_text(
                        json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
                    )
                    return subprocess.CompletedProcess(argv, 0, "", "")

                with (
                    patch.dict("os.environ", self.bypass_environment(), clear=True),
                    patch.object(supply_chain.subprocess, "run", side_effect=run),
                    self.assertRaisesRegex(
                        supply_chain.SupplyChainError, f"command failed: {failed_tool}"
                    ),
                ):
                    supply_chain.inspect_image(
                        "repo@sha256:" + "a" * 64,
                        Path(temporary),
                        "b" * 40,
                        expected_syft_version="1.2.3",
                        expected_grype_version="1.2.3",
                    )
                self.assertFalse((Path(temporary) / "scan-evidence.json").exists())

    def test_inspection_writes_digest_linked_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"

            def run(argv, **kwargs):
                if argv[1] == "version":
                    return subprocess.CompletedProcess(argv, 0, "Version: 1.2.3\n", "")
                if argv[0] == "syft":
                    Path(argv[argv.index("--file") + 1]).write_text(
                        json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}),
                        encoding="utf-8",
                    )
                elif argv[0] == "grype":
                    Path(argv[argv.index("--file") + 1]).write_text(
                        json.dumps({"matches": []}), encoding="utf-8"
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(supply_chain.subprocess, "run", side_effect=run):
                manifest = supply_chain.inspect_image(
                    "registry.example/image@sha256:" + "a" * 64,
                    output,
                    "b" * 40,
                    expected_syft_version="1.2.3",
                    expected_grype_version="1.2.3",
                )
            evidence = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(evidence["digest"], "a" * 64)
            self.assertEqual(
                set(evidence["files"]),
                {"sbom.spdx.json", "vulnerabilities.json", "provenance.json"},
            )

    def test_critical_finding_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            def run(argv, **kwargs):
                if argv[1] == "version":
                    return subprocess.CompletedProcess(argv, 0, "Version: 1.2.3", "")
                path = Path(argv[argv.index("--file") + 1])
                payload = (
                    {"spdxVersion": "SPDX-2.3", "packages": []}
                    if argv[0] == "syft"
                    else {
                        "matches": [
                            {
                                "vulnerability": {
                                    "id": "CVE-2025-1234",
                                    "severity": "Critical",
                                    "fix": {"versions": ["2.0"]},
                                },
                                "artifact": {"name": "pkg", "version": "1.0"},
                            },
                            {
                                "vulnerability": {
                                    "id": "CVE-2025-5678",
                                    "severity": "High",
                                },
                                "artifact": {"name": "other", "version": "3.0"},
                            },
                        ]
                    }
                )
                path.write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                patch.object(supply_chain.subprocess, "run", side_effect=run),
                self.assertRaises(supply_chain.SupplyChainError) as raised,
            ):
                supply_chain.inspect_image(
                    "repo@sha256:" + "a" * 64,
                    output,
                    "b" * 40,
                    expected_syft_version="1.2.3",
                    expected_grype_version="1.2.3",
                )
            self.assertIn(
                "Critical CVE-2025-1234: pkg 1.0 (fixed versions: 2.0)",
                str(raised.exception),
            )
            self.assertIn(
                "High CVE-2025-5678: other 3.0 (fixed versions: unknown)",
                str(raised.exception),
            )
            self.assertFalse((output / "scan-evidence.json").exists())
            self.assertTrue((output / "vulnerabilities.json").exists())

    def test_unexpected_tool_version_fails(self):
        with (
            patch.object(
                supply_chain.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["syft", "version"], 0, "Version: 9.9.0", ""
                ),
            ),
            self.assertRaises(supply_chain.SupplyChainError),
        ):
            supply_chain._version("syft", "1.2.3")

    def test_checksums_allowlist_and_sort_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "z.iso").write_bytes(b"z")
            (directory / "a.qcow2").write_bytes(b"a")
            (directory / "unrelated.txt").write_bytes(b"x")
            sums = supply_chain.write_checksums(directory)
            self.assertEqual(
                [line.split()[-1] for line in sums.read_text().splitlines()],
                ["a.qcow2", "z.iso"],
            )

    def test_checksums_recurse_evidence_and_reject_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            evidence = directory / "image-a"
            evidence.mkdir()
            (evidence / "vulnerabilities.json").write_text("{}")
            (evidence / "scan-evidence.json").write_text("{}")
            sums = supply_chain.write_checksums(directory)
            self.assertIn("image-a/vulnerabilities.json", sums.read_text())
            for name in ("candidate.json", "validation.json", "release-evidence.json"):
                (evidence / name).write_text("{}")
            sums = supply_chain.write_checksums(directory)
            for name in ("candidate.json", "validation.json", "release-evidence.json"):
                self.assertIn(f"image-a/{name}", sums.read_text())
            (directory / "bad\\n.iso").write_bytes(b"bad")
            with self.assertRaises(supply_chain.SupplyChainError):
                supply_chain.write_checksums(directory)

    def test_checksum_hashing_does_not_read_whole_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "large.iso"
            image.write_bytes(b"x" * 1024)
            with patch.object(
                Path, "read_bytes", side_effect=AssertionError("read_bytes called")
            ):
                self.assertEqual(len(supply_chain._file_hash(image)), 64)

    def test_checksums_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "artifact.iso").symlink_to(directory / "missing.iso")
            with self.assertRaises(supply_chain.SupplyChainError):
                supply_chain.write_checksums(directory)

    def test_exception_validation_rejects_expired_unjustified_and_broad(self):
        cases = [
            {
                "cve": "CVE-2025-1234",
                "package": "pkg",
                "reason": "justified reason",
                "expires": "2000-01-01",
            },
            {
                "cve": "CVE-2025-1234",
                "package": "pkg",
                "reason": "short",
                "expires": "2999-01-01",
            },
            {
                "cve": "CVE-2025-1234",
                "package": "*",
                "reason": "justified reason",
                "expires": "2999-01-01",
            },
        ]
        for entry in cases:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "exceptions.json"
                path.write_text(json.dumps({"exceptions": [entry]}))
                with self.assertRaises(supply_chain.SupplyChainError):
                    supply_chain._exceptions(path)

    def test_invalid_semver_and_signature_failure_are_rejected(self):
        with self.assertRaises(supply_chain.SupplyChainError):
            supply_chain._version("syft", "")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "artifact"
            target.write_text("x")
            with (
                patch.dict(
                    "os.environ",
                    self.bypass_environment() | {"COSIGN_PRIVATE_KEY": "secret"},
                ),
                patch.object(
                    supply_chain,
                    "_run",
                    side_effect=[None, supply_chain.SupplyChainError("bad signature")],
                ),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                supply_chain.sign_file(target, Path(temporary) / "key")

    def test_signing_verifies_detached_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "SHA256SUMS"
            key = Path(temporary) / "pub.pem"
            target.write_text("hash\n")
            with (
                patch.dict("os.environ", {"COSIGN_PRIVATE_KEY": "secret"}),
                patch.object(supply_chain, "_run") as command,
            ):
                self.assertEqual(
                    supply_chain.sign_file(target, key), Path(f"{target}.sig")
                )
            self.assertEqual(command.call_count, 2)
            self.assertIn("verify-blob", command.call_args_list[1].args[0])


class ScopedExceptionTests(unittest.TestCase):
    def test_local_seam_reuses_exact_scoped_exceptions_and_pretool_validation(self):
        output = self.root / "private-output"
        output.mkdir(mode=0o700)

        def scan(value, destination, **kwargs):
            (destination / "sbom.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})
            )
            (destination / "vulnerabilities.json").write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "vulnerability": {
                                    "id": self.entry["advisory"],
                                    "severity": "Critical",
                                },
                                "artifact": {
                                    "name": "pkg",
                                    "version": "1.0",
                                    "type": "rpm",
                                },
                            }
                        ]
                    }
                )
            )
            return {"tools": {"syft": "Version: 1.34.2", "grype": "Version: 0.101.1"}}

        args = {
            "expected_syft_version": "1.34.2",
            "expected_grype_version": "0.101.1",
            "now": self.now,
            **self.context,
            "local_input": local_input_paths(output),
        }
        digest = self.write_policy()
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(supply_chain.local_oci_scan, "scan", side_effect=scan),
        ):
            result = supply_chain.inspect_image(
                "repo@sha256:" + "a" * 64,
                output,
                "b" * 40,
                self.path,
                expected_policy_sha256=digest,
                **args,
            )
        self.assertEqual(
            json.loads(result.read_text())["scan"]["decision"], "accepted_risk"
        )
        for failure in ("expired", "evidence"):
            if failure == "expired":
                self.entry["expires_at"] = "2026-11-08T00:00:00Z"
            else:
                self.entry["expires_at"] = "2026-12-01T00:00:00Z"
                (self.root / "triage.txt").write_bytes(b"unreviewed changed evidence")
            digest = self.write_policy()
            with (
                self.subTest(failure=failure),
                patch.dict("os.environ", {}, clear=True),
                patch.object(supply_chain.local_oci_scan, "scan") as execute,
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                supply_chain.inspect_image(
                    "repo@sha256:" + "a" * 64,
                    output,
                    "b" * 40,
                    self.path,
                    expected_policy_sha256=digest,
                    **args,
                )
            execute.assert_not_called()
            self.assertFalse((output / "scan-evidence.json").exists())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "policy.json"
        self.now = datetime(2026, 11, 9, tzinfo=UTC)
        self.context = {
            "edition": "core",
            "component_scope": "core_payload",
            "channel": "testing",
            "fedora": "45",
        }
        evidence = b"Reviewed exact advisory; aliases require separate exact entries.\n"
        (self.root / "triage.txt").write_bytes(evidence)
        self.entry = {
            "advisory": "CVE-2026-1234",
            "package": "pkg",
            "package_version": "1.0",
            **self.context,
            "owner": "reviewer",
            "reason": "Reviewed temporary exact risk.",
            "classification": "accepted_risk",
            "component_type": "rpm",
            "issued_at": "2026-11-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
            "evidence": [
                {
                    "path": "triage.txt",
                    "size_bytes": len(evidence),
                    "sha256": hashlib.sha256(evidence).hexdigest(),
                }
            ],
        }
        self.policy = {
            "kind": "policy",
            "schema_version": 2,
            "evidence_class": "runtime",
            "exceptions": [self.entry],
        }

    def write_policy(self):
        raw = json.dumps(self.policy).encode()
        self.path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def load(self, **changes):
        args = {
            "context": self.context,
            "now": self.now,
            "expected_sha256": self.write_policy(),
        }
        return supply_chain._exceptions(self.path, **(args | changes))

    def inspect(self, artifact=None, advisory=None, sbom=None, failure=None, **changes):
        artifact = artifact or {"name": "pkg", "version": "1.0", "type": "rpm"}
        advisory = advisory or self.entry["advisory"]
        sbom = sbom or {"spdxVersion": "SPDX-2.3", "packages": []}
        digest = self.write_policy()

        def run(argv, **kwargs):
            if argv[1] == "version":
                return subprocess.CompletedProcess(argv, 0, "Version: 1.2.3", "")
            if failure == argv[0]:
                raise subprocess.CalledProcessError(1, argv)
            payload = (
                sbom
                if argv[0] == "syft"
                else {
                    "matches": [
                        {
                            "vulnerability": {"id": advisory, "severity": "Critical"},
                            "artifact": artifact,
                            "relatedVulnerabilities": [{"id": self.entry["advisory"]}],
                        }
                    ]
                }
            )
            Path(argv[argv.index("--file") + 1]).write_text(json.dumps(payload))
            return subprocess.CompletedProcess(argv, 0, "", "")

        args = dict(
            expected_syft_version="1.2.3",
            expected_grype_version="1.2.3",
            expected_policy_sha256=digest,
            now=self.now,
            **self.context,
        )
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(supply_chain.subprocess, "run", side_effect=run),
        ):
            path = supply_chain.inspect_image(
                "repo@sha256:" + "a" * 64,
                self.root / "out",
                "b" * 40,
                self.path,
                **(args | changes),
            )
        return json.loads(path.read_text())

    def test_exact_advisories_have_auditable_record_and_policy_hashes(self):
        for advisory in ("CVE-2026-1234", "GHSA-2345-6789-cfgh", "GO-2026-1234"):
            for classification in ("accepted_risk", "proven_false_positive"):
                with self.subTest(advisory=advisory, classification=classification):
                    self.entry.update(advisory=advisory, classification=classification)
                    result = self.inspect()
                    record = (
                        json.dumps(
                            self.entry,
                            sort_keys=True,
                            indent=2,
                            ensure_ascii=True,
                            allow_nan=False,
                        )
                        + "\n"
                    )
                    applied = hashlib.sha256(record.encode()).hexdigest()
                    self.assertEqual(result["scan"]["decision"], "accepted_risk")
                    self.assertEqual(result["scan"]["applied_exceptions"], [applied])
                    self.assertEqual(
                        result["security"]["exception_summary"], [self.entry]
                    )
                    self.assertEqual(
                        result["policy_sha256"],
                        hashlib.sha256(self.path.read_bytes()).hexdigest(),
                    )
                    provenance = json.loads(
                        (self.root / "out/provenance.json").read_text()
                    )
                    self.assertEqual(
                        provenance["predicate"]["inputs"]["exceptions_sha256"],
                        result["policy_sha256"],
                    )

    def test_rejects_malformed_unknown_duplicate_and_wildcard_records(self):
        changes = [
            {"advisory": "CVE-*"},
            {"advisory": "GHSA-invalid"},
            {"package": ""},
            {"package": "pkg*"},
            {"package_version": "1.*"},
            {"owner": ""},
            {"reason": "short"},
            {"classification": "waive"},
            {"component_type": "unknown"},
            {"evidence": []},
            {"unexpected": True},
            {"issued_at": "2026-11-01T00:00:00+00:00"},
            {"issued_at": "2026-02-30T00:00:00Z"},
            {"issued_at": "2026-11-10T00:00:00Z"},
            {"expires_at": "2026-12-01T00:00:00.000000001Z"},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.policy["exceptions"] = [self.entry | change]
                with self.assertRaises(supply_chain.SupplyChainError):
                    self.load()
        for records in (
            [self.entry, self.entry],
            [self.entry, self.entry | {"owner": "another-reviewer"}],
        ):
            self.policy["exceptions"] = records
            with self.assertRaises(supply_chain.SupplyChainError):
                self.load()

    def test_scope_clock_and_version_do_not_transfer(self):
        for change in (
            {"edition": "workstation", "component_scope": "workstation_payload"},
            {"component_scope": "installer_live"},
            {"channel": "stable"},
            {"fedora": "46"},
            {"fedora": 45},
            {"edition": "installer"},
        ):
            with (
                self.subTest(change=change),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                self.load(context=self.context | change)
        for clock in (
            "2026-11-09T00:00:00Z",
            self.now.replace(tzinfo=None),
            datetime(2026, 12, 1, tzinfo=UTC),
        ):
            with (
                self.subTest(clock=clock),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                self.load(now=clock)
        with self.assertRaises(supply_chain.SupplyChainError):
            self.inspect(artifact={"name": "pkg", "version": "1.1", "type": "rpm"})
        with self.assertRaises(supply_chain.SupplyChainError):
            self.inspect(advisory="GO-2026-1234")

    def test_rebinding_policy_does_not_renew_expired_exception(self):
        self.entry["reason"] += " Newly rebound bytes."
        with self.assertRaises(supply_chain.SupplyChainError):
            self.load(now=datetime(2026, 12, 1, tzinfo=UTC))
        self.entry["issued_at"] = "2026-11-01T00:00:00.000000001Z"
        with self.assertRaises(supply_chain.SupplyChainError):
            self.load(now=datetime(2026, 11, 1, tzinfo=UTC))

    def test_policy_hash_context_legacy_and_synthetic_are_fail_closed(self):
        digest = self.write_policy()
        self.path.write_bytes(self.path.read_bytes() + b"\n")
        with self.assertRaises(supply_chain.SupplyChainError):
            supply_chain._exceptions(
                self.path, context=self.context, now=self.now, expected_sha256=digest
            )
        for kwargs in ({}, {"context": self.context}, {"expected_sha256": digest}):
            with self.assertRaises(supply_chain.SupplyChainError):
                supply_chain._exceptions(self.path, now=self.now, **kwargs)
        for policy in (
            {"exceptions": []},
            self.policy | {"schema_version": True},
            self.policy | {"schema_version": 3},
            self.policy | {"evidence_class": "synthetic"},
            self.policy | {"unexpected": True},
        ):
            self.policy = policy
            with self.assertRaises(supply_chain.SupplyChainError):
                self.load()

    def test_evidence_bytes_duplicates_json_and_symlinks_are_rejected(self):
        original = self.entry["evidence"]
        for evidence in (
            [original[0] | {"path": "../triage.txt"}],
            [original[0] | {"sha256": "f" * 64}],
            [original[0] | {"size_bytes": True}],
            [original[0], original[0]],
        ):
            self.entry["evidence"] = evidence
            with self.assertRaises(supply_chain.SupplyChainError):
                self.load()
        self.entry["evidence"] = original
        self.write_policy()
        raw = self.path.read_bytes().replace(
            b'"schema_version": 2', b'"schema_version": 2, "schema_version": 2'
        )
        self.path.write_bytes(raw)
        with self.assertRaises(supply_chain.SupplyChainError):
            supply_chain._exceptions(
                self.path,
                context=self.context,
                now=self.now,
                expected_sha256=hashlib.sha256(raw).hexdigest(),
            )
        (self.root / "triage.txt").unlink()
        (self.root / "triage.txt").symlink_to(self.path)
        with self.assertRaises(supply_chain.SupplyChainError):
            self.load()

    def test_embedded_go_binds_observed_binary_hash_rpm_and_locations(self):
        binary = {
            "path": "/usr/bin/tool",
            "sha256": "c" * 64,
            "rpm_nevra": "tool-1.0-1.fc45.x86_64",
        }
        self.entry.update(component_type="embedded_go", binary=binary)
        artifact = {
            "name": "pkg",
            "version": "1.0",
            "type": "go-module",
            "locations": [{"path": "/usr/bin/tool"}],
        }
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "rpm",
                    "name": "tool",
                    "versionInfo": "1.0-1.fc45",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:rpm/fedora/tool@1.0-1.fc45?arch=x86_64",
                        }
                    ],
                }
            ],
            "files": [
                {
                    "SPDXID": "binary",
                    "fileName": "usr/bin/tool",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "c" * 64}],
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "rpm",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "binary",
                }
            ],
        }
        self.assertEqual(
            self.inspect(artifact=artifact, sbom=sbom)["scan"]["decision"],
            "accepted_risk",
        )
        for case in (
            "missing_owner",
            "invalid_owner_id",
            "duplicate_package_id",
            "invalid_package_id",
            "owner_without_purl",
            "conflicting_nevra",
        ):
            changed = copy.deepcopy(sbom)
            package = changed["packages"][0]
            if case in ("missing_owner", "invalid_owner_id", "owner_without_purl"):
                owner = None if case == "invalid_owner_id" else "second"
                changed["relationships"].append(
                    changed["relationships"][0] | {"spdxElementId": owner}
                )
                if case == "owner_without_purl":
                    changed["packages"].append(
                        package | {"SPDXID": owner, "externalRefs": []}
                    )
            elif case == "duplicate_package_id":
                changed["packages"].append(copy.deepcopy(package))
            elif case == "invalid_package_id":
                changed["packages"].append(package | {"SPDXID": []})
            else:
                package["externalRefs"].append(
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:rpm/fedora/tool@1.0-1.fc45?arch=aarch64",
                    }
                )
            with (
                self.subTest(case=case),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                self.inspect(artifact=artifact, sbom=changed)
        for field, value in (
            ("path", "/usr/bin/other"),
            ("sha256", "d" * 64),
            ("rpm_nevra", "tool-2.0-1.fc45.x86_64"),
        ):
            self.entry["binary"] = binary | {field: value}
            with (
                self.subTest(field=field),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                self.inspect(artifact=artifact, sbom=sbom)
        self.entry["binary"] = binary
        changed = copy.deepcopy(sbom)
        changed["files"][0]["checksums"] = []
        with self.assertRaises(supply_chain.SupplyChainError):
            self.inspect(artifact=artifact, sbom=changed)
        artifact["locations"].append({"path": "/usr/bin/other"})
        with self.assertRaises(supply_chain.SupplyChainError):
            self.inspect(artifact=artifact, sbom=sbom)

    def test_scanner_failures_cannot_be_excepted(self):
        for tool in ("syft", "grype"):
            with (
                self.subTest(tool=tool),
                self.assertRaises(supply_chain.SupplyChainError),
            ):
                self.inspect(failure=tool)
        self.assertFalse((self.root / "out/scan-evidence.json").exists())

    def test_cli_context_is_forwarded_without_inference(self):
        with patch.object(supply_chain, "inspect_image") as inspect:
            self.assertEqual(
                supply_chain.main(
                    [
                        "inspect",
                        "--image",
                        "repo@sha256:" + "a" * 64,
                        "--output",
                        str(self.root),
                        "--source-sha",
                        "b" * 40,
                        "--exceptions",
                        str(self.path),
                        "--syft-version",
                        "1.2.3",
                        "--grype-version",
                        "1.2.3",
                        "--edition",
                        "core",
                        "--component-scope",
                        "core_payload",
                        "--channel",
                        "testing",
                        "--fedora",
                        "45",
                        "--policy-sha256",
                        "d" * 64,
                    ]
                ),
                0,
            )
        self.assertEqual(inspect.call_args.kwargs["expected_policy_sha256"], "d" * 64)
        self.assertEqual(inspect.call_args.kwargs["component_scope"], "core_payload")


if __name__ == "__main__":
    unittest.main()
