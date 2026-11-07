import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / ".github/scripts/workflow/supply_chain.py"
SPEC = importlib.util.spec_from_file_location("supply_chain", SCRIPT)
supply_chain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supply_chain)


class SupplyChainTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
