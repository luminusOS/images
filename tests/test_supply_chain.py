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
    def test_rejects_tag(self):
        with self.assertRaises(supply_chain.SupplyChainError):
            supply_chain._digest_image("registry.example/image:latest")

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
                patch.dict("os.environ", {"COSIGN_PRIVATE_KEY": "secret"}),
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
