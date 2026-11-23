import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apt_diagnostics", ROOT / ".github/scripts/workflow/apt_diagnostics.py"
)
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


class AptDiagnosticsTests(unittest.TestCase):
    def test_fixed_commands_clean_environment_and_bounds(self):
        completed = subprocess.CompletedProcess([], 0, "200", "hidden-secret")
        with (
            patch.object(diagnostics.subprocess, "run", return_value=completed) as run,
            patch.object(diagnostics, "source_summary", return_value={}),
            patch.dict(os.environ, {"HTTPS_PROXY": "hidden-secret"}),
        ):
            diagnostics.collect()
        calls = run.call_args_list
        expected = [
            (["apt-get", "--version"], 5),
            (["getent", "ahostsv4", "archive.ubuntu.com"], 5),
            (["getent", "ahostsv4", "security.ubuntu.com"], 5),
        ]
        for endpoint in (
            "https://archive.ubuntu.com/ubuntu/dists/noble/InRelease",
            "https://security.ubuntu.com/ubuntu/dists/noble-security/InRelease",
        ):
            expected.append(
                (
                    [
                        "curl",
                        "--disable",
                        "--fail",
                        "--silent",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "15",
                        "--output",
                        "/dev/null",
                        "--write-out",
                        "%{http_code}",
                        endpoint,
                    ],
                    20,
                )
            )
        self.assertEqual(len(calls), len(expected))
        for call, (arguments, timeout) in zip(calls, expected):
            self.assertEqual(call.args, (arguments,))
            self.assertEqual(
                call.kwargs,
                {
                    "env": {"PATH": os.defpath},
                    "capture_output": True,
                    "text": True,
                    "timeout": timeout,
                    "check": False,
                },
            )

    def test_success_and_failure_reports_are_redacted(self):
        results = [
            subprocess.CompletedProcess([], 0, "apt 2.8.3 (amd64)\nsecret", "secret"),
            subprocess.CompletedProcess([], 0, "1.2.3.4 alias-secret", "secret"),
            subprocess.CompletedProcess([], 2, "", "secret"),
            subprocess.CompletedProcess([], 0, "200", "secret"),
            subprocess.CompletedProcess([], 22, "503", "secret"),
        ]
        with (
            patch.object(diagnostics.subprocess, "run", side_effect=results),
            patch.object(diagnostics, "source_summary", return_value={}),
        ):
            report = diagnostics.collect()
        self.assertEqual(report["apt_version"], "2.8.3")
        self.assertTrue(report["dns"][0]["resolved"])
        self.assertFalse(report["dns"][1]["resolved"])
        self.assertEqual(report["https"][1]["http_status"], "503")
        self.assertEqual(report["https"][1]["returncode"], 22)
        self.assertNotIn("secret", json.dumps(report))

    def test_command_errors_are_nonfatal_and_redacted(self):
        failures = (
            subprocess.TimeoutExpired("secret", 5, output="secret", stderr="secret"),
            FileNotFoundError("secret"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(diagnostics.subprocess, "run", side_effect=failure),
                patch.object(diagnostics, "source_summary", return_value={}),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(diagnostics.main(), 0)
                report = json.loads(output.getvalue())
                self.assertEqual(report["apt_version"], "unknown")
                self.assertEqual(report["https"][0]["returncode"], "unknown")
                self.assertEqual(report["https"][0]["http_status"], "unknown")
                self.assertFalse(report["dns"][0]["resolved"])
                self.assertNotIn("secret", output.getvalue())

    def test_unexpected_stdout_is_not_logged(self):
        completed = subprocess.CompletedProcess([], 1, "secret\n200", "secret")
        with (
            patch.object(diagnostics.subprocess, "run", return_value=completed),
            patch.object(diagnostics, "source_summary", return_value={}),
        ):
            report = diagnostics.collect()
        self.assertEqual(report["apt_version"], "unknown")
        self.assertEqual(report["https"][0]["http_status"], "unknown")
        self.assertNotIn("secret", json.dumps(report))

    def test_source_files_only_report_public_hosts_and_known_suites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ubuntu.sources"
            path.write_text(
                "URIs: https://secret@archive.ubuntu.com/ubuntu/?token=secret\n"
                "URIs: https://thirdparty.invalid/secret\n"
                "URIs: https://archive.ubuntu.com.evil.invalid/\n"
                "URIs: http://azure.archive.ubuntu.com/ubuntu/\n"
                "Suites: noble noble-updates noble-backports noble-security\n"
            )
            observed = diagnostics.source_summary(path)
            self.assertEqual(
                observed,
                {
                    "exists": True,
                    "ubuntu_hosts": ["archive.ubuntu.com", "azure.archive.ubuntu.com"],
                    "suites": [
                        "noble",
                        "noble-backports",
                        "noble-security",
                        "noble-updates",
                    ],
                },
            )
            self.assertNotIn("secret", json.dumps(observed))
            missing = diagnostics.source_summary(Path(directory) / "missing")
            self.assertFalse(missing["exists"])
        with patch.object(Path, "open", side_effect=PermissionError("secret")):
            unreadable = diagnostics.source_summary(Path("/unreadable"))
        self.assertEqual(unreadable["exists"], "unknown")
        self.assertNotIn("secret", json.dumps(unreadable))


if __name__ == "__main__":
    unittest.main()
