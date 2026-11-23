import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_mount_probe", ROOT / ".github/scripts/ci-mount-probe.py"
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class MountProbeTests(unittest.TestCase):
    def test_only_packaging_jobs_use_pinned_runner(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())[
            "jobs"
        ]
        self.assertEqual(
            {
                name
                for name, job in jobs.items()
                if job.get("runs-on") == "ubuntu-24.04"
            },
            {"iso", "qcow2"},
        )

    def test_namespace_setup_and_cleanup_on_success_or_failure(self):
        for denied in (False, True):
            sources = []

            def execute(command, sources=sources, denied=denied, **kwargs):
                source = Path(command[command.index("--bind") + 1])
                sources.append(source)
                self.assertTrue(source.is_dir())
                for flag in (
                    "--die-with-parent",
                    "--new-session",
                    "--unshare-ipc",
                    "--unshare-pid",
                    "--unshare-net",
                ):
                    self.assertIn(flag, command)
                self.assertNotIn("--unshare-user", command)
                self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
                self.assertIn("CAP_SYS_ADMIN", command)
                self.assertEqual(
                    command[-4:], ["--", "/usr/bin/python3", probe.SCRIPT, "--child"]
                )
                self.assertEqual(command.count("--tmpfs"), 2)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(set(kwargs["env"]), {"PATH", "PYTHONUNBUFFERED"})
                self.assertTrue(kwargs["check"])
                self.assertEqual(kwargs["timeout"], 30)
                if denied:
                    raise subprocess.CalledProcessError(1, ["bwrap"])

            with (
                self.subTest(denied=denied),
                patch.object(probe.shutil, "which", return_value="/usr/bin/tool"),
                patch.object(probe, "security_context"),
                patch.object(probe.subprocess, "run", side_effect=execute) as run,
                patch.object(sys, "argv", ["ci-mount-probe.py"]),
                patch("sys.stderr", new_callable=io.StringIO) as stderr,
            ):
                self.assertEqual(probe.main(), int(denied))
                run.assert_called_once()
                self.assertFalse(sources[0].exists())
                if denied:
                    self.assertIn("packaging cannot continue", stderr.getvalue())

    def test_missing_tools_fail_explicitly_without_starting_sandbox(self):
        for missing in ("bwrap", "mount", "python3"):
            with (
                self.subTest(missing=missing),
                patch.object(
                    probe.shutil,
                    "which",
                    side_effect=lambda tool, missing=missing: (
                        None if tool == missing else "/usr/bin/tool"
                    ),
                ),
                patch.object(probe.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, f"required tool.*{missing}"),
            ):
                probe.run_probe()
            run.assert_not_called()

    def test_child_tests_compound_mount_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = Path(directory) / "storage"
            with (
                patch.object(probe, "STORAGE", storage),
                patch.object(probe, "security_context") as context,
                patch.object(probe.subprocess, "run") as run,
            ):
                run.side_effect = subprocess.CalledProcessError(32, ["mount"])
                with self.assertRaises(subprocess.CalledProcessError):
                    probe.probe_child()
                self.assertTrue(storage.is_dir())
                context.assert_called_once_with("bwrap child")
                run.assert_called_once_with(
                    [
                        "mount",
                        "--make-private",
                        "-o",
                        "rbind,rw,0755",
                        probe.SOURCE,
                        str(storage),
                    ],
                    check=True,
                )

    def test_diagnostics_only_print_allowlisted_process_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "attr").mkdir()
            (proc / "attr/current").write_text("unconfined\n")
            (proc / "status").write_text(
                "Name:\tprivate-name\nCapEff:\tffff\nNoNewPrivs:\t1\nSeccomp:\t2\n"
            )
            with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                probe.security_context("test", proc)
            output = stdout.getvalue()
            self.assertIn("attr/current=unconfined", output)
            self.assertIn("CapEff:", output)
            self.assertIn("NoNewPrivs:", output)
            self.assertIn("Seccomp:", output)
            self.assertNotIn("private-name", output)
