import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
import install_feasibility as vmlib
import validation_driver as driver

SPEC = importlib.util.spec_from_file_location(
    "boot_test", ROOT / ".github/scripts/boot-test.py"
)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)
sys.path.insert(0, str(ROOT / "tests"))
import test_boot_smoke as boot_fixtures

LISTING = (
    "systemd-random-seed.service loaded failed failed Load/Save OS Random Seed\n"
    "getty@tty1.service loaded failed failed Getty on tty1\n"
)
MALICIOUS = (
    "$(touch${IFS}/tmp/pwned).service loaded failed failed x\n"
    "a;reboot.service loaded failed failed x\n"
    "-u.service loaded failed failed x\n"
    "dev-disk-by\\x2duuid.swap loaded failed failed x\n"
    "x`id`.mount loaded failed failed x\n"
    "● bullet.service loaded failed failed x\n"
)
JOURNAL = "".join(f"[    {n}.0] random-seed: line {n}\n" for n in range(1, 16))


def done(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class Recorder:
    def __init__(self, fail=()):
        self.calls = []
        self.fail = fail

    def __call__(self, name, command):
        self.calls.append((name, command))
        for word, error in self.fail:
            if word in command:
                raise error
        if command.startswith("journalctl -b --no-pager -o short-monotonic -u "):
            return done(JOURNAL)
        return done("")


class HelperTests(unittest.TestCase):
    def test_each_failed_unit_gets_status_and_journal_then_boot_context(self):
        run = Recorder()
        excerpt = vmlib.failed_unit_diagnostics(run, "base-boot", LISTING)
        self.assertEqual(
            run.calls,
            [
                (
                    "base-boot-unit-1-status",
                    "systemctl status --no-pager -l -- systemd-random-seed.service",
                ),
                (
                    "base-boot-unit-1-journal",
                    (
                        "journalctl -b --no-pager -o short-monotonic"
                        " -u systemd-random-seed.service"
                    ),
                ),
                (
                    "base-boot-unit-2-status",
                    "systemctl status --no-pager -l -- getty@tty1.service",
                ),
                (
                    "base-boot-unit-2-journal",
                    "journalctl -b --no-pager -o short-monotonic -u getty@tty1.service",
                ),
                (
                    "base-boot-avc",
                    (
                        "journalctl -b --no-pager -o short-monotonic _TRANSPORT=audit"
                        " | grep -E 'avc|denied' | tail -200"
                    ),
                ),
                ("base-boot-systemd-state", "ls -laZ /var/lib/systemd"),
                (
                    "base-boot-mounts",
                    "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS",
                ),
            ],
        )
        self.assertIn("--- systemd-random-seed.service", excerpt)
        self.assertIn("line 15", excerpt)
        self.assertIn("line 6", excerpt)
        self.assertNotIn("line 5\n", excerpt)

    def test_malicious_unit_names_never_reach_a_command(self):
        run = Recorder()
        excerpt = vmlib.failed_unit_diagnostics(run, "p", MALICIOUS + LISTING)
        units = [c for n, c in run.calls if "-unit-" in n]
        self.assertEqual(len(units), 4)
        for command in units:
            self.assertTrue(
                command.endswith(("systemd-random-seed.service", "getty@tty1.service"))
            )
        for bad in ("$(", ";", "`", "\\x2d", "-u.service", "bullet"):
            self.assertNotIn(bad, " ".join(units))
        self.assertNotIn("pwned", excerpt)
        self.assertEqual(vmlib.failed_unit_names(MALICIOUS), [])

    def test_unit_count_is_bounded(self):
        listing = "".join(f"u{n}.service loaded failed failed x\n" for n in range(30))
        run = Recorder()
        vmlib.failed_unit_diagnostics(run, "p", listing)
        statuses = [n for n, _ in run.calls if n.endswith("-status")]
        self.assertEqual(len(statuses), vmlib.MAX_DIAGNOSED_UNITS)

    def test_diagnostic_errors_are_reported_not_raised(self):
        for error in (
            driver.CheckFailed("journal timed out after 300 s"),
            subprocess.TimeoutExpired("ssh", 300),
            OSError("broken pipe"),
        ):
            run = Recorder(fail=(("journalctl", error), ("ls -laZ", error)))
            with self.subTest(error=type(error).__name__):
                excerpt = vmlib.failed_unit_diagnostics(run, "p", LISTING)
                self.assertIn("journal unavailable", excerpt)
                self.assertEqual(run.calls[-1][0], "p-mounts")


class DriverHealthTests(unittest.TestCase):
    def guest(self, results, fail=()):
        directory = Path(tempfile.mkdtemp())
        commands = []

        class Guest:
            def run(self, name, command, **_kwargs):
                commands.append((name, command))
                for word, error in fail:
                    if word in command:
                        raise error
                if name in results:
                    return ["ssh", command], results[name]
                if "-unit-" in name and name.endswith("-journal"):
                    return ["ssh", command], done(JOURNAL)
                return ["ssh", command], done("")

        guest = Guest()
        guest.directory = directory
        return guest, commands

    def test_healthy_system_runs_no_diagnostics(self):
        guest, commands = self.guest({"base-boot-state": done("running\n")})
        driver.system_health(guest, "base-boot")
        self.assertEqual(
            commands, [("base-boot-state", "systemctl is-system-running --wait")]
        )

    def test_degraded_system_records_every_failed_unit_and_still_fails(self):
        guest, commands = self.guest(
            {
                "base-boot-state": done("degraded\n", 1),
                "base-boot-failed": done(LISTING),
            }
        )
        with self.assertRaises(driver.CheckFailed) as raised:
            driver.system_health(guest, "base-boot")
        message = str(raised.exception)
        self.assertIn("system is 'degraded'", message)
        self.assertIn("systemd-random-seed.service", message)
        self.assertIn("line 15", message)
        names = [name for name, _ in commands]
        for expected in (
            "base-boot-failed",
            "base-boot-unit-1-status",
            "base-boot-unit-1-journal",
            "base-boot-unit-2-status",
            "base-boot-unit-2-journal",
            "base-boot-avc",
            "base-boot-systemd-state",
            "base-boot-mounts",
        ):
            self.assertIn(expected, names)

    def test_diagnostic_timeouts_keep_the_original_failure(self):
        timeout = driver.CheckFailed("timed out after 300 s")
        guest, commands = self.guest(
            {
                "first-boot-state": done("degraded\n", 1),
                "first-boot-failed": done(LISTING),
            },
            fail=(("journalctl", timeout), ("systemctl status", timeout)),
        )
        with self.assertRaisesRegex(driver.CheckFailed, "system is 'degraded'"):
            driver.system_health(guest, "first-boot")
        self.assertEqual(commands[-1][0], "first-boot-mounts")
        guest, _ = self.guest(
            {"first-boot-state": done("degraded\n", 1)},
            fail=(("--failed", timeout),),
        )
        with self.assertRaisesRegex(
            driver.CheckFailed, "system is 'degraded', failed units: 'unavailable"
        ):
            driver.system_health(guest, "first-boot")

    def test_guest_transcripts_land_in_the_diagnostics_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            vm = vmlib.VM(3, Path(), Path("k"), "", Path(tmp), Path(), Path())
            guest = driver.Guest(vm, Path(tmp))
            outputs = {
                "systemctl is-system-running --wait": done("degraded\n", 1),
                vmlib.FAILED_UNITS: done(LISTING),
            }

            def ssh(argv, **_kwargs):
                return outputs.get(argv[-1], done(JOURNAL))

            with (
                mock.patch.object(driver.subprocess, "run", side_effect=ssh),
                self.assertRaises(driver.CheckFailed),
            ):
                driver.system_health(guest, "base-boot")
            written = {path.stem for path in Path(tmp).glob("*.txt")}
            self.assertLessEqual(
                {
                    "base-boot-unit-1-status",
                    "base-boot-unit-1-journal",
                    "base-boot-avc",
                    "base-boot-systemd-state",
                    "base-boot-mounts",
                },
                written,
            )


BOOT_HEALTHY = boot_fixtures.HEALTHY


class BootGateDiagnosticsTests(unittest.TestCase):
    def check(self, fail=(), **overrides):
        calls = []

        def remote(name, command, timeout):
            calls.append(name)
            for word, error in fail:
                if word in command:
                    raise error
            if name.startswith("diagnostics-") and name.endswith("-journal"):
                return done(JOURNAL)
            return {**BOOT_HEALTHY, **overrides}.get(name, done(""))

        return boot.guest_checks(remote), calls

    def test_healthy_disk_runs_no_diagnostics(self):
        problems, calls = self.check()
        self.assertEqual(problems, [])
        self.assertEqual(calls, list(BOOT_HEALTHY))

    def test_failed_units_are_diagnosed_and_the_gate_still_fails(self):
        problems, calls = self.check(
            **{
                "is-system-running": done("degraded\n", 1),
                "failed-units": done(LISTING),
            }
        )
        self.assertIn("system is 'degraded' (1)", problems)
        self.assertTrue(any("line 15" in p for p in problems))
        for name in (
            "diagnostics-unit-1-status",
            "diagnostics-unit-1-journal",
            "diagnostics-unit-2-journal",
            "diagnostics-avc",
            "diagnostics-systemd-state",
            "diagnostics-mounts",
        ):
            self.assertIn(name, calls)

    def test_diagnostic_errors_do_not_change_the_failure(self):
        error = subprocess.TimeoutExpired("ssh", 300)
        problems, calls = self.check(
            fail=(("journalctl", error), ("systemctl status", error)),
            **{
                "is-system-running": done("degraded\n", 1),
                "failed-units": done(LISTING),
            },
        )
        self.assertEqual(problems[0], "system is 'degraded' (1)")
        self.assertTrue(problems[1].startswith("failed units: systemd-random-seed"))
        self.assertIn("diagnostics-mounts", calls)
        self.assertEqual(calls[-1], "restorecon")

    def test_boot_evidence_keeps_the_diagnostic_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            vm = vmlib.VM(3, Path(), Path("k"), "", Path(tmp), Path(), Path())
            outputs = {
                "systemctl is-system-running --wait": done("degraded\n", 1),
                vmlib.FAILED_UNITS: done(LISTING),
            }

            def ssh(argv, **_kwargs):
                return outputs.get(argv[-1], done(JOURNAL))

            with (
                mock.patch.object(vmlib, "wait_for_ssh"),
                mock.patch.object(vmlib.subprocess, "run", side_effect=ssh),
                self.assertRaisesRegex(RuntimeError, "unhealthy"),
            ):
                boot.check_guest(vm)
            out = Path(tmp)
            for name in (
                "diagnostics-unit-1-status",
                "diagnostics-unit-1-journal",
                "diagnostics-avc",
                "diagnostics-systemd-state",
                "diagnostics-mounts",
            ):
                self.assertTrue((out / f"{name}.stdout").is_file(), name)
            summary = json.loads((out / "guest-checks.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertTrue(any("line 15" in p for p in summary["problems"]))


if __name__ == "__main__":
    unittest.main()
