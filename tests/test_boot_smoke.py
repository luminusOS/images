import importlib.util
import json
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "boot_test", ROOT / ".github/scripts/boot-test.py"
)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


class BootSmokeTests(unittest.TestCase):
    def test_cancellation_terminates_qemu_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, code, template = (
                root / "image.iso",
                root / "code.fd",
                root / "template.fd",
            )
            for path in (image, code, template):
                path.touch()
            with (
                patch.object(
                    sys, "argv", ["boot-test.py", "iso", str(image), str(root / "out")]
                ),
                patch.object(boot, "resolve_ovmf", return_value=(code, template)),
                patch.object(boot.subprocess, "Popen") as popen,
                patch.object(boot.time, "sleep", side_effect=KeyboardInterrupt),
                patch.object(boot.os, "killpg") as killpg,
            ):
                popen.return_value.pid = 1234
                self.assertEqual(boot.main(), 130)
                killpg.assert_called_once_with(1234, signal.SIGTERM)
                popen.return_value.wait.assert_called_once_with(timeout=10)


def done(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def home_mount(fstype="btrfs", options="rw,relatime,subvol=/home", count=1):
    return json.dumps(
        {
            "filesystems": [
                {
                    "target": "/var/home",
                    "source": "/dev/vda4[/home]",
                    "fstype": fstype,
                    "options": options,
                }
            ]
            * count
        }
    )


HEALTHY = {
    "is-system-running": done("running\n"),
    "failed-units": done(""),
    "var-home-mount": done(home_mount()),
    "home-link": done("/var/home\n"),
}


class GuestGateTests(unittest.TestCase):
    def check(self, **overrides):
        calls = []

        def remote(name, command, timeout):
            calls.append((name, command))
            if name.startswith("diagnostics-"):
                return done("")
            return {**HEALTHY, **overrides}[name]

        return boot.guest_checks(remote), calls

    def test_healthy_disk_passes_with_the_exact_commands(self):
        problems, calls = self.check()
        self.assertEqual(problems, [])
        self.assertEqual(
            calls,
            [
                ("is-system-running", "systemctl is-system-running --wait"),
                (
                    "failed-units",
                    "systemctl --failed --no-legend --plain --no-pager",
                ),
                (
                    "var-home-mount",
                    "findmnt -J --mountpoint /var/home -o TARGET,SOURCE,FSTYPE,OPTIONS",
                ),
                ("home-link", "readlink -f /home"),
            ],
        )

    def test_degraded_boot_is_rejected(self):
        for overrides in (
            {
                "is-system-running": done("degraded\n", 1),
                "failed-units": done("home.mount loaded failed failed /home\n"),
            },
            {"is-system-running": done("running\n", 1)},
            {"is-system-running": done("", 255, "timed out")},
            {"failed-units": done("x.service loaded failed failed X\n")},
            {"failed-units": done("", 1)},
        ):
            with self.subTest(overrides=overrides):
                self.assertTrue(self.check(**overrides)[0])

    def test_home_mounted_layout_is_rejected(self):
        # The old disk.yaml mounted the subvolume at /home: home.mount fails
        # and nothing is mounted at /var/home.
        problems, _ = self.check(
            **{
                "is-system-running": done("degraded\n", 1),
                "failed-units": done("home.mount loaded failed failed /home\n"),
                "var-home-mount": done("", 1),
            }
        )
        self.assertIn("/var/home is not a mount point", problems)
        for overrides in (
            {"var-home-mount": done(home_mount(fstype="xfs"))},
            {"var-home-mount": done(home_mount(options="rw,subvol=/root"))},
            {"var-home-mount": done(home_mount(options="rw,subvol=/home2"))},
            {"var-home-mount": done(home_mount(count=2))},
            {"var-home-mount": done("not json")},
            {"home-link": done("/home\n")},
        ):
            with self.subTest(overrides=overrides):
                self.assertTrue(self.check(**overrides)[0])

    def test_both_subvol_spellings_are_the_home_subvolume(self):
        for options in ("rw,subvol=/home", "rw,subvolid=257,subvol=home"):
            self.assertEqual(boot.home_problems(home_mount(options=options)), [])


class CheckGuestTests(unittest.TestCase):
    def test_guest_results_are_saved_with_the_boot_evidence(self):
        for results, passed in (
            (HEALTHY, True),
            ({**HEALTHY, "is-system-running": done("degraded\n", 1)}, False),
        ):
            with self.subTest(passed=passed), tempfile.TemporaryDirectory() as tmp:
                vm = boot.vmlib.VM(3, Path(), Path(), "", Path(tmp), Path(), Path())
                with (
                    patch.object(boot.vmlib, "wait_for_ssh") as wait,
                    patch.object(
                        boot.vmlib,
                        "remote",
                        side_effect=lambda vm, name, command, timeout, r=results: r.get(
                            name, done("")
                        ),
                    ),
                ):
                    if passed:
                        boot.check_guest(vm)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "unhealthy"):
                            boot.check_guest(vm)
                wait.assert_called_once_with(vm, timeout=900)
                summary = json.loads((Path(tmp) / "guest-checks.json").read_text())
                self.assertEqual(summary["passed"], passed)

    def test_ssh_timeout_is_a_failure(self):
        vm = boot.vmlib.VM(3, Path(), Path(), "", Path(), Path(), Path())
        with (
            patch.object(
                boot.vmlib, "wait_for_ssh", side_effect=boot.vmlib.ProbeError("x")
            ),
            self.assertRaises(RuntimeError),
        ):
            boot.check_guest(vm)


class DiskModeTests(unittest.TestCase):
    def run_main(self, mode, *, guest=None, colors=100):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        image = root / f"image.{mode}"
        out = root / "out"
        for path in (image, root / "code.fd", root / "template.fd"):
            path.touch()
        seen = {}

        def keygen(argv, **_kwargs):
            key = Path(argv[argv.index("-f") + 1])
            key.write_text("private")
            key.with_suffix(".pub").write_text("ssh-ed25519 AAAA test")
            seen["key"] = key
            return done()

        def shot(_socket, path):
            path.write_bytes(b"P6")

        with (
            patch.object(sys, "argv", ["boot-test.py", mode, str(image), str(out)]),
            patch.object(
                boot,
                "resolve_ovmf",
                return_value=(root / "code.fd", root / "template.fd"),
            ),
            patch.object(boot.subprocess, "Popen") as popen,
            patch.object(boot.subprocess, "run", side_effect=keygen),
            patch.object(boot.time, "sleep"),
            patch.object(boot.os, "access", return_value=True),
            patch.object(boot.os, "killpg"),
            patch.object(boot, "screendump", side_effect=shot),
            patch.object(boot, "count_colors", return_value=colors),
            patch.object(boot.shutil, "which", return_value=None),
            patch.object(boot, "check_guest", side_effect=guest) as check,
        ):
            popen.return_value.poll.return_value = None
            popen.return_value.pid = 1234
            code = boot.main()
        return code, popen.call_args.args[0], check, seen, out

    def test_disk_mode_boots_a_snapshot_with_a_vsock_credential(self):
        code, command, check, seen, out = self.run_main("disk")
        self.assertEqual(code, 0)
        self.assertIn("-snapshot", command)
        self.assertTrue(
            any(a.startswith("vhost-vsock-pci,guest-cid=") for a in command)
        )
        self.assertIn(
            "type=11,value=io.systemd.credential:ssh.authorized_keys.root="
            "ssh-ed25519 AAAA test",
            command,
        )
        self.assertNotIn("hostfwd", " ".join(command))
        check.assert_called_once()
        self.assertFalse(seen["key"].is_relative_to(out))
        self.assertFalse(seen["key"].parent.exists())

    def test_disk_mode_fails_when_the_guest_gate_fails(self):
        def unhealthy(_vm):
            raise RuntimeError("installed disk is unhealthy: failed units")

        code, _, _, seen, _ = self.run_main("disk", guest=unhealthy)
        self.assertEqual(code, 1)
        self.assertFalse(seen["key"].parent.exists())

    def test_disk_mode_fails_without_vhost_vsock(self):
        tmp = Path("/nonexistent")
        with (
            patch.object(boot.os, "access", return_value=False),
            patch.object(boot.subprocess, "run") as keygen,
            self.assertRaisesRegex(RuntimeError, "vhost-vsock"),
        ):
            boot.disk_vm(tmp, tmp, tmp / "d.qcow2", tmp, tmp)
        keygen.assert_not_called()

    def test_iso_mode_is_unchanged(self):
        code, command, check, seen, _ = self.run_main("iso")
        self.assertEqual(code, 0)
        check.assert_not_called()
        self.assertEqual(seen, {})
        self.assertEqual(command[-4:], ["-cdrom", command[-3], "-boot", "d"])
        self.assertFalse(any("vsock" in a or "type=11" in a for a in command))
        self.assertEqual(self.run_main("iso", colors=10)[0], 1)


class BootTestJobTests(unittest.TestCase):
    def test_boot_test_job_can_reach_the_guest_over_vsock(self):
        import yaml

        job = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())[
            "jobs"
        ]["boot-test"]
        steps = {step.get("name"): step for step in job["steps"]}
        access = steps["Enable KVM and vhost-vsock for the runner user"]["run"]
        self.assertIn('KERNEL=="vhost-vsock", GROUP="kvm", MODE="0666"', access)
        self.assertIn("sudo modprobe vhost_vsock", access)
        self.assertIn("--name-match=vhost-vsock", access)
        packages = steps["Install QEMU"]["run"].split()
        for package in ("qemu-system-x86", "ovmf", "socat", "openssh-client"):
            self.assertIn(package, packages)
        ordered = list(steps)
        self.assertLess(
            ordered.index("Enable KVM and vhost-vsock for the runner user"),
            ordered.index("Boot installed system (qcow2)"),
        )
        self.assertIn(
            "boot-test.py disk", steps["Boot installed system (qcow2)"]["run"]
        )
        self.assertEqual(steps["Upload boot evidence"]["with"]["path"], "boot-test/")


if __name__ == "__main__":
    unittest.main()
