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


def mount(target, source, fstype="btrfs", count=1):
    return done(
        json.dumps(
            {
                "filesystems": [
                    {
                        "target": target,
                        "source": source,
                        "fstype": fstype,
                        "options": "rw,relatime,seclabel",
                    }
                ]
                * count
            }
        )
    )


STATEROOT_VAR = "/dev/vda4[/root/ostree/deploy/default/var]"
HEALTHY = {
    "is-system-running": done("running\n"),
    "failed-units": done(""),
    "sysroot-mount": mount("/sysroot", "/dev/vda4[/root]"),
    "var-mount": mount("/var", STATEROOT_VAR),
    "var-home-mount": mount("/var", STATEROOT_VAR),
    "home-link": done("/var/home\n"),
    "random-seed": done("Result=success\nActiveState=active\n"),
    "labels": done(
        "drwxr-xr-x. 1 root root system_u:object_r:var_t:s0 72 Nov 19 /var\n"
        "lrwxrwxrwx. 1 root root system_u:object_r:home_root_t:s0 10 Nov 19 /var/home\n"
        "drwxr-xr-x. 1 root root system_u:object_r:init_var_lib_t:s0 104 Nov 19"
        " /var/lib/systemd\n"
    ),
    "restorecon": done(""),
}
OLD_VAR = {
    "var-mount": mount("/var", "/dev/vda4[/var]"),
    "var-home-mount": mount("/var/home", "/dev/vda4[/home]"),
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
        findmnt = "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS --target"
        self.assertEqual(
            calls,
            [
                ("is-system-running", "systemctl is-system-running --wait"),
                (
                    "failed-units",
                    "systemctl --failed --no-legend --plain --no-pager",
                ),
                ("sysroot-mount", f"{findmnt} /sysroot"),
                ("var-mount", f"{findmnt} /var"),
                ("var-home-mount", f"{findmnt} /var/home"),
                ("home-link", "readlink -f /home"),
                (
                    "random-seed",
                    (
                        "systemctl show -p Result -p ActiveState"
                        " systemd-random-seed.service"
                    ),
                ),
                ("labels", "ls -ldZ /var /var/home /var/lib/systemd"),
                ("restorecon", "restorecon -n -v /var /var/home /var/lib/systemd"),
            ],
        )

    def test_stateroot_and_root_subvolume_paths_are_not_pinned(self):
        for sysroot, var in (
            ("/dev/vda4", "/dev/vda4[/ostree/deploy/default/var]"),
            ("/dev/vda4[/root]", "/dev/vda4[/root/ostree/deploy/luminusos/var]"),
            ("/dev/sda3[/@]", "/dev/sda3[/@/ostree/deploy/fedora/var]"),
        ):
            with self.subTest(var=var):
                problems, _ = self.check(
                    **{
                        "sysroot-mount": mount("/sysroot", sysroot),
                        "var-mount": mount("/var", var),
                        "var-home-mount": mount("/var", var),
                    }
                )
                self.assertEqual(problems, [])

    def test_degraded_boot_is_rejected(self):
        for overrides in (
            {
                "is-system-running": done("degraded\n", 1),
                "failed-units": done(
                    "systemd-random-seed.service loaded failed failed X\n"
                ),
            },
            {"is-system-running": done("running\n", 1)},
            {"is-system-running": done("", 255, "timed out")},
            {"failed-units": done("x.service loaded failed failed X\n")},
            {"failed-units": done("", 1)},
        ):
            with self.subTest(overrides=overrides):
                self.assertTrue(self.check(**overrides)[0])

    def test_separate_var_or_home_subvolumes_are_rejected(self):
        for overrides, message in (
            (OLD_VAR, "/var is the separate var subvolume"),
            (
                {"var-home-mount": mount("/var/home", "/dev/vda4[/home]")},
                "/var/home is the separate home subvolume",
            ),
            (
                {"var-home-mount": mount("/var/home", "/dev/vda4[/var/home]")},
                "/var/home is a separate mount",
            ),
            (
                {"var-mount": mount("/var", "/dev/vda4[/root/var]")},
                "not the ostree stateroot",
            ),
            (
                {"var-mount": mount("/var", "/dev/vdb1[/root/ostree/deploy/x/var]")},
                "/var is on /dev/vdb1",
            ),
            (
                {"var-mount": mount("/", "overlay", fstype="overlay")},
                "want the root Btrfs filesystem",
            ),
            ({"var-mount": mount("/var", STATEROOT_VAR, fstype="xfs")}, "xfs"),
            ({"var-mount": mount("/var", STATEROOT_VAR, count=2)}, "2 filesystems"),
            ({"var-mount": done("not json")}, "JSON"),
            ({"var-mount": done("", 1)}, "findmnt exited 1"),
            ({"home-link": done("/home\n")}, "/home resolves"),
        ):
            with self.subTest(message=message):
                problems, _ = self.check(**overrides)
                self.assertTrue(
                    any(message in p for p in problems), (message, problems)
                )

    def test_random_seed_must_have_succeeded_in_this_boot(self):
        for result in (
            done("Result=exit-code\nActiveState=failed\n"),
            done("Result=success\nActiveState=inactive\n"),
            done("ActiveState=active\n"),
            done("Result=success\nActiveState=active\n", 1),
            done("", 255, "ssh: timed out"),
        ):
            with self.subTest(result=result.stdout):
                problems, _ = self.check(**{"random-seed": result})
                self.assertTrue(
                    any("systemd-random-seed" in p for p in problems), problems
                )
        self.assertEqual(
            self.check(**{"random-seed": done("ActiveState=active\nResult=success")})[
                0
            ],
            [],
        )

    def test_labels_must_match_policy(self):
        for result in (
            done(
                "Would relabel /var from system_u:object_r:unlabeled_t:s0"
                " to system_u:object_r:var_t:s0\n"
            ),
            done("", 255, "restorecon: command not found"),
        ):
            with self.subTest(result=result.stdout or result.stderr):
                problems, _ = self.check(restorecon=result)
                self.assertTrue(any("SELinux labels" in p for p in problems))
        problems, _ = self.check(
            restorecon=done("", 0, "restorecon: lstat(/var/home) failed")
        )
        self.assertTrue(any("SELinux labels" in p for p in problems))

    def test_labels_must_be_readable_and_never_unlabeled(self):
        healthy = HEALTHY["labels"].stdout
        for result in (
            done("", 2, "ls: cannot access '/var/lib/systemd'"),
            done(healthy, 0, "ls: warning"),
            done(healthy.splitlines()[0] + "\n"),
            done(healthy.replace("var_t", "unlabeled_t", 1)),
        ):
            with self.subTest(result=result.stdout or result.stderr):
                problems, _ = self.check(labels=result)
                self.assertTrue(any("cannot confirm SELinux" in p for p in problems))


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
