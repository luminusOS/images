import json
import shlex
import signal
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import qemu as qemu_launcher
import qemu_security


class QemuSecurityTests(unittest.TestCase):
    def test_security_options_default_off_and_reject_other_values(self):
        self.assertFalse(qemu_security.enabled({}, "QEMU_TPM"))
        self.assertFalse(qemu_security.enabled({}, "QEMU_SECURE_BOOT"))
        self.assertTrue(qemu_security.enabled({"QEMU_TPM": "1"}, "QEMU_TPM"))

        for value in ("", "true", "2"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "must be 0 or 1"),
            ):
                qemu_security.enabled({"QEMU_TPM": value}, "QEMU_TPM")

    def test_tpm_and_secure_boot_options_are_independent(self):
        for tpm, secure_boot in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            with self.subTest(tpm=tpm, secure_boot=secure_boot):
                environment = {
                    "QEMU_TPM": "1" if tpm else "0",
                    "QEMU_SECURE_BOOT": "1" if secure_boot else "0",
                }
                self.assertEqual(qemu_security.enabled(environment, "QEMU_TPM"), tpm)
                self.assertEqual(
                    qemu_security.enabled(environment, "QEMU_SECURE_BOOT"),
                    secure_boot,
                )

    def test_vm_state_uses_resolved_disk_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "subdir"
            nested.mkdir()
            disk = nested / ".." / "disk.qcow2"

            self.assertEqual(
                qemu_security.state_path(root / ".test", disk),
                qemu_security.state_path(root / ".test", root / "disk.qcow2"),
            )

    def test_different_disks_receive_different_vm_state_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_disk = root / "first.qcow2"
            second_disk = root / "second.qcow2"

            self.assertNotEqual(
                qemu_security.state_path(root / ".test", first_disk),
                qemu_security.state_path(root / ".test", second_disk),
            )

    def test_locked_state_refuses_simultaneous_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            test_dir = Path(tmp) / ".test"
            test_dir.mkdir()
            state = test_dir / "qemu-vms" / "vm"

            with qemu_security.locked_state(state):
                self.assertRaisesRegex(
                    ValueError,
                    "already in use",
                    qemu_security.locked_state(state).__enter__,
                )

    def test_locked_state_creates_private_directories_and_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            test_dir = Path(tmp) / ".test"
            test_dir.mkdir()
            state = test_dir / "qemu-vms" / "vm"

            with qemu_security.locked_state(state):
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                self.assertEqual((state / "lock").stat().st_mode & 0o777, 0o600)

    def test_secure_firmware_requires_a_compatible_enrolled_key_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = root / "OVMF_CODE.secboot.fd"
            variables = root / "OVMF_VARS.secboot.fd"
            code.touch()
            variables.touch()
            descriptor = root / "firmware.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "mapping": {
                            "device": "flash",
                            "mode": "split",
                            "executable": {
                                "filename": str(code),
                                "format": "raw",
                            },
                            "nvram-template": {
                                "filename": str(variables),
                                "format": "raw",
                            },
                        },
                        "features": ["secure-boot", "enrolled-keys", "requires-smm"],
                        "interface-types": ["uefi"],
                        "targets": [
                            {"architecture": "x86_64", "machines": ["pc-q35-*"]}
                        ],
                    }
                )
            )
            template = descriptor.read_text()
            for mode, omitted in (
                (None, None),
                ("split", None),
                ("combined", None),
                ("stateless", None),
                (None, "enrolled-keys"),
                (None, "requires-smm"),
            ):
                with self.subTest(mode=mode, omitted=omitted):
                    data = json.loads(template)
                    if mode is None:
                        del data["mapping"]["mode"]
                    else:
                        data["mapping"]["mode"] = mode
                    if omitted:
                        data["features"].remove(omitted)
                    descriptor.write_text(json.dumps(data))
                    with patch.object(Path, "glob", return_value=[descriptor]):
                        if omitted or mode in ("combined", "stateless"):
                            with self.assertRaises(ValueError):
                                qemu_security.secure_firmware({})
                        else:
                            self.assertEqual(
                                qemu_security.secure_firmware({}), (code, variables)
                            )

    def test_secure_firmware_rejects_unenrolled_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = root / "code.fd"
            variables = root / "vars.fd"
            code.touch()
            variables.touch()
            descriptor = root / "firmware.json"
            descriptor.write_text(
                json.dumps(
                    {
                        "mapping": {
                            "device": "flash",
                            "mode": "split",
                            "executable": {"filename": str(code), "format": "raw"},
                            "nvram-template": {
                                "filename": str(variables),
                                "format": "raw",
                            },
                        },
                        "features": ["secure-boot", "requires-smm"],
                        "interface-types": ["uefi"],
                        "targets": [
                            {"architecture": "x86_64", "machines": ["pc-q35-*"]}
                        ],
                    }
                )
            )
            with (
                patch.object(Path, "glob", return_value=[descriptor]),
                self.assertRaisesRegex(ValueError, "enrolled-keys"),
            ):
                qemu_security.secure_firmware({})

    def test_secure_firmware_requires_both_explicit_files(self):
        with self.assertRaisesRegex(ValueError, "requires both"):
            qemu_security.secure_firmware({"QEMU_OVMF_CODE": "/firmware/code.fd"})

    def test_tpm_arguments_attach_local_socket_to_tis_device(self):
        arguments = qemu_security.tpm_arguments(Path("/tmp/test.sock"))

        self.assertEqual(
            arguments,
            [
                "-chardev",
                "socket,id=chrtpm,path=/tmp/test.sock",
                "-tpmdev",
                "emulator,id=tpm0,chardev=chrtpm",
                "-device",
                "tpm-tis,tpmdev=tpm0",
            ],
        )

    def test_missing_swtpm_reports_actionable_error(self):
        with (
            patch.object(qemu_security.shutil, "which", return_value=None),
            self.assertRaisesRegex(ValueError, "swtpm is missing"),
        ):
            qemu_security.require_swtpm({"PATH": "/empty"})

    def test_run_terminates_swtpm_after_qemu_exits(self):
        processes = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = None
                processes.append(self)
                if "--ctrl" in command:
                    socket_arg = command[command.index("--ctrl") + 1]
                    socket_path = socket_arg.split("path=", 1)[1]
                    with socket.socket(socket.AF_UNIX) as control_socket:
                        control_socket.bind(socket_path)

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if "--ctrl" not in self.command:
                    self.returncode = 7
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = -9

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "vm"
            state.mkdir()
            with (
                patch.object(qemu_security, "require_swtpm", return_value="swtpm"),
                patch.object(qemu_security.subprocess, "Popen", FakeProcess),
            ):
                result = qemu_security.run(["qemu-system-x86_64"], {}, state, True)

            self.assertEqual(result, 7)
            self.assertEqual(len(processes), 2)
            self.assertEqual(processes[0].returncode, 0)
            self.assertTrue((state / "tpm").is_dir())

    def test_run_terminates_swtpm_when_qemu_cannot_start(self):
        swtpm_processes = []

        class FakeSwtpm:
            def __init__(self, command, **kwargs):
                self.returncode = None
                swtpm_processes.append(self)
                control = command[command.index("--ctrl") + 1]
                socket_path = control.split("path=", 1)[1]
                with socket.socket(socket.AF_UNIX) as control_socket:
                    control_socket.bind(socket_path)

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = -9

        def start_process(command, **kwargs):
            if "--ctrl" not in command:
                raise OSError("qemu could not start")
            return FakeSwtpm(command)

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "vm"
            state.mkdir()
            with (
                patch.object(qemu_security, "require_swtpm", return_value="swtpm"),
                patch.object(
                    qemu_security.subprocess, "Popen", side_effect=start_process
                ),
                self.assertRaisesRegex(OSError, "qemu could not start"),
            ):
                qemu_security.run(["qemu-system-x86_64"], {}, state, True)

            self.assertEqual(len(swtpm_processes), 1)
            self.assertEqual(swtpm_processes[0].returncode, 0)

    def test_run_restores_signal_handlers_and_stops_processes_when_interrupted(self):
        processes = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = None
                self.wait_count = 0
                processes.append(self)
                if "--ctrl" in command:
                    control = command[command.index("--ctrl") + 1]
                    socket_path = control.split("path=", 1)[1]
                    with socket.socket(socket.AF_UNIX) as control_socket:
                        control_socket.bind(socket_path)

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if "--ctrl" not in self.command:
                    self.wait_count += 1
                    if self.wait_count == 1:
                        raise InterruptedError("simulated interruption")
                    return self.returncode
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def kill(self):
                self.returncode = -9

        watched_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        previous_handlers = {sig: signal.getsignal(sig) for sig in watched_signals}
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "vm"
            state.mkdir()
            with (
                patch.object(qemu_security, "require_swtpm", return_value="swtpm"),
                patch.object(qemu_security.subprocess, "Popen", FakeProcess),
                self.assertRaisesRegex(InterruptedError, "simulated interruption"),
            ):
                qemu_security.run(["qemu-system-x86_64"], {}, state, True)

            self.assertEqual([process.returncode for process in processes], [0, 0])
            self.assertEqual(
                {sig: signal.getsignal(sig) for sig in watched_signals},
                previous_handlers,
            )

    def test_repeated_termination_signals_are_ignored_during_cleanup(self):
        watched_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        handlers = {sig: signal.getsignal(sig) for sig in watched_signals}
        original_handlers = handlers.copy()
        deliveries = []

        def mocked_signal(signum, handler):
            previous = handlers[signum]
            handlers[signum] = handler
            return previous

        class FakeQemu:
            returncode = None
            wait_count = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.wait_count += 1
                if self.wait_count == 1:
                    raise InterruptedError("first termination signal")
                return self.returncode

            def terminate(self):
                for _ in range(3):
                    handler = handlers[signal.SIGTERM]
                    if handler is not signal.SIG_IGN:
                        handler(signal.SIGTERM, None)
                    deliveries.append(handler)
                self.returncode = 0

            def kill(self):
                self.returncode = -9

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "vm"
            state.mkdir()
            with (
                patch.object(signal, "signal", side_effect=mocked_signal),
                patch.object(
                    qemu_security.subprocess, "Popen", return_value=FakeQemu()
                ),
                self.assertRaisesRegex(InterruptedError, "first termination signal"),
            ):
                qemu_security.run(["qemu-system-x86_64"], {}, state, False)

            self.assertEqual(deliveries, [signal.SIG_IGN] * 3)
            self.assertEqual(handlers, original_handlers)

    def test_default_and_secure_boot_launches_share_the_disk_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = root / "vm.qcow2"
            disk.touch()
            active_environment = [{"QEMU_DISK_PATH": str(disk), "QEMU_DRY_RUN": "0"}]

            def launch_secure_while_default_is_running(*args):
                active_environment[0] = {
                    "QEMU_DISK_PATH": str(disk),
                    "QEMU_DRY_RUN": "0",
                    "QEMU_SECURE_BOOT": "1",
                }
                with self.assertRaisesRegex(ValueError, "already in use"):
                    qemu_launcher.main()
                return 0

            with (
                patch.object(qemu_launcher, "ROOT", root),
                patch.object(
                    qemu_launcher,
                    "load_environment",
                    side_effect=lambda _root, _environment: active_environment[0],
                ),
                patch.object(
                    qemu_launcher, "secure_firmware", return_value=(disk, disk)
                ),
                patch.object(
                    qemu_launcher,
                    "launch",
                    side_effect=launch_secure_while_default_is_running,
                ),
                patch("sys.argv", ["qemu.py", "disk"]),
            ):
                self.assertEqual(qemu_launcher.main(), 0)

    def test_copy_vars_failure_leaves_no_partial_destination_or_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = root / "template.fd"
            destination = root / "OVMF_VARS.fd"
            template.write_bytes(b"firmware template")

            def partial_copy(source, target):
                target.write(b"partial")
                raise OSError("simulated copy failure")

            with (
                patch.object(
                    qemu_security.shutil, "copyfileobj", side_effect=partial_copy
                ),
                self.assertRaisesRegex(OSError, "simulated copy failure"),
            ):
                qemu_security.copy_vars(template, destination)

            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob(".vars-*")), [])

    def test_run_preserves_state_directory_after_qemu_exits(self):
        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "vm"
            (state / "tpm").mkdir(parents=True)
            (state / "tpm" / "persistent-state").write_bytes(b"preserve me")
            with patch.object(qemu_security.subprocess, "Popen", FakeProcess):
                self.assertEqual(
                    qemu_security.run(["qemu-system-x86_64"], {}, state, False), 0
                )

            self.assertEqual(
                (state / "tpm" / "persistent-state").read_bytes(), b"preserve me"
            )

    def test_qemu_dry_run_options_are_independent_and_create_no_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = root / "vm.qcow2"
            code = root / "OVMF_CODE.fd"
            variables = root / "OVMF_VARS.fd"
            for artifact in (disk, code, variables):
                artifact.touch()
            for tpm, secure_boot in (
                (False, False),
                (True, False),
                (False, True),
                (True, True),
            ):
                with self.subTest(tpm=tpm, secure_boot=secure_boot):
                    environment = {
                        "QEMU_DRY_RUN": "1",
                        "QEMU_TPM": "1" if tpm else "0",
                        "QEMU_SECURE_BOOT": "1" if secure_boot else "0",
                        "QEMU_BOOT": "uefi",
                        "QEMU_DEBUG": "0",
                        "QEMU_DISK_PATH": str(disk),
                    }
                    output = StringIO()
                    with (
                        patch.object(qemu_launcher, "ROOT", root),
                        patch.object(
                            qemu_launcher,
                            "load_environment",
                            return_value=environment,
                        ),
                        patch.object(
                            qemu_launcher, "require_swtpm", return_value="swtpm"
                        ) as require_swtpm,
                        patch.object(
                            qemu_launcher,
                            "secure_firmware",
                            return_value=(code, variables),
                        ) as secure_firmware,
                        patch.object(
                            qemu_launcher,
                            "resolve_ovmf",
                            return_value=(code, variables),
                        ) as resolve_ovmf,
                        patch("sys.argv", ["qemu.py", "disk"]),
                        redirect_stdout(output),
                    ):
                        qemu_launcher.main()

                    command = shlex.split(output.getvalue().splitlines()[-1])
                    machine = command[command.index("-machine") + 1]
                    self.assertEqual("-tpmdev" in command, tpm)
                    self.assertEqual("smm=on" in machine, secure_boot)
                    self.assertEqual(
                        "-global" in command
                        and "driver=cfi.pflash01,property=secure,value=on" in command,
                        secure_boot,
                    )
                    self.assertEqual(require_swtpm.called, tpm)
                    self.assertEqual(secure_firmware.called, secure_boot)
                    self.assertEqual(resolve_ovmf.called, not secure_boot)
                    self.assertFalse((root / ".test").exists())

    def test_reset_nvram_is_rejected_for_opt_in_without_starting_qemu(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = root / "vm.qcow2"
            disk.touch()
            test_dir = root / ".test"
            state = qemu_security.state_path(test_dir, disk)
            state.mkdir(mode=0o700, parents=True)
            variables = state / "OVMF_VARS.secure.fd"
            variables.write_bytes(b"existing firmware variables")
            environment = {
                "QEMU_DRY_RUN": "0",
                "QEMU_SECURE_BOOT": "1",
                "QEMU_DISK_PATH": str(disk),
                "QEMU_RESET_NVRAM": "1",
            }
            with (
                patch.object(qemu_launcher, "ROOT", root),
                patch.object(
                    qemu_launcher, "load_environment", return_value=environment
                ),
                patch.object(
                    qemu_launcher, "secure_firmware", return_value=(disk, disk)
                ),
                patch.object(qemu_launcher, "launch") as launch,
                patch("sys.argv", ["qemu.py", "disk"]),
                self.assertRaisesRegex(ValueError, "QEMU_RESET_NVRAM cannot"),
            ):
                qemu_launcher.main()

            launch.assert_not_called()
            self.assertEqual(variables.read_bytes(), b"existing firmware variables")


if __name__ == "__main__":
    unittest.main()
