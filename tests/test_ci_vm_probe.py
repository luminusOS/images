import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_vm_probe", ROOT / ".github/scripts/ci-vm-probe.py"
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

FAKE = """
import json, sys, time
mode = MODE
if mode == "timeout":
    print("partial", flush=True)
    time.sleep(30)
elif mode == "invalid":
    print("invalid")
else:
    print(json.dumps({"QMP": {"version": {}, "capabilities": []}}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        command = request["execute"]
        result = {}
        if command == "query-kvm":
            result = {"enabled": mode != "disabled", "present": True}
        elif command == "query-status":
            result = {"running": True, "status": "running"}
        print(json.dumps({"return": result, "id": request["id"]}), flush=True)
        if command == "quit":
            break
"""


class ProbeTests(unittest.TestCase):
    def test_missing_and_denied_kvm(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(FileNotFoundError),
        ):
            probe.check_kvm(Path(temporary) / "missing")
        with (
            patch.object(probe.os, "open", side_effect=PermissionError("denied")),
            self.assertRaises(PermissionError),
        ):
            probe.check_kvm()

    def run_fake(self, output, mode):
        popen = subprocess.Popen
        command = [sys.executable, "-c", FAKE.replace("MODE", repr(mode))]
        with patch.object(
            probe.subprocess,
            "Popen",
            side_effect=lambda args, **kw: popen(command, **kw),
        ):
            return probe.qmp_probe(output, timeout=1)

    def test_valid_invalid_and_disabled_qmp(self):
        for mode in ("valid", "invalid", "disabled"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                if mode == "valid":
                    self.assertTrue(self.run_fake(output, mode)["kvm"]["enabled"])
                else:
                    with self.assertRaises(ValueError):
                        self.run_fake(output, mode)
                record = json.loads((output / "qemu.json").read_text())
                self.assertEqual(record["exit_code"], 0)
                self.assertIn("q35,accel=kvm", record["command"])
                self.assertNotIn("tcg", " ".join(record["command"]))
                self.assertTrue((output / "qemu.stderr").is_file())

    def test_timeout_reaps_child_and_preserves_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_fake(output, "timeout")
            record = json.loads((output / "qemu.json").read_text())
            self.assertIsNotNone(record["exit_code"])
            self.assertIn("error", record)
            self.assertIn("partial", (output / "qemu.stdout").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(record["pid"], 0)

    def test_manifest_and_resources_survive_required_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            descriptor = Path(temporary) / "secure.json"
            descriptor.write_bytes(b'{"mapping":{}}\n')
            with (
                patch.object(probe.shutil, "which", return_value=None),
                patch.object(
                    Path,
                    "glob",
                    autospec=True,
                    side_effect=lambda directory, pattern: (
                        [descriptor]
                        if directory == Path("/usr/share/qemu/firmware")
                        else []
                    ),
                ),
                patch.object(
                    probe, "secure_firmware", side_effect=ValueError("missing")
                ),
                patch.object(probe, "check_kvm", return_value=12) as kvm,
                patch.object(probe, "capture") as capture,
                patch.object(
                    probe, "qmp_probe", return_value={"kvm": {"enabled": True}}
                ) as qmp,
            ):
                self.assertEqual(probe.run_probe(output), 1)
            kvm.assert_called_once_with()
            capture.assert_called_once_with(
                output, "qemu-version", ["qemu-system-x86_64", "--version"]
            )
            qmp.assert_called_once_with(output)
            result = json.loads((output / "manifest.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(set(result["errors"]), {"firmware"})
            self.assertIn("missing", result["errors"]["firmware"])
            saved = output / result["firmware_descriptors"][str(descriptor)]
            self.assertEqual(saved.read_bytes(), descriptor.read_bytes())
            self.assertEqual(result["kvm_api"], 12)
            self.assertTrue(result["qmp"]["kvm"]["enabled"])
            self.assertFalse(result["guest_security_validated"])
            self.assertGreater(result["resources"]["disk_bytes"]["free"], 0)
            self.assertTrue((output / "meminfo.txt").is_file())

    def test_workflow_is_manual_readonly_and_uploads_failures(self):
        text = (ROOT / ".github/workflows/vm-capability-probe.yml").read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        mode = workflow["on"]["workflow_dispatch"]["inputs"]["probe_mode"]
        self.assertEqual(mode["type"], "choice")
        self.assertEqual(mode["default"], "kvm")
        self.assertEqual(mode["options"], ["kvm", "vsock-inventory"])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), {"probe"})
        job = workflow["jobs"]["probe"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertLessEqual(int(job["timeout-minutes"]), 15)
        self.assertNotIn("environment", job)
        for forbidden in ("secrets.", "continue-on-error", "chmod", "udevadm"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(job["steps"][0]["with"]["persist-credentials"], "false")
        self.assertIn("!cancelled()", job["steps"][2]["if"])
        self.assertEqual(job["steps"][-1]["if"], "always()")
        self.assertEqual(job["steps"][-1]["with"]["if-no-files-found"], "error")
        launcher = job["steps"][2]["run"]
        self.assertEqual(
            job["steps"][2]["env"], {"PROBE_MODE": "${{ inputs.probe_mode }}"}
        )
        self.assertIn("inputs.probe_mode == 'kvm'", job["steps"][1]["if"])
        self.assertIn('case "$PROBE_MODE" in', launcher)
        self.assertIn("kvm) probe_args=() ;;", launcher)
        self.assertIn(
            "vsock-inventory) probe_args=(--vsock-inventory-only) ;;", launcher
        )
        self.assertIn("*) exit 2 ;;", launcher)
        self.assertIn('"${probe_args[@]}"', launcher)
        for required in (
            'uid="$(id -u)"',
            'test "$uid" -ne 0',
            'passwd_entry="$(getent passwd "$uid")"',
            'user="${passwd_entry%%:*}"',
            'test "$(id -u "$user")" = "$uid"',
            'group_entry="$(getent group kvm)"',
            'IFS=: read -r group_name _ gid _ <<< "$group_entry"',
            'test "$group_name" = kvm',
            'test -n "$gid"',
            "test -x /usr/sbin/runuser",
            "/usr/sbin/runuser --version",
            "sudo -n -l",
            'sudo -n -- /usr/sbin/runuser -u "$user" -g kvm --',
            "/usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8",
            '"${helper[@]}" /usr/bin/id',
            'test "$actual_uid" = "$uid"',
            'test "$actual_gid" = "$gid"',
            '--expected-uid "$uid"',
            '>"$output/runner-identity.stdout" 2>"$output/runner-identity.stderr"',
            '>"$output/launcher.stdout" 2>"$output/launcher.stderr"',
            'ImageVersion="${ImageVersion:-}"',
        ):
            self.assertIn(required, launcher)
        for name in ("GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID"):
            self.assertIn(f'{name}="${name}"', launcher)
        for forbidden in (
            "-E",
            "usermod",
            "udev",
            "AppArmor",
            "chmod",
            "-u root",
            "sudo python",
            "sudo bash",
            "sudo -n -u",
            "|| true",
            "${{",
        ):
            self.assertNotIn(forbidden, launcher)
        self.assertEqual(
            [
                line.strip()
                for line in launcher.splitlines()
                if line.strip().startswith("sudo ")
            ],
            ["sudo -n -l", 'sudo -n -- /usr/sbin/runuser -u "$user" -g kvm --'],
        )
        self.assertLess(
            launcher.index('test "$actual_gid" = "$gid"'),
            launcher.index("/usr/bin/python3"),
        )

    def test_identity_guard_precedes_resources_and_kvm(self):
        for uid, gid, expected, accepted in (
            (1001, 993, 1001, True),
            (0, 993, 1001, False),
            (1002, 993, 1001, False),
            (1001, 1001, 1001, False),
            (0, 993, 0, False),
        ):
            with (
                self.subTest(uid=uid, gid=gid, expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary)
                with (
                    patch.object(probe.os, "geteuid", return_value=uid),
                    patch.object(probe.os, "getegid", return_value=gid),
                    patch.object(probe.os, "getgroups", return_value=[gid]),
                    patch.object(probe.grp, "getgrnam") as group,
                    patch.object(
                        Path, "read_text", side_effect=ValueError("resources sentinel")
                    ) as read,
                    patch.object(probe, "check_kvm") as kvm,
                    patch.object(probe, "qmp_probe") as qmp,
                ):
                    group.return_value.gr_gid = 993
                    self.assertEqual(probe.run_probe(output, expected), 1)
                    self.assertEqual(read.call_count, int(accepted))
                    kvm.assert_not_called()
                    qmp.assert_not_called()
                result = json.loads((output / "manifest.json").read_text())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["identity"]["euid"], uid)
                self.assertEqual(result["identity"]["egid"], gid)
                self.assertEqual(result["identity"]["expected_uid"], expected)
                self.assertEqual(result["identity"]["expected_gid"], 993)
                self.assertEqual(
                    set(result["errors"]), {"resources" if accepted else "identity"}
                )

    def test_cli_requires_expected_uid_in_both_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            for flags in ([], ["--vsock-inventory-only"]):
                result = subprocess.run(
                    [sys.executable, SPEC.origin, temporary, *flags],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("--expected-uid", result.stderr)

    def test_vsock_identity_guard_precedes_inventory(self):
        for uid, gid, expected in (
            (0, 993, 1001),
            (1002, 993, 1001),
            (1001, 1001, 1001),
            (1001, 993, None),
            (0, 993, 0),
        ):
            with (
                self.subTest(uid=uid, gid=gid, expected=expected),
                tempfile.TemporaryDirectory() as temporary,
            ):
                with (
                    patch.object(probe.os, "geteuid", return_value=uid),
                    patch.object(probe.os, "getegid", return_value=gid),
                    patch.object(probe.grp, "getgrnam") as group,
                    patch.object(Path, "read_text", side_effect=AssertionError("read")),
                    patch.object(
                        probe.os, "access", side_effect=AssertionError("access")
                    ),
                ):
                    group.return_value.gr_gid = 993
                    self.assertEqual(
                        probe.run_probe(Path(temporary), expected, True), 1
                    )
                saved = json.loads((Path(temporary) / "manifest.json").read_text())
                self.assertEqual(set(saved["errors"]), {"identity"})

    def test_vsock_inventory_is_static_and_preserves_failures(self):
        original_stat, original_read = os.stat, Path.read_text
        for case in (
            "present",
            "missing",
            "denied",
            "access",
            "regular",
            "modules",
            "acl",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)

                def metadata(path, *args, case=case, **kwargs):
                    if os.fspath(path) != "/dev/vhost-vsock":
                        return original_stat(path, *args, **kwargs)
                    if case in ("missing", "denied"):
                        error = (
                            FileNotFoundError if case == "missing" else PermissionError
                        )
                        raise error(case)
                    mode = 0o100660 if case == "regular" else 0o20660
                    return os.stat_result((mode, 0, 0, 1, 0, 993, 0, 0, 0, 0))

                def modules(path, *args, case=case, **kwargs):
                    if path != Path("/proc/modules"):
                        return original_read(path, *args, **kwargs)
                    if case == "modules":
                        raise PermissionError("modules denied")
                    return "vsock 1 0 - Live 0\nvhost_vsock 1 0 - Live 0\nother 1 0 - Live 0\n"

                def capture(directory, name, command):
                    self.assertEqual(
                        command, ["/usr/bin/getfacl", "--", "/dev/vhost-vsock"]
                    )
                    self.assertEqual(name, "vsock-getfacl")
                    (directory / f"{name}.stdout").write_text("acl evidence\n")
                    (directory / f"{name}.stderr").write_text("")

                with (
                    patch.object(probe.os, "geteuid", return_value=1001),
                    patch.object(probe.os, "getegid", return_value=993),
                    patch.object(probe.grp, "getgrnam") as group,
                    patch.object(probe.grp, "getgrgid") as owner,
                    patch.object(probe.os, "stat", side_effect=metadata),
                    patch.object(Path, "read_text", modules),
                    patch.object(probe.os, "access", return_value=case != "access"),
                    patch.object(
                        probe.shutil,
                        "which",
                        return_value="/usr/bin/getfacl" if case == "acl" else None,
                    ),
                    patch.object(
                        probe.os, "open", side_effect=AssertionError("device open")
                    ),
                    patch.object(probe, "check_kvm", side_effect=AssertionError("kvm")),
                    patch.object(
                        probe, "secure_firmware", side_effect=AssertionError("firmware")
                    ),
                    patch.object(probe, "qmp_probe", side_effect=AssertionError("qmp")),
                    patch.object(
                        probe.subprocess, "Popen", side_effect=AssertionError("process")
                    ),
                    patch.object(probe, "capture", side_effect=capture) as acl,
                    patch.dict(os.environ, {"GITHUB_RUN_ID": "inventory-test"}),
                ):
                    group.return_value.gr_gid, owner.return_value.gr_name = 993, "kvm"
                    self.assertEqual(
                        probe.run_probe(output, 1001, True),
                        int(case not in ("present", "acl")),
                    )
                    self.assertEqual(acl.call_count, int(case == "acl"))
                result = json.loads((output / "manifest.json").read_text())
                for field in (
                    "guest_security_validated",
                    "transport_validated",
                    "transport_ready",
                    "promotable",
                    "release_validation",
                ):
                    self.assertFalse(result[field])
                self.assertEqual(result["context"]["GITHUB_RUN_ID"], "inventory-test")
                if case == "modules":
                    self.assertIn("modules denied", result["errors"]["vsock-modules"])
                elif case in ("present", "acl"):
                    self.assertEqual(result["status"], "inventoried")
                    self.assertEqual(result["vsock_device"]["group"], "kvm")
                    self.assertEqual(len(result["vsock_modules"]), 2)
                else:
                    self.assertEqual(result["status"], "not-ready")

    def test_kvm_metadata_survives_denied_open(self):
        original_stat = os.stat
        metadata = os.stat_result((0o20660, 0, 0, 1, 0, 108, 0, 0, 0, 0))
        for failure in (None, "stat", "group", "acl"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary)

                def device_stat(path, *args, failure=failure, **kwargs):
                    if path != "/dev/kvm":
                        return original_stat(path, *args, **kwargs)
                    if failure == "stat":
                        raise FileNotFoundError("stat unavailable")
                    return metadata

                def acl_capture(directory, name, command, failure=failure):
                    (directory / f"{name}.stdout").write_text("acl evidence\n")
                    (directory / f"{name}.stderr").write_text("acl stderr\n")
                    if failure == "acl":
                        raise subprocess.CalledProcessError(1, command)

                with (
                    patch.object(probe.os, "stat", side_effect=device_stat),
                    patch.object(probe.grp, "getgrgid") as group,
                    patch.object(
                        probe.shutil,
                        "which",
                        side_effect=lambda name, failure=failure: (
                            "/usr/bin/getfacl"
                            if name == "getfacl" and failure != "stat"
                            else None
                        ),
                    ),
                    patch.object(Path, "glob", return_value=[]),
                    patch.object(probe, "secure_firmware", return_value=()),
                    patch.object(probe, "capture", side_effect=acl_capture) as capture,
                    patch.object(
                        probe,
                        "check_kvm",
                        side_effect=PermissionError(13, "denied", "/dev/kvm"),
                    ),
                ):
                    group.return_value.gr_name = "kvm"
                    group.side_effect = KeyError(108) if failure == "group" else None
                    self.assertEqual(probe.run_probe(output), 1)
                result = json.loads((output / "manifest.json").read_text())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["errors"], {"kvm": result["error"]})
                self.assertIn("PermissionError: [Errno 13]", result["error"])
                device = result["kvm_device"]
                if failure == "stat":
                    self.assertIn("stat unavailable", device["stat_error"])
                    self.assertFalse(device["acl"]["available"])
                    capture.assert_not_called()
                else:
                    self.assertEqual(
                        [device[key] for key in ("file_type", "mode", "uid", "gid")],
                        [0o20000, "0o660", 0, 108],
                    )
                    group.assert_called_once_with(108)
                    if failure == "group":
                        self.assertIn("group_error", device)
                    else:
                        self.assertEqual(device["group"], "kvm")
                    capture.assert_called_once_with(
                        output, "kvm-getfacl", ["/usr/bin/getfacl", "--", "/dev/kvm"]
                    )
                    self.assertEqual(
                        (output / "kvm-getfacl.stdout").read_text(), "acl evidence\n"
                    )
                    self.assertEqual(
                        (output / "kvm-getfacl.stderr").read_text(), "acl stderr\n"
                    )
                    self.assertEqual("error" in device["acl"], failure == "acl")


if __name__ == "__main__":
    unittest.main()
