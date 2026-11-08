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
        self.assertEqual(workflow["on"], {"workflow_dispatch": ""})
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


if __name__ == "__main__":
    unittest.main()
