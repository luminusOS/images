import importlib.util
import signal
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


if __name__ == "__main__":
    unittest.main()
