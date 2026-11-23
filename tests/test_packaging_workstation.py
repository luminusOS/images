import importlib.util
import signal
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "package_workstation", ROOT / "tools/package-workstation.py"
)
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageLayoutTests(unittest.TestCase):
    def test_cancelled_subprocess_group_is_terminated(self):
        with (
            patch.object(package.sys.stdin, "isatty", return_value=False),
            patch.object(package.subprocess, "Popen") as popen,
            patch.object(package.os, "killpg") as killpg,
            self.assertRaises(KeyboardInterrupt),
        ):
            popen.return_value.pid = 1234
            popen.return_value.communicate.side_effect = KeyboardInterrupt
            package.run(["image-builder"])
        killpg.assert_called_once_with(1234, signal.SIGTERM)
        popen.return_value.wait.assert_called_once_with(timeout=10)

    def test_boot_ext4_and_cleanup(self):
        layout = (
            ROOT
            / "editions/workstation/files/system/usr/lib/image-builder/bootc/disk.yaml"
        ).read_text()
        with (
            patch.object(package, "run", side_effect=["ctr\n", "/mnt/image\n", layout]),
            patch.object(package.subprocess, "run") as cleanup,
        ):
            package.verify_disk_layout("localhost/test:latest")
        self.assertEqual(
            [call.args[0][2] for call in cleanup.call_args_list], ["umount", "rm"]
        )

    def test_boot_btrfs_is_rejected_and_cleanup_runs(self):
        layout = 'type: "btrfs"\nmountpoint: "/boot"\n'
        with (
            patch.object(package, "run", side_effect=["ctr\n", "/mnt/image\n", layout]),
            patch.object(package.subprocess, "run") as cleanup,
            self.assertRaises(ValueError),
        ):
            package.verify_disk_layout("localhost/test:latest")
        self.assertEqual(
            [call.args[0][2] for call in cleanup.call_args_list], ["umount", "rm"]
        )

    def test_mount_failure_still_removes_container(self):
        with (
            patch.object(
                package, "run", side_effect=["ctr\n", OSError("mount failed")]
            ),
            patch.object(package.subprocess, "run") as cleanup,
            self.assertRaises(OSError),
        ):
            package.verify_disk_layout("localhost/test:latest")
        self.assertEqual([call.args[0][2] for call in cleanup.call_args_list], ["rm"])


if __name__ == "__main__":
    unittest.main()
