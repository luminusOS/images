import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BuildHelperTests(unittest.TestCase):
    def test_release_keys_and_invalid_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "os-release"
            path.write_text('NAME="old"\nVERSION="old"\n')
            env = {**os.environ, "OS_RELEASE_FILE": str(path)}
            command = [sys.executable, str(ROOT / "shared/scripts/os-release-set.py")]
            subprocess.run(
                command + ["NAME", 'new "name"', "BUILD_ID", "42"], env=env, check=True
            )
            self.assertEqual(
                path.read_text(),
                'NAME="new \\"name\\""\nVERSION="old"\nBUILD_ID="42"\n',
            )
            result = subprocess.run(
                command + ["NAME|bad", "oops"],
                env=env,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_session_modes_merge_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metadata.json"
            path.write_text('{"uuid":"extension", "session-modes":["user"]}')
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "shared/scripts/aurora-session-modes.py"),
                    str(path),
                    "initial-setup",
                    "user",
                ],
                check=True,
            )
            self.assertEqual(
                json.loads(path.read_text())["session-modes"], ["initial-setup", "user"]
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            path.write_text('{"uuid":"extension"}')
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "shared/scripts/aurora-session-modes.py"),
                    str(path),
                    "initial-setup",
                ],
                check=True,
            )
            self.assertEqual(
                json.loads(path.read_text())["session-modes"], ["initial-setup", "user"]
            )


if __name__ == "__main__":
    unittest.main()
