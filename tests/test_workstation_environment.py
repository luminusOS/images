import os
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch


class WorkstationEnvironmentTests(unittest.TestCase):
    def test_system_commands_receive_clean_copy_of_environment(self):
        script = Path(__file__).resolve().parents[1] / "editions/workstation/build.py"
        contaminated = {
            "PYTHONHOME": "/opt/python",
            "LD_LIBRARY_PATH": "/opt/python/lib64",
            "PATH": "/usr/bin",
            "WORKSTATION_TEST": "preserved",
        }
        with (
            patch.dict(os.environ, contaminated, clear=True),
            patch.object(Path, "mkdir"),
            patch.object(Path, "unlink"),
            patch.object(Path, "symlink_to"),
            patch("shutil.which", side_effect=lambda command: f"/usr/bin/{command}"),
            patch("subprocess.run") as run,
        ):
            runpy.run_path(str(script))
            self.assertEqual(dict(os.environ), contaminated)
            self.assertEqual(run.call_count, 9)
            for call in run.call_args_list:
                self.assertTrue(call.kwargs["check"])
                self.assertEqual(
                    call.kwargs.get("env"),
                    {"PATH": "/usr/bin", "WORKSTATION_TEST": "preserved"},
                )
                self.assertIsNot(call.kwargs.get("env"), os.environ)


if __name__ == "__main__":
    unittest.main()
