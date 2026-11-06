import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_package", ROOT / ".github/scripts/ci-package.py"
)
ci_package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_package)


class PackageTests(unittest.TestCase):
    def test_invalid_format_has_no_side_effects(self):
        with (
            patch.object(sys, "argv", ["ci-package.py", "bad"]),
            patch.object(ci_package.subprocess, "run") as run,
        ):
            with self.assertRaises(SystemExit):
                ci_package.main()
            run.assert_not_called()

    def test_iso_uses_live_image_and_password_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output.iso"
            output.touch()
            env = {
                "WORKSTATION_ISO_IMAGE": "example/live:tag",
                "OUTPUT_NAME": str(output),
                "GHCR_TOKEN": "test-secret",
                "GHCR_USER": "tester",
            }
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["ci-package.py", "iso"]),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                self.assertEqual(ci_package.main(), 0)
            calls = run.call_args_list
            self.assertEqual(
                calls[1].args[0],
                ["podman", "login", "ghcr.io", "-u", "tester", "--password-stdin"],
            )
            self.assertEqual(calls[1].kwargs["input"], "test-secret")
            self.assertEqual(calls[2].args[0], ["podman", "pull", "example/live:tag"])
            self.assertEqual(
                calls[3].args[0],
                [
                    "python3",
                    "./tools/package-artifact.py",
                    "iso",
                    "example/live:tag",
                    str(output),
                ],
            )
            self.assertEqual(
                calls[3].kwargs["env"]["IMAGE_BUILDER_CACHE"],
                str(Path.cwd() / ".osbuild-cache"),
            )


if __name__ == "__main__":
    unittest.main()
