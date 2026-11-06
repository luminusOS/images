import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "digest", ROOT / "tools/fedora-bootc-digest.py"
)
digest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(digest)


class FedoraDigestTests(unittest.TestCase):
    def test_valid_digest(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout="Docker-Content-Digest: sha256:" + "a" * 64 + "\r\n"
        )
        with (
            patch.object(sys, "argv", ["fedora-bootc-digest.py", "45"]),
            patch.object(digest.subprocess, "run", return_value=result) as run,
        ):
            self.assertEqual(digest.main(), 0)
            self.assertEqual(
                run.call_args.args[0][-1],
                "https://quay.io/v2/fedora/fedora-bootc/manifests/45",
            )

    def test_invalid_version_never_runs_curl(self):
        with (
            patch.object(sys, "argv", ["fedora-bootc-digest.py", "../../bad"]),
            patch.object(digest.subprocess, "run") as run,
        ):
            with self.assertRaises(SystemExit):
                digest.main()
            run.assert_not_called()

    def test_invalid_digest_fails(self):
        result = subprocess.CompletedProcess(
            [], 0, stdout="Docker-Content-Digest: broken\n"
        )
        with (
            patch.object(sys, "argv", ["fedora-bootc-digest.py", "45"]),
            patch.object(digest.subprocess, "run", return_value=result),
        ):
            self.assertEqual(digest.main(), 1)


if __name__ == "__main__":
    unittest.main()
