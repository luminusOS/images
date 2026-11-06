import unittest
from pathlib import Path

import yaml


class CIToolingTests(unittest.TestCase):
    def test_quality_installs_verified_just_before_checks(self):
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        steps = workflow["jobs"]["quality"]["steps"]
        system = next(
            step for step in steps if step.get("name") == "Install system tooling"
        )
        self.assertNotIn(" just ", f" {system['run'].splitlines()[-1]} ")
        install_index = next(
            i for i, step in enumerate(steps) if step.get("name") == "Install just"
        )
        check_index = next(
            i for i, step in enumerate(steps) if step.get("name") == "Check tooling"
        )
        install = steps[install_index]["run"]
        self.assertLess(install_index, check_index)
        self.assertIn("just-1.46.0-x86_64-unknown-linux-musl.tar.gz", install)
        self.assertIn(
            "79966e6e353f535ee7d1c6221641bcc8e3381c55b0d0a6dc6e54b34f9db36eaa", install
        )
        self.assertLess(install.index("sha256sum --check"), install.index("tar -x"))
        self.assertIn("GITHUB_PATH", install)
