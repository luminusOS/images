import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ImageIdentityTests(unittest.TestCase):
    def test_workstation_version_does_not_depend_on_core_version(self):
        containerfile = (ROOT / "editions/workstation/Containerfile").read_text()
        for key in ("VERSION", "BUILD_ID", "IMAGE_VERSION"):
            with self.subTest(key=key):
                self.assertIn(f'{key} "${{image_version}}"', containerfile)

    def test_core_contains_scoped_image_trust(self):
        containerfile = (ROOT / "editions/core/Containerfile").read_text()
        self.assertIn("COPY shared/trust/ /", containerfile)
        workstation = (ROOT / "editions/workstation/Containerfile").read_text()
        self.assertIn("COPY shared/trust/ /", workstation)
        trust = ROOT / "shared/trust/etc"
        policy = json.loads((trust / "containers/policy.json").read_text())
        self.assertEqual(policy["default"][0]["type"], "insecureAcceptAnything")
        for repository in ("luminusos", "luminusos-workstation"):
            with self.subTest(repository=repository):
                rule = policy["transports"]["docker"][
                    f"ghcr.io/luminusos/{repository}"
                ][0]
                self.assertEqual(rule["type"], "sigstoreSigned")
                self.assertEqual(rule["keyPath"], "/etc/pki/containers/luminusos.pub")
                self.assertEqual(rule["signedIdentity"]["type"], "matchRepository")
        self.assertTrue((trust / "pki/containers/luminusos.pub").stat().st_size)


if __name__ == "__main__":
    unittest.main()
