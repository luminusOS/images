import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKSTATION = ROOT / "editions/workstation"


class HardwareFeatureIntegrationTests(unittest.TestCase):
    def test_pull_request_lab_needs_no_publication_access(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        lab = workflow["jobs"].get("sysext-lab")
        self.assertIsNotNone(lab, "CI must exercise hardware features on pull requests")
        self.assertEqual(lab["if"], "github.event_name == 'pull_request'")
        self.assertEqual(lab["name"], "Hardware feature lab")
        self.assertNotIn("environment", lab)
        self.assertNotIn("secrets.", str(lab))
        self.assertTrue(
            any(
                step.get("with", {}).get("persist-credentials") is False
                for step in lab["steps"]
            )
        )
        self.assertTrue(
            any(step.get("run") == "bash tests/sysext-lab.sh" for step in lab["steps"])
        )

    def test_workstation_binds_hardware_features_to_the_oci_version(self):
        image = (WORKSTATION / "Containerfile").read_text()
        config = (WORKSTATION / "build.py").read_text()
        self.assertIn('SYSEXT_LEVEL "${image_version}"', image)
        self.assertIn(
            'LABEL org.opencontainers.image.version="${image_version}"', image
        )
        self.assertIn("systemd-container", image)
        self.assertIn("feature-manifest.sh generate", image)
        self.assertIn('"luminusos-sysext-sync.timer"', config)
        self.assertIn('"luminusos-sysext-units.service"', config)
        self.assertNotIn('"systemd-sysupdate-update.timer"', config)
        runtime = WORKSTATION / "files/system/usr/libexec/luminusos/sysext"
        self.assertTrue(runtime.is_file())
