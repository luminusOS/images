import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "editions/workstation/Containerfile.installer").read_text()
VERSIONS = (ROOT / "config/versions.env").read_text()

PRIMARY_FINGERPRINTS = {
    "stable": "92F1F4F04BC9E2A3C44CC2D35AF0A19B97265C0D",
    "testing": "11DDF884BFC46A5C548304028B3CED01A7D81531",
}


def pin(name):
    return re.search(rf"^{name}=(.+)$", VERSIONS, re.MULTILINE).group(1)


class SiriusPinTests(unittest.TestCase):
    def test_the_package_comes_from_the_luminus_repository_not_a_github_release(self):
        self.assertIn(
            "https://rpm.luminusos.org/${sirius_channel}/${fedora_version}/x86_64/Packages/",
            INSTALLER,
        )
        self.assertNotIn("github.com/luminusOS/sirius/releases", INSTALLER)

    def test_the_digest_signature_and_installation_checks_are_all_required(self):
        install = INSTALLER.index("sha256sum -c -")
        key = INSTALLER.index("rpmkeys --import")
        checksig = INSTALLER.index("rpmkeys --checksig")
        dnf = INSTALLER.index("localpkg_gpgcheck=1")
        self.assertLess(install, key)
        self.assertLess(key, checksig)
        self.assertLess(checksig, dnf)
        for forbidden in ("--nogpgcheck", "gpgcheck=0", "--nosignature", "--nodigest"):
            self.assertNotIn(forbidden, INSTALLER)

    def test_release_candidates_use_the_testing_channel_and_final_versions_stable(self):
        self.assertIn("*-rc.*) sirius_channel=testing", INSTALLER)
        self.assertIn("*) sirius_channel=stable", INSTALLER)

    def test_rpm_and_file_versions_describe_the_same_release(self):
        version, rpm_version = pin("SIRIUS_VERSION"), pin("SIRIUS_RPM_VERSION")
        self.assertEqual(version.replace("-rc.", "~rc."), rpm_version)
        self.assertRegex(pin("SIRIUS_SHA256"), r"^[0-9a-f]{64}$")

    def test_the_bundled_keys_are_the_pinned_channel_keys(self):
        for channel, fingerprint in PRIMARY_FINGERPRINTS.items():
            key = ROOT / f"shared/rpm-keys/luminus-{channel}.asc"
            output = subprocess.run(
                ["gpg", "--show-keys", "--with-colons", str(key)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            fingerprints = [
                line.split(":")[9]
                for line in output.splitlines()
                if line.startswith("fpr:")
            ]
            self.assertEqual(fingerprints[0], fingerprint, channel)
        self.assertNotEqual(
            PRIMARY_FINGERPRINTS["stable"], PRIMARY_FINGERPRINTS["testing"]
        )

    def test_the_live_root_does_not_trust_the_keys_for_the_installed_system(self):
        workstation = (ROOT / "editions/workstation/Containerfile").read_text()
        self.assertNotIn("rpm-keys", workstation)
        self.assertNotIn("luminus.asc", workstation)


if __name__ == "__main__":
    unittest.main()
