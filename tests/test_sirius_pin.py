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


def repo_file(name):
    return (
        ROOT / f"editions/workstation/files/system/etc/yum.repos.d/{name}.repo"
    ).read_text()


def pin(name):
    return re.search(rf"^{name}=(.+)$", VERSIONS, re.MULTILINE).group(1)


class SiriusPinTests(unittest.TestCase):
    def test_the_package_comes_from_the_configured_luminus_repository(self):
        self.assertIn('"sirius-installer-${sirius_rpm_version}"', INSTALLER)
        for download in (
            "curl",
            "wget",
            "github.com/luminusOS/sirius/releases",
            "rpm.luminusos.org",
        ):
            self.assertNotIn(download, INSTALLER)

    def test_package_and_metadata_signatures_are_never_disabled(self):
        for forbidden in ("--nogpgcheck", "gpgcheck=0", "--nosignature", "--nodigest"):
            self.assertNotIn(forbidden, INSTALLER)
        for channel in ("luminus", "luminus-testing"):
            text = repo_file(channel)
            self.assertIn("gpgcheck=1", text)
            self.assertIn("repo_gpgcheck=1", text)
            self.assertNotIn("gpgcheck=0", text)

    def test_release_candidates_use_the_testing_repository_and_final_versions_stable(
        self,
    ):
        self.assertIn("*-rc.*) sirius_repo=luminus-testing", INSTALLER)
        self.assertIn("*) sirius_repo=luminus ", INSTALLER)
        self.assertIn('--enablerepo="${sirius_repo}"', INSTALLER)

    def test_rpm_and_file_versions_describe_the_same_release(self):
        version, rpm_version = pin("SIRIUS_VERSION"), pin("SIRIUS_RPM_VERSION")
        self.assertEqual(version.replace("-rc.", "~rc."), rpm_version)

    def test_the_repositories_trust_only_the_bundled_channel_keys(self):
        self.assertIn(
            "rpm.luminusos.org/stable/$releasever/$basearch/", repo_file("luminus")
        )
        self.assertIn(
            "rpm.luminusos.org/testing/$releasever/$basearch/",
            repo_file("luminus-testing"),
        )
        self.assertIn(
            "gpgkey=file:///usr/share/luminus/rpm-keys/luminus-stable.asc",
            repo_file("luminus"),
        )
        self.assertIn(
            "gpgkey=file:///usr/share/luminus/rpm-keys/luminus-testing.asc",
            repo_file("luminus-testing"),
        )

    def test_stable_is_enabled_by_default_and_testing_is_opt_in(self):
        self.assertIn("enabled=1", repo_file("luminus"))
        self.assertIn("enabled=0", repo_file("luminus-testing"))

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

    def test_the_installed_system_ships_the_repositories_and_their_keys(self):
        workstation = (ROOT / "editions/workstation/Containerfile").read_text()
        self.assertIn("COPY shared/rpm-keys/ /usr/share/luminus/rpm-keys/", workstation)
        self.assertIn("COPY editions/workstation/files/system/ /", workstation)
        self.assertNotIn("rpm-keys", INSTALLER)


if __name__ == "__main__":
    unittest.main()
