import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = ROOT / "editions/workstation/files/system"
SCRIPT = SYSTEM / "usr/libexec/luminus-flatpak-remotes"
DATA = SYSTEM / "usr/share/luminus/flatpak"

FLATPAK_STUB = """#!/usr/bin/python3
import json, sys
from pathlib import Path
state = Path(sys.argv[0]).with_name("remotes.json")
remotes = json.loads(state.read_text())
args = sys.argv[1:]
if args[0] == "remotes":
    print("\\n".join(f"{n}\\t{u}" for n, u in remotes.items()))
elif args[0] == "remote-add":
    name, path = args[-2], args[-1]
    if name in remotes and "--if-not-exists" in args:
        sys.exit(0)
    url = [l.split("=", 1)[1] for l in Path(path).read_text().splitlines() if l.startswith("Url=")][0]
    remotes[name] = url
    state.write_text(json.dumps(remotes))
    Path(sys.argv[0]).with_name("calls.log").open("a").write(" ".join(args) + "\\n")
else:
    sys.exit(2)
"""


def bootc_stub(image):
    return (
        "#!/bin/sh\necho '" + json.dumps({"spec": {"image": {"image": image}}}) + "'\n"
    )


class RemoteMigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="flatpak-remotes-")
        self.addCleanup(self.directory.cleanup)
        self.bin = Path(self.directory.name) / "bin"
        self.bin.mkdir()
        self.channel_file = Path(self.directory.name) / "flatpak-channel"

    def install(
        self, remotes, image="ghcr.io/luminusos/luminusos-workstation:testing-45"
    ):
        flatpak = self.bin / "flatpak"
        flatpak.write_text(FLATPAK_STUB)
        flatpak.chmod(0o755)
        (self.bin / "remotes.json").write_text(json.dumps(remotes))
        bootc = self.bin / "bootc"
        bootc.write_text(bootc_stub(image))
        bootc.chmod(0o755)

    def run_script(self):
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LUMINUS_FLATPAK_DATA": str(DATA),
            "LUMINUS_FLATPAK_CHANNEL_FILE": str(self.channel_file),
        }
        return subprocess.run(
            [str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def remotes(self):
        return json.loads((self.bin / "remotes.json").read_text())

    def calls(self):
        log = self.bin / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def test_a_new_testing_system_gets_only_the_testing_remote(self):
        self.install({})
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.remotes(),
            {"luminus-testing": "https://flatpak.luminusos.org/testing/"},
        )

    def test_a_stable_image_gets_the_stable_remote(self):
        self.install({}, "ghcr.io/luminusos/luminusos-workstation:45")
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(
            self.remotes(), {"luminus": "https://flatpak.luminusos.org/stable/"}
        )

    def test_an_image_reference_without_a_tag_is_stable(self):
        self.install({}, "localhost:5000/luminusos-workstation")
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(list(self.remotes()), ["luminus"])

    def test_repeating_the_migration_changes_nothing(self):
        self.install({})
        self.run_script()
        before = self.remotes()
        for _ in range(3):
            self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.remotes(), before)
        self.assertEqual(len(self.calls()), 1)

    def test_an_updated_system_keeps_its_existing_remotes(self):
        existing = {
            "flathub": "https://dl.flathub.org/repo/",
            "aetheris-origin": "file:///x/bundle",
        }
        self.install(dict(existing))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(
            {k: v for k, v in self.remotes().items() if k in existing}, existing
        )
        self.assertIn("luminus-testing", self.remotes())

    def test_a_remote_with_the_same_name_and_another_url_is_not_rewritten(self):
        self.install({"luminus-testing": "https://example.invalid/mine/"})
        result = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            self.remotes(), {"luminus-testing": "https://example.invalid/mine/"}
        )
        self.assertEqual(self.calls(), [])
        self.assertIn("leaving it unchanged", result.stdout)

    def test_the_channel_follows_an_administrator_override(self):
        self.install({})
        self.channel_file.write_text("stable\n")
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(list(self.remotes()), ["luminus"])

    def test_an_unknown_override_is_ignored(self):
        self.install({})
        self.channel_file.write_text("nightly\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(list(self.remotes()), ["luminus-testing"])

    def test_no_application_is_installed_or_removed(self):
        self.install({})
        self.run_script()
        for call in self.calls():
            self.assertTrue(call.startswith("remote-add"))
            self.assertNotIn("install", call.split()[:1])


class ShippedFilesTests(unittest.TestCase):
    def test_descriptors_carry_a_key_and_the_channel_branch(self):
        for channel, name in (("stable", "luminus"), ("testing", "luminus-testing")):
            text = (DATA / f"luminus-{channel}.flatpakrepo").read_text()
            self.assertIn(f"SuggestRemoteName={name}\n", text)
            self.assertIn(f"Url=https://flatpak.luminusos.org/{channel}/\n", text)
            self.assertIn(f"DefaultBranch={channel}\n", text)
            self.assertRegex(text, r"\nGPGKey=[A-Za-z0-9+/=]{200,}\n")

    def test_the_service_never_runs_before_local_filesystems_and_is_enabled_by_the_build(
        self,
    ):
        unit = (
            SYSTEM / "usr/lib/systemd/system/luminus-flatpak-remotes.service"
        ).read_text()
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStart=/usr/libexec/luminus-flatpak-remotes", unit)
        self.assertIn(
            "luminus-flatpak-remotes.service",
            (ROOT / "editions/workstation/build.py").read_text(),
        )

    def test_the_script_is_executable_and_installs_no_applications(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        self.assertNotIn('"install"', SCRIPT.read_text())
        self.assertNotIn("remote-delete", SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
