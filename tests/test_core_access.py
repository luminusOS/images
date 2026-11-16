import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "editions/core/Containerfile"
TRUST = ROOT / "shared/trust/etc/containers"


def run_instructions(path):
    text = re.sub(r"\\[ \t]*\n", " ", path.read_text(encoding="utf-8"))
    return [line for line in text.splitlines() if line.startswith("RUN ")]


class CoreRemoteAccessTests(unittest.TestCase):
    def setUp(self):
        self.runs = run_instructions(CORE)
        self.text = "\n".join(self.runs)

    def index(self, fragment):
        for position, line in enumerate(self.runs):
            if fragment in line:
                return position
        self.fail(f"missing core build step: {fragment}")

    def test_tcp_ssh_is_closed_after_firewalld_installation(self):
        disable = self.index("systemctl disable sshd.service sshd.socket")
        firewall = self.index(
            "firewall-offline-cmd --zone=public --remove-service-from-zone=ssh"
        )
        self.assertLess(self.index("install firewalld"), disable)
        self.assertLessEqual(disable, firewall)

    def test_core_build_asserts_closed_tcp_ssh(self):
        for check in (
            "! systemctl is-enabled sshd.service",
            "! systemctl is-enabled sshd.socket",
            "! systemctl is-enabled ssh.socket",
            'test "$(firewall-offline-cmd --get-default-zone)" = public',
            "! firewall-offline-cmd --query-service=ssh",
            "! firewall-offline-cmd --zone=public --query-service=ssh",
            "test -f /usr/lib/systemd/system/sshd@.service",
            "test -x /usr/lib/systemd/system-generators/systemd-ssh-generator",
            "test -f /etc/containers/registries.d/luminusos.yaml",
        ):
            with self.subTest(check=check):
                self.assertIn(check, self.text)

    def test_ephemeral_vsock_channel_is_not_masked(self):
        for line in self.runs:
            with self.subTest(line=line[:60]):
                self.assertNotRegex(line, r"systemctl\s+mask\b")
                self.assertNotIn("systemd.ssh_auto", line)
                self.assertNotRegex(line, r"systemctl\s+disable[^&;]*sshd@")
                self.assertNotRegex(line, r"\brm\b[^&;]*(sshd@|ssh-generator)")


class WorkstationRemoteAccessTests(unittest.TestCase):
    def test_workstation_rechecks_inherited_tcp_ssh_closure(self):
        text = "\n".join(run_instructions(ROOT / "editions/workstation/Containerfile"))
        for check in (
            "! systemctl is-enabled sshd.service",
            "! systemctl is-enabled sshd.socket",
            "! systemctl is-enabled ssh.socket",
            "! firewall-offline-cmd --zone=public --query-service=ssh",
        ):
            with self.subTest(check=check):
                self.assertIn(check, text)


class SharedAttachmentTests(unittest.TestCase):
    def test_attachments_cover_exactly_signed_repositories(self):
        policy = json.loads((TRUST / "policy.json").read_text(encoding="utf-8"))
        signed = {
            repository
            for repository, rules in policy["transports"]["docker"].items()
            if any(rule.get("type") == "sigstoreSigned" for rule in rules)
        }
        self.assertEqual(
            signed,
            {"ghcr.io/luminusos/luminusos", "ghcr.io/luminusos/luminusos-workstation"},
        )
        config = yaml.safe_load(
            (TRUST / "registries.d/luminusos.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(set(config), {"docker"})
        self.assertEqual(set(config["docker"]), signed)
        for repository in signed:
            with self.subTest(repository=repository):
                self.assertEqual(
                    config["docker"][repository], {"use-sigstore-attachments": True}
                )

    def test_workstation_does_not_duplicate_shared_attachments(self):
        self.assertFalse(
            (
                ROOT
                / "editions/workstation/files/system/etc/containers/registries.d/luminusos.yaml"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()
