import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_feasibility", ROOT / ".github/scripts/workflow/install_feasibility.py"
)
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


class InstallFeasibilityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.key = self.root / "id"
        self.vm = probe.VM(
            cid=42,
            disk=self.root / "target.qcow2",
            key=self.key,
            public_key="ssh-ed25519 AAAAC3Nza fixture",
            output=self.root / "out",
            code=Path("/fw/CODE.fd"),
            variables=self.root / "vars.fd",
        )

    def test_request_targets_the_blank_virtio_disk_without_encryption(self):
        request = json.loads(probe.install_request("/dev/vda"))
        self.assertEqual(request["target_disk"], "/dev/vda")
        self.assertFalse(request["encrypt"])
        self.assertFalse(request["tpm"])
        self.assertEqual(request["encryption_key"], "")
        self.assertIsNone(request["partition_plan"])
        self.assertEqual(
            set(request),
            {
                "target_disk",
                "encrypt",
                "tpm",
                "encryption_key",
                "locale",
                "keyboard",
                "timezone",
                "hostname",
                "username",
                "full_name",
                "partition_plan",
            },
        )

    def test_live_boot_attaches_iso_and_requires_kvm_vsock_and_credential(self):
        argv = probe.qemu_argv(self.vm, iso=Path("/data/live.iso"))
        self.assertIn("-enable-kvm", argv)
        self.assertNotIn("max", argv)
        self.assertIn("vhost-vsock-pci,guest-cid=42", argv)
        self.assertIn(
            "type=11,value=io.systemd.credential:ssh.authorized_keys.root="
            "ssh-ed25519 AAAAC3Nza fixture",
            argv,
        )
        self.assertNotIn("-cdrom", argv)
        self.assertIn(
            "id=live,if=none,media=cdrom,readonly=on,format=raw,file=/data/live.iso",
            argv,
        )
        self.assertIn("ide-cd,bus=ide.0,drive=live,bootindex=0", argv)
        self.assertIn(f"file={self.vm.disk},format=qcow2,if=virtio", argv)

    def test_installed_boot_has_no_iso(self):
        argv = probe.qemu_argv(self.vm, iso=None)
        self.assertFalse(any("media=cdrom" in item for item in argv))
        self.assertIn(f"file={self.vm.disk},format=qcow2,if=virtio", argv)

    def test_ssh_uses_vsock_proxy_and_ephemeral_key_only(self):
        argv = probe.ssh_argv(self.vm, "true")
        self.assertEqual(argv[0], "ssh")
        self.assertIn("ProxyCommand=socat - VSOCK-CONNECT:42:22", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(argv[argv.index("-i") + 1], str(self.key))
        self.assertEqual(argv[-2:], ["root@vsock", "true"])

    def test_playbook_requires_finished_and_success(self):
        for stdout, code, ok in (
            ('{"Step":{"fraction":1.0,"message":"x"}}\n"Finished"\n', 0, True),
            ('"Finished"\n', 1, False),
            ('{"Error":{"message":"boom"}}\n', 0, False),
            ('{"Step":{"fraction":0.5,"message":"x"}}\n', 0, False),
            ('{"Log":{"line":"\\"Finished\\""}}\n', 0, False),
        ):
            with self.subTest(stdout=stdout, code=code):
                self.assertEqual(probe.playbook_finished(stdout, code), ok)

    def test_preflight_rejects_missing_kvm_vsock_or_disk(self):
        cases = (
            ({"/dev/kvm": False, "/dev/vhost-vsock": True}, 100, "KVM"),
            ({"/dev/kvm": True, "/dev/vhost-vsock": False}, 100, "vsock"),
            ({"/dev/kvm": True, "/dev/vhost-vsock": True}, 1, "disk"),
        )
        for access, free_gib, message in cases:
            usage = mock.Mock(free=free_gib * 1024**3)
            with (
                self.subTest(message=message),
                mock.patch.object(
                    probe.os,
                    "access",
                    side_effect=lambda p, _m, access=access: access[str(p)],
                ),
                mock.patch.object(probe.shutil, "disk_usage", return_value=usage),
                self.assertRaisesRegex(probe.ProbeError, message),
            ):
                probe.preflight(self.root, required_bytes=40 * 1024**3)

    def test_wait_for_ssh_times_out(self):
        failure = subprocess.CompletedProcess([], 255, "", "refused")
        clock = iter(range(0, 1000, 30))
        with (
            mock.patch.object(probe.subprocess, "run", return_value=failure),
            mock.patch.object(probe.time, "monotonic", side_effect=lambda: next(clock)),
            mock.patch.object(probe.time, "sleep"),
            self.assertRaisesRegex(probe.ProbeError, "ssh"),
        ):
            probe.wait_for_ssh(self.vm, timeout=120)

    def test_installed_facts_require_every_check_to_succeed(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        outputs = {
            "is-system-running": subprocess.CompletedProcess([], 0, "running\n", ""),
            "failed-units": ok,
            "bootc-status": subprocess.CompletedProcess([], 0, '{"status": {}}', ""),
            "findmnt": subprocess.CompletedProcess([], 0, '{"filesystems": []}', ""),
            "getenforce": subprocess.CompletedProcess([], 0, "Enforcing\n", ""),
        }
        with mock.patch.object(
            probe, "remote", side_effect=lambda _vm, name, *_a, **_k: outputs[name]
        ):
            facts = probe.installed_facts(self.vm)
        self.assertEqual(facts["system_state"], "running")
        self.assertEqual(facts["selinux"], "Enforcing")
        for name, broken in (
            ("is-system-running", subprocess.CompletedProcess([], 1, "starting\n", "")),
            ("bootc-status", subprocess.CompletedProcess([], 1, "", "boom")),
            ("bootc-status", subprocess.CompletedProcess([], 0, "not json", "")),
            ("findmnt", subprocess.CompletedProcess([], 1, "", "")),
            ("getenforce", subprocess.CompletedProcess([], 127, "", "")),
        ):
            failing = {**outputs, name: broken}
            with (
                self.subTest(name=name, broken=broken.stdout),
                mock.patch.object(
                    probe,
                    "remote",
                    side_effect=lambda _vm, n, *_a, failing=failing, **_k: failing[n],
                ),
                self.assertRaises(probe.ProbeError),
            ):
                probe.installed_facts(self.vm)

    def test_degraded_system_is_recorded_not_fatal(self):
        ok = subprocess.CompletedProcess([], 0, "{}", "")
        outputs = {
            "is-system-running": subprocess.CompletedProcess([], 1, "degraded\n", ""),
            "failed-units": subprocess.CompletedProcess([], 0, "x.service\n", ""),
            "bootc-status": ok,
            "findmnt": ok,
            "getenforce": subprocess.CompletedProcess([], 0, "Permissive\n", ""),
        }
        with mock.patch.object(
            probe, "remote", side_effect=lambda _vm, name, *_a, **_k: outputs[name]
        ):
            facts = probe.installed_facts(self.vm)
        self.assertEqual(facts["system_state"], "degraded")
        self.assertEqual(facts["failed_units"], ["x.service"])

    def test_setup_failure_still_writes_manifest_and_removes_key(self):
        iso = self.root / "live.iso"
        iso.write_bytes(b"iso")
        out = self.root / "evidence"

        def keygen(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                key = Path(argv[argv.index("-f") + 1])
                key.write_text("private")
                key.with_suffix(".pub").write_text("ssh-ed25519 AAAA test")
                return subprocess.CompletedProcess(argv, 0)
            raise subprocess.CalledProcessError(1, argv)

        with (
            mock.patch.dict(probe.os.environ, {"RUNNER_TEMP": str(self.root)}),
            mock.patch.object(probe, "preflight", return_value={}),
            mock.patch.object(probe, "resolve_ovmf", return_value=(iso, iso)),
            mock.patch.object(probe.subprocess, "run", side_effect=keygen),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            probe.run(iso, out, cid=7)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertNotEqual(manifest.get("status"), "installed-and-booted")
        self.assertFalse((self.root / "feasibility-key").exists())
        self.assertFalse((self.root / "feasibility-key.pub").exists())

    def test_workflow_is_read_only_diagnostic_without_signing(self):
        text = (ROOT / ".github/workflows/installation-feasibility.yml").read_text()
        workflow = yaml.safe_load(text)
        self.assertEqual(
            workflow["permissions"], {"contents": "read", "actions": "read"}
        )
        job = workflow["jobs"]["install"]
        self.assertNotIn("environment", job)
        self.assertNotIn("permissions", job)
        self.assertEqual(set(re.findall(r"secrets\.([A-Z_]+)", text)), {"GITHUB_TOKEN"})
        self.assertNotIn("cosign", text)
        self.assertNotIn("record-validation", text)


if __name__ == "__main__":
    unittest.main()
