import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github/scripts/workflow"))
import validation_driver as driver

CHECKSUM = "c" * 64
DIFF_IDS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]


def gvariant(value):
    text = json.dumps(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{text}'\n"


def done(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class FakeGuest:
    def __init__(self, results):
        self.results = results
        self.commands = {}

    def run(self, name, command, **_kwargs):
        self.commands[name] = command
        return ["ssh", "root@vsock", command], self.results[name]


def candidate():
    return {
        "version": 1,
        "release_kind": "full",
        "run_id": 12,
        "repository": "Org/repo",
        "source_sha": "a" * 40,
        "build_version": "45.20261116.1",
        "images": {
            name: "ghcr.io/org/luminusos-candidates@sha256:" + str(i) * 64
            for i, name in enumerate(("core", "workstation", "installer"), 1)
        },
        "artifacts": {"live.iso": "c" * 64},
    }


def bootc(digest, staged=None):
    return json.dumps(
        {
            "status": {
                "staged": staged,
                "booted": {
                    "image": {
                        "image": {
                            "image": "ghcr.io/org/luminusos-workstation:testing-45"
                        },
                        "imageDigest": digest,
                        "version": "45.20261116.1",
                    },
                    "ostree": {"checksum": CHECKSUM, "deploySerial": 0},
                },
            }
        }
    )


def mounts(sysroot="btrfs", var="btrfs", boot="ext4"):
    return json.dumps(
        {
            "filesystems": [
                {
                    "target": "/",
                    "fstype": "overlay",
                    "children": [
                        {"target": "/sysroot", "fstype": sysroot},
                        {
                            "target": "/var",
                            "fstype": var,
                            "children": [{"target": "/boot", "fstype": boot}],
                        },
                    ],
                }
            ]
        }
    )


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.receipts = driver.Receipts(self.tmp, candidate())

    def written(self):
        return {p.stem for p in self.tmp.glob("*.json")}

    def test_receipts_satisfy_the_release_contract_only_when_complete(self):
        for name in driver.release_pipeline.CHECKS:
            self.receipts.write(name, ["ssh", name], driver.now(), f"observed {name}\n")
        data = [json.loads(p.read_text()) for p in sorted(self.tmp.glob("*.json"))]
        driver.release_pipeline.validate_receipts(data, self.tmp, candidate())
        with self.assertRaises(driver.CheckFailed):
            self.receipts.write("sirius_install", ["ssh"], driver.now(), "again")
        with self.assertRaises(driver.CheckFailed):
            self.receipts.write("not_a_check", ["ssh"], driver.now(), "x")
        with self.assertRaisesRegex(ValueError, "missing receipts"):
            driver.release_pipeline.validate_receipts(data[:-1], self.tmp, candidate())

    def test_vm_boots_with_enforced_secure_boot_firmware_and_network(self):
        vm = driver.vmlib.VM(
            cid=9,
            disk=self.tmp / "d.qcow2",
            key=self.tmp / "k",
            public_key="ssh-ed25519 AAAA",
            output=self.tmp,
            code=Path("/fw/OVMF_CODE_4M.ms.fd"),
            variables=self.tmp / "vars.fd",
        )
        argv = driver.qemu_argv(vm, iso=None, serial=self.tmp / "boot1.serial")
        self.assertEqual(argv[argv.index("-machine") + 1], "q35,smm=on")
        self.assertIn("driver=cfi.pflash01,property=secure,value=on", argv)
        self.assertIn(
            "if=pflash,format=raw,readonly=on,file=/fw/OVMF_CODE_4M.ms.fd", argv
        )
        self.assertEqual(
            argv[argv.index("-serial") + 1], f"file:{self.tmp}/boot1.serial"
        )
        self.assertEqual(argv[argv.index("-nic") + 1], "user,model=virtio-net-pci")

    def test_layout_requires_btrfs_root_and_var_and_ext4_boot_in_nested_tree(self):
        self.assertEqual(driver.check_layout(json.loads(mounts())), [])
        for broken in (mounts(sysroot="xfs"), mounts(var="ext4"), mounts(boot="btrfs")):
            self.assertTrue(driver.check_layout(json.loads(broken)))
        self.assertTrue(driver.check_layout({"filesystems": [{"target": "/"}]}))

    def test_first_boot_binds_running_state_version_and_layout(self):
        good = {
            "first-boot-state": done("running\n"),
            "first-boot-bootc": done(bootc("sha256:" + "a" * 64)),
            "first-boot-mounts": done(mounts()),
            "first-boot-failed": done("x.service\n"),
            "first-boot-config": done(
                gvariant(
                    {
                        "history": [{"created_by": "it's"}],
                        "rootfs": {"diff_ids": DIFF_IDS},
                    }
                )
            ),
        }
        guest = FakeGuest(good)
        digest = driver.first_boot(guest, self.receipts, candidate(), DIFF_IDS)
        command = guest.commands["first-boot-config"]
        self.assertIn(CHECKSUM, command)
        self.assertIn("--print-metadata-key=ostree.container.image-config", command)
        self.assertEqual(digest, "sha256:" + "a" * 64)
        self.assertEqual(self.written(), {"first_boot"})
        wrong_version = json.loads(good["first-boot-bootc"].stdout)
        wrong_version["status"]["booted"]["image"]["version"] = "45.20261105.1"
        for name, result in (
            ("first-boot-state", done("degraded\n", 1)),
            ("first-boot-bootc", done(json.dumps(wrong_version))),
            ("first-boot-mounts", done(mounts(boot="vfat"))),
            (
                "first-boot-config",
                done(gvariant({"rootfs": {"diff_ids": DIFF_IDS[:1]}})),
            ),
            ("first-boot-config", done("", 1, "No such metadata key")),
            ("first-boot-config", done("'not json'\n")),
        ):
            with self.subTest(name=name), self.assertRaises(driver.CheckFailed):
                driver.first_boot(
                    FakeGuest({**good, name: result}),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                    candidate(),
                    DIFF_IDS,
                )

    def test_live_isolation_checks_every_live_only_path(self):
        # Observed in run 44028202057: rpm reports the missing package on stdout.
        guest = FakeGuest(
            {
                "live-isolation": done(
                    "package sirius-installer is not installed\nisolated\n"
                )
            }
        )
        driver.live_isolation(guest, self.receipts)
        command = guest.commands["live-isolation"]
        self.assertIn("! rpm -q --quiet sirius-installer", command)
        for path in driver.LIVE_ONLY:
            self.assertIn(f"! test -e {path}", command)
        self.assertIn("! id liveuser", command)
        self.assertIn("AutomaticLoginEnable", command)
        for result in (
            done("", 1),
            done("isolated\n", 1),
            done("package sirius-installer is not installed\n"),
            done("isolated\nextra\n"),
        ):
            with self.subTest(result=result), self.assertRaises(driver.CheckFailed):
                driver.live_isolation(
                    FakeGuest({"live-isolation": result}),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                )

    def test_expected_key_compares_guest_trust_files_with_the_repository(self):
        lines = "".join(
            f"{hashlib.sha256((driver.TRUST / p).read_bytes()).hexdigest()}  /{p}\n"
            for p in driver.OFFICIAL_FILES
        )
        driver.expected_key(FakeGuest({"expected-key": done(lines)}), self.receipts)
        tampered = lines.replace(lines[:64], "0" * 64, 1)
        with self.assertRaises(driver.CheckFailed):
            driver.expected_key(
                FakeGuest({"expected-key": done(tampered)}),
                driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
            )

    def test_secure_boot_selinux_and_firewall_need_the_exact_state(self):
        driver.secure_boot(
            FakeGuest({"secure-boot": done("SecureBoot enabled\n")}), self.receipts
        )
        for result in (done("SecureBoot disabled\n"), done("", 1)):
            with self.assertRaises(driver.CheckFailed):
                driver.secure_boot(
                    FakeGuest({"secure-boot": result}),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                )
        with self.assertRaises(driver.CheckFailed):
            driver.exact(
                FakeGuest({"selinux_enforcing": done("Permissive\n")}),
                self.receipts,
                "selinux_enforcing",
                "getenforce",
                "Enforcing",
            )

    def test_installed_system_has_no_tcp_ssh_listener(self):
        clean = done(
            'LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=9,fd=7))\n'
            'LISTEN 0 4096 [::1]:631 [::]:* users:(("cupsd",pid=9,fd=8))\n'
            'LISTEN 0 4096 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=7,fd=9))\n'
            'LISTEN 0 4096 0.0.0.0:5355 0.0.0.0:* users:(("systemd-resolve",pid=7,fd=11))\n'
            'LISTEN 0 4096 [::]:5355 [::]:* users:(("systemd-resolve",pid=7,fd=13))\n'
            "---\n"
            "vsock::22 sshd-vsock.socket sshd-vsock@0.service\n"
            "/run/dbus/system_bus_socket dbus.socket dbus-broker.service\n"
            "127.0.0.1:631 cups.socket cups.service\n"
        )
        guest = FakeGuest({"no_tcp_ssh": clean})
        driver.no_tcp_ssh(guest, self.receipts)
        self.assertIn("ss -Hltnp", guest.commands["no_tcp_ssh"])
        self.assertIn("systemctl list-sockets", guest.commands["no_tcp_ssh"])
        self.assertEqual(self.written(), {"no_tcp_ssh"})
        for output, code in (
            ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n---\n", 0),
            ("LISTEN 0 128 [::]:22 [::]:*\n---\n", 0),
            (
                'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=4,fd=3))\n---\n',
                0,
            ),
            (
                'LISTEN 0 128 127.0.0.1:8022 0.0.0.0:* users:(("sshd-session",pid=4,fd=3))\n---\n',
                0,
            ),
            ("---\n[::]:2222 sshd.socket sshd@0.service\n", 0),
            ("---\n0.0.0.0:2200 ssh-alt.socket sshd.service\n", 0),
            (
                'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("dropbear",pid=4,fd=3))\n---\n',
                0,
            ),
            ('LISTEN 0 128 [::]:8080 [::]:* users:(("httpd",pid=4,fd=3))\n---\n', 0),
            (
                'LISTEN 0 128 192.168.1.5:631 0.0.0.0:* users:(("cupsd",pid=4,fd=3))\n---\n',
                0,
            ),
            ("---\n0.0.0.0:2200 remote-shell.socket dropbear.service\n", 0),
            (
                'LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:* users:(("systemd-resolve",pid=7,fd=11))\n---\n',
                0,
            ),
            ("no separator\n", 0),
            ("---\n", 1),
        ):
            receipts = driver.Receipts(Path(tempfile.mkdtemp()), candidate())
            with self.subTest(output=output), self.assertRaises(driver.CheckFailed):
                driver.no_tcp_ssh(
                    FakeGuest({"no_tcp_ssh": done(output, code)}), receipts
                )
            self.assertEqual(list(receipts.directory.glob("*.json")), [])

    def test_sirius_install_receipt_requires_finished(self):
        finished = done('{"Step":{"fraction":1.0,"message":"x"}}\n"Finished"\n')
        guest = FakeGuest({"sirius-run-playbook": finished})
        driver.sirius_install(guest, self.receipts)
        self.assertEqual(guest.commands["sirius-run-playbook"], "sirius run-playbook")
        self.assertEqual(self.written(), {"sirius_install"})
        for result in (done('{"Error":{"message":"boom"}}\n'), done('"Finished"\n', 1)):
            receipts = driver.Receipts(Path(tempfile.mkdtemp()), candidate())
            with self.assertRaises(driver.CheckFailed):
                driver.sirius_install(
                    FakeGuest({"sirius-run-playbook": result}), receipts
                )
            self.assertEqual(list(receipts.directory.glob("*.json")), [])

    def test_security_state_requires_enforcing_selinux_and_running_firewall(self):
        good = {"selinux_enforcing": done("Enforcing\n"), "firewall": done("running\n")}
        guest = FakeGuest(good)
        driver.security_state(guest, self.receipts)
        self.assertEqual(guest.commands["firewall"], "firewall-cmd --state")
        self.assertEqual(self.written(), {"selinux_enforcing", "firewall"})
        for name, result in (
            ("firewall", done("not running\n", 252)),
            ("firewall", done("running?\n")),
        ):
            with (
                self.subTest(result=result.stdout),
                self.assertRaises(driver.CheckFailed),
            ):
                driver.security_state(
                    FakeGuest({**good, name: result}),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                )

    def test_only_the_expected_policy_rejection_counts(self):
        unsigned = (
            "error: Switching: Pulling: Source image rejected: "
            "A signature was required, but no signature exists"
        )
        foreign = (
            "error: Switching: Pulling: Source image rejected: "
            "cryptographic signature verification failed: invalid signature"
        )
        self.assertTrue(driver.rejected(done("", 1, unsigned), "unsigned"))
        # Observed from bootc 1.17 in run 44033490829, through the skopeo proxy.
        proxied = (
            "error: Switching: Switching (ostree): Preparing import: Fetching manifest: "
            "failed to invoke method OpenImage: A signature was required, but no "
            "signature exists"
        )
        self.assertTrue(driver.rejected(done("", 1, proxied), "unsigned"))
        self.assertFalse(driver.rejected(done("", 1, proxied), "foreign"))
        proxied_foreign = (
            "error: Switching: failed to invoke method OpenImage: cryptographic "
            "signature verification failed: invalid signature"
        )
        self.assertTrue(driver.rejected(done("", 1, proxied_foreign), "foreign"))
        self.assertTrue(driver.rejected(done("", 1, foreign), "foreign"))
        self.assertFalse(driver.rejected(done("", 1, foreign), "unsigned"))
        self.assertFalse(driver.rejected(done("", 1, unsigned), "foreign"))
        self.assertFalse(driver.rejected(done(unsigned, 0), "unsigned"))
        for noise in (
            "connection refused",
            "manifest rejected: signature blob too large",
            "Source image rejected: Running image docker://x is rejected by policy.",
            "Source image rejected: fetching signature: MANIFEST_UNKNOWN",
            "failed to invoke method OpenImage: manifest unknown",
            "failed to invoke method OpenImage: reading signatures: connection refused",
        ):
            for kind in ("unsigned", "foreign"):
                self.assertFalse(driver.rejected(done("", 1, noise), kind))

    def test_rejection_requires_nothing_staged_and_the_same_booted_image(self):
        rejected = done(
            "",
            1,
            "Source image rejected: A signature was required, but no signature exists",
        )
        a, b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        driver.rejection(
            FakeGuest(
                {
                    "unsigned_rejected": rejected,
                    "unsigned_rejected-status": done(bootc(a)),
                }
            ),
            self.receipts,
            "unsigned_rejected",
            "unsigned",
            a,
        )
        for status in (done(bootc(a, staged={})), done(bootc(b))):
            with (
                self.subTest(status=status.stdout),
                self.assertRaises(driver.CheckFailed),
            ):
                driver.rejection(
                    FakeGuest(
                        {
                            "unsigned_rejected": rejected,
                            "unsigned_rejected-status": status,
                        }
                    ),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                    "unsigned_rejected",
                    "unsigned",
                    a,
                )

    def test_update_and_rollback_check_booted_digest_and_marker(self):
        a, b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        ok = done("")
        driver.moved(
            FakeGuest(
                {"update-status": done(bootc(b)), "update-marker": done("update\n")}
            ),
            self.receipts,
            "update",
            ["ssh"],
            ok,
            driver.now(),
            b,
            marker="update",
        )
        driver.moved(
            FakeGuest(
                {"rollback-status": done(bootc(a)), "rollback-marker": done("", 1)}
            ),
            self.receipts,
            "rollback",
            ["ssh"],
            ok,
            driver.now(),
            a,
            marker=None,
        )
        for results, digest, marker in (
            (
                {"rollback-status": done(bootc(b)), "rollback-marker": done("", 1)},
                a,
                None,
            ),
            (
                {
                    "rollback-status": done(bootc(a)),
                    "rollback-marker": done("update\n"),
                },
                a,
                None,
            ),
            (
                {"update-status": done(bootc(b)), "update-marker": done("unsigned\n")},
                b,
                "update",
            ),
        ):
            name = next(iter(results)).split("-")[0]
            with self.subTest(results=results), self.assertRaises(driver.CheckFailed):
                driver.moved(
                    FakeGuest(results),
                    driver.Receipts(Path(tempfile.mkdtemp()), candidate()),
                    name,
                    ["ssh"],
                    ok,
                    driver.now(),
                    digest,
                    marker=marker,
                )

    def test_guest_timeout_keeps_partial_output_as_diagnostics(self):
        vm = driver.vmlib.VM(
            9,
            self.tmp / "d",
            self.tmp / "k",
            "pub",
            self.tmp,
            Path("/c"),
            self.tmp / "v",
        )
        guest = driver.Guest(vm, self.tmp)
        expired = subprocess.TimeoutExpired(
            ["ssh"], 5, output="half done", stderr="slow"
        )
        with (
            unittest.mock.patch.object(driver.subprocess, "run", side_effect=expired),
            self.assertRaisesRegex(driver.CheckFailed, "timed out"),
        ):
            guest.run("sirius-run-playbook", "sirius run-playbook", timeout=5)
        text = (self.tmp / "sirius-run-playbook.txt").read_text()
        self.assertIn("half done", text)
        self.assertIn("slow", text)

    def test_registry_must_answer_the_api_and_exit_is_fatal(self):
        exited = unittest.mock.Mock(poll=unittest.mock.Mock(return_value=1), pid=1)
        with (
            unittest.mock.patch.object(driver.subprocess, "Popen", return_value=exited),
            self.assertRaisesRegex(driver.CheckFailed, "exited"),
        ):
            driver.start_registry(self.tmp, self.tmp)
        running = unittest.mock.Mock(poll=unittest.mock.Mock(return_value=None), pid=1)
        with (
            unittest.mock.patch.object(
                driver.subprocess, "Popen", return_value=running
            ),
            unittest.mock.patch.object(
                driver, "registry_ready", side_effect=[False, True]
            ),
            unittest.mock.patch.object(driver.time, "sleep"),
        ):
            self.assertIs(driver.start_registry(self.tmp, self.tmp), running)

    def test_boot_fails_fast_when_qemu_exits(self):
        vm = driver.vmlib.VM(
            9,
            self.tmp / "d",
            self.tmp / "k",
            "pub",
            self.tmp,
            Path("/c"),
            self.tmp / "v",
        )
        machine = driver.Machine(vm, self.tmp)
        exited = unittest.mock.Mock(poll=unittest.mock.Mock(return_value=1), pid=1)
        clock = iter(range(0, 100000, 5))
        with (
            unittest.mock.patch.object(driver.subprocess, "Popen", return_value=exited),
            unittest.mock.patch.object(
                driver.subprocess, "run", return_value=done("", 255)
            ) as ssh,
            unittest.mock.patch.object(driver.time, "sleep"),
            unittest.mock.patch.object(
                driver.time, "monotonic", side_effect=lambda: next(clock)
            ),
            self.assertRaisesRegex(driver.CheckFailed, "QEMU exited"),
        ):
            machine.start(None)
        ssh.assert_not_called()
        alive = unittest.mock.Mock(poll=unittest.mock.Mock(return_value=None), pid=1)
        with (
            unittest.mock.patch.object(driver.subprocess, "Popen", return_value=alive),
            unittest.mock.patch.object(
                driver.subprocess, "run", side_effect=[done("", 255), done("")]
            ),
            unittest.mock.patch.object(driver.time, "sleep"),
        ):
            machine.start(None)

    def test_registry_listens_only_on_loopback(self):
        running = unittest.mock.Mock(poll=unittest.mock.Mock(return_value=None), pid=1)
        with (
            unittest.mock.patch.object(
                driver.subprocess, "Popen", return_value=running
            ),
            unittest.mock.patch.object(driver, "registry_ready", return_value=True),
        ):
            driver.start_registry(self.tmp, self.tmp)
        config = json.loads((self.tmp / "registry.yml").read_text())
        self.assertEqual(config["http"]["addr"], "127.0.0.1:5000")

    def test_stopping_an_exited_process_is_harmless(self):
        with unittest.mock.patch.object(
            driver.os, "killpg", side_effect=ProcessLookupError
        ):
            driver.terminate(unittest.mock.Mock(pid=123, wait=unittest.mock.Mock()))

    def test_base_diff_ids_come_from_the_staged_candidate_image(self):
        layout = self.tmp / "layout"
        (layout / "blobs/sha256").mkdir(parents=True)

        def put(data):
            digest = hashlib.sha256(data).hexdigest()
            (layout / "blobs/sha256" / digest).write_bytes(data)
            return f"sha256:{digest}"

        config = put(json.dumps({"rootfs": {"diff_ids": DIFF_IDS}}).encode())
        manifest = put(
            json.dumps({"config": {"digest": config}, "layers": []}).encode()
        )
        (layout / "index.json").write_text(
            json.dumps(
                {
                    "manifests": [
                        {
                            "digest": manifest,
                            "annotations": {
                                "org.opencontainers.image.ref.name": "base"
                            },
                        }
                    ]
                }
            )
        )
        self.assertEqual(driver.base_diff_ids(layout), DIFF_IDS)

    def test_fixture_policy_adds_only_the_fixture_scope(self):
        official = json.loads((driver.TRUST / "etc/containers/policy.json").read_text())
        before = json.dumps(official)
        updated = driver.fixture_policy(official)
        self.assertEqual(json.dumps(official), before)
        added = set(updated["transports"]["docker"]) - set(
            official["transports"]["docker"]
        )
        self.assertEqual(added, {driver.FIXTURE})
        for scope, rules in official["transports"]["docker"].items():
            self.assertEqual(updated["transports"]["docker"][scope], rules)
        self.assertEqual(updated["default"], official["default"])
        self.assertEqual(
            updated["transports"]["docker"][driver.FIXTURE][0]["keyPath"],
            driver.FIXTURE_KEY_PATH,
        )

    def test_marker_layer_reuses_base_blobs_and_extends_the_config(self):
        layout = self.tmp / "layout"
        (layout / "blobs/sha256").mkdir(parents=True)

        def put(data):
            digest = hashlib.sha256(data).hexdigest()
            (layout / "blobs/sha256" / digest).write_bytes(data)
            return {"digest": f"sha256:{digest}", "size": len(data)}

        base_layer = put(b"base layer")
        config = put(
            json.dumps(
                {"rootfs": {"diff_ids": ["sha256:" + "0" * 64]}, "history": [{}]}
            ).encode()
        )
        manifest = put(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        **config,
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            **base_layer,
                        }
                    ],
                }
            ).encode()
        )
        (layout / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            **manifest,
                            "annotations": {
                                "org.opencontainers.image.ref.name": "base"
                            },
                        }
                    ],
                }
            )
        )
        driver.add_marker_layer(layout, "base", "update", "update")
        driver.add_marker_layer(layout, "base", "unsigned", "unsigned")
        index = json.loads((layout / "index.json").read_text())
        refs = {
            m["annotations"]["org.opencontainers.image.ref.name"]: m
            for m in index["manifests"]
        }
        self.assertNotEqual(refs["update"]["digest"], refs["unsigned"]["digest"])

        def blob(digest):
            return (layout / "blobs" / digest.replace(":", "/")).read_bytes()

        for ref in ("update", "unsigned"):
            derived = json.loads(blob(refs[ref]["digest"]))
            self.assertEqual(derived["layers"][0]["digest"], base_layer["digest"])
            top = blob(derived["layers"][1]["digest"])
            self.assertEqual(
                "sha256:" + hashlib.sha256(top).hexdigest(),
                derived["layers"][1]["digest"],
            )
            raw = gzip.decompress(top)
            derived_config = json.loads(blob(derived["config"]["digest"]))
            self.assertEqual(
                derived_config["rootfs"]["diff_ids"],
                ["sha256:" + "0" * 64, "sha256:" + hashlib.sha256(raw).hexdigest()],
            )
            self.assertEqual(len(derived_config["history"]), 2)
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                member = tar.extractfile(driver.MARKER.lstrip("/"))
                self.assertEqual(member.read(), f"{ref}\n".encode())


if __name__ == "__main__":
    unittest.main()
