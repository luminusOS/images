import os
import re
import subprocess
import tempfile
import unittest
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/t03-arm64-proof.sh"
BOOTC_REPO = "quay.io/fedora/fedora-bootc"
BUILDER_REPO = "quay.io/fedora/fedora"
BOOTC_DIGEST = "sha256:" + "1" * 64
BUILDER_DIGEST = "sha256:" + "2" * 64


class Arm64ProofTests(unittest.TestCase):
    def test_build_logger_executes_real_awk_and_caps_the_saved_log(self):
        source = SCRIPT.read_text()
        logger = re.search(
            r"LC_ALL=C awk -v (\w+)=\"\$\{artifact_dir\}/build.log\" '(.*?)'", source, re.S
        )
        self.assertIsNotNone(logger)
        for text in ("building guest\nbuild complete\n", "x" * (1024 * 1024 + 10) + "\n"):
            with self.subTest(input_bytes=len(text)), tempfile.TemporaryDirectory() as directory:
                saved_log = Path(directory) / "build.log"
                saved_log.touch()
                result = subprocess.run(
                    ["awk", "-v", f"{logger[1]}={saved_log}", logger[2]],
                    input=text, text=True, capture_output=True,
                    env={**os.environ, "LC_ALL": "C"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, text)
                if len(text) < 1024 * 1024:
                    self.assertEqual(saved_log.read_text(), text)
                else:
                    saved = saved_log.read_text()
                    self.assertEqual(saved[:1024 * 1024], text[:1024 * 1024])
                    self.assertIn("[build log truncated at 1 MiB]", saved)
                    self.assertLess(len(saved), 1024 * 1024 + 100)

    def run_script(self, *args, env=None):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env={**os.environ, **(env or {})},
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def manifest_index(digest, *, duplicate_arm64=False, include_arm64=True):
        manifests = [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}}
        ]
        if include_arm64:
            arm = {"digest": digest, "platform": {"os": "linux", "architecture": "arm64"}}
            manifests.append(arm)
            if duplicate_arm64:
                manifests.append(arm.copy())
        return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests}

    def install_fake_skopeo(
        self,
        fake_bin,
        directory,
        *,
        bootc_index=None,
        builder_index=None,
        bootc_config=None,
        builder_config=None,
        fail_ref="",
    ):
        bootc_index = bootc_index or self.manifest_index(BOOTC_DIGEST)
        builder_index = builder_index or self.manifest_index(BUILDER_DIGEST)
        bootc_config = bootc_config or {
            "architecture": "arm64",
            "os": "linux",
            "config": {"Labels": {"version": "45.20261020.1"}},
        }
        builder_config = builder_config or {
            "architecture": "arm64",
            "os": "linux",
            "config": {"Labels": {"version": "45"}},
        }
        fixtures = {
            "bootc-index.json": bootc_index,
            "builder-index.json": builder_index,
            "bootc-config.json": bootc_config,
            "builder-config.json": builder_config,
        }
        for name, payload in fixtures.items():
            (directory / name).write_text(json.dumps(payload, separators=(",", ":")))
        self.write_command(
            fake_bin / "skopeo",
            '''printf '%s\\n' "$*" >>"$T03_SKOPEO_LOG"
ref="${!#}"
[[ -z "${T03_FAIL_REF:-}" || "$ref" != "$T03_FAIL_REF" ]] || exit 31
case "$ref" in
  docker://quay.io/fedora/fedora-bootc:45) cat "$T03_BOOTC_INDEX" ;;
  docker://quay.io/fedora/fedora:45) cat "$T03_BUILDER_INDEX" ;;
  docker://quay.io/fedora/fedora-bootc@*) cat "$T03_BOOTC_CONFIG" ;;
  docker://quay.io/fedora/fedora@*) cat "$T03_BUILDER_CONFIG" ;;
  *) exit 32 ;;
esac
''',
        )
        return {
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "T03_SKOPEO_LOG": str(directory / "skopeo.log"),
            "T03_BOOTC_INDEX": str(directory / "bootc-index.json"),
            "T03_BUILDER_INDEX": str(directory / "builder-index.json"),
            "T03_BOOTC_CONFIG": str(directory / "bootc-config.json"),
            "T03_BUILDER_CONFIG": str(directory / "builder-config.json"),
            "T03_FAIL_REF": fail_ref,
        }

    def test_resolver_pins_one_arm64_child_per_fedora45_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            env = self.install_fake_skopeo(fake_bin, directory)
            output = directory / "resolved-inputs.json"
            result = self.run_script("--resolve-inputs", str(output), env=env)

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["platform"], {"os": "linux", "architecture": "arm64"})
            self.assertEqual(data["inputs"]["bootc"]["ref"], f"{BOOTC_REPO}@{BOOTC_DIGEST}")
            self.assertEqual(data["inputs"]["builder"]["ref"], f"{BUILDER_REPO}@{BUILDER_DIGEST}")
            self.assertEqual(data["inputs"]["bootc"]["config"]["version_label"], "45.20261020.1")
            self.assertEqual(
                data["inputs"]["bootc"]["raw_manifest_sha256"],
                "sha256:" + hashlib.sha256((directory / "bootc-index.json").read_bytes()).hexdigest(),
            )
            calls = (directory / "skopeo.log").read_text().splitlines()
            self.assertEqual(sum(f"docker://{BOOTC_REPO}:45" in call for call in calls), 1)
            self.assertEqual(sum(f"docker://{BUILDER_REPO}:45" in call for call in calls), 1)
            self.assertEqual(sum(f"docker://{BOOTC_REPO}@{BOOTC_DIGEST}" in call for call in calls), 1)
            self.assertEqual(sum(f"docker://{BUILDER_REPO}@{BUILDER_DIGEST}" in call for call in calls), 1)
            self.assertTrue(all("--no-creds" in call for call in calls))
            self.assertIn(BOOTC_DIGEST, result.stdout)
            self.assertIn(BUILDER_DIGEST, result.stdout)

    def test_resolver_fails_closed_for_bad_indexes_configs_and_registry_errors(self):
        cases = (
            ("missing arm64", {"bootc_index": self.manifest_index(BOOTC_DIGEST, include_arm64=False)}, {}, "exactly one"),
            ("duplicate arm64", {"bootc_index": self.manifest_index(BOOTC_DIGEST, duplicate_arm64=True)}, {}, "exactly one"),
            ("bad child digest", {"bootc_index": self.manifest_index("sha256:bad")}, {}, "digest"),
            ("wrong config architecture", {}, {"bootc_config": {"architecture": "amd64", "os": "linux"}}, "config platform"),
            ("wrong config OS", {}, {"bootc_config": {"architecture": "arm64", "os": "windows"}}, "config platform"),
            ("wrong builder config architecture", {}, {"builder_config": {"architecture": "amd64", "os": "linux"}}, "config platform"),
            ("tag manifest unavailable", {}, {"fail_ref": f"docker://{BOOTC_REPO}:45"}, "skopeo"),
        )
        for name, index_options, other_options, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                fake_bin = directory / "bin"
                fake_bin.mkdir()
                env = self.install_fake_skopeo(fake_bin, directory, **index_options, **other_options)
                output = directory / "resolved-inputs.json"
                result = self.run_script("--resolve-inputs", str(output), env=env)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr.lower())
                self.assertFalse(output.exists())

    def test_qemu_plan_uses_aarch64_uefi_and_snapshot_disk(self):
        result = self.run_script("--print-qemu")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("qemu-system-aarch64", result.stdout)
        self.assertIn("-machine virt", result.stdout)
        self.assertIn("-smp 4", result.stdout)
        self.assertIn("AAVMF_CODE.fd", result.stdout)
        self.assertIn("AAVMF_VARS.fd", result.stdout)
        self.assertIn("snapshot=on", result.stdout)
        self.assertNotIn("-kernel", result.stdout)

    def test_kvm_uses_host_cpu_and_tcg_uses_max_cpu(self):
        kvm = self.run_script("--print-qemu", "kvm")
        tcg = self.run_script("--print-qemu", "tcg")

        self.assertEqual(kvm.returncode, 0, kvm.stderr)
        self.assertEqual(tcg.returncode, 0, tcg.stderr)
        self.assertIn("-cpu host", kvm.stdout)
        self.assertIn("-accel kvm", kvm.stdout)
        self.assertIn("-cpu max", tcg.stdout)
        self.assertIn("-accel tcg", tcg.stdout)

    def test_workflow_artifact_contains_evidence_files_only(self):
        workflow = (ROOT / ".github/workflows/t03-arm64-proof.yml").read_text()
        upload = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]

        self.assertIn("serial.log", upload)
        self.assertIn("metadata.txt", upload)
        self.assertIn("resolved-inputs.json", upload)
        self.assertNotIn(".qcow2", upload)
        self.assertNotIn(".iso", upload)
        self.assertNotIn(".oci", upload)

    def test_workflow_is_limited_to_manual_and_exact_proof_branch(self):
        workflow = (ROOT / ".github/workflows/t03-arm64-proof.yml").read_text()

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("- proof/t03-arm64-uefi", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("packages: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", workflow)
        self.assertIn("skopeo", workflow)

    def test_proof_verifier_requires_all_fresh_guest_claims(self):
        nonce = "run-unique-1"
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                f"T03_BEGIN={nonce}\n"
                "T03_ARCH=aarch64\n"
                "T03_FEDORA_VERSION=45\n"
                "T03_UEFI=1\n"
                "T03_DEVICE_TIMEOUT_SECONDS=90\n"
                "T03_MOUNT_BOOT=mounted\n"
                "T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n"
                "T03_MOUNT_ESP=mounted\n"
                "T03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi\n"
                "T03_BOOT_COMPLETE=executed\n"
                f"T03_PASS={nonce}\n"
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, nonce)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proof_verifier_rejects_old_or_incomplete_runtime_evidence(self):
        nonce = "run-unique-1"
        valid = (
            f"T03_BEGIN={nonce}\nT03_ARCH=aarch64\nT03_FEDORA_VERSION=45\n"
            "T03_UEFI=1\nT03_DEVICE_TIMEOUT_SECONDS=90\n"
            "T03_MOUNT_BOOT=mounted\nT03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n"
            "T03_MOUNT_ESP=mounted\nT03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi\n"
            "T03_BOOT_COMPLETE=executed\n"
            f"T03_PASS={nonce}\n"
        )
        invalid_logs = (
            valid.replace("T03_DEVICE_TIMEOUT_SECONDS=90", "T03_DEVICE_TIMEOUT_SECONDS=45"),
            valid.replace("T03_MOUNT_BOOT=mounted\n", ""),
            valid.replace("T03_MOUNT_ESP=mounted", "T03_MOUNT_ESP=missing"),
            valid.replace("T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n", ""),
            valid.replace("T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot", "T03_MOUNT_BOOT_DETAILS=/dev/vda4 ext4 /boot"),
            valid.replace("T03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi", "T03_MOUNT_ESP_DETAILS=/dev/vda2 ext4 /boot/efi"),
            valid.replace(
                "T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n",
                "T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\nT03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n",
            ),
            valid.replace("T03_BOOT_COMPLETE=executed", "T03_BOOT_COMPLETE=unknown"),
        )
        for content in invalid_logs:
            with self.subTest(content=content), tempfile.NamedTemporaryFile(mode="w") as serial:
                serial.write(content)
                serial.flush()
                result = self.run_script("--verify-proof", serial.name, nonce)
                self.assertNotEqual(result.returncode, 0)

    def test_proof_verifier_accepts_explicit_ostree_condition_skip(self):
        nonce = "run-unique-1"
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                f"T03_BEGIN={nonce}\nT03_ARCH=aarch64\nT03_FEDORA_VERSION=45\n"
                "T03_UEFI=1\nT03_DEVICE_TIMEOUT_SECONDS=90\n"
                "T03_MOUNT_BOOT=mounted\nT03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\n"
                "T03_MOUNT_ESP=mounted\nT03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi\n"
                "T03_BOOT_COMPLETE=not-applicable\n"
                f"T03_PASS={nonce}\n"
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, nonce)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proof_verifier_accepts_serial_crlf_line_endings(self):
        nonce = "run-unique-1"
        with tempfile.NamedTemporaryFile(mode="wb") as serial:
            serial.write(
                f"T03_BEGIN={nonce}\r\n".encode()
                + b"T03_ARCH=aarch64\r\n"
                + b"T03_FEDORA_VERSION=45\r\n"
                + b"T03_UEFI=1\r\n"
                + b"T03_DEVICE_TIMEOUT_SECONDS=90\r\n"
                + b"T03_MOUNT_BOOT=mounted\r\n"
                + b"T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot\r\n"
                + b"T03_MOUNT_ESP=mounted\r\n"
                + b"T03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi\r\n"
                + b"T03_BOOT_COMPLETE=executed\r\n"
                + f"T03_PASS={nonce}\r\n".encode()
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, nonce)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_build_routes_disk_and_container_storage_to_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            temporary = Path(temp)
            fake_bin = temporary / "bin"
            artifact_dir = temporary / "evidence"
            fake_bin.mkdir()
            capture_service = temporary / "proof.service"
            capture_proof_script = temporary / "proof.sh"
            capture_device_timeout_config = temporary / "device-timeout.conf"
            capture_containerfile = temporary / "Containerfile"
            capture_disk = temporary / "disk.yaml"
            capture_diagnostics_service = temporary / "diagnostics.service"
            capture_diagnostics_script = temporary / "diagnostics.sh"
            capture_journald_config = temporary / "journald.conf"
            capture_hwdb_helper = temporary / "hwdb-prepare.sh"
            capture_udev_rule = temporary / "udev-debug.rules"
            call_log = temporary / "calls.log"
            self.write_command(fake_bin / "dnf", "exit 0\n")
            self.write_command(fake_bin / "sudo", 'exec "$@"\n')
            self.write_command(fake_bin / "rpm", 'printf "image-builder-45\\n"\n')
            self.write_command(fake_bin / "qemu-img", 'printf \'{"format":"qcow2","virtual-size":1073741824}\\n\'\n')
            self.write_command(
                fake_bin / "podman",
                '''printf 'storage=%s tmpdir=%s args=%s\\n' "${CONTAINERS_STORAGE_CONF:-unset}" "${TMPDIR:-unset}" "$*" >>"$T03_CALL_LOG"
[[ "${TMPDIR:-}" == "$T03_EXPECT_TMPDIR" && -d "$TMPDIR" ]] || exit 77
case "$1" in
  image) printf 'linux arm64\\n' ;;
  build)
    cp "$5/proof.service" "$T03_CAPTURE_SERVICE"
    cp "$5/proof.sh" "$T03_CAPTURE_PROOF_SCRIPT"
    cp "$5/90-t03-device-timeout.conf" "$T03_CAPTURE_DEVICE_TIMEOUT_CONFIG"
    cp "$5/diagnostics.service" "$T03_CAPTURE_DIAGNOSTICS_SERVICE"
    cp "$5/diagnostics.sh" "$T03_CAPTURE_DIAGNOSTICS_SCRIPT"
    cp "$5/90-t03-console.conf" "$T03_CAPTURE_JOURNALD_CONFIG"
    cp "$5/00-t03-vda3-debug.rules" "$T03_CAPTURE_UDEV_RULE"
    cp "$5/hwdb-prepare.sh" "$T03_CAPTURE_HWDB_HELPER"
    cp "$5/Containerfile" "$T03_CAPTURE_CONTAINERFILE"
    cp "$5/disk.yaml" "$T03_CAPTURE_DISK"
    ;;
esac
''',
            )
            self.write_command(
                fake_bin / "image-builder",
                '''printf 'cwd=%s storage=%s args=%s\\n' "$PWD" "${CONTAINERS_STORAGE_CONF:-unset}" "$*" >>"$T03_CALL_LOG"
outdir=.
name=
while (($#)); do
  case "$1" in
    --output-dir) outdir="$2"; shift 2 ;;
    --output-name) name="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$outdir"
printf 'qcow2' >"$outdir/$name"
''',
            )

            result = self.run_script(
                "--build",
                "run-unique-1",
                f"{BOOTC_REPO}@{BOOTC_DIGEST}",
                env={
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "T03_ARTIFACT_DIR": str(artifact_dir),
                    "T03_CAPTURE_SERVICE": str(capture_service),
                    "T03_CAPTURE_PROOF_SCRIPT": str(capture_proof_script),
                    "T03_CAPTURE_DEVICE_TIMEOUT_CONFIG": str(capture_device_timeout_config),
                    "T03_CAPTURE_DIAGNOSTICS_SERVICE": str(capture_diagnostics_service),
                    "T03_CAPTURE_DIAGNOSTICS_SCRIPT": str(capture_diagnostics_script),
                    "T03_CAPTURE_JOURNALD_CONFIG": str(capture_journald_config),
                    "T03_CAPTURE_UDEV_RULE": str(capture_udev_rule),
                    "T03_CAPTURE_HWDB_HELPER": str(capture_hwdb_helper),
                    "T03_CAPTURE_CONTAINERFILE": str(capture_containerfile),
                    "T03_CAPTURE_DISK": str(capture_disk),
                    "T03_CALL_LOG": str(call_log),
                    "T03_EXPECT_TMPDIR": str(artifact_dir / "build-tmp"),
                },
            )

            self.assertEqual(
                result.returncode,
                0,
                result.stdout + result.stderr + (call_log.read_text() if call_log.exists() else ""),
            )
            self.assertTrue(
                (artifact_dir / "fedora45-arm64.qcow2").is_file(),
                call_log.read_text() if call_log.exists() else "no fake command was called",
            )
            self.assertFalse((ROOT / "fedora45-arm64.qcow2").exists())
            self.assertIn('graphroot = "/var/lib/containers/storage"', (artifact_dir / "storage.conf").read_text())
            self.assertTrue((artifact_dir / "containers-storage").is_dir())
            self.assertIn("multi-user.target", capture_service.read_text())
            self.assertNotIn("After=multi-user.target", capture_service.read_text())
            self.assertIn("StandardOutput=journal", capture_service.read_text())
            self.assertIn("StandardError=journal", capture_service.read_text())
            self.assertIn("Wants=ostree-boot-complete.service", capture_service.read_text())
            self.assertIn("After=ostree-boot-complete.service", capture_service.read_text())
            self.assertEqual(
                capture_device_timeout_config.read_text(),
                "[Manager]\nDefaultDeviceTimeoutSec=90s\n",
            )
            containerfile = capture_containerfile.read_text()
            self.assertIn(
                "COPY 90-t03-device-timeout.conf /etc/systemd/system.conf.d/90-t03-device-timeout.conf",
                containerfile,
            )
            proof_script = capture_proof_script.read_text()
            for marker in (
                "T03_DEVICE_TIMEOUT_SECONDS=90",
                "T03_MOUNT_BOOT=mounted",
                "T03_MOUNT_ESP=mounted",
                "T03_BOOT_COMPLETE=executed",
                "T03_BOOT_COMPLETE=not-applicable",
            ):
                self.assertIn(marker, proof_script)
            self.assertLess(proof_script.index("T03_BOOT_COMPLETE="), proof_script.index("T03_PASS="))
            diagnostics_service = capture_diagnostics_service.read_text()
            self.assertIn("DefaultDependencies=no", diagnostics_service)
            self.assertIn("After=systemd-journald.service", diagnostics_service)
            self.assertIn("Before=emergency.service", diagnostics_service)
            self.assertIn("TimeoutStartSec=60", diagnostics_service)
            self.assertIn("WantedBy=emergency.target", diagnostics_service)
            self.assertNotIn("RequiresMountsFor=", diagnostics_service)
            self.assertNotIn("WantedBy=multi-user.target", diagnostics_service)
            self.assertIn("COPY diagnostics.service /etc/systemd/system/t03-arm64-diagnostics.service", containerfile)
            self.assertIn("COPY diagnostics.sh /usr/local/libexec/t03-arm64-diagnostics", containerfile)
            self.assertIn("COPY hwdb-prepare.sh /usr/local/libexec/t03-hwdb-prepare", containerfile)
            self.assertIn("COPY 90-t03-console.conf /usr/lib/systemd/journald.conf.d/90-t03-console.conf", containerfile)
            self.assertIn("COPY 00-t03-vda3-debug.rules /etc/udev/rules.d/00-t03-vda3-debug.rules", containerfile)
            self.assertIn("/usr/local/libexec/t03-hwdb-prepare --root /", containerfile)
            self.assertEqual(
                capture_udev_rule.read_text(),
                'SUBSYSTEM=="block", KERNEL=="vda3", OPTIONS="log_level=debug"\n',
            )
            self.assertTrue(capture_hwdb_helper.is_file())
            journald_config = capture_journald_config.read_text()
            self.assertIn("ForwardToConsole=yes", journald_config)
            self.assertIn("TTYPath=/dev/ttyAMA0", journald_config)
            self.assertIn("MaxLevelConsole=info", journald_config)
            diagnostics_script = capture_diagnostics_script.read_text()
            self.assertIn("exec >/dev/ttyAMA0 2>&1", diagnostics_script)
            self.assertIn("T03_DIAGNOSTICS_BEGIN", diagnostics_script)
            self.assertIn("T03_DIAGNOSTICS_END", diagnostics_script)
            self.assertNotIn("T03_BEGIN=", diagnostics_script)
            self.assertNotIn("T03_PASS=", diagnostics_script)
            self.assertIn("COPY disk.yaml /usr/lib/image-builder/bootc/disk.yaml", capture_containerfile.read_text())
            self.assertIn("mountpoint: /boot/efi", capture_disk.read_text())
            self.assertIn("mountpoint: /", capture_disk.read_text())
            self.assertIn("cwd=" + str(artifact_dir), call_log.read_text())
            self.assertIn("storage=" + str(artifact_dir / "storage.conf"), call_log.read_text())
            self.assertIn("tmpdir=" + str(artifact_dir / "build-tmp"), call_log.read_text())
            self.assertIn(f"{BOOTC_REPO}@{BOOTC_DIGEST}", call_log.read_text())
            self.assertIn("Proof device timeout: 90 seconds", (artifact_dir / "metadata.txt").read_text())

    def test_guest_proof_fails_closed_on_timeout_mount_and_ostree_state(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            proof = re.search(
                r'cat >"\$\{context\}/proof\.sh" <<\'EOF\'\n(.*?)\nEOF',
                SCRIPT.read_text(),
                re.S,
            )
            self.assertIsNotNone(proof)
            uart = directory / "uart.log"
            script = proof[1].replace("source /etc/os-release", "VERSION_ID=45")
            script = script.replace("test -d /sys/firmware/efi", "true")
            script = script.replace(">/dev/ttyAMA0", '>>"$T03_UART"')
            proof_path = directory / "proof.sh"
            proof_path.write_text(script)
            proof_path.chmod(0o755)
            self.write_command(fake_bin / "uname", 'printf "aarch64\\n"\n')
            self.write_command(
                fake_bin / "busctl",
                'printf "t %s\\n" "${T03_TIMEOUT_USEC:-90000000}"\n',
            )
            self.write_command(
                fake_bin / "mountpoint",
                '[[ "${T03_MISSING_MOUNT:-}" != "$2" ]]\n',
            )
            self.write_command(
                fake_bin / "findmnt",
                '''case "$*" in
  *" /boot/efi") printf '%s\\n' "${T03_ESP_MOUNT:-/dev/vda2 vfat /boot/efi}" ;;
  *" /boot") printf '%s\\n' "${T03_BOOT_MOUNT:-/dev/vda3 ext4 /boot}" ;;
  *) exit 2 ;;
esac
''',
            )
            self.write_command(
                fake_bin / "systemctl",
                '''if [[ "$1" == is-active ]]; then
  [[ "${T03_INACTIVE_UNIT:-}" != "$3" ]]
elif [[ "$1" == show ]]; then
  printf '%s\\n' "${T03_BOOT_PROPERTIES:-LoadState=loaded
ActiveState=active
SubState=exited
Result=success
ConditionResult=yes}"
else
  exit 2
fi
''',
            )

            cases = (
                ({}, 0, "T03_BOOT_COMPLETE=executed"),
                ({"T03_BOOT_PROPERTIES": "ConditionResult=yes\nLoadState=loaded\nResult=success\nSubState=exited\nActiveState=active"}, 0, "T03_BOOT_COMPLETE=executed"),
                ({"T03_BOOT_PROPERTIES": "ConditionResult=no\nLoadState=loaded\nResult=success\nSubState=dead\nActiveState=inactive"}, 0, "T03_BOOT_COMPLETE=not-applicable"),
                ({"T03_TIMEOUT_USEC": "45000000"}, 1, ""),
                ({"T03_MISSING_MOUNT": "/boot"}, 1, ""),
                ({"T03_INACTIVE_UNIT": "boot-efi.mount"}, 1, ""),
                ({"T03_BOOT_MOUNT": "/dev/vda3 vfat /boot"}, 1, ""),
                ({"T03_BOOT_MOUNT": "/dev/vda3 ext4 /"}, 1, ""),
                ({"T03_BOOT_MOUNT": "/dev/vda4 ext4 /boot"}, 1, ""),
                ({"T03_BOOT_MOUNT": "/dev/vda3 ext4 /boot extra"}, 1, ""),
                ({"T03_BOOT_MOUNT": "/dev/vda3 ext4 /boot\n/dev/vda4 ext4 /other"}, 1, ""),
                ({"T03_ESP_MOUNT": "/dev/vda2 ext4 /boot/efi"}, 1, ""),
                ({"T03_ESP_MOUNT": "/dev/vda2 vfat /boot"}, 1, ""),
                ({"T03_ESP_MOUNT": "/dev/vda4 vfat /boot/efi"}, 1, ""),
                ({"T03_BOOT_PROPERTIES": "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nConditionResult=yes"}, 1, ""),
                ({"T03_BOOT_PROPERTIES": "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\nConditionResult=no"}, 1, ""),
                ({"T03_BOOT_PROPERTIES": "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success"}, 1, ""),
                ({"T03_BOOT_PROPERTIES": "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nResult=success\nConditionResult=yes"}, 1, ""),
                ({"T03_BOOT_PROPERTIES": "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nConditionResult=yes\nUnexpected=value"}, 1, ""),
            )
            for extra_env, expected_status, expected_marker in cases:
                with self.subTest(extra_env=extra_env):
                    uart.write_text("")
                    result = subprocess.run(
                        [str(proof_path)],
                        env={
                            **os.environ,
                            **extra_env,
                            "PATH": f"{fake_bin}:{os.environ['PATH']}",
                            "T03_NONCE": "run-unique-1",
                            "T03_UART": str(uart),
                        },
                        text=True,
                        capture_output=True,
                    )
                    output = uart.read_text()
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    if expected_marker:
                        self.assertIn(expected_marker, output)
                        self.assertIn("T03_PASS=run-unique-1", output)
                        self.assertIn("T03_MOUNT_BOOT_DETAILS=/dev/vda3 ext4 /boot", output)
                        self.assertIn("T03_MOUNT_ESP_DETAILS=/dev/vda2 vfat /boot/efi", output)
                    else:
                        self.assertNotIn("T03_PASS=run-unique-1", output)
                        if "T03_BOOT_MOUNT" in extra_env:
                            self.assertNotIn("T03_MOUNT_BOOT=mounted", output)
                        if "T03_ESP_MOUNT" in extra_env:
                            self.assertNotIn("T03_MOUNT_ESP=mounted", output)

    def test_diagnostic_helper_is_read_only_bounded_and_best_effort(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            helper = re.search(
                r"cat >\"\$\{context\}/diagnostics\.sh\" <<'EOF'\n(.*?)\nEOF",
                SCRIPT.read_text(),
                re.S,
            )
            self.assertIsNotNone(helper)
            captured_output = directory / "uart.log"
            helper_script = helper[1].replace("exec >/dev/ttyAMA0 2>&1", f"exec >{captured_output} 2>&1")
            self.assertNotEqual(helper_script, helper[1])
            helper_path = directory / "diagnostics.sh"
            helper_path.write_text(helper_script)
            helper_path.chmod(0o755)
            calls = directory / "calls.log"
            for command in ("systemctl", "lsblk", "blkid", "journalctl", "ls", "stat", "sha256sum", "udevadm", "cat"):
                self.write_command(
                    fake_bin / command,
                    f'''printf '%s %s\\n' "{command}" "$*" >>"$T03_DIAGNOSTIC_CALLS"
printf 'mock-{command}\\n'
exit 1
''',
                )

            result = subprocess.run(
                [str(helper_path)],
                env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "T03_DIAGNOSTIC_CALLS": str(calls)},
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            output = captured_output.read_text()
            self.assertIn("T03_DIAGNOSTICS_BEGIN", output)
            self.assertIn("T03_DIAGNOSTICS_END", output)
            self.assertLess(output.index("T03_DIAGNOSTICS_BEGIN"), output.index("--- boot device resolution ---"))
            self.assertIn("T03_DIAGNOSTIC_COMMAND_FAILED=boot device resolution", output)
            self.assertIn("mock-systemctl", output)
            self.assertIn("blkid -c /dev/null", calls.read_text())
            self.assertIn("systemd-hwdb-update.service", calls.read_text())
            self.assertIn("systemd-udev-trigger.service", calls.read_text())
            self.assertTrue(calls.read_text().startswith("journalctl --no-pager --boot=0 --output=short-monotonic --unit=systemd-udevd.service"))
            self.assertIn(
                "journalctl --no-pager --boot=0 --output=short-monotonic --unit=systemd-udevd.service --grep=vda3|253:3 --lines=+512",
                calls.read_text(),
            )
            self.assertIn(
                "journalctl --no-pager --boot=0 --output=short-monotonic --lines=+128 --unit=dev-vda3.device",
                calls.read_text(),
            )
            self.assertIn("/dev/disk/by-uuid", calls.read_text())
            self.assertIn("journalctl --no-pager --boot=0 --priority=warning --lines=80", calls.read_text())
            self.assertNotIn("--follow", calls.read_text())
            self.assertNotIn("unlock", calls.read_text().lower())
            self.assertTrue(
                all(line.startswith("udevadm info --query=all") for line in calls.read_text().splitlines() if line.startswith("udevadm "))
            )
            self.assertTrue(
                all(line.startswith("journalctl --no-pager") for line in calls.read_text().splitlines() if line.startswith("journalctl "))
            )
            invoked_commands = {line.split(maxsplit=1)[0] for line in calls.read_text().splitlines()}
            self.assertLessEqual(invoked_commands, {"systemctl", "lsblk", "blkid", "journalctl", "ls", "stat", "sha256sum", "udevadm", "cat"})

    def test_diagnostic_helper_captures_boot_device_udev_and_manager_state_first(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            helper = re.search(
                r"cat >\"\$\{context\}/diagnostics\.sh\" <<'EOF'\n(.*?)\nEOF",
                SCRIPT.read_text(),
                re.S,
            )
            self.assertIsNotNone(helper)
            captured_output = directory / "uart.log"
            helper_script = helper[1].replace("exec >/dev/ttyAMA0 2>&1", f"exec >{captured_output} 2>&1")
            helper_path = directory / "diagnostics.sh"
            helper_path.write_text(helper_script)
            helper_path.chmod(0o755)
            calls = directory / "calls.log"
            self.write_command(
                fake_bin / "systemctl",
                '''printf 'systemctl %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
if [[ "$1" == show && "$*" == *boot.mount* && "$*" == *--value* ]]; then
  printf '/dev/disk/by-uuid/test-boot-uuid\\n'
  exit 0
fi
printf 'mock-systemctl\\n'
exit 1
''',
            )
            for command in ("lsblk", "udevadm", "cat"):
                self.write_command(
                    fake_bin / command,
                    f'''printf '{command} %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
if [[ "{command}" == lsblk && "$*" == *MAJ:MIN* ]]; then
  printf '254:3\\n'
  exit 0
fi
printf 'mock-{command}\\n'
exit 0
''',
                )
            for command in ("blkid", "journalctl", "ls", "stat", "sha256sum"):
                self.write_command(fake_bin / command, f"printf '{command} %s\\n' \"$*\" >>\"$T03_DIAGNOSTIC_CALLS\"\nexit 1\n")

            result = subprocess.run(
                [str(helper_path)],
                env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "T03_DIAGNOSTIC_CALLS": str(calls)},
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            output = captured_output.read_text()
            invocations = calls.read_text()
            self.assertIn("mock-udevadm", output)
            self.assertIn("mock-cat", output)
            self.assertIn("-p Found -p Names -p Following", invocations)
            self.assertIn("udevadm info --query=all --name=/dev/disk/by-uuid/test-boot-uuid", invocations)
            self.assertIn("/run/udev/data/b254:3", invocations)
            self.assertIn("-p StateChangeTimestampMonotonic", invocations)
            self.assertIn("-p ActiveEnterTimestampMonotonic", invocations)
            self.assertIn("-p InactiveEnterTimestampMonotonic", invocations)
            self.assertLess(output.index("T03_DIAGNOSTICS_BEGIN"), output.index("mock-udevadm"))
            self.assertLess(output.index("mock-udevadm"), output.index("--- failed units ---"))

    def test_diagnostic_helper_captures_kernel_device_when_uuid_alias_is_missing(self):
        cases = (
            ("kernel-present", "/dev/disk/by-uuid/test-boot-uuid", "254:3", True),
            ("padded-major", "/dev/disk/by-uuid/test-boot-uuid", "254:3", True),
            ("invalid-major", "/dev/disk/by-uuid/test-boot-uuid", "", True),
            ("parent-traversal-alias", "/dev/../etc/shadow", "254:3", False),
            ("invalid-character-alias", "/dev/disk/by-uuid/test;bad", "254:3", False),
        )
        for mode, alias_path, expected_major_minor, alias_valid in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                fake_bin = directory / "bin"
                fake_bin.mkdir()
                helper = re.search(
                    r"cat >\"\$\{context\}/diagnostics\.sh\" <<'EOF'\n(.*?)\nEOF",
                    SCRIPT.read_text(),
                    re.S,
                )
                self.assertIsNotNone(helper)
                captured_output = directory / "uart.log"
                helper_script = helper[1].replace("exec >/dev/ttyAMA0 2>&1", f"exec >{captured_output} 2>&1")
                helper_path = directory / "diagnostics.sh"
                helper_path.write_text(helper_script)
                helper_path.chmod(0o755)
                calls = directory / "calls.log"
                self.write_command(
                    fake_bin / "systemctl",
                    '''printf 'systemctl %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
if [[ "$1" == show && "$*" == *boot.mount* && "$*" == *--value* ]]; then
  printf '%s\\n' "$T03_ALIAS_DEVICE_PATH"
  exit 0
fi
printf 'mock-systemctl\\n'
exit 1
''',
                )
                self.write_command(
                    fake_bin / "lsblk",
                    f'''printf 'lsblk %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
if [[ "$*" == *MAJ:MIN* && "$*" == */dev/vda3* ]]; then
  if [[ "{mode}" == padded-major && "$*" != *--raw* ]]; then
    printf ' 254:3\\n'
    exit 0
  fi
  printf '{expected_major_minor or 'invalid'}\\n'
  exit 0
fi
printf 'mock-lsblk\\n'
exit 1
''',
                )
                self.write_command(
                    fake_bin / "udevadm",
                    '''printf 'udevadm %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
if [[ "$*" == *--name=/dev/vda3 ]]; then
  printf 'mock-kernel-udev\\n'
  exit 0
fi
exit 1
''',
                )
                self.write_command(
                    fake_bin / "cat",
                    '''printf 'cat %s\\n' "$*" >>"$T03_DIAGNOSTIC_CALLS"
printf 'mock-kernel-database\\n'
exit 0
''',
                )
                for command in ("blkid", "journalctl", "ls", "stat", "sha256sum"):
                    self.write_command(fake_bin / command, f"printf '{command} %s\\n' \"$*\" >>\"$T03_DIAGNOSTIC_CALLS\"\nexit 1\n")

                result = subprocess.run(
                    [str(helper_path)],
                    env={
                        **os.environ,
                        "PATH": f"{fake_bin}:{os.environ['PATH']}",
                        "T03_DIAGNOSTIC_CALLS": str(calls),
                        "T03_ALIAS_DEVICE_PATH": alias_path,
                    },
                    text=True,
                    capture_output=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                output = captured_output.read_text()
                invocations = calls.read_text()
                self.assertIn("udevadm info --query=all --name=/dev/vda3", invocations)
                self.assertIn("mock-kernel-udev", output)
                self.assertIn("-p Found -p Names -p Following", invocations)
                self.assertIn("T03_DIAGNOSTICS_END", output)
                if expected_major_minor:
                    self.assertIn("/run/udev/data/b254:3", invocations)
                    self.assertIn("mock-kernel-database", output)
                else:
                    self.assertIn("T03_DIAGNOSTIC_DEVICE_MAJOR_MINOR_UNAVAILABLE=/dev/vda3", output)
                    self.assertNotIn("cat -- /run/udev/data/", invocations)
                if alias_valid:
                    self.assertIn("T03_DIAGNOSTIC_COMMAND_FAILED=boot UUID alias udev database properties", output)
                else:
                    self.assertIn("T03_DIAGNOSTIC_COMMAND_FAILED=boot device resolution", output)
                    self.assertNotIn(alias_path, invocations)
                    self.assertNotIn(alias_path, output)

    @staticmethod
    def hwdb_helper_source():
        match = re.search(
            r"cat >\"\$\{context\}/hwdb-prepare\.sh\" <<'EOF'\n(.*?)\nEOF",
            SCRIPT.read_text(),
            re.S,
        )
        if match is None:
            raise AssertionError("builder does not generate the hwdb preparation helper")
        return match[1]

    def run_hwdb_helper(self, directory, *, mode="success", local_rule=False, existing_usr_db=True):
        root = directory / "image-root"
        for path in (
            root / "etc/udev/hwdb.d",
            root / "usr/lib/udev",
            root / "usr/lib/systemd/system",
            directory / "bin",
        ):
            path.mkdir(parents=True, exist_ok=True)
        (root / "etc/.updated").write_text("etc-stamp")
        (root / "usr/lib/systemd/system/systemd-hwdb-update.service").write_text(
            "ConditionNeedsUpdate=/etc\n"
            "ConditionPathExists=|!/usr/lib/udev/hwdb.bin\n"
            "ConditionPathExists=|/etc/udev/hwdb.bin\n"
            "ConditionDirectoryNotEmpty=|/etc/udev/hwdb.d/\n"
        )
        (root / "etc/udev/hwdb.bin").write_text("old-etc-database")
        (root / "etc/udev/preserve-me").write_text("preserved")
        if existing_usr_db:
            (root / "usr/lib/udev/hwdb.bin").write_text("old-usr-database")
        if local_rule:
            (root / "etc/udev/hwdb.d/50-local.hwdb").write_text("preserve this local rule")

        helper = directory / "hwdb-prepare.sh"
        helper.write_text(self.hwdb_helper_source())
        helper.chmod(0o755)
        call_log = directory / "hwdb-calls.log"
        self.write_command(
            directory / "bin/systemd-hwdb",
            '''printf '%s\\n' "$*" >>"$T03_HWDB_CALL_LOG"
root=
while (($#)); do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$root" ]] || exit 40
case "$T03_HWDB_MODE" in
  error) printf 'mock parser error\\n' >&2; exit 9 ;;
  missing-output) exit 0 ;;
esac
mkdir -p "$root/usr/lib/udev"
printf 'fresh-generated-database' >"$root/usr/lib/udev/hwdb.bin"
''',
        )
        result = subprocess.run(
            [str(helper), "--root", str(root)],
            env={
                **os.environ,
                "PATH": f"{directory / 'bin'}:{os.environ['PATH']}",
                "T03_HWDB_CALL_LOG": str(call_log),
                "T03_HWDB_MODE": mode,
            },
            text=True,
            capture_output=True,
        )
        return root, result, call_log

    def test_hwdb_helper_rebuilds_in_usr_and_removes_only_the_compiled_etc_database(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root, result, call_log = self.run_hwdb_helper(directory)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("--root " + str(root) + " --usr --strict update", call_log.read_text())
            self.assertEqual((root / "usr/lib/udev/hwdb.bin").read_text(), "fresh-generated-database")
            self.assertFalse((root / "etc/udev/hwdb.bin").exists())
            self.assertEqual((root / "etc/udev/preserve-me").read_text(), "preserved")
            self.assertIn("T03_HWDB_PHASE=before", result.stdout)
            self.assertIn("T03_HWDB_PHASE=after", result.stdout)
            database_hash = hashlib.sha256((root / "usr/lib/udev/hwdb.bin").read_bytes()).hexdigest()
            self.assertIn(f"T03_HWDB_USR_DATABASE=present", result.stdout)
            self.assertIn(f"sha256={database_hash}", result.stdout)
            self.assertIn("ConditionNeedsUpdate=/etc", result.stdout)
            self.assertIn("T03_HWDB_ETC_UPDATED_STAMP=present", result.stdout)

    def test_hwdb_helper_fails_closed_without_touching_local_rules_or_compiled_databases(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root, result, call_log = self.run_hwdb_helper(directory, local_rule=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("local hwdb rules", result.stderr.lower())
            self.assertFalse(call_log.exists())
            self.assertEqual((root / "etc/udev/hwdb.d/50-local.hwdb").read_text(), "preserve this local rule")
            self.assertEqual((root / "etc/udev/hwdb.bin").read_text(), "old-etc-database")

    def test_hwdb_helper_rejects_update_errors_and_missing_output_before_removing_etc_database(self):
        for mode in ("error", "missing-output"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                root, result, _call_log = self.run_hwdb_helper(
                    directory,
                    mode=mode,
                    existing_usr_db=(mode == "error"),
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((root / "etc/udev/hwdb.bin").is_file())
                self.assertIn("T03_HWDB_PHASE=before", result.stdout)
                self.assertIn("T03_HWDB_PHASE=after", result.stdout)

    def test_guest_disk_metadata_is_recorded_before_the_boot_attempt(self):
        function = re.search(r"record_image_metadata\(\) \{\n.*?\n\}", SCRIPT.read_text(), re.S)
        self.assertIsNotNone(function)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            artifact_dir = directory / "evidence"
            artifact_dir.mkdir()
            disk = artifact_dir / "fedora45-arm64.qcow2"
            disk.write_bytes(b"test qcow2 disk")
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            self.write_command(fake_bin / "qemu-img", 'printf \'{"virtual-size":1073741824}\\n\'\n')
            program = f'image_path="{disk}"; artifact_dir="{artifact_dir}";\n{function[0]}\nrecord_image_metadata'
            result = subprocess.run(
                ["bash", "-c", program],
                env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = (artifact_dir / "metadata.txt").read_text()
            self.assertIn(f"Guest disk SHA-256: {hashlib.sha256(disk.read_bytes()).hexdigest()}", metadata)
            self.assertIn(f"Guest disk file size: {disk.stat().st_size} bytes", metadata)
            self.assertIn(f"Guest disk allocated size: {subprocess.check_output(['du', '-B1', str(disk)], text=True).split()[0]} bytes", metadata)
            self.assertIn("Guest disk virtual size: 1073741824 bytes", metadata)

        run_case = SCRIPT.read_text().split('case "${1:-run}" in', 1)[1]
        self.assertLess(run_case.index("record_image_metadata"), run_case.index("boot_once kvm"))

    def test_builder_mounts_the_image_builder_default_store_on_the_workspace(self):
        source = SCRIPT.read_text()
        self.assertIn('-v "${artifact_dir}/containers-storage:/var/lib/containers/storage"', source)

    def test_builder_refuses_to_overwrite_existing_disk(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            disk = artifact_dir / "fedora45-arm64.qcow2"
            disk.write_text("keep this file")
            result = self.run_script(
                "--build",
                "run-unique-1",
                f"{BOOTC_REPO}@{BOOTC_DIGEST}",
                env={"T03_ARTIFACT_DIR": str(artifact_dir)},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(disk.read_text(), "keep this file")

    def test_pinned_ref_validator_requires_a_literal_repository(self):
        function = re.search(r"validate_pinned_ref\(\) \{\n.*?\n\}", SCRIPT.read_text(), re.S)
        self.assertIsNotNone(function)
        program = 'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n' + function[0]
        program += '\nvalidate_pinned_ref bootc "$1" "$2"'
        cases = (
            (f"{BOOTC_REPO}@{BOOTC_DIGEST}", True),
            (f"quayXio/fedora/fedora-bootc@{BOOTC_DIGEST}", False),
            (f"quay.io.evil/fedora/fedora-bootc@{BOOTC_DIGEST}", False),
            (f"{BOOTC_REPO}:45", False),
            (f"{BOOTC_REPO}@{BOOTC_DIGEST}extra", False),
        )
        for ref, accepted in cases:
            with self.subTest(ref=ref):
                result = subprocess.run(
                    ["bash", "-c", program, "validator-test", ref, BOOTC_REPO],
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_builder_rejects_mutable_or_untrusted_base_refs_before_install(self):
        for ref in ("quay.io/fedora/fedora-bootc:45", f"example.invalid/image@{BOOTC_DIGEST}"):
            with self.subTest(ref=ref):
                result = self.run_script("--build", "run-unique-1", ref)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("immutable digest", result.stderr)
                self.assertNotIn("dnf", result.stderr)

    def test_missing_guest_image_fails_before_boot(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            result = self.run_script("--verify-image", env={"T03_ARTIFACT_DIR": artifact_dir})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guest disk is missing", result.stderr)

    @staticmethod
    def write_command(path, body):
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
        path.chmod(0o755)

    def test_proof_verifier_rejects_stale_or_incomplete_serial_output(self):
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                "T03_BEGIN=old-run\n"
                "T03_ARCH=aarch64\n"
                "T03_FEDORA_VERSION=45\n"
                "T03_UEFI=1\n"
                "T03_PASS=old-run\n"
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, "new-run-unique")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("boot proof is incomplete", result.stderr)

    def test_non_arm64_guest_does_not_pass(self):
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                "T03_BEGIN=run-unique-1\n"
                "T03_ARCH=x86_64\n"
                "T03_FEDORA_VERSION=45\n"
                "T03_UEFI=1\n"
                "T03_PASS=run-unique-1\n"
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, "run-unique-1")

        self.assertNotEqual(result.returncode, 0)

    def test_guest_without_uefi_does_not_pass(self):
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                "T03_BEGIN=run-unique-1\n"
                "T03_ARCH=aarch64\n"
                "T03_FEDORA_VERSION=45\n"
                "T03_PASS=run-unique-1\n"
            )
            serial.flush()
            result = self.run_script("--verify-proof", serial.name, "run-unique-1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("T03_UEFI=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
