import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/t03-arm64-proof.sh"


class Arm64ProofTests(unittest.TestCase):
    def run_script(self, *args, env=None):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env={**os.environ, **(env or {})},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_qemu_plan_uses_aarch64_uefi_and_snapshot_disk(self):
        result = self.run_script("--print-qemu")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("qemu-system-aarch64", result.stdout)
        self.assertIn("-machine virt", result.stdout)
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

    def test_proof_verifier_requires_all_fresh_guest_claims(self):
        nonce = "run-unique-1"
        with tempfile.NamedTemporaryFile(mode="w") as serial:
            serial.write(
                f"T03_BEGIN={nonce}\n"
                "T03_ARCH=aarch64\n"
                "T03_FEDORA_VERSION=45\n"
                "T03_UEFI=1\n"
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
            capture_containerfile = temporary / "Containerfile"
            capture_disk = temporary / "disk.yaml"
            call_log = temporary / "calls.log"
            self.write_command(fake_bin / "dnf", "exit 0\n")
            self.write_command(fake_bin / "sudo", 'exec "$@"\n')
            self.write_command(fake_bin / "rpm", 'printf "image-builder-45\\n"\n')
            self.write_command(fake_bin / "qemu-img", 'printf \'{"format":"qcow2","virtual-size":1073741824}\\n\'\n')
            self.write_command(
                fake_bin / "podman",
                '''printf 'storage=%s args=%s\\n' "${CONTAINERS_STORAGE_CONF:-unset}" "$*" >>"$T03_CALL_LOG"
case "$1" in
  image) printf 'linux arm64\\n' ;;
  build)
    cp "$5/proof.service" "$T03_CAPTURE_SERVICE"
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
                env={
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "T03_ARTIFACT_DIR": str(artifact_dir),
                    "T03_CAPTURE_SERVICE": str(capture_service),
                    "T03_CAPTURE_CONTAINERFILE": str(capture_containerfile),
                    "T03_CAPTURE_DISK": str(capture_disk),
                    "T03_CALL_LOG": str(call_log),
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
            self.assertIn(str(artifact_dir / "containers-storage"), (artifact_dir / "storage.conf").read_text())
            self.assertIn("multi-user.target", capture_service.read_text())
            self.assertNotIn("After=multi-user.target", capture_service.read_text())
            self.assertIn("sha256:3c7cf18e9b1eb23d65cdaec7c5d15e8b4d12849ec20f61dba02ac3e3293f66d1", capture_containerfile.read_text())
            self.assertIn("COPY disk.yaml /usr/lib/image-builder/bootc/disk.yaml", capture_containerfile.read_text())
            self.assertIn("mountpoint: /boot/efi", capture_disk.read_text())
            self.assertIn("mountpoint: /", capture_disk.read_text())
            self.assertIn("sha256:54fe92a655ebbcec468dc6fa953c0d1d2b474630a72f953702766c8389dd1a15", SCRIPT.read_text())
            self.assertIn("cwd=" + str(artifact_dir), call_log.read_text())
            self.assertIn("storage=" + str(artifact_dir / "storage.conf"), call_log.read_text())
            self.assertIn("quay.io/fedora/fedora-bootc@sha256:3c7cf18e9b1eb23d65cdaec7c5d15e8b4d12849ec20f61dba02ac3e3293f66d1", call_log.read_text())

    def test_builder_refuses_to_overwrite_existing_disk(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            disk = artifact_dir / "fedora45-arm64.qcow2"
            disk.write_text("keep this file")
            result = self.run_script(
                "--build",
                "run-unique-1",
                env={"T03_ARTIFACT_DIR": str(artifact_dir)},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(disk.read_text(), "keep this file")

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
