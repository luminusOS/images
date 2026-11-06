import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from config_values import read_config
from qemu_common import disk_format, resolve_artifact


class ToolTests(unittest.TestCase):
    def test_config_cli_and_package_formats(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/config-value.py"),
                "DEFAULT_FEDORA_VERSION",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), read_config()["DEFAULT_FEDORA_VERSION"])
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/config-value.py"), "NOT_A_SETTING"],
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        env = {**os.environ, "IMAGE_BUILDER_DRY_RUN": "1"}
        for fmt, expected in (("iso", "bootc-generic-iso"), ("qcow2", "qcow2")):
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/package-artifact.py"),
                    fmt,
                    "image.test",
                    "output",
                ],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn(expected, result.stdout)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/package-artifact.py"),
                "raw",
                "image.test",
                "output",
            ],
            env=env,
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_artifact_resolution_and_disk_formats(self):
        self.assertEqual(disk_format("disk.qcow2"), "qcow2")
        self.assertEqual(disk_format("disk.img"), "raw")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "older.qcow2"
            new = root / "newer.qcow2"
            old.touch()
            new.touch()
            os.utime(old, (100, 100))
            os.utime(new, (200, 200))
            pointer = root / "pointer"
            pointer.write_text(str(old))
            self.assertEqual(resolve_artifact(root, "", pointer, "*.qcow2"), new)
            self.assertEqual(resolve_artifact(root, str(old), pointer, "*.qcow2"), old)

    def test_config_rejects_shell_syntax_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "versions.env"
            for invalid in ("A=$(touch nope)\n", "A=1\nA=2\n"):
                with self.subTest(invalid=invalid):
                    config.write_text(invalid)
                    with self.assertRaises(ValueError):
                        read_config(config)
            config.write_text("A=hello-1\n")
            self.assertEqual(read_config(config), {"A": "hello-1"})

    def test_tool_image_hash_ignores_desktop_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in (root / "ci", root / "tools", root / "config"):
                directory.mkdir()
            for name in (
                "ci/Containerfile",
                "tools/ci-image-name.py",
                "tools/config_values.py",
            ):
                (root / name).write_text(name)
            versions = root / "config/versions.env"
            versions.write_text("DEFAULT_FEDORA_VERSION=45\nAURORA_SHELL_VERSION=v1\n")
            spec = importlib.util.spec_from_file_location(
                "ci_image_name", ROOT / "tools/ci-image-name.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with (
                patch.object(module, "ROOT", root),
                patch.object(
                    module, "read_config", side_effect=lambda: read_config(versions)
                ),
            ):
                initial = module.image_name()
                versions.write_text(
                    "DEFAULT_FEDORA_VERSION=45\nAURORA_SHELL_VERSION=v2\n"
                )
                self.assertEqual(initial, module.image_name())
                (root / "ci/Containerfile").write_text("changed")
                self.assertNotEqual(initial, module.image_name())

    def test_reset_refuses_unowned_install_disk(self):
        spec = importlib.util.spec_from_file_location("qemu", ROOT / "tools/qemu.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / ".test"
            test_dir.mkdir()
            disk = test_dir / "install-disk.qcow2"
            disk.write_bytes(b"do not delete")
            image = root / "image.iso"
            image.touch()
            env = {
                "QEMU_ISO_PATH": str(image),
                "QEMU_BOOT": "bios",
                "QEMU_RESET_DISK": "1",
            }
            with (
                patch.object(module, "ROOT", root),
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["qemu.py", "iso"]),
                self.assertRaises(ValueError),
            ):
                module.main()
            self.assertEqual(disk.read_bytes(), b"do not delete")

    def test_reset_refuses_disk_replaced_after_ownership_recorded(self):
        from qemu_common import record_owned_file

        spec = importlib.util.spec_from_file_location("qemu", ROOT / "tools/qemu.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / ".test"
            directory.mkdir()
            disk = directory / "install-disk.qcow2"
            disk.write_bytes(b"original")
            record_owned_file(
                disk, directory / ".install-disk-owned", "luminusos-install-disk"
            )
            disk.rename(directory / "saved-original")
            disk.write_bytes(b"replacement")
            image = root / "image.iso"
            image.touch()
            env = {
                "QEMU_ISO_PATH": str(image),
                "QEMU_BOOT": "bios",
                "QEMU_RESET_DISK": "1",
            }
            with (
                patch.object(module, "ROOT", root),
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["qemu.py", "iso"]),
                self.assertRaises(ValueError),
            ):
                module.main()
            self.assertEqual(disk.read_bytes(), b"replacement")

    def test_packaging_dry_run_passes_cache_and_image(self):
        env = {
            **os.environ,
            "IMAGE_BUILDER_DRY_RUN": "1",
            "IMAGE_BUILDER_CACHE": "/cache location",
        }
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/package-artifact.py"),
                "iso",
                "localhost/test:v1",
                "output.iso",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--cache '/cache location'", result.stdout)
        self.assertIn("--bootc-ref localhost/test:v1 bootc-generic-iso", result.stdout)

    def test_qemu_dry_run_does_not_reset_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "disk.qcow2"
            disk.write_bytes(b"data")
            env = {
                **os.environ,
                "QEMU_DRY_RUN": "1",
                "QEMU_BOOT": "bios",
                "QEMU_DISK_PATH": str(disk),
                "QEMU_DISK_BUS": "virtio",
            }
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/qemu.py"), "disk"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("virtio-blk-pci,drive=system_disk,bootindex=1", result.stdout)
            self.assertEqual(disk.read_bytes(), b"data")

    def test_ppm_requires_full_frame(self):
        spec = importlib.util.spec_from_file_location(
            "boot_test", ROOT / ".github/scripts/boot-test.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.ppm"
            path.write_bytes(b"P6\n4 1\n255\n" + b"\x01\x02\x03" * 4)
            self.assertEqual(module.count_colors(path), 1)
            path.write_bytes(b"P6\n4 1\n255\nshort")
            with self.assertRaises(ValueError):
                module.count_colors(path)

    def test_release_notes_reports_package_changes_and_rebase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "rpm-list"
            helper.write_text(
                "#!/usr/bin/env python3\nimport sys\n"
                "print('kernel-core 7.2.7-1\\nbootc 1.9-1\\nzsh 5.9-1' if sys.argv[1] == 'old' else "
                "'kernel-core 7.2.8-1\\nbootc 1.9-1\\nzsh 5.9-2\\nfoo 1-1')\n"
            )
            helper.chmod(0o755)
            env = {**os.environ, "RPM_LIST_CMD": str(helper)}
            args = ["new", "testing-45.20261005.1", "old", "testing-45.20261004.2"]
            migrated = subprocess.run(
                [sys.executable, str(ROOT / "tools/release-notes.py"), *args],
                cwd=root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("| kernel-core | 7.2.8-1 | 7.2.7-1 |", migrated.stdout)
            self.assertIn("| bootc | 1.9-1 | |", migrated.stdout)
            self.assertIn("3 packages were added or updated", migrated.stdout)
            self.assertIn("sudo bootc switch new", migrated.stdout)


if __name__ == "__main__":
    unittest.main()
