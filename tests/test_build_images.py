import argparse
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "build_images", ROOT / "tools/build-images.py"
)
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def args():
    return argparse.Namespace(
        base="fedora@sha256:abc",
        fedora="45",
        tag="testing-45.20261105",
        version="45.20261105",
        name="LuminusOS",
        pretty="Luminus OS",
        core="localhost/luminusos:tag",
        workstation="localhost/luminusos-workstation:tag",
        installer="localhost/luminusos-workstation:tag-iso",
        target="ghcr.io/luminusos/luminusos-workstation:testing-45",
        sirius_version="1.0.4",
        sirius_rpm_version="1.0.3",
        skip_flatpaks="0",
        force_core="0",
    )


class BuildImageTests(unittest.TestCase):
    def test_core_build_squashes_and_writes_stamp(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(build, "test_directory", return_value=Path(tmp)),
            patch.object(build, "stamp", return_value="stamp"),
            patch.object(build, "run") as run,
        ):
            build.core(args())
            self.assertIn("distro_version=45.20261105", run.call_args_list[0].args[0])
            self.assertIn("tools/squash-image.py", run.call_args_list[1].args[0])
            self.assertEqual((Path(tmp) / "last-core-stamp").read_text(), "stamp\n")

    def test_installer_refuses_unowned_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            payload = directory / "payload.oci"
            payload.mkdir()
            (payload / "unrelated").write_text("safe")
            with (
                patch.object(build, "test_directory", return_value=directory),
                patch.object(build.subprocess, "run") as inspect,
                patch.object(build, "run") as run,
            ):
                inspect.return_value.returncode = 0
                with self.assertRaises(ValueError):
                    build.installer(args())
                run.assert_not_called()
            self.assertEqual((payload / "unrelated").read_text(), "safe")

    def test_install_refuses_unowned_disk_before_running_podman(self):
        spec = importlib.util.spec_from_file_location(
            "install_qemu", ROOT / "tools/install-qemu.py"
        )
        install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "shared").mkdir()
            (root / "shared/bootc-image-builder.toml").touch()
            (root / ".test").mkdir()
            disk = root / ".test/install-disk.qcow2"
            disk.write_bytes(b"keep")
            with (
                patch.object(install, "ROOT", root),
                patch.object(sys, "argv", ["install-qemu.py", "localhost/image:tag"]),
                patch.object(install, "run") as run,
                self.assertRaises(ValueError),
            ):
                install.main()
            run.assert_not_called()
            self.assertEqual(disk.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
