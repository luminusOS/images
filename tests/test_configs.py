import configparser
import json
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = ROOT / "editions/workstation/files/system"
INSTALLER = ROOT / "editions/workstation/files/installer"


def text(path):
    return path.read_text(encoding="utf-8")


class ConfigurationTests(unittest.TestCase):
    def test_configuration_files_parse(self):
        self.assertTrue(
            (
                SYSTEM / "usr/share/glib-2.0/schemas/zz-99-luminusos.gschema.override"
            ).is_file()
        )
        for path in (
            INSTALLER / "etc/sirius/distro.toml",
            INSTALLER / "etc/sirius/sirius.toml",
            ROOT / "shared/bootc-image-builder.toml.example",
        ):
            with self.subTest(path=path), path.open("rb") as source:
                tomllib.load(source)
        for directory in (SYSTEM, INSTALLER):
            for path in directory.rglob("*.json"):
                with self.subTest(path=path):
                    json.loads(text(path))
        for path in INSTALLER.rglob("*"):
            relative = path.relative_to(INSTALLER)
            if path.is_file() and (
                path.suffix == ".desktop"
                or "repart.d" in relative.parts
                and path.suffix == ".conf"
                or "systemd" in relative.parts
                and path.suffix in (".service", ".mount", ".conf")
                or str(relative).endswith("gdm/custom.conf")
            ):
                with self.subTest(path=path):
                    parser = configparser.ConfigParser(
                        strict=False, interpolation=None, delimiters=("=",)
                    )
                    parser.optionxform = str
                    parser.read(path)

    def test_yaml_files_parse(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML unavailable; CI performs YAML parsing")
        for path in list(ROOT.rglob("*.yml")) + list(ROOT.rglob("*.yaml")):
            if ".git" not in path.parts:
                with self.subTest(path=path):
                    yaml.safe_load(text(path))

    def test_installer_configuration_and_initial_setup(self):
        distro = text(INSTALLER / "etc/sirius/distro.toml")
        sirius = text(INSTALLER / "etc/sirius/sirius.toml")
        self.assertIn("@WORKSTATION_TARGET_IMAGE@", distro)
        self.assertIn('image = "oci:/usr/lib/luminusos/payload.oci:latest"', distro)
        self.assertIn('command = "ptyxis"', sirius.splitlines())
        self.assertIn("show_button = true", sirius.splitlines())
        config = configparser.ConfigParser(interpolation=None)
        config.read(SYSTEM / "etc/gnome-initial-setup/vendor.conf")
        skip = {v for v in config.get("pages", "skip", fallback="").split(";") if v}
        existing = {
            v
            for v in config.get("pages", "existing_user_only", fallback="").split(";")
            if v
        }
        self.assertEqual(skip, {"software"})
        self.assertEqual(existing, {"language"})
        self.assertNotIn("keyboard", skip | existing)
        mode = json.loads(
            text(SYSTEM / "usr/share/gnome-shell/modes/initial-setup.json")
        )
        self.assertEqual(mode["parentMode"], "user")
        self.assertIn("aurora-shell@luminusos.github.io", mode["enabledExtensions"])
        self.assertFalse(mode["hasOverview"])
        self.assertFalse(mode["hasRunDialog"])
        for path, line in (
            (
                INSTALLER / "etc/dconf/db/local.d/00-iso-live-mode",
                "module-aurora-menu=false",
            ),
            (
                SYSTEM / "etc/dconf/profile/gnome-initial-setup",
                "system-db:luminusos-initial-setup",
            ),
            (
                SYSTEM / "etc/dconf/profile/gnome-initial-setup",
                "file-db:/usr/share/gnome-initial-setup/initial-setup-dconf-defaults",
            ),
            (
                SYSTEM / "etc/dconf/db/luminusos-initial-setup.d/00-aurora-shell",
                "module-aurora-menu=false",
            ),
        ):
            with self.subTest(path=path, line=line):
                self.assertIn(line, text(path).splitlines())

    def test_partition_layout_and_overlay_isolation(self):
        repart = INSTALLER / "usr/share/sirius/repart.d"
        self.assertEqual(len(list(repart.glob("*.conf"))), 3)
        for name, fs in (
            ("10-root.conf", "btrfs"),
            ("20-boot.conf", "ext4"),
            ("30-esp.conf", "vfat"),
        ):
            self.assertIn(f"Format={fs}", text(repart / name).splitlines())
        disk = text(SYSTEM / "usr/lib/image-builder/bootc/disk.yaml")
        self.assertRegex(disk, r'type: "ext4"[\s\S]*?mountpoint: "/boot"')
        for path in ("/", "/home", "/var"):
            self.assertIn(f'mountpoint: "{path}"', disk)
        flatpaks = text(ROOT / "shared/flatpaks").splitlines()
        self.assertEqual(flatpaks, sorted(set(flatpaks)))
        for path in ("etc/sirius", "var/lib/AccountsService/users/liveuser"):
            self.assertFalse((SYSTEM / path).exists())
        for path in (
            "etc/sirius/distro.toml",
            "var/lib/AccountsService/users/liveuser",
        ):
            self.assertTrue((INSTALLER / path).is_file())
        self.assertIn(
            "COPY editions/workstation/files/system/ /",
            text(ROOT / "editions/workstation/Containerfile"),
        )
        self.assertIn(
            "COPY editions/workstation/files/installer/ /",
            text(ROOT / "editions/workstation/Containerfile.installer"),
        )

    def test_pins_and_swap_configuration(self):
        versions = text(ROOT / "config/versions.env")
        for pattern in (
            r"^FEDORA_BOOTC_DIGEST=sha256:[0-9a-f]{64}$",
            r"^AURORA_SHELL_SHA256=[0-9a-f]{64}$",
            r"^SIRIUS_VERSION=[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$",
            r"^SIRIUS_RPM_VERSION=[0-9]+\.[0-9]+\.[0-9]+(~rc\.[0-9]+)?$",
            r"^ELASTIC_SWAP_VERSION=[0-9]+\.[0-9]+\.[0-9]+$",
            r"^ELASTIC_SWAP_SHA256=[0-9a-f]{64}$",
        ):
            self.assertRegex(versions, re.compile(pattern, re.MULTILINE))
        for path in (
            ROOT / "ci/Containerfile",
            ROOT / "editions/core/Containerfile",
            ROOT / "editions/workstation/Containerfile",
            ROOT / "editions/workstation/Containerfile.installer",
        ):
            self.assertNotRegex(
                text(path),
                re.compile(
                    r"^ARG (fedora_version|aurora_shell_version|sirius_version)=",
                    re.MULTILINE,
                ),
            )
        workstation = text(ROOT / "editions/workstation/Containerfile")
        build = text(ROOT / "editions/workstation/build.py")
        self.assertRegex(
            workstation,
            re.compile(
                r'^    echo "[0-9a-f]{64}  /tmp/ddcutil-service\.rpm" \| sha256sum -c - && \\$',
                re.MULTILINE,
            ),
        )
        self.assertIn(
            "zswap.enabled=1",
            text(SYSTEM / "usr/lib/bootc/kargs.d/20-luminusos-zswap.toml"),
        )
        self.assertIn('["systemctl", "enable", "elastic-swap.service"]', build)
        self.assertIn('["systemctl", "enable", "systemd-oomd.service"]', build)
        self.assertNotIn(
            "luminusos-swapfile.service",
            [
                path.name
                for path in (SYSTEM / "usr/lib/systemd/system").glob(
                    "luminusos-swapfile.service"
                )
            ],
        )
        self.assertFalse((SYSTEM / "usr/libexec/luminusos-swapfile.sh").exists())
        self.assertIn(
            "r! /var/swap/swapfile - - - - -",
            text(
                SYSTEM / "usr/lib/tmpfiles.d/luminusos-swap-migrate.conf"
            ).splitlines(),
        )
        self.assertIn("systemd-oomd-defaults", workstation)
        self.assertIn("ManagedOOMMemoryPressure=kill", workstation)
        self.assertIn(
            "ManagedOOMSwap=kill",
            text(
                SYSTEM / "usr/lib/systemd/user/app.slice.d/20-luminusos-oomd-swap.conf"
            ).splitlines(),
        )
        for directory in ("session.slice.d", "slice.d"):
            self.assertFalse(
                any(
                    "oomd-swap" in path.name
                    for path in (SYSTEM / "usr/lib/systemd/user" / directory).glob("*")
                )
            )
        build_tool = text(ROOT / "tools/build-images.py")
        workflow = text(ROOT / ".github/workflows/containers.yml")
        for value in ("elastic_swap_sha256", "elastic_swap_version"):
            self.assertIn(value, build_tool)
            self.assertIn(value, workflow)
        for unit in ("elastic-swap", "elastic-swap-prepare"):
            self.assertIn(
                "ConditionVirtualization=!container",
                text(
                    SYSTEM
                    / f"usr/lib/systemd/system/{unit}.service.d/10-luminusos.conf"
                ).splitlines(),
            )
            self.assertIn(
                "ConditionKernelCommandLine=!rd.live.image",
                text(
                    INSTALLER
                    / f"usr/lib/systemd/system/{unit}.service.d/10-live-iso.conf"
                ).splitlines(),
            )
