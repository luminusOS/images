import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / ".github/scripts/workflow" / f"{name}.py"
    )
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


meta = module("build_metadata")
reuse = module("core_reuse")
BASE = "sha256:" + "a" * 64
CONFIG = {
    "UPDATE_CHANNEL": "testing",
    "DEFAULT_FEDORA_VERSION": "45",
    "SIRIUS_SHA256": "b" * 64,
    "SIRIUS_VERSION": "1.0.4",
    "SIRIUS_RPM_VERSION": "1.0.3",
    "AURORA_SHELL_VERSION": "v1",
    "AURORA_SHELL_SHA256": "c" * 64,
    "ELASTIC_SWAP_VERSION": "1.0.0",
    "ELASTIC_SWAP_SHA256": "d" * 64,
}
ENV = {
    "GITHUB_REPOSITORY_OWNER": "LuminusOS",
    "GITHUB_RUN_ID": "12",
    "GITHUB_RUN_ATTEMPT": "2",
}
RELEASES = {"SUPPORTED_RELEASES": "45", "LATEST_RELEASE": "45"}


class MetadataTests(unittest.TestCase):
    def test_testing_and_stable_identities(self):
        result = meta.metadata(ENV, CONFIG, RELEASES, BASE, "20261105")
        self.assertEqual(
            result["workstation_image"],
            "ghcr.io/luminusos/luminusos-workstation:candidate-12-2",
        )
        stable = meta.metadata(
            {**ENV, "CHANNEL": "stable", "PROMOTE_VERSION": "45.20261103.2"},
            CONFIG,
            RELEASES,
            BASE,
            "20261105",
        )
        self.assertTrue(stable["workstation_image"].endswith(":testing-45.20261103.2"))
        self.assertEqual(stable["build_version"], "45.20261103.2")

    def test_rejects_shell_config_and_bad_overrides(self):
        with self.assertRaises(ValueError):
            meta.releases('SUPPORTED_RELEASES="$(touch nope)"\nLATEST_RELEASE=45')
        with self.assertRaises(ValueError):
            meta.metadata(
                {**ENV, "SIRIUS_VERSION": "1.2.3"}, CONFIG, RELEASES, BASE, "20261105"
            )
        with self.assertRaises(ValueError):
            meta.metadata(
                {**ENV, "FEDORA_VERSION": "99"}, CONFIG, RELEASES, BASE, "20261105"
            )

    def test_rejects_owner_namespace_with_invalid_trailing_punctuation(self):
        for owner in (
            "valid-",
            "valid.",
            "valid_",
            "-invalid",
            ".invalid",
            "_invalid",
            "with.dot",
            "with_under",
        ):
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                meta.metadata(
                    {**ENV, "GITHUB_REPOSITORY_OWNER": owner},
                    CONFIG,
                    RELEASES,
                    BASE,
                    "20261105",
                )


class ContainerCachePolicyTests(unittest.TestCase):
    def test_container_jobs_enable_store_before_docker_import_and_cache_scopes(self):
        text = (ROOT / ".github/workflows/containers.yml").read_text()
        for name, scope in (
            ("core", "core"),
            ("workstation", "workstation"),
            ("installer", "installer"),
        ):
            start = text.index(f"  {name}:\n")
            next_job = -1
            for next_name in ("core", "workstation", "installer"):
                candidate = text.find(f"\n  {next_name}:\n", start + 1)
                if candidate >= 0 and (next_job < 0 or candidate < next_job):
                    next_job = candidate
            section = text[start : next_job if next_job != -1 else None]
            setup = section.index("docker/setup-docker-action@")
            build = section.index("docker/build-push-action@")
            self.assertLess(setup, build)
            self.assertIn('"containerd-snapshotter":true', section)
            self.assertIn(
                f"scope={scope}-${{{{ needs.metadata.outputs.fedora_version }}}}-${{{{ runner.arch }}}}",
                section,
            )
            self.assertIn(
                f"scope={scope}-${{{{ needs.metadata.outputs.fedora_version }}}}-${{{{ runner.arch }}}},mode=max",
                section,
            )
            if name != "installer":
                self.assertIn("inputs.force_core", section)


class ReuseTests(unittest.TestCase):
    def test_fingerprint_ignores_workstation_and_changes_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path in (
                "editions/core/Containerfile",
                "shared/trust/key",
                "shared/scripts/dnf-releasever.py",
                "shared/scripts/os-release-set.py",
                "shared/scripts/rpmdb-repair.py",
                "editions/workstation/build.py",
            ):
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(path)
            before = reuse.inputs_hash(root, "45", BASE)
            (root / "editions/workstation/build.py").write_text("change")
            self.assertEqual(before, reuse.inputs_hash(root, "45", BASE))
            (root / "shared/trust/key").write_text("change")
            self.assertNotEqual(before, reuse.inputs_hash(root, "45", BASE))
            self.assertNotEqual(
                before, reuse.inputs_hash(root, "45", "sha256:" + "e" * 64)
            )

    def test_reuse_requires_digest_signature_and_labels(self):
        reference = "ghcr.io/luminusos/luminusos:testing-45"
        fingerprint = "f" * 64
        resolved = subprocess.CompletedProcess([], 0, stdout=BASE)
        labels = {
            "Labels": {
                "org.luminusos.core.fedora": "45",
                "org.luminusos.core.inputs-sha256": fingerprint,
            }
        }
        inspect = subprocess.CompletedProcess([], 0, stdout=json.dumps(labels))
        with patch.object(
            reuse, "command", side_effect=[resolved, None, inspect, None, None]
        ) as cmd:
            self.assertEqual(
                reuse.select(reference, "45", fingerprint, "local:core"), BASE
            )
        self.assertEqual(
            cmd.call_args_list[1].args[0][-1], "ghcr.io/luminusos/luminusos@" + BASE
        )
        for wrong in ("fedora", "hash", "signature"):
            changed = json.loads(json.dumps(labels))
            if wrong == "fedora":
                changed["Labels"]["org.luminusos.core.fedora"] = "44"
            if wrong == "hash":
                changed["Labels"]["org.luminusos.core.inputs-sha256"] = "bad"
            signature = (
                subprocess.CalledProcessError(1, "cosign")
                if wrong == "signature"
                else None
            )
            with (
                self.subTest(wrong=wrong),
                patch.object(
                    reuse,
                    "command",
                    side_effect=[
                        resolved,
                        signature,
                        subprocess.CompletedProcess([], 0, stdout=json.dumps(changed)),
                    ],
                ),
            ):
                self.assertEqual(
                    reuse.select(reference, "45", fingerprint, "local:core"), ""
                )

    def test_archive_checks_before_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "image.tar"
            archive.write_bytes(b"tampered")
            with patch.object(reuse, "command") as cmd, self.assertRaises(ValueError):
                reuse.load("local:core", archive, "a" * 64, BASE)
            cmd.assert_not_called()

    def test_forced_and_absent_refs_never_reuse(self):
        with patch.object(reuse, "command") as command:
            self.assertEqual(reuse.select("", "45", "f" * 64, "local:core"), "")
            self.assertEqual(
                reuse.select(
                    "ghcr.io/luminusos/luminusos:old",
                    "45",
                    "f" * 64,
                    "local:core",
                    force=True,
                ),
                "",
            )
            command.assert_not_called()

    def test_loaded_core_identity_matches_recorded_build_input(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "image.tar"
            archive.write_bytes(b"core archive")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with (
                patch.object(reuse, "command") as command,
                patch.object(reuse, "image_id", return_value=BASE),
            ):
                reuse.load("local:core", archive, checksum, BASE)
            command.assert_called_once_with(["docker", "load", "-i", str(archive)])
            with (
                patch.object(reuse, "command"),
                patch.object(reuse, "image_id", return_value="sha256:" + "b" * 64),
                self.assertRaisesRegex(ValueError, "image id mismatch"),
            ):
                reuse.load("local:core", archive, checksum, BASE)

    def test_stable_installer_requires_digest(self):
        with (
            patch.object(reuse, "command") as cmd,
            patch.object(reuse.Path, "mkdir"),
        ):
            with self.assertRaises(ValueError):
                reuse.export_payload(
                    "ghcr.io/luminusos/luminusos-workstation:testing-45",
                    "stable",
                    "45.20261105",
                )
            cmd.assert_not_called()
            reuse.export_payload(
                "ghcr.io/luminusos/luminusos-workstation:testing-45", "stable", BASE
            )
            self.assertIn("@" + BASE, cmd.call_args_list[0].args[0][-1])
