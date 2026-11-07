import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_package", ROOT / ".github/scripts/ci-package.py"
)
ci_package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_package)

INDEX_IMAGE = f"ghcr.io/example/live@sha256:{'a' * 64}"
CHILD_DIGEST = f"sha256:{'b' * 64}"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def descriptor(
    os_name: str = "linux", architecture: str = "amd64"
) -> dict[str, object]:
    return {
        "mediaType": MANIFEST_TYPE,
        "digest": CHILD_DIGEST,
        "platform": {"os": os_name, "architecture": architecture},
    }


def index(*manifests: object) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": list(manifests),
    }


class ResolveImageTests(unittest.TestCase):
    def test_index_ignores_attestation_first(self) -> None:
        raw = index(descriptor("unknown", "unknown"), descriptor())
        with patch.object(ci_package.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(raw)
            self.assertEqual(
                ci_package.resolve_packaging_image(INDEX_IMAGE),
                f"ghcr.io/example/live@{CHILD_DIGEST}",
            )
            run.assert_called_once_with(
                ["skopeo", "inspect", "--raw", f"docker://{INDEX_IMAGE}"],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_simple_manifest_preserves_reference(self) -> None:
        for media_type in (
            MANIFEST_TYPE,
            "application/vnd.docker.distribution.manifest.v2+json",
        ):
            with (
                self.subTest(media_type=media_type),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(
                    {
                        "schemaVersion": 2,
                        "mediaType": media_type,
                        "config": {},
                        "layers": [],
                    }
                )
                self.assertEqual(
                    ci_package.resolve_packaging_image(INDEX_IMAGE), INDEX_IMAGE
                )

    def test_docker_manifest_list_resolves_child(self) -> None:
        raw = index(descriptor("linux", "arm64"), descriptor())
        raw["mediaType"] = "application/vnd.docker.distribution.manifest.list.v2+json"
        with patch.object(ci_package.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(raw)
            self.assertEqual(
                ci_package.resolve_packaging_image(INDEX_IMAGE),
                f"ghcr.io/example/live@{CHILD_DIGEST}",
            )

    def test_missing_or_ambiguous_platform_is_rejected(self) -> None:
        for raw in (
            index(),
            index(descriptor("unknown", "unknown")),
            index(descriptor("linux", "arm64")),
            index(descriptor(), descriptor()),
        ):
            with (
                self.subTest(raw=raw),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(raw)
                with self.assertRaisesRegex(ValueError, "linux/amd64"):
                    ci_package.resolve_packaging_image(INDEX_IMAGE)

    def test_malformed_manifest_is_rejected(self) -> None:
        bad_digest = descriptor()
        bad_digest["digest"] = "sha256:invalid"
        for raw in (
            [],
            {},
            index(bad_digest),
            index(None),
            index({}),
            index({**descriptor(), "platform": []}),
            index({**descriptor(), "mediaType": "unexpected"}),
            {**index(), "manifests": {}},
            {**index(), "schemaVersion": 1},
            {"schemaVersion": 2, "mediaType": MANIFEST_TYPE},
            {
                "schemaVersion": 2,
                "mediaType": MANIFEST_TYPE,
                "config": {},
                "layers": {},
            },
        ):
            with (
                self.subTest(raw=raw),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(raw)
                with self.assertRaises(ValueError):
                    ci_package.resolve_packaging_image(INDEX_IMAGE)

    def test_mutable_or_malformed_reference_is_rejected_before_inspect(self) -> None:
        for image in (
            "example/live:tag",
            "example/live@sha256:bad",
            f"@sha256:{'a' * 64}",
        ):
            with (
                self.subTest(image=image),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                with self.assertRaises(ValueError):
                    ci_package.resolve_packaging_image(image)
                run.assert_not_called()


class PackageTests(unittest.TestCase):
    def test_invalid_format_has_no_side_effects(self) -> None:
        with (
            patch.object(sys, "argv", ["ci-package.py", "bad"]),
            patch.object(ci_package.subprocess, "run") as run,
        ):
            with self.assertRaises(SystemExit):
                ci_package.main()
            run.assert_not_called()

    def test_iso_uses_live_image_and_password_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output.iso"
            output.touch()
            env = {
                "WORKSTATION_ISO_IMAGE": INDEX_IMAGE,
                "OUTPUT_NAME": str(output),
                "GHCR_TOKEN": "test-secret",
                "GHCR_USER": "tester",
            }
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["ci-package.py", "iso"]),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(
                    index(descriptor("unknown", "unknown"), descriptor())
                )
                self.assertEqual(ci_package.main(), 0)
                self.assertEqual(os.environ["WORKSTATION_ISO_IMAGE"], INDEX_IMAGE)
            calls = run.call_args_list
            self.assertEqual(
                calls[1].args[0],
                ["podman", "login", "ghcr.io", "-u", "tester", "--password-stdin"],
            )
            self.assertEqual(calls[1].kwargs["input"], "test-secret")
            self.assertIn("skopeo", calls[0].args[0])
            self.assertEqual(
                calls[2].args[0],
                ["skopeo", "inspect", "--raw", f"docker://{INDEX_IMAGE}"],
            )
            self.assertEqual(
                calls[3].args[0],
                ["podman", "pull", f"ghcr.io/example/live@{CHILD_DIGEST}"],
            )
            self.assertEqual(
                calls[4].args[0],
                [
                    "python3",
                    "./tools/package-artifact.py",
                    "iso",
                    f"ghcr.io/example/live@{CHILD_DIGEST}",
                    str(output),
                ],
            )
            self.assertEqual(
                calls[4].kwargs["env"]["IMAGE_BUILDER_CACHE"],
                str(Path.cwd() / ".osbuild-cache"),
            )

    def test_qcow2_uses_child_for_pull_and_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output.qcow2"
            output.touch()
            env = {"WORKSTATION_IMAGE": INDEX_IMAGE, "OUTPUT_NAME": str(output)}
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(sys, "argv", ["ci-package.py", "qcow2"]),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(index(descriptor()))
                self.assertEqual(ci_package.main(), 0)
                self.assertEqual(os.environ["WORKSTATION_IMAGE"], INDEX_IMAGE)
            commands = [call.args[0] for call in run.call_args_list]
            child = f"ghcr.io/example/live@{CHILD_DIGEST}"
            self.assertIn(["podman", "pull", child], commands)
            self.assertIn(
                ["python3", "./tools/package-artifact.py", "qcow2", child, str(output)],
                commands,
            )

    def test_inspect_failure_stops_before_pull_or_packaging(self) -> None:
        for failure in (
            subprocess.CalledProcessError(1, ["skopeo", "inspect"]),
            "not json",
        ):
            with (
                self.subTest(failure=failure),
                patch.dict(
                    os.environ,
                    {"WORKSTATION_IMAGE": INDEX_IMAGE, "OUTPUT_NAME": "output.qcow2"},
                    clear=True,
                ),
                patch.object(sys, "argv", ["ci-package.py", "qcow2"]),
                patch.object(ci_package.subprocess, "run") as run,
            ):
                run.side_effect = [
                    Mock(),
                    failure if isinstance(failure, Exception) else Mock(stdout=failure),
                ]
                self.assertEqual(ci_package.main(), 1)
                self.assertEqual(len(run.call_args_list), 2)


if __name__ == "__main__":
    unittest.main()
