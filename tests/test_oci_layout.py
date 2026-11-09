import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "oci_layout",
    Path(__file__).resolve().parents[1] / ".github/scripts/workflow/oci_layout.py",
)
oci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oci)

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
INDEX = "application/vnd.oci.image.index.v1+json"
REF = "org.opencontainers.image.ref.name"


def encoded(value):
    return json.dumps(value, indent=2).encode() + b"\n"


def blob(root, raw, media_type):
    checksum = hashlib.sha256(raw).hexdigest()
    path = root / "blobs/sha256" / checksum
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"digest": "sha256:" + checksum, "size": len(raw), "mediaType": media_type}


def store_manifest(root, manifest, raw=None):
    descriptor = blob(root, encoded(manifest) if raw is None else raw, MANIFEST)
    descriptor["annotations"] = {REF: "core"}
    (root / "index.json").write_bytes(
        encoded(
            {
                "schemaVersion": 2,
                "mediaType": INDEX,
                "manifests": [descriptor],
            }
        )
    )
    return descriptor["digest"]


def sample(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}\n')
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo("hello")
        entry.size = 5
        archive.addfile(entry, io.BytesIO(b"hello"))
    layer = stream.getvalue()
    config = blob(
        root,
        encoded(
            {
                "os": "linux",
                "architecture": "amd64",
                "rootfs": {
                    "type": "layers",
                    "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()],
                },
            }
        ),
        CONFIG,
    )
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": config,
        "layers": [blob(root, gzip.compress(layer, mtime=0), LAYER)],
    }
    return manifest, store_manifest(root, manifest)


class OciLayoutTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "layout"
        self.manifest, self.expected = sample(self.root)

    def index(self):
        return json.loads((self.root / "index.json").read_bytes())

    def write_index(self, index):
        (self.root / "index.json").write_bytes(encoded(index))

    def blob_path(self, descriptor):
        return self.root / "blobs/sha256" / descriptor["digest"].split(":")[1]

    def test_valid_layout_returns_exact_manifest_byte_digest(self):
        self.assertEqual(oci.manifest_digest(self.root, "core"), self.expected)
        self.assertNotEqual(self.expected, self.manifest["config"]["digest"])
        raw = encoded(self.manifest) + b"  \n"
        expected = store_manifest(self.root, self.manifest, raw)
        self.assertEqual(oci.manifest_digest(self.root, "core"), expected)
        self.assertNotEqual(expected, self.expected)

    def test_uncompressed_layer_is_supported(self):
        descriptor = self.manifest["layers"][0]
        raw = gzip.decompress(self.blob_path(descriptor).read_bytes())
        self.manifest["layers"][0] = blob(
            self.root, raw, "application/vnd.oci.image.layer.v1.tar"
        )
        expected = store_manifest(self.root, self.manifest)
        self.assertEqual(oci.manifest_digest(self.root, "core"), expected)

    def test_layers_are_streamed_without_collecting_bytes(self):
        with (
            mock.patch.object(oci, "CHUNK_BYTES", 7),
            mock.patch.object(oci, "contents", wraps=oci.contents) as reader,
        ):
            self.assertEqual(oci.manifest_digest(self.root, "core"), self.expected)
        layer_call = reader.call_args_list[-1]
        self.assertEqual(layer_call.args[1], self.manifest["layers"][0]["digest"][7:])
        self.assertIs(layer_call.kwargs["collect"], False)

    def test_manifest_config_and_layer_tampering(self):
        for descriptor in (
            self.index()["manifests"][0],
            self.manifest["config"],
            self.manifest["layers"][0],
        ):
            with self.subTest(descriptor=descriptor):
                path = self.blob_path(descriptor)
                original = path.read_bytes()
                path.write_bytes(b"x" * len(original))
                with self.assertRaises(ValueError):
                    oci.manifest_digest(self.root, "core")
                path.write_bytes(original)

    def test_missing_and_symlinked_blobs(self):
        for descriptor in (
            self.index()["manifests"][0],
            self.manifest["config"],
            self.manifest["layers"][0],
        ):
            with self.subTest(descriptor=descriptor):
                path = self.blob_path(descriptor)
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises((ValueError, OSError)):
                    oci.manifest_digest(self.root, "core")
                target = self.root / "outside"
                target.write_bytes(original)
                path.symlink_to(target)
                with self.assertRaises((ValueError, OSError)):
                    oci.manifest_digest(self.root, "core")
                path.unlink()
                path.write_bytes(original)

    def test_symlinked_parent_directories_and_layout(self):
        for path in (self.root / "blobs/sha256", self.root / "blobs", self.root):
            with self.subTest(path=path):
                moved = path.with_name(path.name + "-real")
                path.rename(moved)
                path.symlink_to(moved, target_is_directory=True)
                with self.assertRaises((ValueError, OSError)):
                    oci.manifest_digest(self.root, "core")
                path.unlink()
                moved.rename(path)
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            oci.manifest_digest(alias / "layout", "core")

    def test_metadata_symlinks_and_nonregular_files(self):
        path = self.root / "index.json"
        original = path.read_bytes()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises((ValueError, OSError)):
            oci.manifest_digest(self.root, "core")
        path.unlink()
        target = self.root / "real-index"
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            oci.manifest_digest(self.root, "core")

    def test_wrong_ref_multiple_entries_and_index_media_type(self):
        index = self.index()
        for changed in (
            index | {"manifests": []},
            index | {"manifests": index["manifests"] * 2},
            index
            | {
                "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"
            },
            index | {"schemaVersion": True},
        ):
            with self.subTest(index=changed):
                self.write_index(changed)
                with self.assertRaises(ValueError):
                    oci.manifest_digest(self.root, "core")
        self.write_index(index)
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "wrong")
        index["manifests"][0]["mediaType"] = INDEX
        self.write_index(index)
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "core")

    def test_descriptor_sizes_digests_and_external_urls(self):
        for location in ("manifest", "config", "layer"):
            for field, value in (
                ("size", True),
                ("size", -1),
                ("size", 999999),
                ("digest", "sha256:" + "A" * 64),
                ("digest", "sha256:../../outside"),
                ("urls", ["https://example.invalid/blob"]),
            ):
                with self.subTest(location=location, field=field):
                    manifest = copy.deepcopy(self.manifest)
                    store_manifest(self.root, manifest)
                    if location == "manifest":
                        index = self.index()
                        index["manifests"][0][field] = value
                        self.write_index(index)
                    else:
                        target = (
                            manifest["config"]
                            if location == "config"
                            else manifest["layers"][0]
                        )
                        target[field] = value
                        store_manifest(self.root, manifest)
                    with self.assertRaises(ValueError):
                        oci.manifest_digest(self.root, "core")

    def test_manifest_metadata_and_platform(self):
        for field, value in (
            ("schemaVersion", True),
            ("schemaVersion", 1),
            ("mediaType", INDEX),
            ("layers", {}),
        ):
            with self.subTest(field=field):
                store_manifest(self.root, self.manifest | {field: value})
                with self.assertRaises(ValueError):
                    oci.manifest_digest(self.root, "core")
        for os_name, arch in (("windows", "amd64"), ("linux", "arm64")):
            changed = copy.deepcopy(self.manifest)
            changed["config"] = blob(
                self.root, encoded({"os": os_name, "architecture": arch}), CONFIG
            )
            store_manifest(self.root, changed)
            with self.assertRaises(ValueError):
                oci.manifest_digest(self.root, "core")
        for location in ("config", "layers"):
            changed = copy.deepcopy(self.manifest)
            target = changed["config"] if location == "config" else changed["layers"][0]
            target["mediaType"] = "application/octet-stream"
            store_manifest(self.root, changed)
            with self.assertRaises(ValueError):
                oci.manifest_digest(self.root, "core")

    def test_json_rejects_duplicates_constants_invalid_utf8_and_oversize(self):
        for name in ("index.json", "oci-layout"):
            path = self.root / name
            original = path.read_bytes()
            for raw in (
                b'{"x":1,"x":2}',
                b'{"x":NaN}',
                b'{"x":Infinity}',
                b'{"x":1e999}',
                b"\xff",
                b"[]",
            ):
                with self.subTest(name=name, raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        oci.manifest_digest(self.root, "core")
            path.write_bytes(original)
        for raw in (b'{"schemaVersion":2,"schemaVersion":2}', b'{"x":NaN}'):
            store_manifest(self.root, self.manifest, raw)
            with self.assertRaises(ValueError):
                oci.manifest_digest(self.root, "core")
        store_manifest(self.root, self.manifest)
        with (
            mock.patch.object(oci, "MAX_JSON_BYTES", 10),
            self.assertRaises(ValueError),
        ):
            oci.manifest_digest(self.root, "core")

    def test_layout_version_and_layer_limit(self):
        (self.root / "oci-layout").write_bytes(b'{"imageLayoutVersion":"2.0.0"}')
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "core")
        (self.root / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}')
        with (
            mock.patch.object(oci, "MAX_LAYER_BYTES", 1),
            self.assertRaises(ValueError),
        ):
            oci.manifest_digest(self.root, "core")

    def test_validate_cli_is_offline_and_reports_digest(self):
        output = self.root.parent / "outputs"
        with (
            mock.patch.object(
                oci.sys,
                "argv",
                ["oci_layout", "validate", "--layout", str(self.root), "--ref", "core"],
            ),
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(oci.subprocess, "run") as command,
            mock.patch.object(oci.sys, "stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(oci.main(), 0)
            self.assertEqual(
                json.loads(stdout.getvalue()), {"manifest_digest": self.expected}
            )
            command.assert_not_called()
        self.assertEqual(output.read_text(), f"manifest_digest={self.expected}\n")

    def test_config_json_and_blob_metadata_limits(self):
        for raw in (
            b'{"os":"linux","os":"linux"}',
            b'{"x":NaN}',
            b'{"x":1e999}',
            b"\xff",
            b"[]",
            b"{",
        ):
            with self.subTest(raw=raw):
                changed = copy.deepcopy(self.manifest)
                changed["config"] = blob(self.root, raw, CONFIG)
                store_manifest(self.root, changed)
                with self.assertRaises(ValueError):
                    oci.manifest_digest(self.root, "core")
        changed = copy.deepcopy(self.manifest)
        changed["config"] = blob(self.root, b" " * (oci.MAX_JSON_BYTES + 1), CONFIG)
        store_manifest(self.root, changed)
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "core")
        store_manifest(self.root, self.manifest, b" " * (oci.MAX_JSON_BYTES + 1))
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "core")

    def test_descriptor_platform_and_unknown_metadata(self):
        original = self.index()
        for field, value in (
            ("platform", {"os": "linux", "architecture": "arm64"}),
            ("platform", {"os": "linux", "architecture": "amd64", "variant": "v3"}),
            ("annotations", {REF: 123}),
            ("artifactType", "unknown"),
            ("size", 1.0),
            ("size", "1"),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(original)
                changed["manifests"][0][field] = value
                self.write_index(changed)
                with self.assertRaises(ValueError):
                    oci.manifest_digest(self.root, "core")
        changed = copy.deepcopy(original)
        changed["manifests"][0]["platform"] = {"os": "linux", "architecture": "amd64"}
        self.write_index(changed)
        self.assertEqual(oci.manifest_digest(self.root, "core"), self.expected)
        changed["manifests"].append(copy.deepcopy(changed["manifests"][0]))
        changed["manifests"][1]["annotations"][REF] = "other"
        self.write_index(changed)
        with self.assertRaises(ValueError):
            oci.manifest_digest(self.root, "core")

    def test_output_rejects_symlinks_and_injection(self):
        target = self.root.parent / "target-output"
        target.write_text("unchanged\n")
        output = self.root.parent / "output"
        output.symlink_to(target)
        with (
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(oci.sys, "stdout", new_callable=io.StringIO) as stdout,
        ):
            with self.assertRaises((OSError, ValueError)):
                oci.outputs({"manifest_digest": self.expected})
            with self.assertRaises(ValueError):
                oci.outputs({"skopeo_version": "version\ninjected=value"})
            self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(target.read_text(), "unchanged\n")

    def test_export_rejects_parent_symlink_and_unsafe_inputs(self):
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root.parent, target_is_directory=True)
        with mock.patch.object(oci.subprocess, "run") as command:
            for image, path, ref in (
                ("local/core:build", alias / "new", "core"),
                ("local/core:build", self.root / ".." / "new", "core"),
                ("docker://registry/core:build", self.root.parent / "new", "core"),
                ("local/core:build", self.root.parent / "new", "bad\nref"),
            ):
                with (
                    self.subTest(path=path, image=image, ref=ref),
                    self.assertRaises((OSError, ValueError)),
                ):
                    oci.export_layout(image, path, ref)
            command.assert_not_called()

    def test_export_partial_copy_failure_and_stale_retry(self):
        destination = self.root.parent / "partial"
        output = self.root.parent / "outputs"

        def command(argv, **kwargs):
            if argv == ["skopeo", "--version"]:
                return mock.Mock(stdout="skopeo version 1.20.0\n")
            (destination / "partial-blob").write_bytes(b"incomplete")
            raise subprocess.CalledProcessError(1, argv)

        with (
            mock.patch.object(
                oci.sys,
                "argv",
                [
                    "oci_layout",
                    "export",
                    "--layout",
                    str(destination),
                    "--ref",
                    "core",
                    "--image",
                    "local/core:build",
                ],
            ),
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(oci.subprocess, "run", side_effect=command),
            mock.patch.object(oci.sys, "stdout", new_callable=io.StringIO) as stdout,
            mock.patch.object(oci.sys, "stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(oci.main(), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output.exists())
        with mock.patch.object(oci.subprocess, "run") as command:
            with self.assertRaises(ValueError):
                oci.export_layout("local/core:build", destination, "core")
            command.assert_not_called()

    def test_export_cli_copies_then_validates_and_records_version(self):
        destination = self.root.parent / "exported"
        destination.mkdir()
        output = self.root.parent / "outputs"
        calls = []

        def command(argv, **kwargs):
            calls.append(argv)
            self.assertTrue(kwargs["check"])
            self.assertNotIn("shell", kwargs)
            if argv == ["skopeo", "--version"]:
                return mock.Mock(stdout="skopeo version 1.20.0\n")
            (descriptor,) = kwargs["pass_fds"]
            target = Path(f"/proc/self/fd/{descriptor}")
            self.assertTrue(os.path.samestat(os.stat(target), os.stat(destination)))
            self.assertEqual(
                argv,
                [
                    "skopeo",
                    "copy",
                    "--dest-compress",
                    "--dest-compress-format",
                    "gzip",
                    "docker-daemon:local/core:build",
                    f"oci:{target}:core",
                ],
            )
            sample(target)
            return mock.Mock(stdout="copied\n")

        with (
            mock.patch.object(
                oci.sys,
                "argv",
                [
                    "oci_layout",
                    "export",
                    "--layout",
                    str(destination),
                    "--ref",
                    "core",
                    "--image",
                    "local/core:build",
                ],
            ),
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(oci.subprocess, "run", side_effect=command),
            mock.patch.object(oci.sys, "stdout", new_callable=io.StringIO) as stdout,
        ):
            self.assertEqual(oci.main(), 0)
            result = json.loads(stdout.getvalue())
        self.assertEqual(
            result["manifest_digest"], oci.manifest_digest(destination, "core")
        )
        self.assertEqual(result["skopeo_version"], "skopeo version 1.20.0")
        self.assertEqual(len(calls), 2)
        self.assertIn("skopeo_version=skopeo version 1.20.0\n", output.read_text())

    def test_export_rejects_replaced_destination(self):
        destination = self.root.parent / "exported"

        def command(argv, **kwargs):
            if argv == ["skopeo", "--version"]:
                return mock.Mock(stdout="skopeo version 1.20.0\n")
            sample(destination)
            destination.rename(destination.with_name("moved"))
            sample(destination)
            return mock.Mock(stdout="copied\n")

        with (
            mock.patch.object(oci.subprocess, "run", side_effect=command),
            self.assertRaisesRegex(ValueError, "destination changed"),
        ):
            oci.export_layout("local/core:build", destination, "core")

    def test_export_fd_writes_survive_prewrite_path_replacement(self):
        self.assert_prewrite_replacement(False)

    def test_export_fd_writes_survive_prewrite_ancestor_replacement(self):
        self.assert_prewrite_replacement(True)

    def assert_prewrite_replacement(self, replace_ancestor):
        sandbox = self.root.parent / "race"
        parent = sandbox / "parent"
        parent.mkdir(parents=True)
        destination = parent / "layout"
        outside_parent = sandbox / "outside"
        outside_parent.mkdir()
        if replace_ancestor:
            outside = outside_parent / "layout"
            outside.mkdir()
            moved = sandbox / "moved-parent"
            original = moved / "layout"
        else:
            outside = outside_parent
            original = parent / "moved-layout"

        def command(argv, **kwargs):
            if argv == ["skopeo", "--version"]:
                return mock.Mock(stdout="skopeo version 1.20.0\n")
            target = Path(argv[-1].removeprefix("oci:").rsplit(":", 1)[0])
            if replace_ancestor:
                parent.rename(moved)
                parent.symlink_to(outside_parent, target_is_directory=True)
            else:
                destination.rename(original)
                destination.symlink_to(outside, target_is_directory=True)
            sample(target)
            return mock.Mock(stdout="copied\n")

        with (
            mock.patch.object(oci.subprocess, "run", side_effect=command),
            self.assertRaises((OSError, ValueError)),
        ):
            oci.export_layout("local/core:build", destination, "core")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((original / "index.json").is_file())
        self.assertEqual(oci.manifest_digest(original, "core"), self.expected)

    def test_export_rejects_nonempty_or_symlink_destinations(self):
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for destination in (self.root, alias):
            with (
                self.subTest(destination=destination),
                mock.patch.object(oci.subprocess, "run") as command,
                self.assertRaises((ValueError, OSError)),
            ):
                oci.export_layout("local/core:build", destination, "core")
            command.assert_not_called()

    def test_export_cli_has_no_success_output_on_failure(self):
        destination = self.root.parent / "exported"
        for failure in (
            subprocess.CalledProcessError(1, ["skopeo"]),
            mock.Mock(stdout="skopeo version bad\ninjected=value\n"),
            mock.Mock(stdout="skopeo version 1.20.0\n"),
        ):
            output = self.root.parent / "outputs"
            with (
                self.subTest(failure=failure),
                mock.patch.object(
                    oci.sys,
                    "argv",
                    [
                        "oci_layout",
                        "export",
                        "--layout",
                        str(destination),
                        "--ref",
                        "core",
                        "--image",
                        "local/core:build",
                    ],
                ),
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
                mock.patch.object(
                    oci.subprocess,
                    "run",
                    side_effect=failure if isinstance(failure, Exception) else None,
                    return_value=failure,
                ),
                mock.patch.object(
                    oci.sys, "stdout", new_callable=io.StringIO
                ) as stdout,
                mock.patch.object(oci.sys, "stderr", new_callable=io.StringIO),
            ):
                self.assertEqual(oci.main(), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertFalse(output.exists())
