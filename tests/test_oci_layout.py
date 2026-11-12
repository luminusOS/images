import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

SPEC = importlib.util.spec_from_file_location(
    "oci_layout",
    Path(__file__).resolve().parents[1] / ".github/scripts/workflow/oci_layout.py",
)
oci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oci)
PIPELINE_SPEC = importlib.util.spec_from_file_location(
    "release_pipeline", Path(oci.__file__).with_name("release_pipeline.py")
)
pipeline = importlib.util.module_from_spec(PIPELINE_SPEC)
PIPELINE_SPEC.loader.exec_module(pipeline)

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


class DiffIDTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "layout"
        self.manifest, self.digest = sample(self.root)
        self.config = json.loads(self.path(self.manifest["config"]).read_bytes())
        self.raw = gzip.decompress(self.path(self.manifest["layers"][0]).read_bytes())

    def path(self, descriptor):
        return self.root / "blobs/sha256" / descriptor["digest"][7:]

    def store(self, raw=None, media=LAYER, config=None, count=1):
        if raw is not None:
            self.manifest["layers"] = [blob(self.root, raw, media)] * count
        if config is not None:
            self.manifest["config"] = blob(self.root, encoded(config), CONFIG)
        self.digest = store_manifest(self.root, self.manifest)

    def verify(self, digest=None):
        with oci.directory(self.root) as root:
            return oci.verify_diff_ids(root, "core", digest or self.digest)

    def test_valid_tar_gzip_and_concatenated_members_hash_all_output(self):
        expected = self.config["rootfs"]["diff_ids"]
        for raw, media in (
            (self.raw, "application/vnd.oci.image.layer.v1.tar"),
            (gzip.compress(self.raw, mtime=0), LAYER),
            (
                gzip.compress(self.raw[:100], mtime=0)
                + gzip.compress(b"", mtime=0)
                + gzip.compress(self.raw[100:], mtime=0),
                LAYER,
            ),
        ):
            with self.subTest(media=media, size=len(raw)):
                self.store(raw, media)
                self.assertEqual(self.verify(), expected)

    def test_concatenated_gzip_members_across_single_byte_boundaries(self):
        self.store(
            gzip.compress(self.raw[:5000], mtime=0)
            + gzip.compress(self.raw[5000:], mtime=0)
        )
        with mock.patch.object(oci, "CHUNK_BYTES", 1):
            self.assertEqual(self.verify(), self.config["rootfs"]["diff_ids"])

    def test_other_layer_media_types_remain_unsupported(self):
        self.store(b"unsupported", "application/vnd.oci.image.layer.v1.tar+zstd")
        with self.assertRaisesRegex(ValueError, "unsupported OCI blob mediaType"):
            self.verify()

    def test_self_consistent_forged_diff_id_is_not_content_verification(self):
        config = copy.deepcopy(self.config)
        config["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
        self.store(config=config)
        self.assertEqual(oci.manifest_digest(self.root, "core"), self.digest)
        with self.assertRaisesRegex(ValueError, "decompressed OCI diff_id mismatch"):
            self.verify()

    def test_missing_malformed_and_count_mismatched_rootfs_fail(self):
        for rootfs in (
            None,
            {},
            {"type": "other", "diff_ids": self.config["rootfs"]["diff_ids"]},
            {"type": "layers", "diff_ids": []},
            {"type": "layers", "diff_ids": "not-a-list"},
            {"type": "layers", "diff_ids": [True]},
            {"type": "layers", "diff_ids": ["sha256:" + "A" * 64]},
            {"type": "layers", "diff_ids": self.config["rootfs"]["diff_ids"] * 2},
        ):
            with self.subTest(rootfs=rootfs):
                config = copy.deepcopy(self.config)
                if rootfs is None:
                    del config["rootfs"]
                else:
                    config["rootfs"] = rootfs
                self.store(config=config)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_gzip_truncation_crc_and_trailing_garbage_fail_closed(self):
        compressed = gzip.compress(self.raw, mtime=0)
        for raw in (
            compressed[:-1],
            compressed[:-8],
            compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:],
            compressed[:-1] + bytes([compressed[-1] ^ 1]),
            compressed + b"garbage",
            compressed + b"\0",
            compressed + gzip.compress(b"second", mtime=0)[:-1],
            b"not gzip",
        ):
            with self.subTest(size=len(raw), tail=raw[-8:]):
                self.store(raw)
                self.assertEqual(oci.manifest_digest(self.root, "core"), self.digest)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_expected_manifest_and_layer_order_are_bound(self):
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            self.verify("sha256:" + "0" * 64)
        other = self.raw.replace(b"hello", b"world")
        config = copy.deepcopy(self.config)
        config["rootfs"]["diff_ids"].append(
            "sha256:" + hashlib.sha256(other).hexdigest()
        )
        self.manifest["layers"].append(
            blob(self.root, gzip.compress(other, mtime=0), LAYER)
        )
        self.store(config=config)
        self.assertEqual(self.verify(), config["rootfs"]["diff_ids"])
        self.manifest["layers"].reverse()
        self.store()
        with self.assertRaisesRegex(ValueError, "decompressed OCI diff_id mismatch"):
            self.verify()

    def test_per_layer_and_whole_image_expansion_limits(self):
        with (
            mock.patch.object(oci, "MAX_LAYER_BYTES", len(self.raw) - 1),
            self.assertRaisesRegex(ValueError, "decompressed OCI layer limit"),
        ):
            self.verify()
        config = copy.deepcopy(self.config)
        config["rootfs"]["diff_ids"] *= 2
        self.store(gzip.compress(self.raw, mtime=0), config=config, count=2)
        with (
            mock.patch.object(oci, "MAX_DIFFID_TOTAL_BYTES", len(self.raw) * 2 - 1),
            self.assertRaisesRegex(ValueError, "decompressed OCI image limit"),
        ):
            self.verify()
        with mock.patch.object(oci, "MAX_DIFFID_TOTAL_BYTES", len(self.raw) * 2):
            self.assertEqual(self.verify(), config["rootfs"]["diff_ids"])

    def test_decoder_input_and_output_are_bounded_and_time_is_absolute(self):
        factory = oci.zlib.decompressobj
        calls = []
        clock = [0.0]
        test = self

        class Decoder:
            def __init__(self, *args):
                self.decoder = factory(*args)

            def __getattr__(self, name):
                return getattr(self.decoder, name)

            def decompress(self, data, max_length):
                test.assertLessEqual(len(data), 17)
                test.assertEqual(max_length, 17)
                result = self.decoder.decompress(data, max_length)
                test.assertLessEqual(len(result), 17)
                calls.append(len(result))
                clock[0] += 0.1
                return result

        with (
            mock.patch.object(oci, "CHUNK_BYTES", 17),
            mock.patch.object(oci.zlib, "decompressobj", Decoder),
            mock.patch.object(oci.time, "monotonic", side_effect=lambda: clock[0]),
        ):
            self.assertEqual(self.verify(), self.config["rootfs"]["diff_ids"])
            self.assertGreater(len(calls), 100)
            clock[0] = 0.0
            calls.clear()
            with (
                mock.patch.object(oci, "DIFFID_TIMEOUT_SECONDS", 0.15),
                self.assertRaisesRegex(ValueError, "OCI diff_id deadline"),
            ):
                self.verify()
            self.assertEqual(len(calls), 2)

    def test_deadline_is_not_renewed_for_each_layer(self):
        config = copy.deepcopy(self.config)
        config["rootfs"]["diff_ids"] *= 2
        self.store(gzip.compress(self.raw, mtime=0), config=config, count=2)
        original = oci.contents
        clock = [0.0]

        def read(*args, **kwargs):
            if kwargs.get("sink") is not None:
                clock[0] += 0.6
            return original(*args, **kwargs)

        with (
            mock.patch.object(oci, "contents", side_effect=read),
            mock.patch.object(oci.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(oci, "DIFFID_TIMEOUT_SECONDS", 1.0),
            self.assertRaisesRegex(ValueError, "OCI diff_id deadline"),
        ):
            self.verify()

    def test_decompression_rechecks_raw_digest_on_its_own_opened_stream(self):
        self.store(self.raw, "application/vnd.oci.image.layer.v1.tar")
        path = self.path(self.manifest["layers"][0])
        original = oci.contents

        def read(*args, **kwargs):
            if kwargs.get("sink") is not None:
                path.write_bytes(self.raw[:-1] + b"x")
            return original(*args, **kwargs)

        with (
            mock.patch.object(oci, "contents", side_effect=read),
            self.assertRaisesRegex(ValueError, "OCI blob digest mismatch"),
        ):
            self.verify()

    def test_decoder_file_open_rejects_symlink_fifo_and_directory(self):
        path = self.path(self.manifest["layers"][0])
        raw = path.read_bytes()
        target = self.root / "target"
        target.write_bytes(raw)
        original = oci.contents
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):

                def read(*args, kind=kind, **kwargs):
                    if kwargs.get("sink") is not None:
                        path.unlink()
                        if kind == "symlink":
                            path.symlink_to(target)
                        elif kind == "fifo":
                            os.mkfifo(path)
                        else:
                            path.mkdir()
                    return original(*args, **kwargs)

                try:
                    with (
                        mock.patch.object(oci, "contents", side_effect=read),
                        self.assertRaises((OSError, ValueError)),
                    ):
                        self.verify()
                finally:
                    if path.is_dir():
                        path.rmdir()
                    else:
                        path.unlink()
                    path.write_bytes(raw)


class OciLayoutTests(unittest.TestCase):
    def test_negative_subjects_preserve_bytes_and_exclude_attachments(self):
        manifest = json.loads(
            (self.root / "blobs/sha256" / self.expected[7:]).read_bytes()
        )
        manifest["annotations"] = {"existing": "preserved"}
        expected = store_manifest(self.root, manifest)
        index = json.loads((self.root / "index.json").read_bytes())
        index["annotations"] = {"index": "preserved"}
        index["manifests"][0]["platform"] = {"os": "linux", "architecture": "amd64"}
        index["manifests"][0]["annotations"]["descriptor"] = "preserved"
        (self.root / "index.json").write_bytes(encoded(index))
        (self.root / "signatures").symlink_to("/does-not-exist")
        blob(self.root, b"unreferenced signature", LAYER)
        before = {
            p.relative_to(self.root): p.read_bytes()
            for p in self.root.rglob("*")
            if p.is_file()
        }
        destinations = [self.root.parent / name for name in ("unsigned", "foreign-key")]
        with (
            mock.patch.object(
                oci.subprocess, "run", side_effect=AssertionError("external execution")
            ),
            mock.patch.object(
                oci.subprocess,
                "Popen",
                side_effect=AssertionError("external execution"),
            ),
            mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            result = oci.derive_negative_subjects(
                self.root, "core", expected, *destinations
            )
        self.assertEqual(len({expected, *result.values()}), 3)
        for kind, path in zip(("unsigned", "foreign-key"), destinations):
            digest = result[kind]
            actual = json.loads((path / "blobs/sha256" / digest[7:]).read_bytes())
            wanted = copy.deepcopy(manifest)
            wanted["annotations"][oci.NEGATIVE_SUBJECT] = kind
            self.assertEqual(actual, wanted)
            self.assertEqual(
                oci.verify_negative_subject(self.root, "core", expected, path, kind),
                digest,
            )
            descriptors = [manifest["config"], *manifest["layers"]]
            for descriptor in descriptors:
                name = "blobs/sha256/" + descriptor["digest"][7:]
                self.assertEqual(
                    (path / name).read_bytes(), (self.root / name).read_bytes()
                )
            self.assertEqual(
                {p.name for p in (path / "blobs/sha256").iterdir()},
                {digest[7:], *(d["digest"][7:] for d in descriptors)},
            )
            self.assertFalse((path / "signatures").exists())
            output_index = json.loads((path / "index.json").read_bytes())
            wanted_index = copy.deepcopy(index)
            wanted_index["manifests"][0].update(
                digest=digest,
                size=len((path / "blobs/sha256" / digest[7:]).read_bytes()),
            )
            wanted_index["manifests"][0]["annotations"][REF] = "negative-" + kind
            self.assertEqual(output_index, wanted_index)
        self.assertEqual(
            before,
            {
                p.relative_to(self.root): p.read_bytes()
                for p in self.root.rglob("*")
                if p.is_file()
            },
        )

    def test_negative_subjects_reject_wrong_digest_and_existing_paths(self):
        a, b = (self.root.parent / name for name in ("a", "b"))
        with self.assertRaises(ValueError):
            oci.derive_negative_subjects(self.root, "core", "sha256:" + "0" * 64, a, b)
        self.assertFalse(a.exists())
        b.mkdir()
        with self.assertRaises((ValueError, OSError)):
            oci.derive_negative_subjects(self.root, "core", self.expected, a, b)
        self.assertFalse(a.exists())

    def test_negative_subjects_reject_unsafe_paths(self):
        for fault in (
            "source-link",
            "parent-link",
            "destination-link",
            "traversal",
            "same",
            "invalid",
            "inside-source",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                source = self.root
                a, b = parent / "a", parent / "b"
                if fault == "source-link":
                    source = parent / "source"
                    source.symlink_to(self.root)
                elif fault == "parent-link":
                    (parent / "link").symlink_to(parent, target_is_directory=True)
                    a = parent / "link/a"
                elif fault == "destination-link":
                    a.symlink_to(parent / "absent")
                elif fault == "traversal":
                    a = parent / ".." / "a"
                elif fault == "same":
                    b = a
                elif fault == "inside-source":
                    a = self.root / "new-subject"
                else:
                    a = parent / "bad:name"
                with self.assertRaises((ValueError, OSError)):
                    oci.derive_negative_subjects(source, "core", self.expected, a, b)

    def test_negative_subjects_reject_source_corruption_and_reserved_annotation(self):
        for fault in ("config", "layer", "manifest", "annotation"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                source = parent / "source"
                manifest, expected = sample(source)
                if fault == "annotation":
                    manifest["annotations"] = {oci.NEGATIVE_SUBJECT: "unsigned"}
                    expected = store_manifest(source, manifest)
                else:
                    digest = (
                        expected
                        if fault == "manifest"
                        else (
                            manifest["config"]
                            if fault == "config"
                            else manifest["layers"][0]
                        )["digest"]
                    )
                    (source / "blobs/sha256" / digest[7:]).write_bytes(b"corrupt")
                with self.assertRaises((ValueError, OSError)):
                    oci.derive_negative_subjects(
                        source, "core", expected, parent / "a", parent / "b"
                    )
                self.assertFalse((parent / "a").exists())

    def test_negative_subjects_verify_actual_relation(self):
        for fault in (
            "manifest",
            "config",
            "layer",
            "index",
            "extra",
            "root-extra",
            "blob-extra",
            "kind",
            "expected",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                a, b = parent / "a", parent / "b"
                result = oci.derive_negative_subjects(
                    self.root, "core", self.expected, a, b
                )
                kind, expected = "unsigned", self.expected
                if fault in ("manifest", "config", "layer"):
                    manifest = json.loads(
                        (a / "blobs/sha256" / result[kind][7:]).read_bytes()
                    )
                    if fault == "manifest":
                        manifest["annotations"]["extra"] = "forbidden"
                    elif fault == "config":
                        manifest["config"] = blob(
                            a,
                            encoded(
                                {"os": "linux", "architecture": "amd64", "extra": True}
                            ),
                            CONFIG,
                        )
                    else:
                        manifest["layers"] = [blob(a, b"changed layer", LAYER)]
                    digest = store_manifest(a, manifest)
                    index = json.loads((a / "index.json").read_bytes())
                    index["manifests"][0]["annotations"][REF] = "negative-unsigned"
                    (a / "index.json").write_bytes(encoded(index))
                    self.assertEqual(
                        oci.manifest_digest(a, "negative-unsigned"), digest
                    )
                elif fault == "index":
                    index = json.loads((a / "index.json").read_bytes())
                    index["annotations"] = {"extra": "forbidden"}
                    (a / "index.json").write_bytes(encoded(index))
                elif fault == "extra":
                    blob(a, b"attachment", LAYER)
                elif fault == "root-extra":
                    (a / "signature").write_bytes(b"attachment")
                elif fault == "blob-extra":
                    (a / "blobs/extra").mkdir()
                elif fault == "kind":
                    kind = "foreign-signed"
                else:
                    expected = "sha256:" + "0" * 64
                with self.assertRaises((ValueError, OSError)):
                    oci.verify_negative_subject(self.root, "core", expected, a, kind)

    def test_negative_subjects_closed_identifiers_and_source_index_race(self):
        index = self.index()
        for kind in ("foreign-signed", "other", "", None):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                oci.negative_documents(index, self.manifest, kind)
        index["manifests"][0]["annotations"][REF] = "bad:ref"
        self.write_index(index)
        with oci.directory(self.root) as base, self.assertRaises(ValueError):
            oci.negative_base(base, "bad:ref", self.expected)
        index["manifests"][0]["annotations"][REF] = "core"
        self.write_index(index)
        original = oci.checked_manifest

        def changed(base, ref):
            digest = original(base, ref)
            index["annotations"] = {"raced": "true"}
            self.write_index(index)
            return digest

        with (
            mock.patch.object(oci, "checked_manifest", side_effect=changed),
            oci.directory(self.root) as base,
            self.assertRaises(ValueError),
        ):
            oci.negative_base(base, "core", self.expected)

    def test_negative_subjects_reject_byte_identical_directory_replacement(self):
        a, b = self.root.parent / "a", self.root.parent / "b"
        original = oci.write_negative_subject

        def write(base, destination, index, manifest, kind):
            original(base, destination, index, manifest, kind)
            if kind == "foreign-key":
                retained = self.root.parent / "retained"
                a.rename(retained)
                shutil.copytree(retained, a)

        with (
            mock.patch.object(oci, "write_negative_subject", side_effect=write),
            self.assertRaises(ValueError),
        ):
            oci.derive_negative_subjects(self.root, "core", self.expected, a, b)
        self.assertTrue(a.is_dir())

    def test_negative_subjects_reject_parent_replacement_with_same_children(self):
        parent = self.root.parent / "outputs"
        parent.mkdir()
        a, b = parent / "a", parent / "b"
        original = oci.write_negative_subject

        def write(base, destination, index, manifest, kind):
            original(base, destination, index, manifest, kind)
            if kind == "foreign-key":
                retained = self.root.parent / "retained-parent"
                parent.rename(retained)
                parent.mkdir()
                (retained / "a").rename(a)
                (retained / "b").rename(b)

        with (
            mock.patch.object(oci, "write_negative_subject", side_effect=write),
            self.assertRaises(ValueError),
        ):
            oci.derive_negative_subjects(self.root, "core", self.expected, a, b)
        self.assertTrue(a.is_dir())
        self.assertTrue(b.is_dir())

    def test_negative_subjects_reject_directory_swap_before_open_without_writing(self):
        a, b = self.root.parent / "a", self.root.parent / "b"
        original = os.open

        def swapped(name, flags, *args, **kwargs):
            if name == "a" and flags == oci.DIRECTORY_FLAGS and "dir_fd" in kwargs:
                a.rename(self.root.parent / "retained-empty")
                a.mkdir()
            return original(name, flags, *args, **kwargs)

        with (
            mock.patch.object(oci.os, "open", side_effect=swapped),
            self.assertRaises(ValueError),
        ):
            oci.derive_negative_subjects(self.root, "core", self.expected, a, b)
        self.assertEqual(list(a.iterdir()), [])
        self.assertFalse(b.exists())

    def test_negative_subjects_fail_without_cleanup_on_write_or_replacement(self):
        for fault in ("write", "replace", "relocate"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp) / "parent"
                parent.mkdir()
                a, b = parent / "a", parent / "b"
                original = oci.write_negative_subject
                calls = []

                def write(
                    source,
                    destination,
                    index,
                    manifest,
                    kind,
                    *,
                    original=original,
                    calls=calls,
                    fault=fault,
                    a=a,
                    parent=parent,
                    temp=temp,
                ):
                    original(source, destination, index, manifest, kind)
                    calls.append(kind)
                    if kind == "foreign-key":
                        if fault == "write":
                            raise OSError("injected write failure")
                        if fault == "replace":
                            a.rename(parent / "retained")
                            a.mkdir()
                            (a / "unrelated").write_bytes(b"keep")
                        else:
                            parent.rename(Path(temp) / "relocated")
                            parent.mkdir()
                            (parent / "unrelated").write_bytes(b"keep")

                with (
                    mock.patch.object(oci, "write_negative_subject", side_effect=write),
                    self.assertRaises((ValueError, OSError)),
                ):
                    oci.derive_negative_subjects(self.root, "core", self.expected, a, b)
                self.assertEqual(calls, list(oci.NEGATIVE_KINDS))
                if fault == "replace":
                    self.assertEqual((a / "unrelated").read_bytes(), b"keep")
                elif fault == "relocate":
                    self.assertEqual((parent / "unrelated").read_bytes(), b"keep")
                else:
                    self.assertTrue(a.is_dir())
                    self.assertTrue(b.is_dir())

    def test_negative_subjects_verify_before_return_and_rehash_during_copy(self):
        for fault in ("output", "copy"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                source = parent / "source"
                _manifest, expected = sample(source)
                a, b = parent / "a", parent / "b"
                original = oci.write_negative_subject

                def write(
                    base,
                    destination,
                    index,
                    manifest,
                    kind,
                    *,
                    fault=fault,
                    source=source,
                    a=a,
                    original=original,
                ):
                    layer = (
                        source / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
                    )
                    if fault == "copy" and kind == "unsigned":
                        raw = layer.read_bytes()
                        layer.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    original(base, destination, index, manifest, kind)
                    if fault == "output" and kind == "foreign-key":
                        descriptor = manifest["layers"][0]
                        target = a / "blobs/sha256" / descriptor["digest"][7:]
                        target.write_bytes(b"corrupt")

                with (
                    mock.patch.object(oci, "write_negative_subject", side_effect=write),
                    self.assertRaises((ValueError, OSError)),
                ):
                    oci.derive_negative_subjects(source, "core", expected, a, b)

    def run_cli(self, *arguments):
        output = self.root.parent / "cli-outputs"
        output.write_text("unchanged=true\n")
        with (
            mock.patch.object(oci.sys, "argv", ["oci_layout", *map(str, arguments)]),
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(oci.sys, "stdout", new_callable=io.StringIO) as stdout,
            mock.patch.object(oci.sys, "stderr", new_callable=io.StringIO) as stderr,
        ):
            result = oci.main()
        return result, stdout.getvalue(), stderr.getvalue(), output.read_text()

    def download_payload(self, repository, run_id, name, output):
        self.assertEqual(
            (repository, run_id, name), ("owner/repo", 123, "workstation-oci")
        )
        shutil.copytree(self.root, output)
        index = json.loads((output / "index.json").read_bytes())
        index["manifests"][0]["annotations"][REF] = "workstation"
        (output / "index.json").write_bytes(encoded(index))

    def test_fetch_payload_preserves_manifest_and_blobs_and_remaps_only_index_ref(self):
        destination = self.root.parent / "payload.oci"
        index = json.loads((self.root / "index.json").read_bytes())
        index["annotations"] = {"retained": "index annotation"}
        index["manifests"][0]["annotations"]["retained"] = "descriptor annotation"
        (self.root / "index.json").write_bytes(encoded(index))
        before = {
            p.relative_to(self.root): p.read_bytes()
            for p in self.root.rglob("*")
            if p.is_file()
        }
        with (
            mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
            mock.patch.object(
                pipeline, "download", side_effect=self.download_payload
            ) as fetch,
        ):
            result, stdout, stderr, output = self.run_cli(
                "fetch-payload",
                "--repository",
                "owner/repo",
                "--run-id",
                123,
                "--layout",
                destination,
                "--expected-digest",
                self.expected,
            )
        self.assertEqual(result, 0, stderr)
        fetch.assert_called_once()
        self.assertEqual(json.loads(stdout), {"manifest_digest": self.expected})
        self.assertEqual(output, f"unchanged=true\nmanifest_digest={self.expected}\n")
        self.assertEqual(oci.manifest_digest(destination, "latest"), self.expected)
        after = {
            p.relative_to(destination): p.read_bytes()
            for p in destination.rglob("*")
            if p.is_file()
        }
        index = json.loads(before.pop(Path("index.json")))
        index["manifests"][0]["annotations"][REF] = "latest"
        self.assertEqual(json.loads(after.pop(Path("index.json"))), index)
        self.assertEqual(after, before)

    def test_fetch_payload_rejects_missing_digest_corruption_and_invalid_source(self):
        for fault in (
            "missing",
            "mismatch",
            "download",
            "layer",
            "manifest",
            "ref",
            "index",
            "symlink",
        ):
            with self.subTest(fault=fault):
                destination = self.root.parent / "payload.oci"

                def download(repository, run_id, name, output, fault=fault):
                    self.download_payload(repository, run_id, name, output)
                    if fault == "download":
                        raise ValueError("artifact digest mismatch")
                    if fault == "layer":
                        layer = (
                            output
                            / "blobs/sha256"
                            / self.manifest["layers"][0]["digest"][7:]
                        )
                        layer.write_bytes(b"corrupt")
                    if fault == "manifest":
                        (output / "blobs/sha256" / self.expected[7:]).write_bytes(b"{}")
                    index_path = output / "index.json"
                    index = json.loads(index_path.read_bytes())
                    if fault == "ref":
                        index["manifests"][0]["annotations"][REF] = "latest"
                    if fault == "index":
                        index["manifests"] *= 2
                    index_path.write_bytes(encoded(index))
                    if fault == "symlink":
                        index_path.unlink()
                        index_path.symlink_to(self.root / "index.json")

                expected = (
                    ""
                    if fault == "missing"
                    else "sha256:" + "0" * 64
                    if fault == "mismatch"
                    else self.expected
                )
                with (
                    mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
                    mock.patch.object(
                        pipeline, "download", side_effect=download
                    ) as fetch,
                ):
                    result, stdout, _, output = self.run_cli(
                        "fetch-payload",
                        "--repository",
                        "owner/repo",
                        "--run-id",
                        123,
                        "--layout",
                        destination,
                        "--expected-digest",
                        expected,
                    )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")
                self.assertFalse(destination.exists())
                if fault == "missing":
                    fetch.assert_not_called()

    def test_payload_index_remap_rejects_symlink_replacement_without_target_writes(
        self,
    ):
        destination = self.root.parent / "payload.oci"
        sentinel = self.root.parent / "unrelated-index"
        original_open, original_replace = os.open, os.replace
        for phase in ("open", "replace"):
            with self.subTest(phase=phase):
                sentinel.write_bytes(b"preserve\n")

                def open_index(name, *args, phase=phase, **kwargs):
                    if phase == "open" and name == ".index-remap":
                        path = Path(f"/proc/self/fd/{kwargs['dir_fd']}") / name
                        path.symlink_to(sentinel)
                    return original_open(name, *args, **kwargs)

                def replace_index(source, target, phase=phase, **kwargs):
                    if phase == "replace":
                        path = Path(f"/proc/self/fd/{kwargs['src_dir_fd']}") / source
                        path.unlink()
                        path.symlink_to(sentinel)
                    return original_replace(source, target, **kwargs)

                with (
                    mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
                    mock.patch.object(
                        pipeline, "download", side_effect=self.download_payload
                    ),
                    mock.patch.object(oci.os, "open", side_effect=open_index),
                    mock.patch.object(oci.os, "replace", side_effect=replace_index),
                ):
                    result, stdout, _, output = self.run_cli(
                        "fetch-payload",
                        "--repository",
                        "owner/repo",
                        "--run-id",
                        123,
                        "--layout",
                        destination,
                        "--expected-digest",
                        self.expected,
                    )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")
                self.assertFalse(destination.exists())
                self.assertEqual(sentinel.read_bytes(), b"preserve\n")

    def test_fetch_core_cli_delegates_download_and_checks_real_layout(self):
        self.assert_authenticated_acquisition("fetch-core", "core", "core")

    def test_fetch_payload_delegates_authenticated_download_with_real_zip(self):
        self.assert_authenticated_acquisition("fetch-payload", "workstation", "latest")

    def assert_authenticated_acquisition(self, action, ref, destination_ref):
        destination = self.root.parent / f"{ref}-oci"
        before = set(self.root.parent.iterdir())
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in self.root.rglob("*"):
                if path.is_file():
                    raw = path.read_bytes()
                    if path.name == "index.json":
                        index = json.loads(raw)
                        index["manifests"][0]["annotations"][REF] = ref
                        raw = encoded(index)
                    archive.writestr(path.relative_to(self.root).as_posix(), raw)
        raw = buffer.getvalue()
        artifact = {
            "id": 456,
            "name": f"{ref}-oci",
            "expired": False,
            "workflow_run": {"id": 123},
            "size_in_bytes": len(raw),
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        }

        def command(argv, **kwargs):
            self.assertEqual(
                argv,
                [
                    "gh",
                    "api",
                    "--paginate",
                    "--slurp",
                    "repos/owner/repo/actions/runs/123/artifacts?per_page=100",
                ],
            )
            return mock.Mock(stdout=json.dumps([{"artifacts": [artifact]}]))

        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdout = io.BytesIO(raw)
        process.wait.return_value = 0

        with (
            mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
            mock.patch.object(pipeline, "download", wraps=pipeline.download) as fetch,
            mock.patch.object(pipeline, "authorize_run") as authorize,
            mock.patch.object(pipeline.subprocess, "run", side_effect=command),
            mock.patch.object(
                pipeline.subprocess, "Popen", return_value=process
            ) as stream,
        ):
            result, stdout, stderr, output = self.run_cli(
                action,
                "--repository",
                "owner/repo",
                "--run-id",
                123,
                "--layout",
                destination,
                "--expected-digest",
                self.expected,
            )
        self.assertEqual(result, 0, stderr)
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.args[:3], ("owner/repo", 123, f"{ref}-oci"))
        stream.assert_called_once_with(
            ["gh", "api", "repos/owner/repo/actions/artifacts/456/zip"],
            stdout=subprocess.PIPE,
        )
        authorize.assert_not_called()
        self.assertEqual(json.loads(stdout), {"manifest_digest": self.expected})
        self.assertEqual(output, f"unchanged=true\nmanifest_digest={self.expected}\n")
        self.assertEqual(
            oci.manifest_digest(destination, destination_ref), self.expected
        )
        self.assertEqual(
            set(self.root.parent.iterdir()) - before,
            {destination, self.root.parent / "cli-outputs"},
        )

    def test_fetch_core_cli_rejects_expected_digest_before_download(self):
        for expected in ("", "sha256:" + "A" * 64, "sha256:bad", "bad\ninjected=true"):
            with (
                self.subTest(expected=expected),
                mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
                mock.patch.object(pipeline, "download") as download,
            ):
                result, stdout, stderr, output = self.run_cli(
                    "fetch-core",
                    "--repository",
                    "owner/repo",
                    "--run-id",
                    123,
                    "--layout",
                    self.root.parent / "core-oci",
                    "--expected-digest",
                    expected,
                )
                self.assertEqual(result, 1)
                self.assertIn("invalid expected OCI digest", stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")
                download.assert_not_called()

    def test_fetch_core_cli_cleans_failure_and_never_publishes_partial_layout(self):
        for fault in ("digest", "download", "invalid-layout"):
            with self.subTest(fault=fault):
                destination = self.root.parent / "core-oci"
                before = set(self.root.parent.iterdir())

                def download(repository, run_id, name, output, fault=fault):
                    shutil.copytree(self.root, output)
                    if fault == "download":
                        raise ValueError("artifact run binding mismatch")
                    if fault == "invalid-layout":
                        (output / "oci-layout").write_text("{}")

                with (
                    mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
                    mock.patch.object(pipeline, "download", side_effect=download),
                ):
                    result, stdout, stderr, output = self.run_cli(
                        "fetch-core",
                        "--repository",
                        "owner/repo",
                        "--run-id",
                        123,
                        "--layout",
                        destination,
                        "--expected-digest",
                        "sha256:" + "0" * 64 if fault == "digest" else self.expected,
                    )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")
                self.assertFalse(destination.exists())
                self.assertEqual(
                    set(self.root.parent.iterdir()) - before,
                    {self.root.parent / "cli-outputs"} - before,
                )
                if fault == "digest":
                    self.assertIn("core OCI manifest digest mismatch", stderr)

    def test_fetch_core_cli_rejects_stale_or_symlinked_destination(self):
        stale = self.root.parent / "stale"
        stale.mkdir()
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root.parent, target_is_directory=True)
        for path in (stale, alias / "core-oci", alias):
            with (
                self.subTest(path=path),
                mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
                mock.patch.object(pipeline, "download") as download,
            ):
                result, stdout, _, output = self.run_cli(
                    "fetch-core",
                    "--repository",
                    "owner/repo",
                    "--run-id",
                    123,
                    "--layout",
                    path,
                    "--expected-digest",
                    self.expected,
                )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")
                download.assert_not_called()

    def test_fetch_core_rejects_staged_directory_replacement_at_rename(self):
        for action in ("fetch-core", "fetch-payload"):
            with self.subTest(action=action):
                self.assert_staged_replacement_rejected(action)

    def assert_staged_replacement_rejected(self, action):
        parent = self.root.parent / action / "requested"
        parent.mkdir(parents=True)
        destination = parent / "core-oci"
        rename = os.rename
        replacements = []

        def replace_then_rename(source, target, **kwargs):
            source_fd = kwargs["src_dir_fd"]
            rename(
                source, "validated-aside", src_dir_fd=source_fd, dst_dir_fd=source_fd
            )
            replacement = Path(f"/proc/self/fd/{source_fd}") / source
            manifest, _ = sample(replacement)
            replacements.append(
                store_manifest(replacement, manifest, encoded(manifest) + b" \n")
            )
            ref = "latest" if action == "fetch-payload" else "core"
            index = json.loads((replacement / "index.json").read_bytes())
            index["manifests"][0]["annotations"][REF] = ref
            (replacement / "index.json").write_bytes(encoded(index))
            rename(source, target, **kwargs)

        with (
            mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
            mock.patch.object(
                pipeline,
                "download",
                side_effect=self.download_payload
                if action == "fetch-payload"
                else lambda repo, run, name, output: shutil.copytree(self.root, output),
            ),
            mock.patch.object(
                oci.os, "rename", side_effect=replace_then_rename
            ) as handoff,
        ):
            result, stdout, _, output = self.run_cli(
                action,
                "--repository",
                "owner/repo",
                "--run-id",
                123,
                "--layout",
                destination,
                "--expected-digest",
                self.expected,
            )
        handoff.assert_called_once()
        self.assertNotEqual(replacements[0], self.expected)
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(output, "unchanged=true\n")
        ref = "latest" if action == "fetch-payload" else "core"
        self.assertEqual(oci.manifest_digest(destination, ref), replacements[0])

    def test_fetch_core_rejects_parent_relocation_at_rename_without_unsafe_cleanup(
        self,
    ):
        for action in ("fetch-core", "fetch-payload"):
            with self.subTest(action=action):
                self.assert_parent_relocation_rejected(action)

    def assert_parent_relocation_rejected(self, action):
        sandbox = self.root.parent / action
        parent = sandbox / "requested"
        parent.mkdir(parents=True)
        moved = sandbox / "moved"
        destination = parent / "core-oci"
        rename = os.rename
        unrelated = []

        def relocate_then_rename(source, target, **kwargs):
            temporary_name = Path(
                os.readlink(f"/proc/self/fd/{kwargs['src_dir_fd']}")
            ).name
            rename(parent, moved)
            parent.mkdir()
            replacement = parent / temporary_name
            replacement.mkdir()
            sentinel = replacement / "unrelated"
            sentinel.write_text("preserve\n")
            unrelated.append(sentinel)
            rename(source, target, **kwargs)

        with (
            mock.patch.dict(oci.sys.modules, {"release_pipeline": pipeline}),
            mock.patch.object(
                pipeline,
                "download",
                side_effect=self.download_payload
                if action == "fetch-payload"
                else lambda repo, run, name, output: shutil.copytree(self.root, output),
            ),
            mock.patch.object(
                oci.os, "rename", side_effect=relocate_then_rename
            ) as handoff,
        ):
            result, stdout, _, output = self.run_cli(
                action,
                "--repository",
                "owner/repo",
                "--run-id",
                123,
                "--layout",
                destination,
                "--expected-digest",
                self.expected,
            )
        handoff.assert_called_once()
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(output, "unchanged=true\n")
        self.assertEqual(unrelated[0].read_text(), "preserve\n")
        self.assertFalse(destination.exists())
        ref = "latest" if action == "fetch-payload" else "core"
        self.assertEqual(oci.manifest_digest(moved / "core-oci", ref), self.expected)

    def ancestry_fixture(
        self, core_rootfs=None, workstation_rootfs=None, shorter=False
    ):
        child = self.root.parent / "workstation-oci"
        manifest, _ = sample(child)
        config = json.loads(self.blob_path(self.manifest["config"]).read_bytes())
        core_config = copy.deepcopy(config)
        if core_rootfs is not None:
            core_config["rootfs"] = core_rootfs
        if shorter:
            self.manifest["layers"] *= 2
            core_config["rootfs"]["diff_ids"] *= 2
        self.manifest["config"] = blob(self.root, encoded(core_config), CONFIG)
        core_digest = store_manifest(self.root, self.manifest)
        if not shorter:
            manifest["layers"] *= 2
            config["rootfs"]["diff_ids"] *= 2
        if workstation_rootfs is not None:
            config["rootfs"] = workstation_rootfs
        manifest["config"] = blob(child, encoded(config), CONFIG)
        child_digest = store_manifest(child, manifest)
        index = json.loads((child / "index.json").read_bytes())
        index["manifests"][0]["annotations"][REF] = "workstation"
        (child / "index.json").write_bytes(encoded(index))
        return child, core_digest, child_digest

    def test_ancestry_cli_accepts_declared_core_prefix(self):
        child, core_digest, child_digest = self.ancestry_fixture()
        result, stdout, stderr, output = self.run_cli(
            "ancestry",
            "--core-layout",
            self.root,
            "--layout",
            child,
            "--core-digest",
            core_digest,
            "--expected-digest",
            child_digest,
        )
        self.assertEqual(result, 0, stderr)
        self.assertEqual(json.loads(stdout), {"declared_diff_ids_prefix": "true"})
        self.assertEqual(output, "unchanged=true\ndeclared_diff_ids_prefix=true\n")

    def test_workflow_ancestry_command_runs_real_cli_before_success_output(self):
        child, core_digest, child_digest = self.ancestry_fixture()
        workspace = self.root.parent / "workspace"
        workspace.mkdir()
        shutil.copytree(child, workspace / "workstation-oci")
        runner_temp = self.root.parent / "runner-temp"
        runner_temp.mkdir()
        shutil.copytree(self.root, runner_temp / "core-oci")
        data = yaml.safe_load(
            (
                Path(oci.__file__).parents[3] / ".github/workflows/containers.yml"
            ).read_text()
        )
        step = next(
            step
            for step in data["jobs"]["workstation"]["steps"]
            if step.get("id") == "check-core-ancestry"
        )
        command = step["run"].replace(
            ".github/scripts/workflow/oci_layout.py", str(Path(oci.__file__).absolute())
        )
        output = workspace / "process-output"
        for expected, status in ((core_digest, 0), ("sha256:" + "0" * 64, 1)):
            with self.subTest(expected=expected):
                output.write_text("unchanged=true\n")
                result = subprocess.run(
                    ["bash", "-e", "-o", "pipefail", "-c", command],
                    cwd=workspace,
                    env=os.environ
                    | {
                        "GITHUB_WORKSPACE": str(workspace),
                        "RUNNER_TEMP": str(runner_temp),
                        "CORE_DIGEST": expected,
                        "WORKSTATION_DIGEST": child_digest,
                        "GITHUB_OUTPUT": str(output),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                if status:
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(output.read_text(), "unchanged=true\n")
                else:
                    self.assertEqual(
                        json.loads(result.stdout), {"declared_diff_ids_prefix": "true"}
                    )

    def test_ancestry_cli_rejects_malformed_short_and_different_prefix(self):
        invalid = (
            {},
            {"type": "other", "diff_ids": ["sha256:" + "0" * 64]},
            {"type": "layers", "diff_ids": "not-an-array"},
            {"type": "layers", "diff_ids": []},
            {"type": "layers", "diff_ids": [True]},
            {"type": "layers", "diff_ids": ["sha256:" + "A" * 64]},
            {"type": "layers", "diff_ids": ["sha256:" + "0" * 64] * 3},
            {
                "type": "layers",
                "diff_ids": ["sha256:" + "0" * 64] * (oci.MAX_LAYERS + 1),
            },
        )
        for side in ("core", "workstation"):
            for rootfs in invalid:
                with self.subTest(side=side, rootfs=rootfs):
                    child, core_digest, child_digest = self.ancestry_fixture(
                        **{side + "_rootfs": rootfs}
                    )
                    result, stdout, _, output = self.run_cli(
                        "ancestry",
                        "--core-layout",
                        self.root,
                        "--layout",
                        child,
                        "--core-digest",
                        core_digest,
                        "--expected-digest",
                        child_digest,
                    )
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(output, "unchanged=true\n")
                    self.manifest, self.expected = sample(self.root)
        for shorter in (False, True):
            with self.subTest(shorter=shorter):
                child, core_digest, child_digest = self.ancestry_fixture(
                    shorter=shorter,
                    workstation_rootfs=None
                    if shorter
                    else {
                        "type": "layers",
                        "diff_ids": ["sha256:" + "0" * 64] * 2,
                    },
                )
                result, stdout, stderr, output = self.run_cli(
                    "ancestry",
                    "--core-layout",
                    self.root,
                    "--layout",
                    child,
                    "--core-digest",
                    core_digest,
                    "--expected-digest",
                    child_digest,
                )
                self.assertEqual(result, 1)
                self.assertIn("OCI declared core diff_ids prefix mismatch", stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")

    def test_ancestry_cli_rechecks_expected_manifests_and_nofollow(self):
        child, core_digest, child_digest = self.ancestry_fixture()
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for core, expected_core, expected_child in (
            (self.root, "sha256:" + "0" * 64, child_digest),
            (self.root, core_digest, "sha256:" + "0" * 64),
            (alias, core_digest, child_digest),
        ):
            with self.subTest(core=core, expected_core=expected_core):
                result, stdout, _, output = self.run_cli(
                    "ancestry",
                    "--core-layout",
                    core,
                    "--layout",
                    child,
                    "--core-digest",
                    expected_core,
                    "--expected-digest",
                    expected_child,
                )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(output, "unchanged=true\n")

    def test_workflow_export_command_uses_real_helper_and_fails_closed(self):
        workflow = yaml.safe_load(
            (
                Path(__file__).resolve().parents[1] / ".github/workflows/containers.yml"
            ).read_text()
        )
        step = next(
            step
            for step in workflow["jobs"]["core"]["steps"]
            if step.get("id") == "export-core-oci"
        )
        script = str(Path(oci.__file__).absolute())
        command = step["run"].replace(".github/scripts/workflow/oci_layout.py", script)
        binary = self.root.parent / "bin"
        binary.mkdir()
        executable = binary / "skopeo"
        executable.write_text(
            f"#!{oci.sys.executable}\n"
            "import json, os, shutil, sys\n"
            "from pathlib import Path\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('skopeo version fixture')\n"
            "    sys.exit(0)\n"
            "Path(os.environ['CALL_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "target = sys.argv[-1].removeprefix('oci:').rsplit(':', 1)[0]\n"
            "if os.environ['FAIL_COPY'] == '1':\n"
            "    Path(target, 'partial').write_text('incomplete')\n"
            "    sys.exit(1)\n"
            "shutil.copytree(os.environ['SOURCE_LAYOUT'], target, dirs_exist_ok=True)\n"
        )
        executable.chmod(0o700)
        for fail in (False, True):
            with self.subTest(fail=fail):
                work = self.root.parent / f"work-{fail}"
                work.mkdir()
                output = work / "outputs"
                call_log = work / "calls.json"
                env = os.environ | {
                    "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                    "IMAGE": "local/core:built",
                    "DOCKER_HOST": "unix:///tmp/opencode/core-build.sock",
                    "GITHUB_OUTPUT": str(output),
                    "SOURCE_LAYOUT": str(self.root),
                    "CALL_LOG": str(call_log),
                    "FAIL_COPY": str(int(fail)),
                }
                result = subprocess.run(
                    ["bash", "-e", "-o", "pipefail", "-c", command],
                    cwd=work,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, int(fail), result.stderr)
                argv = json.loads(call_log.read_text())
                self.assertEqual(
                    argv[argv.index("--src-daemon-host") + 1], env["DOCKER_HOST"]
                )
                self.assertEqual(argv[-2], "docker-daemon:" + env["IMAGE"])
                self.assertRegex(argv[-1], r"\Aoci:/proc/self/fd/[0-9]+:core\Z")
                if fail:
                    self.assertFalse(output.exists())
                    self.assertEqual(result.stdout, "")
                else:
                    self.assertEqual(
                        oci.manifest_digest(work / "core-oci", "core"), self.expected
                    )
                    self.assertIn(
                        f"manifest_digest={self.expected}\n", output.read_text()
                    )
                    self.assertIn(
                        "skopeo_version=skopeo version fixture\n", output.read_text()
                    )
        missing_host = self.root.parent / "missing-host"
        missing_host.mkdir()
        env["DOCKER_HOST"] = ""
        env["GITHUB_OUTPUT"] = str(missing_host / "outputs")
        env["CALL_LOG"] = str(missing_host / "calls.json")
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", command],
            cwd=missing_host,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((missing_host / "outputs").exists())
        self.assertFalse((missing_host / "calls.json").exists())

    def test_export_rejects_nonlocal_explicit_daemon_hosts(self):
        with mock.patch.object(oci.subprocess, "run") as command:
            for host in (
                "tcp://remote:2375",
                "ssh://remote",
                "unix:///tmp/x\ninjected",
                "unix:///tmp/../socket",
            ):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    oci.export_layout(
                        "local/core:built",
                        self.root.parent / "export",
                        "core",
                        docker_host=host,
                    )
            command.assert_not_called()

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
