import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
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


class OciLayoutTests(unittest.TestCase):
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
