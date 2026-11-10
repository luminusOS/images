import copy
import hashlib
import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "release_pipeline",
    Path(__file__).resolve().parents[1]
    / ".github/scripts/workflow/release_pipeline.py",
)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


def sample(tmp_path):
    artifact = tmp_path / "disk.qcow2"
    artifact.write_bytes(b"disk")
    key = tmp_path / "key.pub"
    key.write_text("key")
    path = tmp_path / "candidate.json"
    document = {
        "version": 1,
        "repository": "owner/repo",
        "source_sha": "a" * 40,
        "run_id": 123,
        "channel": "testing",
        "version_tag": "testing-42",
        "build_version": "42",
        "fedora_version": "42",
        "fedora_bootc_digest": "sha256:" + "1" * 64,
        "images": {
            name: f"ghcr.io/owner/{image}@sha256:" + str(index) * 64
            for index, (name, image) in enumerate(
                (
                    ("core", "luminusos"),
                    ("workstation", "luminusos-workstation"),
                    ("installer", "luminusos-workstation"),
                ),
                1,
            )
        },
        "artifacts": {"disk.qcow2": pipeline.digest(artifact)},
    }
    path.write_text(json.dumps(document))
    (tmp_path / "candidate.json.sig").write_text("signature")
    return path, key, document


def artifact_sample():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("candidate.json", "data")
    data = buffer.getvalue()
    return data, {
        "name": "release-candidate",
        "id": 10,
        "expired": False,
        "size_in_bytes": len(data),
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "workflow_run": {
            "id": 123,
            "repository_id": 456,
            "head_repository_id": 456,
            "head_sha": "a" * 40,
        },
    }


def run_document():
    return {
        "id": 123,
        "repository": {"full_name": "owner/repo"},
        "head_repository": {"full_name": "owner/repo"},
        "path": ".github/workflows/publish.yml",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
    }


def core_reader_sample(directory):
    evidence = directory / "fixture-B.json"
    evidence.write_text('{"notice":"synthetic unit-test bytes, not provenance"}\n')
    descriptor = {
        "path": evidence.name,
        "sha256": pipeline.digest(evidence),
        "size_bytes": evidence.stat().st_size,
    }
    image = "ghcr.io/owner/luminusos"
    identity = {
        "repository": "owner/repo",
        "source_sha": "a" * 40,
        "source_ref": "refs/heads/main",
        "run_id": 123,
        "run_attempt": 1,
        "fedora": "45",
        "architecture": "x86_64",
        "selection": "core",
        "channel": "testing",
        "build_version": "45.20261109.1",
        "base_digest": "sha256:" + "1" * 64,
        "core_digest": "sha256:" + "2" * 64,
        "policy_sha256": "3" * 64,
    }
    inputs = {}
    official_key_fingerprint = pipeline.digest(directory / "key.pub")
    for role, number, signer in (
        ("update", "4", official_key_fingerprint),
        ("signed", "4", official_key_fingerprint),
        ("unsigned", "5", None),
        ("foreign", "6", "8" * 64),
    ):
        image_digest = "sha256:" + number * 64
        inputs[role] = {
            "digest": image_digest,
            "derived_from": identity["core_digest"]
            if role == "update"
            else "sha256:" + "4" * 64,
            "logical_reference": f"{image}@{image_digest}",
            "signing_key_fingerprint": signer,
            "producer": {
                "repository": "owner/repo",
                "source_sha": identity["source_sha"],
                "source_ref": "refs/heads/main",
                "workflow": ".github/workflows/publish.yml",
                "run_id": identity["run_id"],
                "run_attempt": 1,
            },
            "producer_evidence": [copy.deepcopy(descriptor)],
        }
    source = directory / "source"
    for name in (
        "editions/core/Containerfile",
        "shared/trust/key.pub",
        "shared/scripts/dnf-releasever.py",
        "shared/scripts/os-release-set.py",
        "shared/scripts/rpmdb-repair.py",
    ):
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("unit test core input\n")
    proof = {
        "kind": "core-build",
        "schema_version": 2,
        "digest": identity["core_digest"],
        **{
            field: identity[field]
            for field in (
                "source_sha",
                "source_ref",
                "fedora",
                "channel",
                "architecture",
                "base_digest",
                "policy_sha256",
                "run_id",
                "run_attempt",
            )
        },
        "inputs_sha256": pipeline.core_inputs_hash(
            source, "45", identity["base_digest"]
        ),
        "workflow": ".github/workflows/publish.yml",
    }
    proof_path = directory / "core/core-build.json"
    proof_path.parent.mkdir(exist_ok=True)
    proof_path.write_text(json.dumps(proof))
    return {
        "kind": "candidate",
        "schema_version": 2,
        "evidence_class": "runtime",
        "identity": identity,
        "components": {
            "core": {"repository": image, "digest": identity["core_digest"]}
        },
        "artifacts": {},
        "installed": {
            "core": {
                "edition": "core",
                "channel": "testing",
                "fedora": "45",
                "reference": f"{image}:testing-45",
                "digest": identity["core_digest"],
            }
        },
        "core_dependency": {
            "mode": "built",
            "digest": identity["core_digest"],
            "evidence_sha256": pipeline.digest(proof_path),
            **{
                field: identity[field]
                for field in (
                    "source_sha",
                    "source_ref",
                    "fedora",
                    "channel",
                    "architecture",
                    "base_digest",
                    "policy_sha256",
                )
            },
        },
        "validation_images": {"core": inputs},
    }


class ReleasePipelineTests(unittest.TestCase):
    def validate_core(self, document, directory, *, context=None):
        pipeline.validate_candidate(
            document,
            directory,
            context=context,
            official_key_fingerprint=pipeline.digest(self.sample[1]),
        )

    def core_context(self, document):
        run = run_document() | {"run_attempt": 1}
        expected = {
            field: document["identity"][field]
            for field in (
                "fedora",
                "channel",
                "architecture",
                "base_digest",
                "policy_sha256",
            )
        }
        with mock.patch.object(
            pipeline.subprocess,
            "run",
            side_effect=[
                mock.Mock(stdout="a" * 40 + "\n"),
                mock.Mock(stdout=""),
            ],
        ):
            return pipeline.core_context(run, self.tmp_path / "source", expected)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp_path = Path(self.directory.name)
        self.sample = sample(self.tmp_path)

    def test_core_v2_reader_without_workstation_artifacts(self):
        path, key, _ = self.sample
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        path.write_text(json.dumps(document))
        with mock.patch.object(pipeline, "verify") as verify:
            self.assertEqual(pipeline.candidate(path, key, context=context), document)
            verify.assert_called_once_with(path, key)
        with (
            mock.patch.object(
                pipeline, "verify", side_effect=ValueError("bad signature")
            ),
            self.assertRaisesRegex(ValueError, "signature"),
        ):
            pipeline.candidate(path, key)

    def test_core_v2_rebound_validation_keys_match_exact_public_key_bytes(self):
        path, key, _ = self.sample
        key.write_bytes(b"unit-test public key bytes\r\n")
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        path.write_text(json.dumps(document))
        with mock.patch.object(pipeline, "verify"):
            self.assertEqual(pipeline.candidate(path, key, context=context), document)
            for role, fingerprint in (
                ("update", "f" * 64),
                ("signed", "f" * 64),
                ("both", "f" * 64),
                ("foreign", pipeline.digest(key)),
                ("foreign", None),
            ):
                with self.subTest(role=role, fingerprint=fingerprint):
                    changed = copy.deepcopy(document)
                    for selected in ("update", "signed") if role == "both" else (role,):
                        changed["validation_images"]["core"][selected][
                            "signing_key_fingerprint"
                        ] = fingerprint
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        pipeline.candidate(path, key, context=context)
            path.write_text(json.dumps(document))
            key.write_bytes(b"unit-test public key bytes\n")
            with self.assertRaisesRegex(ValueError, "signing identity"):
                pipeline.candidate(path, key, context=context)

    def test_core_v2_rebound_validation_producers_require_trusted_context(self):
        path, key, _ = self.sample
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        for role in ("update", "signed", "unsigned", "foreign"):
            for field, value in (
                ("repository", "other/repo"),
                ("source_sha", "f" * 40),
                ("source_ref", "refs/heads/release/45"),
                ("run_id", 124),
                ("run_attempt", 2),
                ("run_attempt", True),
                ("workflow", ".github/workflows/untrusted.yml"),
                ("workflow", ".github/workflows/auto-testing.yml"),
            ):
                with self.subTest(role=role, field=field, value=value):
                    changed = copy.deepcopy(document)
                    changed["validation_images"]["core"][role]["producer"][field] = (
                        value
                    )
                    path.write_text(json.dumps(changed))
                    with (
                        mock.patch.object(pipeline, "verify"),
                        self.assertRaisesRegex(
                            ValueError, "validation image producer requires T5"
                        ),
                    ):
                        pipeline.candidate(path, key, context=context)

    def test_core_v2_validators_require_explicit_official_fingerprint(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        for validator in (
            pipeline.validate_candidate,
            pipeline.validate_core_candidate,
        ):
            for fingerprint in (None, "invalid", "f" * 64):
                with (
                    self.subTest(validator=validator.__name__, fingerprint=fingerprint),
                    self.assertRaises(ValueError),
                ):
                    validator(
                        document,
                        self.tmp_path,
                        context=context,
                        official_key_fingerprint=fingerprint,
                    )

    def test_core_v2_rejects_inconsistent_candidate_and_evidence(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        cases = [
            (("schema_version",), 3),
            (("version",), 1),
            (("identity", "selection"), "unknown"),
            (("identity", "selection"), "workstation"),
            (("identity", "selection"), "all"),
            (("identity", "architecture"), "aarch64"),
            (("identity", "source_ref"), "refs/heads/release/45"),
            (("identity", "source_sha"), "a" * 40 + "\n"),
            (("identity", "run_id"), True),
            (("identity", "base_digest"), "sha256:" + "F" * 64),
            (("identity", "build_version"), "44.20261109.1"),
            (("identity", "build_version"), "45.20260230.1"),
            (("core_dependency", "base_digest"), "sha256:" + "f" * 64),
            (("core_dependency", "policy_sha256"), "f" * 64),
            (("core_dependency", "source_sha"), "f" * 40),
            (("core_dependency", "evidence_sha256"), "f" * 64),
            (("components", "installer"), document["components"]["core"]),
            (("installed", "core", "reference"), "ghcr.io/owner/luminusos:45"),
            (("validation_images", "core", "update", "digest"), "sha256:" + "f" * 64),
            (
                ("validation_images", "core", "foreign", "signing_key_fingerprint"),
                pipeline.digest(self.sample[1]),
            ),
            (
                (
                    "validation_images",
                    "core",
                    "signed",
                    "producer_evidence",
                    0,
                    "size_bytes",
                ),
                1,
            ),
            (
                ("validation_images", "core", "signed", "producer_evidence", 0, "path"),
                "../core-build.json",
            ),
        ]
        for path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(document)
                target = changed
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    self.validate_core(changed, self.tmp_path, context=context)
        evidence = self.tmp_path / "fixture-B.json"
        evidence.write_text("tampered")
        with self.assertRaises(ValueError):
            self.validate_core(document, self.tmp_path, context=context)

    def test_core_v2_not_adapted_into_legacy_authorization(self):
        path, _, _ = self.sample
        document = core_reader_sample(self.tmp_path)
        with self.assertRaisesRegex(ValueError, "v2.*T5"):
            pipeline.binding(document)
        output = self.tmp_path / "outputs"
        output.write_text("existing=unchanged\n")
        with (
            mock.patch.dict(pipeline.os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            self.assertRaisesRegex(ValueError, "v2.*T5"),
        ):
            pipeline.candidate_outputs(document, path)
        self.assertEqual(output.read_text(), "existing=unchanged\n")

    def test_core_v2_proof_mutations_rejected_after_hash_rebinding(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        proof_path = self.tmp_path / "core/core-build.json"
        proof = pipeline.load(proof_path)
        for field, value in (
            ("kind", "fixture-B"),
            ("schema_version", True),
            ("unknown", "extra"),
            ("digest", "sha256:" + "f" * 64),
            ("source_sha", "f" * 40),
            ("source_ref", "refs/heads/release/45"),
            ("fedora", "46"),
            ("channel", "stable"),
            ("architecture", "aarch64"),
            ("base_digest", "sha256:" + "f" * 64),
            ("policy_sha256", "f" * 64),
            ("inputs_sha256", "f" * 64),
            ("run_id", 124),
            ("run_attempt", 2),
            ("run_id", True),
            ("workflow", ".github/workflows/other.yml"),
        ):
            with self.subTest(field=field, value=value):
                proof_path.write_text(json.dumps(proof | {field: value}))
                changed = copy.deepcopy(document)
                changed["core_dependency"]["evidence_sha256"] = pipeline.digest(
                    proof_path
                )
                with self.assertRaises(ValueError):
                    self.validate_core(changed, self.tmp_path, context=context)

    def test_core_v2_proof_safe_reads_and_exact_bytes(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        proof_path = self.tmp_path / "core/core-build.json"
        original = proof_path.read_bytes()
        for raw in (b"", original + b" ", b'{"kind":"core-build","kind":"core-build"}'):
            with self.subTest(raw=raw[:30]):
                proof_path.write_bytes(raw)
                changed = copy.deepcopy(document)
                if b'"kind":"core-build"' in raw:
                    changed["core_dependency"]["evidence_sha256"] = pipeline.digest(
                        proof_path
                    )
                with self.assertRaises(ValueError):
                    self.validate_core(changed, self.tmp_path, context=context)
        proof_path.write_bytes(original)
        with (
            mock.patch.object(pipeline, "MAX_CORE_BUILD_BYTES", len(original) - 1),
            self.assertRaisesRegex(ValueError, "core build.*size"),
        ):
            self.validate_core(document, self.tmp_path, context=context)
        proof_path.unlink()
        with self.assertRaisesRegex(ValueError, "missing file"):
            self.validate_core(document, self.tmp_path, context=context)
        target = self.tmp_path / "elsewhere.json"
        target.write_bytes(original)
        proof_path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.validate_core(document, self.tmp_path, context=context)

    def test_core_v2_requires_trusted_context_and_core_A_proof(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        with self.assertRaisesRegex(ValueError, "trusted core context"):
            pipeline.validate_candidate(document, self.tmp_path)
        with self.assertRaisesRegex(ValueError, "candidate v2"):
            pipeline.validate_core_candidate(
                self.sample[2], self.tmp_path, context=context
            )
        for field in context:
            changed = dict(context)
            changed.pop(field)
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.validate_core(document, self.tmp_path, context=changed)
        document["core_dependency"]["evidence_sha256"] = document["validation_images"][
            "core"
        ]["update"]["producer_evidence"][0]["sha256"]
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.validate_core(document, self.tmp_path, context=context)
        (self.tmp_path / "core/core-build.json").write_bytes(
            (self.tmp_path / "fixture-B.json").read_bytes()
        )
        with self.assertRaisesRegex(ValueError, "core build proof"):
            self.validate_core(document, self.tmp_path, context=context)

    def test_core_v2_reused_and_synthetic_are_not_accepted(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        for field, value in (("evidence_class", "synthetic"), ("schema_version", True)):
            changed = copy.deepcopy(document)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate_core(changed, self.tmp_path, context=context)
        document["core_dependency"]["mode"] = "reused"
        with self.assertRaisesRegex(ValueError, "T5"):
            self.validate_core(document, self.tmp_path, context=context)

    def test_core_v2_rebound_identity_cannot_replace_trusted_context(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        proof_path = self.tmp_path / "core/core-build.json"
        proof = pipeline.load(proof_path)
        for field, value in (
            ("source_sha", "f" * 40),
            ("source_ref", "refs/heads/release/45"),
            ("run_id", 124),
            ("run_attempt", 2),
            ("base_digest", "sha256:" + "f" * 64),
            ("policy_sha256", "f" * 64),
            ("fedora", "46"),
            ("architecture", "aarch64"),
            ("channel", "stable"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(document)
                changed["identity"][field] = value
                if field in changed["core_dependency"]:
                    changed["core_dependency"][field] = value
                proof_path.write_text(json.dumps(proof | {field: value}))
                changed["core_dependency"]["evidence_sha256"] = pipeline.digest(
                    proof_path
                )
                with self.assertRaises(ValueError):
                    self.validate_core(changed, self.tmp_path, context=context)

    def test_core_context_uses_real_input_hash_and_rejects_wrong_source(self):
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        source = self.tmp_path / "source"
        (source / "editions/core/Containerfile").write_text("changed trusted input")
        changed_context = self.core_context(document)
        self.assertNotEqual(context["inputs_sha256"], changed_context["inputs_sha256"])
        with self.assertRaisesRegex(ValueError, "inputs_sha256"):
            self.validate_core(document, self.tmp_path, context=changed_context)
        run = run_document() | {"run_attempt": 1}
        expected = {
            field: context[field]
            for field in (
                "fedora",
                "channel",
                "architecture",
                "base_digest",
                "policy_sha256",
            )
        }
        for outputs, error in (
            ([mock.Mock(stdout="f" * 40)], "revision"),
            (
                [
                    mock.Mock(stdout="a" * 40),
                    mock.Mock(stdout=" M editions/core/Containerfile"),
                ],
                "dirty",
            ),
        ):
            with (
                self.subTest(error=error),
                mock.patch.object(pipeline.subprocess, "run", side_effect=outputs),
                self.assertRaisesRegex(ValueError, error),
            ):
                pipeline.core_context(run, source, expected)
        for field, value in (
            ("path", ".github/workflows/untrusted.yml"),
            ("run_attempt", True),
            ("head_repository", {"full_name": "attacker/repo"}),
            ("conclusion", "failure"),
            ("head_branch", "feature"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                pipeline.core_context(run | {field: value}, source, expected)

    def test_core_v2_legacy_commands_stop_before_side_effects(self):
        path, key, _ = self.sample
        document = core_reader_sample(self.tmp_path)
        path.write_text(json.dumps(document))
        output = self.tmp_path / "must-not-exist/result.json"
        for action, flags in (
            ("record-validation", ["--receipts", str(self.tmp_path)]),
            ("fetch-validation", ["--repository", "owner/repo", "--run-id", "123"]),
            (
                "assemble-evidence",
                ["--validation", "absent.json", "--results", "absent.json"],
            ),
        ):
            args = [
                "release_pipeline",
                action,
                "--candidate",
                str(path),
                "--output",
                str(output),
                "--public-key",
                str(key),
                *flags,
            ]
            with (
                self.subTest(action=action),
                mock.patch.object(pipeline.sys, "argv", args),
                mock.patch.object(pipeline, "verify"),
                mock.patch.object(pipeline, "download") as download,
                mock.patch.object(pipeline, "sign") as sign,
                mock.patch.object(
                    pipeline.sys, "stderr", new_callable=io.StringIO
                ) as stderr,
            ):
                self.assertEqual(pipeline.main(), 1)
                self.assertIn("v2 legacy consumers require T5", stderr.getvalue())
                download.assert_not_called()
                sign.assert_not_called()
                self.assertFalse(output.parent.exists())
        with self.assertRaisesRegex(ValueError, "T5"):
            pipeline.validate_receipts([], self.tmp_path, document)
        with mock.patch.object(pipeline, "verify") as verify:
            with self.assertRaisesRegex(ValueError, "T5"):
                pipeline.validate_validation(Path("absent.json"), key, document)
            verify.assert_not_called()

    def test_core_v2_fetch_is_read_only_and_requires_source_context(self):
        path, key, _ = self.sample
        document = core_reader_sample(self.tmp_path)
        context = self.core_context(document)
        path.write_text(json.dumps(document))
        args = [
            "release_pipeline",
            "fetch-candidate",
            "--repository",
            "owner/repo",
            "--run-id",
            "123",
            "--output",
            str(self.tmp_path),
            "--public-key",
            str(key),
        ]
        outputs = self.tmp_path / "outputs"
        outputs.write_text("unchanged=true\n")
        with (
            mock.patch.object(pipeline.sys, "argv", args),
            mock.patch.object(pipeline, "run_info", return_value=run_document()),
            mock.patch.object(pipeline, "download"),
            mock.patch.object(pipeline, "verify"),
            mock.patch.dict(pipeline.os.environ, {"GITHUB_OUTPUT": str(outputs)}),
            mock.patch.object(
                pipeline.sys, "stderr", new_callable=io.StringIO
            ) as stderr,
        ):
            self.assertEqual(pipeline.main(), 1)
            self.assertIn("trusted core context", stderr.getvalue())
            args.extend(
                [
                    "--source-root",
                    str(self.tmp_path / "source"),
                    "--fedora",
                    "45",
                    "--base-digest",
                    context["base_digest"],
                    "--policy-sha256",
                    context["policy_sha256"],
                    "--channel",
                    "testing",
                ]
            )
            with (
                mock.patch.object(
                    pipeline, "core_context", return_value=context
                ) as factory,
                mock.patch.object(
                    pipeline.sys, "stdout", new_callable=io.StringIO
                ) as stdout,
            ):
                self.assertEqual(pipeline.main(), 0)
                self.assertEqual(
                    json.loads(stdout.getvalue()),
                    {
                        "schema_version": 2,
                        "selection": "core",
                        "read_only": True,
                    },
                )
                factory.assert_called_once()
        self.assertEqual(outputs.read_text(), "unchanged=true\n")

    def test_load_rejects_duplicate_keys(self):
        path = self.tmp_path / "duplicate.json"
        path.write_text('{"version": 1, "version": 2}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pipeline.load(path)

    def test_fetch_candidate_cli_workflow_authorization(self):
        path, key, _ = self.sample
        run = run_document()
        run["path"] = ".github/workflows/auto-testing.yml"
        output = self.tmp_path / "download"
        args = [
            "release_pipeline",
            "fetch-candidate",
            "--repository",
            "owner/repo",
            "--run-id",
            "123",
            "--output",
            str(output),
            "--public-key",
            str(key),
        ]

        def download(repository, run_id, name, directory):
            self.assertEqual(
                (repository, run_id, name), ("owner/repo", 123, "release-candidate")
            )
            directory.mkdir(exist_ok=True)
            for filename in ("candidate.json", "candidate.json.sig", "disk.qcow2"):
                (directory / filename).write_bytes(
                    (path.parent / filename).read_bytes()
                )

        def command(argv, **kwargs):
            return mock.Mock(stdout=json.dumps(run) if argv[0] == "gh" else "")

        with (
            mock.patch.object(pipeline.sys, "argv", args),
            mock.patch.object(pipeline.subprocess, "run", side_effect=command),
            mock.patch.object(pipeline, "download", side_effect=download),
            mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            mock.patch.dict(pipeline.os.environ, {"GITHUB_OUTPUT": ""}),
        ):
            self.assertEqual(pipeline.main(), 0)
        for field, value, extra in (
            ("path", ".github/workflows/unknown.yml", []),
            ("head_repository", {"full_name": "fork/repo"}, []),
            (
                "path",
                ".github/workflows/auto-testing.yml",
                ["--workflow", ".github/workflows/publish.yml"],
            ),
        ):
            with self.subTest(field=field, extra=extra):
                changed = run_document()
                changed[field] = value
                run = changed
                with (
                    mock.patch.object(pipeline.sys, "argv", args + extra),
                    mock.patch.object(pipeline.subprocess, "run", side_effect=command),
                    mock.patch.object(pipeline, "download") as fetch,
                    mock.patch.object(pipeline.sys, "stderr", new_callable=io.StringIO),
                ):
                    self.assertEqual(pipeline.main(), 1)
                    fetch.assert_not_called()

    def test_record_and_assemble_cli_success_and_missing_gate(self):
        path, key, candidate = self.sample
        receipts = self.tmp_path / "receipts"
        receipts.mkdir()
        log = receipts / "install.log"
        log.write_text("trusted executor observation")
        for name in pipeline.CHECKS:
            receipt = {
                "name": name,
                "command": ["checked"],
                "exit_code": 0,
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:01:00Z",
                "log": "install.log",
                "sha256": pipeline.digest(log),
                "binding": pipeline.binding(candidate),
            }
            (receipts / f"{name}.json").write_text(json.dumps(receipt))
        validation = receipts / "validation.json"
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "b" * 40,
            "GITHUB_RUN_ID": "456",
        }

        def command(argv, **kwargs):
            if argv[:2] == ["cosign", "sign-blob"]:
                Path(argv[argv.index("--output-signature") + 1]).write_text("signature")
            return mock.Mock(stdout="")

        record = [
            "release_pipeline",
            "record-validation",
            "--candidate",
            str(path),
            "--receipts",
            str(receipts),
            "--output",
            str(validation),
            "--public-key",
            str(key),
        ]
        results = self.tmp_path / "results.json"
        evidence_log = self.tmp_path / "quality.log"
        evidence_log.write_text("trusted job result")
        gates = {
            gate: {
                "conclusion": "success",
                "binding": pipeline.binding(candidate),
                "artifact": evidence_log.name,
                "sha256": pipeline.digest(evidence_log),
            }
            for gate in pipeline.GATES
        }
        results.write_text(json.dumps(gates))
        evidence = self.tmp_path / "release" / "evidence.json"
        assemble = [
            "release_pipeline",
            "assemble-evidence",
            "--candidate",
            str(path),
            "--validation",
            str(validation),
            "--results",
            str(results),
            "--output",
            str(evidence),
            "--public-key",
            str(key),
        ]
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline.subprocess, "run", side_effect=command),
            mock.patch.object(pipeline.sys, "stdout", new_callable=io.StringIO),
            mock.patch.object(pipeline.sys, "stderr", new_callable=io.StringIO),
        ):
            with mock.patch.object(pipeline.sys, "argv", record):
                self.assertEqual(pipeline.main(), 0)
            self.assertEqual(json.loads(validation.read_text())["runner_sha"], "b" * 40)
            with mock.patch.object(pipeline.sys, "argv", assemble):
                self.assertEqual(pipeline.main(), 0)
                result = json.loads(evidence.read_text())
                self.assertEqual(result["source"]["commit"], "a" * 40)
                self.assertTrue(all(result["gates"].values()))
                self.assertTrue(
                    (
                        evidence.parent / "evidence/installation/validation.json.sig"
                    ).is_file()
                )
                evidence.unlink()
                del gates["quality"]
                results.write_text(json.dumps(gates))
                self.assertEqual(pipeline.main(), 1)
                self.assertFalse(evidence.exists())

    def test_candidate_signature_and_artifact_tampering(self):
        sample = self.sample
        path, key, document = sample
        with mock.patch.object(pipeline.subprocess, "run") as run:
            assert pipeline.candidate(path, key) == document
            assert run.call_args.args[0][:2] == ["cosign", "verify-blob"]
            (path.parent / "disk.qcow2").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                pipeline.candidate(path, key)
            run.side_effect = subprocess.CalledProcessError(1, "cosign")
            with self.assertRaises(subprocess.CalledProcessError):
                pipeline.candidate(path, key)

    def test_zip_traversal(self):
        tmp_path = self.tmp_path
        for filename in ["../escape", "/absolute", "dir/../../escape", "dir\\escape"]:
            with self.subTest(filename=filename):
                archive = tmp_path / "a.zip"
                with zipfile.ZipFile(archive, "w") as z:
                    z.writestr(filename, "data")
                with self.assertRaises(ValueError):
                    pipeline.extract_archive(archive, tmp_path / "out")

    def test_zip_symlink_and_duplicate(self):
        tmp_path = self.tmp_path
        archive = tmp_path / "a.zip"
        entry = zipfile.ZipInfo("link")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(entry, "target")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            pipeline.extract_archive(archive, tmp_path / "out")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("x", "1")
            with self.assertWarns(UserWarning):
                z.writestr("x", "2")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pipeline.extract_archive(archive, tmp_path / "out2")

    def test_zip_limits_and_disk_space(self):
        tmp_path = self.tmp_path
        archive = tmp_path / "a.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("large.qcow2", b"0" * 128)
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_FILE_BYTES": "127"}),
            self.assertRaisesRegex(ValueError, "too large"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_TOTAL_BYTES": "127"}),
            self.assertRaisesRegex(ValueError, "too large"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.object(
                pipeline.shutil, "disk_usage", return_value=mock.Mock(free=127)
            ),
            self.assertRaisesRegex(ValueError, "disk"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")
        with (
            mock.patch.dict(
                pipeline.os.environ,
                {"RELEASE_MAX_FILE_BYTES": str(pipeline.MAX_FILE + 1)},
            ),
            self.assertRaisesRegex(ValueError, "invalid"),
        ):
            pipeline.extract_archive(archive, tmp_path / "out")

    def test_download_streams_authenticated_gh_artifact(self):
        tmp_path = self.tmp_path
        data, artifact = artifact_sample()
        result = mock.Mock(stdout=json.dumps([{"artifacts": [artifact]}]))
        process = mock.MagicMock()
        process.stdout = io.BytesIO(data)
        process.wait.return_value = 0
        process.__enter__.return_value = process
        with (
            mock.patch.object(pipeline, "CHUNK_SIZE", 7),
            mock.patch.object(
                pipeline.hashlib,
                "file_digest",
                side_effect=AssertionError("ZIP reread"),
            ),
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            mock.patch.object(
                pipeline.subprocess, "Popen", return_value=process
            ) as popen,
        ):
            pipeline.download("owner/repo", 123, "release-candidate", tmp_path / "out")
        assert (tmp_path / "out/candidate.json").read_text() == "data"
        assert popen.call_args.args[0] == [
            "gh",
            "api",
            "repos/owner/repo/actions/artifacts/10/zip",
        ]
        assert popen.call_args.kwargs["stdout"] == subprocess.PIPE

    def test_download_rejects_digest_or_size_mismatch_before_extraction(self):
        data, artifact = artifact_sample()
        existing_names = {path.name for path in self.tmp_path.iterdir()}
        for changes, payload in (
            ({"digest": "sha256:" + "0" * 64}, data),
            ({"size_in_bytes": len(data) + 1}, data),
            ({"size_in_bytes": len(data) - 1}, data),
            ({}, data[:-1]),
            ({}, data + b"extra"),
            ({}, b""),
        ):
            with self.subTest(changes=changes, actual_size=len(payload)):
                process = mock.MagicMock()
                process.stdout = io.BytesIO(payload)
                process.wait.return_value = 0
                process.__enter__.return_value = process
                result = mock.Mock(
                    stdout=json.dumps([{"artifacts": [artifact | changes]}])
                )
                with (
                    mock.patch.object(pipeline.subprocess, "run", return_value=result),
                    mock.patch.object(
                        pipeline.subprocess, "Popen", return_value=process
                    ),
                    mock.patch.object(pipeline, "extract_archive") as extract,
                    self.assertRaises(ValueError),
                ):
                    pipeline.download(
                        "owner/repo", 123, "release-candidate", self.tmp_path / "out"
                    )
                extract.assert_not_called()
                process.kill.assert_called_once()
                process.wait.assert_called()
                self.assertFalse(any((self.tmp_path / "out").iterdir()))
                self.assertEqual(
                    {path.name for path in self.tmp_path.iterdir()},
                    existing_names | {"out"},
                )

    def test_download_rejects_invalid_artifact_metadata_before_streaming(self):
        _, artifact = artifact_sample()
        cases = []
        for field, values in (
            (
                "digest",
                [
                    None,
                    True,
                    1,
                    "",
                    "sha512:" + "a" * 64,
                    "sha256:" + "A" * 64,
                    "sha256:" + "a" * 63,
                    "sha256:" + "a" * 65,
                    "sha256:" + "a" * 64 + "\n",
                ],
            ),
            ("id", [None, True, 0, -1, "10"]),
            ("size_in_bytes", [None, True, 0, -1, "1"]),
            ("expired", [None, 0, "false", True]),
            ("workflow_run", [None, [], {}, {"id": True}, {"id": "123"}, {"id": 124}]),
        ):
            for value in values:
                cases.append(artifact | {field: value})
            changed = dict(artifact)
            changed.pop(field)
            cases.append(changed)
        for index, changed in enumerate(cases):
            output = self.tmp_path / f"out-{index}"
            with self.subTest(artifact=changed):
                result = mock.Mock(stdout=json.dumps([{"artifacts": [changed]}]))
                with (
                    mock.patch.object(pipeline.subprocess, "run", return_value=result),
                    mock.patch.object(pipeline.subprocess, "Popen") as popen,
                    mock.patch.object(pipeline, "extract_archive") as extract,
                    self.assertRaises(ValueError),
                ):
                    pipeline.download("owner/repo", 123, "release-candidate", output)
                popen.assert_not_called()
                extract.assert_not_called()
                self.assertFalse(output.exists())

    def test_download_rejects_invalid_paginated_metadata(self):
        _, artifact = artifact_sample()
        for pages in (
            None,
            {},
            [],
            [None],
            [{"artifacts": None}],
            [{"artifacts": {}}],
            [{"artifacts": [None]}],
            [{"artifacts": [artifact, artifact]}],
        ):
            with self.subTest(pages=pages):
                with (
                    mock.patch.object(
                        pipeline.subprocess,
                        "run",
                        return_value=mock.Mock(stdout=json.dumps(pages)),
                    ),
                    mock.patch.object(pipeline.subprocess, "Popen") as popen,
                    mock.patch.object(pipeline, "extract_archive") as extract,
                    self.assertRaises(ValueError),
                ):
                    pipeline.download(
                        "owner/repo", 123, "release-candidate", self.tmp_path / "out"
                    )
                popen.assert_not_called()
                extract.assert_not_called()

    def test_download_stops_at_declared_size_before_global_limit(self):
        data, artifact = artifact_sample()
        result = mock.Mock(
            stdout=json.dumps([{"artifacts": [artifact | {"size_in_bytes": 1}]}])
        )
        process = mock.MagicMock()
        process.stdout = mock.Mock(wraps=io.BytesIO(data))
        process.__enter__.return_value = process
        with (
            mock.patch.object(pipeline, "CHUNK_SIZE", 2),
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            mock.patch.object(pipeline.subprocess, "Popen", return_value=process),
            mock.patch.object(pipeline, "extract_archive") as extract,
            self.assertRaisesRegex(ValueError, "declared size"),
        ):
            pipeline.download(
                "owner/repo", 123, "release-candidate", self.tmp_path / "out"
            )
        process.stdout.read.assert_called_once_with(2)
        process.kill.assert_called_once()
        process.wait.assert_called()
        extract.assert_not_called()

    def test_download_stops_stream_exceeding_limit(self):
        tmp_path = self.tmp_path
        _, artifact = artifact_sample()
        result = mock.Mock(
            stdout=json.dumps([{"artifacts": [artifact | {"size_in_bytes": 1}]}])
        )
        process = mock.MagicMock()
        process.stdout = io.BytesIO(b"excessive")
        process.__enter__.return_value = process
        with (
            mock.patch.dict(pipeline.os.environ, {"RELEASE_MAX_TOTAL_BYTES": "4"}),
            mock.patch.object(pipeline.subprocess, "run", return_value=result),
            mock.patch.object(pipeline.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(ValueError, "archive too large"),
        ):
            pipeline.download("owner/repo", 123, "release-candidate", tmp_path / "out")
        process.kill.assert_called_once()

    def test_reject_untrusted_run(self):
        for field, value in [
            ("id", 124),
            ("repository", {"full_name": "other/repo"}),
            ("path", ".github/workflows/evil.yml"),
            ("head_branch", "feature"),
            ("conclusion", "cancelled"),
            ("event", "pull_request"),
        ]:
            with self.subTest(field=field):
                run = run_document()
                run[field] = value
                with (
                    mock.patch.object(
                        pipeline.subprocess,
                        "run",
                        return_value=mock.Mock(stdout=json.dumps(run)),
                    ),
                    self.assertRaises(ValueError),
                ):
                    pipeline.run_info(
                        "owner/repo", 123, {".github/workflows/publish.yml"}
                    )

    def test_receipts_bind_original_candidate_and_logs(self):
        sample = self.sample
        path, key, document = sample
        log = path.parent / "install.log"
        log.write_text("trusted executor observation")
        receipts = [
            {
                "name": name,
                "command": ["test-command"],
                "exit_code": 0,
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:01:00Z",
                "log": "install.log",
                "sha256": pipeline.digest(log),
                "binding": pipeline.binding(document),
            }
            for name in pipeline.CHECKS
        ]
        with mock.patch.object(pipeline.subprocess, "run"):
            assert pipeline.candidate(path, key)["source_sha"] == "a" * 40
            pipeline.validate_receipts(receipts, path.parent, document)
            receipts[0]["binding"] = dict(receipts[0]["binding"], source_run_id=124)
            with self.assertRaisesRegex(ValueError, "binding"):
                pipeline.validate_receipts(receipts, path.parent, document)
            receipts[0]["binding"] = pipeline.binding(document)
            log.write_text("tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                pipeline.validate_receipts(receipts, path.parent, document)

    def test_create_candidate_hashes_artifacts_and_signs(self):
        tmp_path = self.tmp_path
        sample = self.sample
        path, key, document = sample
        metadata = tmp_path / "metadata.input"
        metadata.write_text(
            json.dumps({k: v for k, v in document.items() if k != "artifacts"})
        )
        nested = tmp_path / "nested"
        nested.mkdir()
        (nested / "notes.txt").write_text("evidence")
        (nested / "qemu.ppm").write_bytes(b"ppm screenshot")
        (nested / "qemu.png").write_bytes(b"png screenshot")
        (nested / "ignored.bin").write_bytes(b"ignored")
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline, "sign") as sign,
        ):
            result = pipeline.create_candidate(metadata, tmp_path, path, key)
        assert result["artifacts"] == {
            "disk.qcow2": pipeline.digest(tmp_path / "disk.qcow2"),
            "nested/notes.txt": pipeline.digest(nested / "notes.txt"),
            "nested/qemu.ppm": pipeline.digest(nested / "qemu.ppm"),
            "nested/qemu.png": pipeline.digest(nested / "qemu.png"),
        }
        assert json.loads(path.read_text()) == result
        sign.assert_called_once_with(path, key)
        for filename in ("qemu.ppm", "qemu.png"):
            with self.subTest(screenshot=filename):
                screenshot = nested / filename
                original = screenshot.read_bytes()
                screenshot.write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    pipeline.validate_candidate(result, tmp_path)
                screenshot.write_bytes(original)

    def test_create_candidate_rejects_wrong_context(self):
        tmp_path = self.tmp_path
        sample = self.sample
        for field, value in [
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_REF", "refs/heads/branch"),
            ("GITHUB_SHA", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("GITHUB_RUN_ID", "124"),
        ]:
            with self.subTest(field=field):
                path, key, document = sample
                metadata = tmp_path / "metadata.input"
                metadata.write_text(
                    json.dumps({k: v for k, v in document.items() if k != "artifacts"})
                )
                env = {
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "123",
                    field: value,
                }
                with (
                    mock.patch.dict(pipeline.os.environ, env),
                    mock.patch.object(pipeline, "sign") as sign,
                    self.assertRaises(ValueError),
                ):
                    pipeline.create_candidate(metadata, tmp_path, path, key)
                sign.assert_not_called()

    def test_create_candidate_rejects_symlinks(self):
        tmp_path = self.tmp_path
        sample = self.sample
        path, key, document = sample
        metadata = tmp_path / "metadata.input"
        metadata.write_text(
            json.dumps({k: v for k, v in document.items() if k != "artifacts"})
        )
        (tmp_path / "link.txt").symlink_to(tmp_path / "disk.qcow2")
        env = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
        }
        with (
            mock.patch.dict(pipeline.os.environ, env),
            mock.patch.object(pipeline, "sign") as sign,
            self.assertRaisesRegex(ValueError, "symlink"),
        ):
            pipeline.create_candidate(metadata, tmp_path, path, key)
        sign.assert_not_called()
