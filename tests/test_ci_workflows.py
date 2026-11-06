import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_policy", ROOT / ".github/scripts/workflow/release_policy.py"
)
release_policy = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_policy)
PROMOTE_SPEC = importlib.util.spec_from_file_location(
    "promote_images", ROOT / ".github/scripts/workflow/promote_images.py"
)
promote_images = importlib.util.module_from_spec(PROMOTE_SPEC)
assert PROMOTE_SPEC.loader is not None
PROMOTE_SPEC.loader.exec_module(promote_images)
SIGN_SPEC = importlib.util.spec_from_file_location(
    "sign_candidates", ROOT / ".github/scripts/workflow/sign_candidates.py"
)
sign_candidates = importlib.util.module_from_spec(SIGN_SPEC)
assert SIGN_SPEC.loader is not None
SIGN_SPEC.loader.exec_module(sign_candidates)
TOOLS_SPEC = importlib.util.spec_from_file_location(
    "install_tools", ROOT / ".github/scripts/workflow/install_tools.py"
)
install_tools = importlib.util.module_from_spec(TOOLS_SPEC)
assert TOOLS_SPEC.loader is not None
TOOLS_SPEC.loader.exec_module(install_tools)
PUBLISH_SPEC = importlib.util.spec_from_file_location(
    "release_publish", ROOT / ".github/scripts/workflow/release_publish.py"
)
release_publish = importlib.util.module_from_spec(PUBLISH_SPEC)
assert PUBLISH_SPEC.loader is not None
PUBLISH_SPEC.loader.exec_module(release_publish)


class ReleasePublisherTests(unittest.TestCase):
    def test_testing_candidate_cannot_be_promoted_as_stable(self):
        with (
            patch.object(
                release_publish, "verify_release", return_value={"channel": "testing"}
            ),
            patch.object(release_publish, "stage") as stage,
            patch.object(release_publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "channel does not match"),
        ):
            release_publish.promote(
                Path("candidate"), Path("evidence"), Path("key"), Path("dist"), "stable"
            )
        stage.assert_not_called()
        run.assert_not_called()

    def test_staged_candidate_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.json"
            original.write_text("original", encoding="utf-8")
            (root / "candidate.json").write_text("changed", encoding="utf-8")
            helper = types.SimpleNamespace(verify=lambda *_: None)
            with (
                patch.object(release_publish, "verify_checksums"),
                patch.object(release_publish, "release_artifacts"),
                patch.object(release_publish, "load_helper", return_value=helper),
                self.assertRaisesRegex(ValueError, "staged candidate does not match"),
            ):
                release_publish.verify_staged_distribution(
                    original, root / "release-evidence.json", root, {}, Path("key")
                )

    def test_invalid_staged_checksum_blocks_registry_and_promotion(self):
        with (
            patch.object(release_publish, "verify_release", return_value={}),
            patch.object(release_publish, "release_artifacts"),
            patch.object(release_publish, "stage"),
            patch.object(
                release_publish,
                "verify_staged_distribution",
                side_effect=ValueError("checksum"),
            ),
            patch.object(release_publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "checksum"),
        ):
            release_publish.promote(
                Path("candidate"), Path("evidence"), Path("key"), Path("publication")
            )
        run.assert_not_called()

    def test_release_artifacts_require_exact_channel_version(self):
        candidate = {
            "channel": "stable",
            "version_tag": "testing-45.20261105",
            "build_version": "45.20261105",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for extension in ("iso", "qcow2"):
                (
                    root / f"luminusos-workstation-testing-45.20261105.{extension}"
                ).touch()
            with self.assertRaisesRegex(ValueError, "versioned ISO"):
                release_publish.release_artifacts(root, candidate)
            for image in list(root.iterdir()):
                image.rename(root / image.name.replace("testing-", ""))
            self.assertEqual(len(release_publish.release_artifacts(root, candidate)), 2)

    def test_older_supported_release_never_moves_floating_tags(self):
        digest = "sha256:" + "a" * 64
        candidate = {
            "channel": "testing",
            "fedora_version": "44",
            "version_tag": "testing-44.20261105",
            "build_version": "44.20261105",
            "repository": "org/repo",
            "source_sha": "c" * 40,
            "images": {
                name: f"ghcr.io/org/{name}@{digest}"
                for name in ("core", "workstation", "installer")
            },
        }
        promotion = types.SimpleNamespace(promote=unittest.mock.Mock())
        inspect = subprocess.CompletedProcess([], 0, stdout=digest)
        with (
            patch.object(release_publish, "verify_release", return_value=candidate),
            patch.object(release_publish, "release_artifacts"),
            patch.object(release_publish, "verify_staged_distribution"),
            patch.object(release_publish, "stage"),
            patch.object(
                release_publish,
                "release_configuration",
                return_value={"LATEST_RELEASE": "45"},
            ),
            patch.object(release_publish, "load_helper", return_value=promotion),
            patch.object(
                release_publish.subprocess, "run", side_effect=[None, inspect] * 3
            ),
        ):
            release_publish.promote(
                Path("candidate"), Path("evidence"), Path("key"), Path("publication")
            )
        self.assertEqual(promotion.promote.call_count, 3)
        for call in promotion.promote.call_args_list:
            self.assertTrue(
                all(
                    not destination.endswith((":testing", ":latest"))
                    for destination in call.args[2]
                )
            )

    def test_results_reject_signed_failed_gate_without_circular_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gates").mkdir()
            candidate = {
                "repository": "org/repo",
                "source_sha": "c" * 40,
                "run_id": 42,
                "images": {"workstation": "ghcr.io/org/workstation@sha256:" + "a" * 64},
                "artifacts": {},
            }
            for gate in release_publish.GATES:
                name = f"gates/{gate}.json"
                report = {
                    "gate": gate,
                    "conclusion": "failure" if gate == "boot" else "success",
                    "repository": candidate["repository"],
                    "source_sha": candidate["source_sha"],
                    "run_id": candidate["run_id"],
                    "images": candidate["images"],
                    "artifacts": {"observed.log": "f" * 64},
                }
                (root / name).write_text(json.dumps(report), encoding="utf-8")
                candidate["artifacts"][name] = release_publish.sha256(root / name)
            pipeline = types.SimpleNamespace(
                candidate=lambda *_: candidate, checked_file=lambda *_: None
            )
            with (
                patch.object(release_publish, "load_helper", return_value=pipeline),
                self.assertRaisesRegex(
                    ValueError, "invalid recorded gate outcome: boot"
                ),
            ):
                release_publish.prepare_results(root)
            self.assertFalse((root / "results.json").exists())
            self.assertNotIn("results.json", candidate["artifacts"])

    def test_stable_source_allows_refreshed_upstream_digest(self):
        candidate = {
            "channel": "testing",
            "version_tag": "testing-45.20261105",
            "fedora_version": "45",
            "fedora_bootc_digest": "sha256:" + "a" * 64,
            "images": {
                "core": "ghcr.io/org/core@sha256:" + "b" * 64,
                "workstation": "ghcr.io/org/workstation@sha256:" + "c" * 64,
            },
        }
        pipeline = types.SimpleNamespace(candidate=lambda *_: candidate)
        metadata = types.SimpleNamespace(
            releases=lambda _: {"SUPPORTED_RELEASES": "45 46"}
        )
        upstream = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps(
                {"Digest": "sha256:" + "d" * 64, "Labels": {"version": "45"}}
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with (
                patch.dict(release_publish.os.environ, {"GITHUB_OUTPUT": str(output)}),
                patch.object(
                    release_publish,
                    "load_helper",
                    side_effect=lambda name: (
                        pipeline if name == "release_pipeline" else metadata
                    ),
                ),
                patch.object(
                    release_publish.subprocess,
                    "run",
                    side_effect=[upstream, None, None],
                ),
            ):
                release_publish.verify_source(
                    Path("candidate.json"), Path("key"), "45.20261105"
                )
            self.assertIn(
                candidate["images"]["workstation"].split("@", 1)[1], output.read_text()
            )

    def test_stable_source_rejects_future_supported_fedora(self):
        candidate = {
            "channel": "testing",
            "version_tag": "testing-46.20261105",
            "fedora_version": "46",
        }
        pipeline = types.SimpleNamespace(candidate=lambda *_: candidate)
        metadata = types.SimpleNamespace(
            releases=lambda _: {"SUPPORTED_RELEASES": "45 46"}
        )
        upstream = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"Labels": {"version": "45"}})
        )
        with (
            patch.object(
                release_publish,
                "load_helper",
                side_effect=lambda name: (
                    pipeline if name == "release_pipeline" else metadata
                ),
            ),
            patch.object(
                release_publish.subprocess, "run", return_value=upstream
            ) as run,
            self.assertRaisesRegex(ValueError, "not yet GA"),
        ):
            release_publish.verify_source(
                Path("candidate.json"), Path("key"), "46.20261105"
            )
        self.assertEqual(run.call_count, 1)

    def test_stable_source_rejects_malformed_upstream_ga_label(self):
        candidate = {
            "channel": "testing",
            "version_tag": "testing-45.20261105",
            "fedora_version": "45",
        }
        pipeline = types.SimpleNamespace(candidate=lambda *_: candidate)
        metadata = types.SimpleNamespace(
            releases=lambda _: {"SUPPORTED_RELEASES": "45"}
        )
        for labels in ({}, {"version": "rawhide"}, {"version": "45-beta"}):
            upstream = subprocess.CompletedProcess(
                [], 0, stdout=json.dumps({"Labels": labels})
            )
            with (
                self.subTest(labels=labels),
                patch.object(
                    release_publish,
                    "load_helper",
                    side_effect=lambda name: (
                        pipeline if name == "release_pipeline" else metadata
                    ),
                ),
                patch.object(
                    release_publish.subprocess, "run", return_value=upstream
                ) as run,
                self.assertRaisesRegex(ValueError, "cannot determine Fedora GA"),
            ):
                release_publish.verify_source(
                    Path("candidate.json"), Path("key"), "45.20261105"
                )
            self.assertEqual(run.call_count, 1)

    def test_signed_checksums_detect_tampered_allowlisted_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "candidate.json"
            artifact.write_text("original", encoding="utf-8")
            (root / "SHA256SUMS").write_text(
                f"{hashlib.sha256(b'original').hexdigest()}  candidate.json\n",
                encoding="utf-8",
            )
            helper = types.SimpleNamespace(verify=lambda *_: None)
            with patch.object(release_publish, "load_helper", return_value=helper):
                release_publish.verify_checksums(root, Path("key"))
                artifact.write_text("tampered", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "checksum manifest mismatch"):
                    release_publish.verify_checksums(root, Path("key"))

    def test_failed_scanner_prevents_signatures_and_registry_calls(self):
        with (
            patch.dict(
                release_publish.os.environ,
                {
                    "QUALITY_RESULT": "success",
                    "BOOT_RESULT": "success",
                    "SCAN_RESULT": "failure",
                },
            ),
            patch.object(release_publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "SCAN_RESULT"),
        ):
            release_publish.prepare_gates(Path("unused"))
        run.assert_not_called()

    def test_failed_third_image_preflight_prevents_all_tag_changes(self):
        digest = "sha256:" + "a" * 64
        images = {
            name: f"ghcr.io/org/{name}@{digest}"
            for name in ("core", "workstation", "installer")
        }
        candidate = {
            "images": images,
            "artifacts": {},
            "repository": "org/repo",
            "source_sha": "c" * 40,
            "channel": "testing",
            "fedora_version": "45",
            "build_version": "45.20261105",
            "version_tag": "testing-45.20261105",
        }
        evidence = {"images": images, "artifacts": {}}
        pipeline = types.SimpleNamespace(
            candidate=lambda *_: candidate, verify=lambda *_: None
        )
        promotion = types.SimpleNamespace(
            validate_candidate=lambda *_: [],
            verify_evidence_artifacts=lambda *_: None,
            promote=unittest.mock.Mock(),
        )
        inspect = subprocess.CompletedProcess([], 0, stdout=digest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            (Path(directory) / "gates").mkdir()
            (Path(directory) / "gates/boot.json").write_text('{"artifacts": {}}')
            candidate["artifacts"]["gates/boot.json"] = hashlib.sha256(
                b'{"artifacts": {}}'
            ).hexdigest()
            evidence["artifacts"] = candidate["artifacts"]
            path.write_text(json.dumps(evidence), encoding="utf-8")
            with (
                patch.object(
                    release_publish,
                    "load_helper",
                    side_effect=lambda name: (
                        pipeline if name == "release_pipeline" else promotion
                    ),
                ),
                patch.object(
                    release_publish,
                    "release_configuration",
                    return_value={"LATEST_RELEASE": "45"},
                ),
                patch.object(release_publish, "release_artifacts"),
                patch.object(release_publish, "verify_staged_distribution"),
                patch.object(release_publish, "stage"),
                patch.object(
                    release_publish.subprocess,
                    "run",
                    side_effect=[
                        None,
                        inspect,
                        None,
                        inspect,
                        subprocess.CalledProcessError(1, "cosign"),
                    ],
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                release_publish.promote(
                    Path(directory) / "candidate.json",
                    path,
                    Path("key"),
                    Path("publication"),
                )
        promotion.promote.assert_not_called()


class ScannerInstallerTests(unittest.TestCase):
    def test_checksum_mismatch_does_not_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(
                    install_tools.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(b"untrusted"),
                ),
                self.assertRaisesRegex(ValueError, "checksum mismatch"),
            ):
                install_tools.install("syft", Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_matching_archive_extracts_only_named_executable(self):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as archive:
            member = tarfile.TarInfo("syft")
            member.size = 4
            archive.addfile(member, io.BytesIO(b"tool"))
            other = tarfile.TarInfo("../outside")
            other.size = 1
            archive.addfile(other, io.BytesIO(b"x"))
        data = content.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict(
                    install_tools.TOOLS,
                    {"syft": ("1.0.0", hashlib.sha256(data).hexdigest())},
                ),
                patch.object(
                    install_tools.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(data),
                ),
            ):
                install_tools.install("syft", Path(directory))
            self.assertEqual((Path(directory) / "syft").read_bytes(), b"tool")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


class CandidateSigningTests(unittest.TestCase):
    def test_candidate_metadata_captures_immutable_job_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "metadata.json"
            digest = "sha256:" + "a" * 64
            images = [
                f"ghcr.io/org/{name}@{digest}"
                for name in ("core", "workstation", "installer")
            ]
            env = {
                "GITHUB_REPOSITORY": "org/repository",
                "GITHUB_SHA": "c" * 40,
                "GITHUB_RUN_ID": "123",
                "CHANNEL": "testing",
                "VERSION_TAG": "testing-45.1",
                "BUILD_VERSION": "45.1",
                "FEDORA_VERSION": "45",
                "FEDORA_BOOTC_DIGEST": digest,
            }
            with (
                patch.dict(sign_candidates.os.environ, env),
                patch.object(
                    sys,
                    "argv",
                    ["sign_candidates.py", "--metadata", str(target), *images],
                ),
            ):
                self.assertEqual(sign_candidates.main(), 0)
            metadata = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(metadata["images"]["workstation"], images[1])
            self.assertEqual(metadata["run_id"], 123)

    def test_push_digest_is_signed_and_verified_before_return(self):
        digest = "sha256:" + "a" * 64
        pushed = subprocess.CompletedProcess(
            [], 0, stdout=f"digest: {digest} size: 123\n", stderr=""
        )
        with patch.object(
            sign_candidates.subprocess, "run", side_effect=[pushed, None, None]
        ) as run:
            result = sign_candidates.push_and_sign(
                "ghcr.io/luminusos/image:candidate-1-1"
            )
        self.assertEqual(result, f"ghcr.io/luminusos/image@{digest}")
        self.assertEqual(run.call_args_list[1].args[0][-1], result)
        self.assertEqual(run.call_args_list[2].args[0][-1], result)
        self.assertEqual(run.call_args_list[1].args[0][:2], ["cosign", "sign"])
        self.assertEqual(run.call_args_list[2].args[0][:2], ["cosign", "verify"])

    def test_missing_push_digest_never_signs(self):
        pushed = subprocess.CompletedProcess([], 0, stdout="success", stderr="")
        with (
            patch.object(sign_candidates.subprocess, "run", return_value=pushed) as run,
            self.assertRaises(ValueError),
        ):
            sign_candidates.push_and_sign("ghcr.io/luminusos/image:candidate-1-1")
        self.assertEqual(run.call_count, 1)

    def test_invalid_reference_never_pushes(self):
        with (
            patch.object(sign_candidates.subprocess, "run") as run,
            self.assertRaises(ValueError),
        ):
            sign_candidates.push_and_sign("ghcr.io/luminusos/image@sha256:abc")
        run.assert_not_called()


class ReleasePolicyTests(unittest.TestCase):
    def evidence(self):
        digest = "sha256:" + "a" * 64
        gates = release_policy.REQUIRED_GATES
        return {
            "repository": "org/repository",
            "candidate_digest": digest,
            "source": {
                "repository": "org/repository",
                "ref": "refs/heads/main",
                "run_id": 10,
                "commit": "c" * 40,
            },
            "gates": {name: True for name in gates},
            "evidence": {
                name: {
                    "artifact": name + ".json",
                    "sha256": "b" * 64,
                    "candidate_digest": digest,
                }
                for name in gates
            },
        }

    def test_accepts_matching_digest_with_all_gates(self):
        self.assertEqual(release_policy.validate_candidate(self.evidence()), [])

    def test_rejects_mutable_candidate_and_mismatched_requested_digest(self):
        evidence = self.evidence()
        evidence["candidate_digest"] = "latest"
        errors = release_policy.validate_candidate(evidence, "sha256:" + "b" * 64)
        self.assertTrue(any("sha256 digest" in error for error in errors))
        self.assertTrue(any("does not match" in error for error in errors))

    def test_missing_installation_gate_fails_closed(self):
        evidence = self.evidence()
        del evidence["gates"]["installation"]
        self.assertIn(
            "required gate is missing or failed: installation",
            release_policy.validate_candidate(evidence),
        )

    def test_failed_scanner_blocks_promotion(self):
        evidence = self.evidence()
        evidence["gates"]["vulnerability"] = False
        self.assertTrue(release_policy.validate_candidate(evidence))

    def test_cli_refuses_manifest_without_installation_evidence(self):
        evidence = self.evidence()
        del evidence["gates"]["installation"]
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "evidence.json"
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / ".github/scripts/workflow/release_policy.py"),
                    str(manifest),
                    "--candidate-digest",
                    evidence["candidate_digest"],
                ],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("installation", result.stderr)

    def test_release_policy_rejects_foreign_key_or_untrusted_evidence_source(self):
        evidence = self.evidence()
        evidence["source"]["ref"] = "refs/pull/4/merge"
        self.assertTrue(
            any(
                "refs/heads/main" in error
                for error in release_policy.validate_candidate(evidence)
            )
        )


class PromotionTests(unittest.TestCase):
    def write_artifacts(self, root, evidence):
        for name, entry in evidence["evidence"].items():
            data = ("evidence:" + name).encode()
            (root / entry["artifact"]).write_bytes(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()

    def test_unbound_core_and_installer_never_contact_registry(self):
        evidence = ReleasePolicyTests().evidence()
        digest = "sha256:" + "a" * 64
        evidence["images"] = {
            "core": "ghcr.io/org/core@" + digest,
            "workstation": "ghcr.io/org/workstation@" + digest,
            "installer": "ghcr.io/org/workstation@sha256:" + "b" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            for role in ("core", "installer"):
                image = evidence["images"][role]
                repository = image.split("@", 1)[0]
                with (
                    self.subTest(role=role),
                    patch.object(promote_images.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "source does not match"),
                ):
                    promote_images.promote(
                        repository + "@sha256:" + "f" * 64,
                        digest,
                        [repository + ":testing"],
                        root / "key",
                        manifest,
                        root / "signature",
                        "org/repository",
                        "c" * 40,
                        role,
                    )
                run.assert_not_called()

    def test_other_image_role_is_bound_to_signed_evidence(self):
        evidence = ReleasePolicyTests().evidence()
        core_digest = "sha256:" + "d" * 64
        core = "ghcr.io/org/core@" + core_digest
        evidence["images"] = {
            "core": core,
            "workstation": "ghcr.io/org/image@" + evidence["candidate_digest"],
            "installer": "ghcr.io/org/image@sha256:" + "e" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_artifacts(root, evidence)
            manifest, signature, key = (
                root / "evidence.json",
                root / "sig",
                root / "key",
            )
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            signature.touch()
            key.touch()
            inspect = subprocess.CompletedProcess([], 0, stdout=core_digest)
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[None, inspect, None, None, inspect],
            ) as run:
                promote_images.promote(
                    core,
                    core_digest,
                    ["ghcr.io/org/core:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            self.assertEqual(run.call_args_list[3].args[0][4], "docker://" + core)
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "source does not match"),
            ):
                promote_images.promote(
                    "ghcr.io/org/core@sha256:" + "f" * 64,
                    core_digest,
                    ["ghcr.io/org/core:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            run.assert_not_called()

    def test_verified_evidence_and_signature_precede_digest_preserving_copy(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, signature, key = (
                root / "evidence.json",
                root / "sig",
                root / "key",
            )
            self.write_artifacts(root, evidence)
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            signature.touch()
            key.touch()
            inspect = subprocess.CompletedProcess(
                [], 0, stdout=evidence["candidate_digest"]
            )
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[None, inspect, None, None, inspect],
            ) as run:
                promote_images.promote(
                    "ghcr.io/org/image:testing-1",
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                )
        calls = [entry.args[0] for entry in run.call_args_list]
        self.assertEqual(calls[0][:2], ["cosign", "verify-blob"])
        self.assertIn("--insecure-ignore-tlog", calls[0])
        self.assertIn("--key", calls[0])
        self.assertEqual(calls[0][calls[0].index("--key") + 1], str(key))
        self.assertEqual(calls[2][:2], ["cosign", "verify"])
        self.assertEqual(
            calls[3][:4], ["skopeo", "copy", "--all", "--preserve-digests"]
        )
        self.assertIn("@" + evidence["candidate_digest"], calls[3][4])

    def test_immutable_source_is_not_truncated_at_digest_colon(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_artifacts(root, evidence)
            manifest, signature, key = (
                root / "evidence.json",
                root / "sig",
                root / "key",
            )
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            signature.touch()
            key.touch()
            inspect = subprocess.CompletedProcess(
                [], 0, stdout=evidence["candidate_digest"]
            )
            source = "ghcr.io/org/image@" + evidence["candidate_digest"]
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[None, inspect, None, None, inspect],
            ) as run:
                promote_images.promote(
                    source,
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                )
            self.assertEqual(run.call_args_list[2].args[0][-1], source)
            self.assertEqual(run.call_args_list[3].args[0][4], "docker://" + source)

    def test_missing_gate_blocks_all_registry_mutations(self):
        evidence = ReleasePolicyTests().evidence()
        evidence["gates"]["installation"] = False
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            key = Path(directory) / "key.pub"
            key.write_text("key", encoding="utf-8")
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "installation"),
            ):
                promote_images.promote(
                    "ghcr.io/org/image:testing-1",
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    evidence_path,
                    Path(directory) / "signature",
                    "org/repository",
                    "c" * 40,
                )
            run.assert_not_called()

    def test_foreign_signature_key_blocks_copy(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            self.write_artifacts(Path(directory), evidence)
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            key = Path(directory) / "key.pub"
            key.write_text("key", encoding="utf-8")
            signature = Path(directory) / "signature"
            signature.write_text("signature", encoding="utf-8")
            inspect = type("Completed", (), {"stdout": evidence["candidate_digest"]})()
            with (
                patch.object(
                    promote_images.subprocess,
                    "run",
                    side_effect=[
                        None,
                        inspect,
                        subprocess.CalledProcessError(1, "cosign"),
                    ],
                ) as run,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                promote_images.promote(
                    "ghcr.io/org/image:testing-1",
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    evidence_path,
                    signature,
                    "org/repository",
                    "c" * 40,
                )
            self.assertEqual(run.call_count, 3)

    def test_foreign_evidence_signature_blocks_all_registry_calls(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, signature, key = (
                root / "evidence.json",
                root / "sig",
                root / "key",
            )
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            signature.touch()
            key.touch()
            with (
                patch.object(
                    promote_images.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "cosign"),
                ) as run,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                promote_images.promote(
                    "ghcr.io/org/image:testing-1",
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                )
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:2], ["cosign", "verify-blob"])

    def test_tampered_artifact_blocks_registry_calls(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_artifacts(root, evidence)
            manifest, signature, key = (
                root / "evidence.json",
                root / "sig",
                root / "key",
            )
            manifest.write_text(json.dumps(evidence), encoding="utf-8")
            signature.touch()
            key.touch()
            (root / evidence["evidence"]["installation"]["artifact"]).write_text(
                "tampered"
            )
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "checksum mismatch"),
            ):
                promote_images.promote(
                    "ghcr.io/org/image:testing-1",
                    evidence["candidate_digest"],
                    ["ghcr.io/org/image:stable"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                )
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:2], ["cosign", "verify-blob"])


class ContainerWorkflowTests(unittest.TestCase):
    def load_workflow(self, name):
        return yaml.load(
            (ROOT / ".github/workflows" / name).read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )

    def test_resume_imports_original_candidate_without_rebuilding(self):
        workflow = self.load_workflow("publish.yml")
        jobs = workflow["jobs"]
        self.assertIn("inputs.candidate_run_id == ''", jobs["containers"]["if"])
        resume = jobs["release"]
        self.assertEqual(resume["needs"], ["quality", "inputs"])
        self.assertIn("inputs.candidate_run_id != ''", resume["if"])
        self.assertIn("inputs.validation_run_id != ''", resume["if"])
        commands = "\n".join(step.get("run", "") for step in resume["steps"])
        self.assertIn("fetch-candidate", commands)
        self.assertIn("fetch-validation", commands)
        self.assertIn("--candidate candidate/candidate.json", commands)
        self.assertIn("--evidence dist/release-evidence.json", commands)

    def test_prepare_succeeds_without_installation_validation_and_resume_is_separate(
        self,
    ):
        jobs = self.load_workflow("publish.yml")["jobs"]
        prepare = jobs["prepare-candidate"]
        self.assertIn("inputs.candidate_run_id == ''", prepare["if"])
        self.assertNotIn("validation_run_id", prepare["if"])
        self.assertNotIn("release", prepare["needs"])
        self.assertTrue(
            any(
                step.get("with", {}).get("name") == "release-candidate"
                for step in prepare["steps"]
            )
        )
        release = jobs["release"]
        self.assertIn("inputs.candidate_run_id != ''", release["if"])
        self.assertIn("inputs.validation_run_id != ''", release["if"])
        self.assertFalse(
            {"containers", "iso", "qcow2", "prepare-candidate"} & set(release["needs"])
        )

    def test_candidate_gate_results_are_recorded_once(self):
        workflow = self.load_workflow("publish.yml")
        steps = workflow["jobs"]["prepare-candidate"]["steps"]
        gates = [
            s for s in steps if "release_publish.py prepare-gates" in s.get("run", "")
        ]
        self.assertEqual(len(gates), 1)
        self.assertIn("SOURCE_IMAGE_SHA", gates[0]["env"])

    def test_validation_caller_is_read_only_and_does_not_inherit_secrets(self):
        workflow = self.load_workflow("build-containers.yml")
        caller = workflow["jobs"]["build-containers"]
        self.assertEqual(
            caller["permissions"], {"contents": "read", "packages": "read"}
        )
        self.assertNotIn("secrets", caller)
        self.assertEqual(caller["with"]["publish"], "false")

    def test_container_build_dag_and_digest_dependency(self):
        workflow = self.load_workflow("containers.yml")
        jobs = workflow["jobs"]
        self.assertEqual(jobs["core"]["needs"], ["metadata"])
        self.assertEqual(jobs["workstation"]["needs"], ["metadata", "core"])
        workstation_build = next(
            step
            for step in jobs["workstation"]["steps"]
            if step.get("name") == "Build workstation"
        )
        self.assertIn(
            "needs.metadata.outputs.core_image", workstation_build["with"]["build-args"]
        )
        self.assertTrue(
            any(
                step.get("name") == "Load core image"
                for step in jobs["workstation"]["steps"]
            )
        )

    def test_validation_callers_and_reusable_jobs_are_read_only(self):
        caller_workflows = ("build-containers.yml", "auto-testing.yml", "publish.yml")
        for workflow_name in caller_workflows:
            workflow = self.load_workflow(workflow_name)
            for job in workflow["jobs"].values():
                if job.get("uses") != "./.github/workflows/containers.yml":
                    continue
                self.assertEqual(
                    job["permissions"].get("contents"), "read", workflow_name
                )
                self.assertEqual(
                    job["permissions"].get("packages"), "read", workflow_name
                )
                self.assertNotIn("secrets", job, workflow_name)

        workflow = self.load_workflow("containers.yml")
        for name in ("core", "workstation"):
            job = workflow["jobs"][name]
            self.assertEqual(job["permissions"]["contents"], "read")
            self.assertEqual(job["permissions"]["packages"], "read")
            self.assertFalse(
                any(
                    "docker/login-action" in step.get("uses", "")
                    for step in job["steps"]
                )
            )
            self.assertFalse(
                any(step.get("with", {}).get("push") == "true" for step in job["steps"])
            )
            self.assertFalse(any("secrets." in str(step) for step in job["steps"]))
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if "docker/build-push-action" in step.get("uses", ""):
                    self.assertEqual(step["with"].get("push"), "false")
                self.assertNotIn("secrets.", str(step))

    def test_reusable_installer_workflow_is_read_only_and_uses_approved_payload(self):
        workflow = self.load_workflow("installer.yml")
        build = workflow["jobs"]["build"]
        self.assertEqual(build["permissions"], {"contents": "read", "packages": "read"})
        self.assertEqual(
            workflow["on"]["workflow_call"]["outputs"]["image_id"]["value"],
            "${{ jobs.build.outputs.image_id }}",
        )
        self.assertEqual(
            workflow["on"]["workflow_call"]["outputs"]["archive_sha256"]["value"],
            "${{ jobs.build.outputs.archive_sha256 }}",
        )
        steps = build["steps"]
        docker_setup = next(
            step
            for step in steps
            if "docker/setup-docker-action@" in step.get("uses", "")
        )
        self.assertEqual(docker_setup["with"]["set-host"], "true")
        load = next(
            step for step in steps if step.get("name") == "Load workstation image"
        )
        export = next(
            step for step in steps if step.get("name") == "Export installer payload"
        )
        self.assertEqual(load["if"], "inputs.channel == 'testing'")
        self.assertEqual(
            load["env"]["ARCHIVE_SHA256"], "${{ inputs.workstation_archive_sha256 }}"
        )
        self.assertEqual(load["env"]["IMAGE_ID"], "${{ inputs.workstation_image_id }}")
        self.assertEqual(
            export["env"]["WORKSTATION_DIGEST"], "${{ inputs.workstation_digest }}"
        )
        self.assertLess(steps.index(load), steps.index(export))
        build_step = next(
            step
            for step in steps
            if step.get("name") == "Build workstation ISO live root"
        )
        self.assertEqual(build_step["with"]["push"], "false")
        self.assertEqual(build_step["with"]["load"], "true")
        self.assertEqual(
            build_step["with"]["file"], "editions/workstation/Containerfile.installer"
        )

    def test_publish_false_uses_loaded_docker_archive(self):
        workflow = self.load_workflow("containers.yml")
        core_steps = workflow["jobs"]["core"]["steps"]
        workstation_steps = workflow["jobs"]["workstation"]["steps"]
        self.assertTrue(
            any(step.get("name") == "Save core image archive" for step in core_steps)
        )
        self.assertTrue(
            any(step.get("name") == "Load core image" for step in workstation_steps)
        )
        build = next(
            step
            for step in workstation_steps
            if step.get("name") == "Build workstation"
        )
        self.assertEqual(build["with"]["load"], "true")
        self.assertEqual(build["with"]["push"], "false")
        self.assertTrue(
            any(
                step.get("name") == "Save workstation image archive"
                for step in workstation_steps
            )
        )

    def test_publication_writes_are_isolated_from_reusable_validation(self):
        workflow = self.load_workflow("publish.yml")
        reusable = workflow["jobs"]["containers"]
        self.assertEqual(reusable["permissions"]["packages"], "read")
        self.assertEqual(reusable["with"]["publish"], "false")
        self.assertNotIn("secrets", reusable)
        publisher = workflow["jobs"]["publish-images"]
        self.assertEqual(publisher["permissions"]["packages"], "write")
        self.assertEqual(publisher["needs"], ["containers"])
        self.assertTrue(
            any(
                "docker/login-action" in step.get("uses", "")
                for step in publisher["steps"]
            )
        )
        self.assertIn("github.ref == 'refs/heads/main'", publisher["if"])
        for workflow_name in ("publish.yml", "auto-testing.yml"):
            workflow = self.load_workflow(workflow_name)
            for name, job in workflow["jobs"].items():
                if job.get("permissions", {}).get("packages") == "write":
                    self.assertIn(
                        name,
                        (
                            "publish-images",
                            "publish-stable-installer",
                            "prepare",
                            "release",
                        ),
                        workflow_name,
                    )
                    if name == "publish-images":
                        self.assertEqual(
                            job.get("needs"), ["containers"], workflow_name
                        )
                    elif name == "publish-stable-installer":
                        self.assertEqual(
                            job.get("needs"),
                            ["stable-installer", "stable-source"],
                            workflow_name,
                        )
            if workflow_name == "auto-testing.yml":
                self.assertEqual(
                    workflow["jobs"]["check"]["if"], "github.ref == 'refs/heads/main'"
                )
                self.assertEqual(workflow["jobs"]["prepare"]["needs"], ["check"])

    def test_stable_metadata_uses_testing_candidate_and_does_not_depend_on_skipped_builds(
        self,
    ):
        workflow = self.load_workflow("containers.yml")
        script = next(
            step["run"]
            for step in workflow["jobs"]["metadata"]["steps"]
            if step.get("id") == "version"
        )
        self.assertEqual(script, "python3 .github/scripts/workflow/build_metadata.py")
        outputs = workflow["on"]["workflow_call"]["outputs"]
        self.assertEqual(
            outputs["core_image"]["value"], "${{ jobs.metadata.outputs.core_image }}"
        )
        self.assertEqual(
            outputs["workstation_image"]["value"],
            "${{ jobs.metadata.outputs.workstation_image }}",
        )
        self.assertEqual(workflow["jobs"]["core"]["if"], "inputs.channel != 'stable'")
        self.assertEqual(
            workflow["jobs"]["workstation"]["if"], "inputs.channel != 'stable'"
        )
        self.assertEqual(workflow["jobs"]["workstation"]["needs"], ["metadata", "core"])

    def test_stable_publishing_does_not_gate_packaging_on_skipped_candidate_publish(
        self,
    ):
        workflow = self.load_workflow("publish.yml")
        for name in ("iso", "qcow2"):
            condition = workflow["jobs"][name]["if"]
            self.assertIn("always()", condition)
            self.assertIn("inputs.channel == 'stable'", condition)
        stable_installer = workflow["jobs"]["stable-installer"]
        self.assertEqual(stable_installer["needs"], ["stable-source"])
        self.assertEqual(
            stable_installer["with"]["workstation_digest"],
            "${{ needs.stable-source.outputs.workstation_digest }}",
        )
        self.assertEqual(stable_installer["permissions"]["packages"], "read")
        stable_source = workflow["jobs"]["stable-source"]
        commands = "\n".join(step.get("run", "") for step in stable_source["steps"])
        self.assertIn("fetch-candidate", commands)
        self.assertIn("fetch-validation", commands)
        self.assertIn("verify-source", commands)

    def test_auto_testing_signs_only_candidates_and_does_not_create_releases(self):
        workflow = self.load_workflow("auto-testing.yml")
        self.assertNotIn("publish-images", workflow["jobs"])
        self.assertNotIn("release", workflow["jobs"])
        job = workflow["jobs"]["prepare"]
        self.assertEqual(job["permissions"]["packages"], "write")
        self.assertEqual(job["needs"], ["check"])
        self.assertEqual(job["uses"], "./.github/workflows/publish.yml")
        self.assertEqual(job["with"]["channel"], "testing")
        self.assertNotIn("candidate_run_id", job["with"])


if __name__ == "__main__":
    unittest.main()
