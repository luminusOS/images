import copy
import hashlib
import importlib.util
import io
import json
import re
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
    def test_candidate_and_publication_keys_are_separate(self):
        self.assertEqual(release_publish.CANDIDATE_KEY, "shared/release/candidate.pub")
        self.assertEqual(
            release_publish.OFFICIAL_KEY,
            "shared/trust/etc/pki/containers/luminusos.pub",
        )

    def test_checksum_signature_uses_fixed_official_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "candidate.json"
            artifact.write_text("original")
            (root / "SHA256SUMS").write_text(
                f"{hashlib.sha256(b'original').hexdigest()}  candidate.json\n"
            )
            (root / "SHA256SUMS.sig").write_text("signature")
            with patch.object(release_publish.subprocess, "run") as run:
                release_publish.verify_checksums(root)
            command = run.call_args.args[0]
            self.assertEqual(command[:2], ["cosign", "verify-blob"])
            self.assertEqual(
                command[command.index("--key") + 1], release_publish.OFFICIAL_KEY
            )

    def test_candidate_results_use_candidate_key(self):
        helper = types.SimpleNamespace(
            candidate=unittest.mock.Mock(side_effect=ValueError("stop"))
        )
        with (
            patch.object(release_publish, "load_helper", return_value=helper),
            self.assertRaisesRegex(ValueError, "stop"),
        ):
            release_publish.prepare_results(Path("candidate"))
        helper.candidate.assert_called_once_with(
            Path("candidate/candidate.json"), Path("shared/release/candidate.pub")
        )

    def test_candidate_gate_image_verification_uses_candidate_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan = root / "scan/core/scan-evidence.json"
            scan.parent.mkdir(parents=True)
            scan.write_text('{"security":{"gate":"bypassed"}}')
            with (
                patch.dict(
                    release_publish.os.environ,
                    {
                        "SECURITY_FINDINGS_BYPASS": "false",
                        "QUALITY_RESULT": "success",
                        "BOOT_RESULT": "success",
                        "SCAN_RESULT": "success",
                        "CORE": "core",
                        "WORKSTATION": "workstation",
                        "INSTALLER": "installer",
                    },
                ),
                patch.object(release_publish.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "bypass"),
            ):
                release_publish.prepare_gates(root)
            self.assertEqual(
                run.call_args.args[0],
                ["cosign", "verify", "--key", "shared/release/candidate.pub", "core"],
            )

    def test_candidate_signing_jobs_never_receive_official_key(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        for name in ("publish-images", "prepare-candidate", "release-evidence"):
            with self.subTest(job=name):
                job = workflow["jobs"][name]
                self.assertEqual(job["environment"], "candidate-staging")
                self.assertNotIn("secrets.COSIGN_PRIVATE_KEY", str(job))
                commands = " ".join(step.get("run", "") for step in job["steps"])
                self.assertNotIn(
                    "shared/trust/etc/pki/containers/luminusos.pub", commands
                )
        self.assertIn("release-evidence", workflow["jobs"]["release"]["needs"])
        release = workflow["jobs"]["release"]
        self.assertNotIn("secrets.CANDIDATE_COSIGN_PRIVATE_KEY", str(release))

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
        promotion = types.SimpleNamespace(
            promote=unittest.mock.Mock(),
            public_repository=lambda role, repository: f"ghcr.io/org/{role}",
        )
        inspect = subprocess.CompletedProcess([], 0, stdout=digest)
        with (
            patch.object(release_publish, "verify_release", return_value=candidate),
            patch.object(release_publish, "release_artifacts"),
            patch.object(release_publish, "verify_staged_distribution"),
            patch.object(release_publish, "release_preflight"),
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

    def test_stable_promotion_rejects_a_fedora_release_before_ga(self):
        upstream = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"Labels": {"version": "45"}})
        )
        with (
            patch.object(
                release_publish.subprocess, "run", return_value=upstream
            ) as run,
            self.assertRaisesRegex(ValueError, "not yet GA"),
        ):
            release_publish.check_fedora_ga("46")
        self.assertEqual(run.call_count, 1)

    def test_stable_promotion_rejects_malformed_upstream_ga_label(self):
        for labels in ({}, {"version": "rawhide"}, {"version": "45-beta"}):
            upstream = subprocess.CompletedProcess(
                [], 0, stdout=json.dumps({"Labels": labels})
            )
            with (
                self.subTest(labels=labels),
                patch.object(
                    release_publish.subprocess, "run", return_value=upstream
                ) as run,
                self.assertRaisesRegex(ValueError, "cannot determine Fedora GA"),
            ):
                release_publish.check_fedora_ga("45")
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
            (root / "SHA256SUMS.sig").write_text("signature")
            with patch.object(release_publish.subprocess, "run"):
                release_publish.verify_checksums(root)
                artifact.write_text("tampered", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "checksum manifest mismatch"):
                    release_publish.verify_checksums(root)

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

    def test_bypass_cannot_be_converted_to_successful_release_gates(self):
        with (
            patch.dict(
                release_publish.os.environ,
                {
                    "SECURITY_FINDINGS_BYPASS": "true",
                    "QUALITY_RESULT": "success",
                    "BOOT_RESULT": "success",
                    "SCAN_RESULT": "success",
                },
            ),
            patch.object(release_publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "bypass"),
        ):
            release_publish.prepare_gates(Path("unused"))
        run.assert_not_called()

    def test_archived_bypass_scan_cannot_become_release_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scan = directory / "scan/core/scan-evidence.json"
            scan.parent.mkdir(parents=True)
            scan.write_text(json.dumps({"security": {"gate": "bypassed"}}))
            with (
                patch.dict(
                    release_publish.os.environ,
                    {
                        "SECURITY_FINDINGS_BYPASS": "false",
                        "QUALITY_RESULT": "success",
                        "BOOT_RESULT": "success",
                        "SCAN_RESULT": "success",
                        "CORE": "core",
                        "WORKSTATION": "workstation",
                        "INSTALLER": "installer",
                    },
                ),
                patch.object(release_publish.subprocess, "run"),
                self.assertRaisesRegex(ValueError, "bypass"),
            ):
                release_publish.prepare_gates(directory)
            self.assertFalse((directory / "gates").exists())

    def test_scan_without_successful_security_gate_cannot_become_release_gate(self):
        for evidence in ({}, {"security": None}, {"security": []}, {"security": {}}):
            with self.subTest(evidence=evidence):
                self.assert_scan_rejected(evidence)

    def assert_scan_rejected(self, evidence):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scan = directory / "scan/core/scan-evidence.json"
            scan.parent.mkdir(parents=True)
            scan.write_text(json.dumps(evidence))
            with (
                patch.dict(
                    release_publish.os.environ,
                    {
                        "SECURITY_FINDINGS_BYPASS": "false",
                        "QUALITY_RESULT": "success",
                        "BOOT_RESULT": "success",
                        "SCAN_RESULT": "success",
                        "CORE": "core",
                        "WORKSTATION": "workstation",
                        "INSTALLER": "installer",
                    },
                ),
                patch.object(release_publish.subprocess, "run"),
                self.assertRaisesRegex(ValueError, "security"),
            ):
                release_publish.prepare_gates(directory)
            self.assertFalse((directory / "gates").exists())

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
            candidate=lambda *_: candidate,
            verify=lambda *_: None,
            release_ref=lambda *_: "refs/heads/main",
        )
        promotion = types.SimpleNamespace(
            validate_candidate=lambda *_, **__: [],
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
                patch.object(release_publish, "release_preflight"),
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
    STAGING = "ghcr.io/luminusos/luminusos-candidates"

    def anonymous(self, *codes):
        responses = []
        for code in codes:
            if code == 200:
                responses.append(io.BytesIO(b'{"token": "anonymous"}'))
            else:
                responses.append(
                    sign_candidates.urllib.error.HTTPError(
                        "https://ghcr.io", code, "denied", {}, None
                    )
                )
        return patch.object(
            sign_candidates.urllib.request, "urlopen", side_effect=responses
        )

    def test_private_staging_requires_existing_package_and_denied_anonymous_pull(self):
        for token, manifest in ((200, 403), (200, 401), (401, None), (403, None)):
            codes = (token,) if manifest is None else (token, manifest)
            with (
                self.subTest(codes=codes),
                self.anonymous(*codes),
                patch.object(sign_candidates.subprocess, "run") as run,
            ):
                sign_candidates.require_private_staging(self.STAGING)
            self.assertEqual(
                run.call_args.args[0],
                ["docker", "manifest", "inspect", self.STAGING + ":placeholder"],
            )

    def test_public_or_missing_staging_is_rejected(self):
        for codes in ((200, 200), (200, 404), (404,), (500,)):
            with (
                self.subTest(codes=codes),
                self.anonymous(*codes),
                patch.object(sign_candidates.subprocess, "run"),
                self.assertRaisesRegex(ValueError, "private"),
            ):
                sign_candidates.require_private_staging(self.STAGING)

    def test_staging_without_authenticated_access_is_rejected(self):
        with (
            patch.object(sign_candidates.urllib.request, "urlopen") as urlopen,
            patch.object(
                sign_candidates.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, "docker"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            sign_candidates.require_private_staging(self.STAGING)
        urlopen.assert_not_called()

    def test_public_staging_blocks_every_push(self):
        images = [
            f"{self.STAGING}:{role}-candidate-1-1"
            for role in ("core", "workstation", "workstation-iso")
        ]
        with (
            tempfile.NamedTemporaryFile() as output,
            patch.dict(
                sign_candidates.os.environ,
                {
                    "CANDIDATE_COSIGN_PRIVATE_KEY": "fixture",
                    "GITHUB_OUTPUT": output.name,
                },
                clear=True,
            ),
            patch.object(sys, "argv", ["sign_candidates.py", *images]),
            self.anonymous(200, 200),
            patch.object(sign_candidates.subprocess, "run") as run,
        ):
            self.assertEqual(sign_candidates.main(), 1)
        self.assertNotIn("push", str(run.call_args_list))

    def test_candidates_in_different_repositories_are_rejected_before_probing(self):
        images = [
            f"{self.STAGING}:core-candidate-1-1",
            "ghcr.io/other/luminusos-candidates:workstation-candidate-1-1",
        ]
        with (
            tempfile.NamedTemporaryFile() as output,
            patch.dict(
                sign_candidates.os.environ,
                {
                    "CANDIDATE_COSIGN_PRIVATE_KEY": "fixture",
                    "GITHUB_OUTPUT": output.name,
                },
                clear=True,
            ),
            patch.object(sys, "argv", ["sign_candidates.py", *images]),
            patch.object(sign_candidates.urllib.request, "urlopen") as urlopen,
            patch.object(sign_candidates.subprocess, "run") as run,
        ):
            self.assertEqual(sign_candidates.main(), 1)
        urlopen.assert_not_called()
        run.assert_not_called()

    def test_pushed_candidates_are_rechecked_for_anonymous_access(self):
        images = [
            f"{self.STAGING}:{role}-candidate-1-1"
            for role in ("core", "workstation", "workstation-iso")
        ]
        with (
            tempfile.NamedTemporaryFile() as output,
            patch.dict(
                sign_candidates.os.environ,
                {
                    "CANDIDATE_COSIGN_PRIVATE_KEY": "fixture",
                    "GITHUB_OUTPUT": output.name,
                },
                clear=True,
            ),
            patch.object(sys, "argv", ["sign_candidates.py", *images]),
            patch.object(sign_candidates, "require_private_staging"),
            patch.object(
                sign_candidates,
                "push_and_sign",
                side_effect=lambda image: (
                    image.rsplit(":", 1)[0] + "@sha256:" + "a" * 64
                ),
            ),
            self.anonymous(200, 403, 200, 403, 200, 200),
        ):
            self.assertEqual(sign_candidates.main(), 1)
            self.assertEqual(Path(output.name).read_text(), "")

    def test_public_candidate_references_are_rejected_before_push(self):
        for image in (
            "ghcr.io/luminusos/luminusos:candidate-1",
            "ghcr.io/luminusos/luminusos-workstation:candidate-1",
        ):
            with (
                self.subTest(image=image),
                patch.dict(
                    sign_candidates.os.environ,
                    {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
                    clear=True,
                ),
                patch.object(sign_candidates.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                sign_candidates.push_and_sign(image)
            run.assert_not_called()

    def test_candidate_key_is_required_and_official_key_forbidden(self):
        image = "ghcr.io/luminusos/luminusos-candidates:core-candidate-1"
        for env in (
            {"COSIGN_PRIVATE_KEY": "fixture"},
            {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture", "COSIGN_PRIVATE_KEY": ""},
            {},
        ):
            with (
                self.subTest(env=env),
                patch.dict(sign_candidates.os.environ, env, clear=True),
                patch.object(sign_candidates.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                sign_candidates.push_and_sign(image)
            run.assert_not_called()

    def test_candidate_signing_uses_isolated_key(self):
        digest = "sha256:" + "a" * 64
        pushed = subprocess.CompletedProcess(
            [], 0, stdout=f"digest: {digest}", stderr=""
        )
        with (
            patch.dict(
                sign_candidates.os.environ,
                {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
                clear=True,
            ),
            patch.object(
                sign_candidates.subprocess, "run", side_effect=[pushed, None, None]
            ) as run,
        ):
            sign_candidates.push_and_sign(
                "ghcr.io/luminusos/luminusos-candidates:core-candidate-1"
            )
        self.assertIn(
            "env://CANDIDATE_COSIGN_PRIVATE_KEY", run.call_args_list[1].args[0]
        )
        self.assertIn("shared/release/candidate.pub", run.call_args_list[2].args[0])

    def test_candidate_workflow_uses_isolated_environment(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        job = workflow["jobs"]["publish-images"]
        self.assertEqual(job["environment"], "candidate-staging")
        self.assertEqual(job["permissions"]["packages"], "write")
        step = next(s for s in job["steps"] if s.get("id") == "candidates")
        self.assertEqual(
            step["env"]["CANDIDATE_COSIGN_PRIVATE_KEY"],
            "${{ secrets.CANDIDATE_COSIGN_PRIVATE_KEY }}",
        )
        self.assertEqual(
            step["env"]["COSIGN_PASSWORD"], "${{ secrets.CANDIDATE_COSIGN_PASSWORD }}"
        )
        self.assertNotIn("COSIGN_PRIVATE_KEY", step["env"])
        self.assertNotIn("secrets.COSIGN_PRIVATE_KEY", str(job))
        self.assertNotIn("secrets.COSIGN_PASSWORD", str(job))
        self.assertIn("/luminusos-candidates", step["run"])
        for role in ("core", "workstation", "workstation-iso"):
            self.assertIn(f"{role}-candidate-", step["run"])

    def test_candidate_scan_runs_read_only_with_reviewed_policies(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        jobs = workflow["jobs"]
        self.assertNotIn("supply_chain.py inspect", str(jobs["publish-images"]))
        job = jobs["scan-candidates"]
        self.assertNotIn("environment", job)
        self.assertEqual(job["permissions"], {"contents": "read", "packages": "read"})
        self.assertIn("publish-images", job["needs"])
        self.assertEqual(
            set(re.findall(r"secrets\.[A-Z_]+", str(job))), {"secrets.GITHUB_TOKEN"}
        )
        runs = [step.get("run", "") for step in job["steps"]]
        verify = next(i for i, r in enumerate(runs) if "cosign verify" in r)
        scan = next(i for i, r in enumerate(runs) if "supply_chain.py inspect" in r)
        self.assertLess(verify, scan)
        self.assertIn("shared/release/candidate.pub", runs[verify])
        self.assertNotIn("luminusos.pub", runs[verify])
        command = runs[scan]
        policies = ROOT / "shared/release/exceptions"
        for edition, scope, excluded in (
            ("core", "core_payload", False),
            ("workstation", "workstation_payload", True),
            ("workstation", "installer_live", True),
        ):
            name = f"{edition}-{scope}-testing-45.json"
            digest = hashlib.sha256((policies / name).read_bytes()).hexdigest()
            line = next(
                item
                for item in command.splitlines()
                if f"--component-scope {scope}" in item
            )
            with self.subTest(scope=scope):
                self.assertIn(f"--exceptions shared/release/exceptions/{name}", line)
                self.assertIn(f"--policy-sha256 {digest}", line)
                self.assertIn(f"--edition {edition}", line)
                self.assertIn("--channel testing", line)
                self.assertIn('--fedora "$FEDORA"', line)
                self.assertEqual(
                    "--scan-exclusion shared/release/flatpak-scan-risk.json" in line,
                    excluded,
                )
        upload = next(
            step
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        )
        self.assertEqual(upload["with"]["name"], "candidate-scans")
        prepare = jobs["prepare-candidate"]
        self.assertIn("scan-candidates", prepare["needs"])
        self.assertIn("needs.scan-candidates.result == 'success'", prepare["if"])
        gates = next(
            s for s in prepare["steps"] if s.get("name") == "Bind real gate outcomes"
        )
        self.assertIn("needs.scan-candidates.result", gates["env"]["SCAN_RESULT"])

    def test_publish_callers_pass_candidate_environment_secrets(self):
        workflows = ROOT / ".github/workflows"
        publish = yaml.safe_load((workflows / "publish.yml").read_text())
        declared = set(publish.get("on", publish.get(True))["workflow_call"]["secrets"])
        staged = {
            name
            for job in publish["jobs"].values()
            if job.get("environment") == "candidate-staging"
            for name in re.findall(r"secrets\.([A-Z_]+)", str(job))
        } & declared
        self.assertTrue(
            {"CANDIDATE_COSIGN_PRIVATE_KEY", "CANDIDATE_COSIGN_PASSWORD"} <= staged
        )
        for name, job in publish["jobs"].items():
            read = set(re.findall(r"secrets\.([A-Z_]+)", str(job))) - {"GITHUB_TOKEN"}
            with self.subTest(job=name):
                if job.get("environment") == "candidate-staging":
                    self.assertLessEqual(read, declared)
                if any(secret.startswith("CANDIDATE_") for secret in read):
                    self.assertEqual(job.get("environment"), "candidate-staging")
        callers = 0
        for path in workflows.glob("*.yml"):
            for name, job in (yaml.safe_load(path.read_text())["jobs"] or {}).items():
                if job.get("uses") != "./.github/workflows/publish.yml":
                    continue
                callers += 1
                passed = job.get("secrets")
                with self.subTest(workflow=path.name, job=name):
                    self.assertIsInstance(passed, dict)
                    for secret in staged:
                        self.assertEqual(
                            passed.get(secret), f"${{{{ secrets.{secret} }}}}"
                        )
        self.assertGreater(callers, 0)

    def test_boot_test_runs_when_packaging_succeeds_despite_skipped_stable_jobs(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        condition = workflow["jobs"]["boot-test"]["if"]
        self.assertIn("!cancelled()", condition)
        self.assertNotIn("always()", condition)
        self.assertIn("needs.iso.result == 'success'", condition)
        self.assertIn("needs.qcow2.result == 'success'", condition)
        self.assertIn("inputs.inert_r2_probe == true", condition)

    def test_public_tag_writers_are_serialized_and_testing_enabled(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
        # Channels write disjoint tags, paths and releases, so each channel
        # serializes only with itself: a stable run waiting days for approval
        # must not hold back, or let GitHub cancel, testing publications.
        for job, channel in (("release", "testing"), ("release-stable", "stable")):
            with self.subTest(job=job):
                self.assertEqual(
                    workflow["jobs"][job]["concurrency"],
                    {
                        "group": f"image-publication-${{{{ github.repository }}}}-{channel}",
                        "cancel-in-progress": False,
                    },
                )
        group = workflow["concurrency"]["group"]
        self.assertIn(
            "format('luminus-release-{0}-{1}-{2}', github.repository,"
            " inputs.channel, github.ref_name)",
            group,
        )
        self.assertIn("luminus-inert-r2-", group)
        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        self.assertNotIn("require slice 5b", str(workflow["jobs"]["prepare-candidate"]))
        self.assertNotIn("require slice 5b", str(workflow["jobs"]["release"]))
        self.assertIn(
            "release_pipeline.py check-phase", str(workflow["jobs"]["inputs"])
        )
        release = workflow["jobs"]["release"]
        self.assertEqual(release["permissions"]["packages"], "write")
        login = next(
            step
            for step in release["steps"]
            if step.get("uses", "").startswith("docker/login-action@")
        )
        self.assertEqual(login["with"]["registry"], "ghcr.io")
        self.assertEqual(login["with"]["password"], "${{ secrets.GITHUB_TOKEN }}")

    def test_diagnostic_or_invalid_bypass_never_pushes_or_signs(self):
        for value in ("true", "", "False", "TRUE", "0", "invalid"):
            with (
                self.subTest(value=value),
                patch.dict(
                    sign_candidates.os.environ,
                    {"SECURITY_FINDINGS_BYPASS": value},
                    clear=True,
                ),
                patch.object(sign_candidates.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "diagnostic"),
            ):
                sign_candidates.push_and_sign("ghcr.io/luminusos/image:candidate-1-1")
            run.assert_not_called()

    def test_only_absent_or_false_bypass_allows_signing(self):
        digest = "sha256:" + "a" * 64
        pushed = subprocess.CompletedProcess(
            [], 0, stdout=f"digest: {digest} size: 123\n", stderr=""
        )
        for env in (
            {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
            {
                "SECURITY_FINDINGS_BYPASS": "false",
                "CANDIDATE_COSIGN_PRIVATE_KEY": "fixture",
            },
        ):
            with (
                self.subTest(env=env),
                patch.dict(sign_candidates.os.environ, env, clear=True),
                patch.object(
                    sign_candidates.subprocess, "run", side_effect=[pushed, None, None]
                ) as run,
            ):
                result = sign_candidates.push_and_sign(
                    "ghcr.io/luminusos/luminusos-candidates:core-candidate-1-1"
                )
                self.assertEqual(
                    result, f"ghcr.io/luminusos/luminusos-candidates@{digest}"
                )
                self.assertEqual(
                    [call.args[0][:2] for call in run.call_args_list],
                    [["docker", "push"], ["cosign", "sign"], ["cosign", "verify"]],
                )

    def test_diagnostic_blocks_normal_and_installer_only_cli(self):
        image = "ghcr.io/luminusos/luminusos-candidates:core-candidate-1-1"
        for arguments in ([image, image], ["--installer-only", image]):
            with (
                self.subTest(arguments=arguments),
                tempfile.TemporaryDirectory() as directory,
            ):
                output = Path(directory) / "output"
                with (
                    patch.dict(
                        sign_candidates.os.environ,
                        {
                            "SECURITY_FINDINGS_BYPASS": "true",
                            "CANDIDATE_COSIGN_PRIVATE_KEY": "fixture",
                            "GITHUB_OUTPUT": str(output),
                        },
                        clear=True,
                    ),
                    patch.object(sign_candidates.Path, "is_file", return_value=True),
                    patch.object(sys, "argv", ["sign_candidates.py", *arguments]),
                    patch.object(sign_candidates.subprocess, "run") as run,
                ):
                    self.assertEqual(sign_candidates.main(), 1)
                run.assert_not_called()
                self.assertFalse(output.exists())

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
                "SECURITY_FINDINGS_BYPASS": "true",
            }
            with (
                patch.dict(sign_candidates.os.environ, env),
                patch.object(
                    sys,
                    "argv",
                    ["sign_candidates.py", "--metadata", str(target), *images],
                ),
                patch.object(sign_candidates.subprocess, "run") as run,
            ):
                self.assertEqual(sign_candidates.main(), 0)
            run.assert_not_called()
            metadata = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(metadata["images"]["workstation"], images[1])
            self.assertEqual(metadata["run_id"], 123)

    def test_push_digest_is_signed_and_verified_before_return(self):
        digest = "sha256:" + "a" * 64
        pushed = subprocess.CompletedProcess(
            [], 0, stdout=f"digest: {digest} size: 123\n", stderr=""
        )
        with (
            patch.dict(
                sign_candidates.os.environ,
                {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
                clear=True,
            ),
            patch.object(
                sign_candidates.subprocess, "run", side_effect=[pushed, None, None]
            ) as run,
        ):
            result = sign_candidates.push_and_sign(
                "ghcr.io/luminusos/luminusos-candidates:core-candidate-1-1"
            )
        self.assertEqual(result, f"ghcr.io/luminusos/luminusos-candidates@{digest}")
        self.assertEqual(run.call_args_list[1].args[0][-1], result)
        self.assertEqual(run.call_args_list[2].args[0][-1], result)
        self.assertEqual(run.call_args_list[1].args[0][:2], ["cosign", "sign"])
        self.assertEqual(run.call_args_list[2].args[0][:2], ["cosign", "verify"])

    def test_missing_push_digest_never_signs(self):
        pushed = subprocess.CompletedProcess([], 0, stdout="success", stderr="")
        with (
            patch.dict(
                sign_candidates.os.environ,
                {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
                clear=True,
            ),
            patch.object(sign_candidates.subprocess, "run", return_value=pushed) as run,
            self.assertRaises(ValueError),
        ):
            sign_candidates.push_and_sign(
                "ghcr.io/luminusos/luminusos-candidates:core-candidate-1-1"
            )
        self.assertEqual(run.call_count, 1)

    def test_invalid_reference_never_pushes(self):
        with (
            patch.dict(
                sign_candidates.os.environ,
                {"CANDIDATE_COSIGN_PRIVATE_KEY": "fixture"},
                clear=True,
            ),
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
            "images": {
                role: "ghcr.io/org/luminusos-candidates@" + digest
                for role in ("core", "workstation", "installer")
            },
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
        for ref in ("refs/pull/4/merge", "refs/heads/release/x", "refs/heads/f45"):
            evidence = self.evidence()
            evidence["source"]["ref"] = ref
            with self.subTest(ref=ref):
                self.assertTrue(
                    any(
                        "release line" in error
                        for error in release_policy.validate_candidate(evidence)
                    )
                )

    def test_release_policy_binds_evidence_to_the_expected_line(self):
        evidence = self.evidence()
        evidence["source"]["ref"] = "refs/heads/release/45"
        self.assertEqual(release_policy.validate_candidate(evidence), [])
        self.assertEqual(
            release_policy.validate_candidate(
                evidence, expected_ref="refs/heads/release/45"
            ),
            [],
        )
        for expected in ("refs/heads/main", "refs/heads/release/46"):
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(
                        "release line" in error
                        for error in release_policy.validate_candidate(
                            evidence, expected_ref=expected
                        )
                    )
                )


class PromotionTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict("os.environ", {"GITHUB_REPOSITORY_OWNER": "org"})
        environment.start()
        self.addCleanup(environment.stop)
        self.real_inspect_version = promote_images.inspect_version
        inspection = patch.object(promote_images, "inspect_version", return_value=None)
        inspection.start()
        self.addCleanup(inspection.stop)

    def test_version_inspection_only_accepts_precise_missing_manifest(self):
        ref = "ghcr.io/org/luminusos:testing-45.20261105"
        for returncode, error, accepted in (
            (
                1,
                'time="now" level=fatal msg="reading manifest testing-45.20261105 in ghcr.io/org/luminusos: manifest unknown"',
                True,
            ),
            (
                2,
                (
                    'time="2026-11-16T09:04:42-03:00" level=fatal msg="Error parsing image name '
                    '\\"docker://ghcr.io/org/luminusos:testing-45.20261105\\": reading manifest '
                    'testing-45.20261105 in ghcr.io/org/luminusos: manifest unknown"'
                ),
                True,
            ),
            (1, "manifest unknown: manifest unknown", True),
            (2, "manifest unknown", True),
            (1, "unauthorized: access denied", False),
            (2, "unauthorized: access denied", False),
            (1, "connection refused", False),
            (3, "manifest unknown", False),
            (1, "manifest unknown: access denied", False),
            (
                2,
                (
                    "reading manifest testing-45.20261105 in ghcr.io/org/luminusos: "
                    "unauthorized: manifest unknown"
                ),
                False,
            ),
            (
                2,
                (
                    "reading manifest testing-45.20261105 in ghcr.io/org/other: "
                    "manifest unknown"
                ),
                False,
            ),
        ):
            with (
                self.subTest(returncode=returncode, error=error),
                patch.object(
                    promote_images.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(
                        returncode, "skopeo", stderr=error
                    ),
                ),
            ):
                if accepted:
                    self.assertIsNone(self.real_inspect_version(ref))
                else:
                    with self.assertRaisesRegex(
                        ValueError, "cannot inspect version tag"
                    ):
                        self.real_inspect_version(ref)
        with patch.object(
            promote_images.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="sha256:" + "a" * 64
            ),
        ):
            self.assertEqual(self.real_inspect_version(ref), "sha256:" + "a" * 64)

    def test_private_to_public_copy_signature_and_conflict(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        source = f"ghcr.io/org/luminusos-candidates@{digest}"
        evidence["images"] = {
            role: source for role in ("core", "workstation", "installer")
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_artifacts(root, evidence)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "signature"
            signature.touch()
            key = root / "candidate.pub"
            key.touch()
            version = "ghcr.io/org/luminusos:testing-45.20261105"
            destinations = [version, "ghcr.io/org/luminusos:testing-45"]

            def invoke(tags, existing_digest=digest):
                def command(argv, **kwargs):
                    if argv[:2] == ["skopeo", "inspect"]:
                        return subprocess.CompletedProcess(argv, 0, stdout=digest)
                    return subprocess.CompletedProcess(argv, 0, stdout="")

                with (
                    patch.dict("os.environ", {"GITHUB_REPOSITORY_OWNER": "Org"}),
                    patch.object(promote_images, "CANDIDATE_KEY", key),
                    patch.object(
                        promote_images,
                        "inspect_version",
                        return_value=existing_digest if tags else None,
                    ),
                    patch.object(
                        promote_images.subprocess, "run", side_effect=command
                    ) as run,
                ):
                    promote_images.promote(
                        source,
                        digest,
                        destinations,
                        key,
                        manifest,
                        signature,
                        "org/repository",
                        "c" * 40,
                        "core",
                    )
                return [call.args[0] for call in run.call_args_list]

            for tags in ([], ["testing-45.20261105"]):
                calls = invoke(tags)
                self.assertEqual(sum(c[:2] == ["skopeo", "copy"] for c in calls), 2)
                signs = [c for c in calls if c[:2] == ["cosign", "sign"]]
                self.assertEqual(len(signs), 1)
                self.assertEqual(signs[0][-1], f"ghcr.io/org/luminusos@{digest}")
                self.assertIn("env://COSIGN_PRIVATE_KEY", signs[0])
                version_copy = next(
                    i for i, c in enumerate(calls) if c[:2] == ["skopeo", "copy"]
                )
                signing = next(
                    i for i, c in enumerate(calls) if c[:2] == ["cosign", "sign"]
                )
                official_verify = next(
                    i
                    for i, c in enumerate(calls)
                    if c[:2] == ["cosign", "verify"]
                    and str(promote_images.OFFICIAL_KEY) in c
                )
                moving_copy = next(
                    i
                    for i, c in enumerate(calls)
                    if c[:2] == ["skopeo", "copy"] and c[-1].endswith(":testing-45")
                )
                self.assertLess(version_copy, signing)
                self.assertLess(signing, official_verify)
                self.assertLess(official_verify, moving_copy)
            with self.assertRaisesRegex(ValueError, "different digest"):
                invoke(["testing-45.20261105"], "sha256:" + "f" * 64)

    def test_public_repository_is_fixed_by_role_and_owner(self):
        with patch.dict("os.environ", {"GITHUB_REPOSITORY_OWNER": "Org"}):
            self.assertEqual(
                promote_images.public_repository("core", "org/repository"),
                "ghcr.io/org/luminusos",
            )
            self.assertEqual(
                promote_images.public_repository("installer", "org/repository"),
                "ghcr.io/org/luminusos-workstation",
            )
            with self.assertRaises(ValueError):
                promote_images.public_repository("core", "other/repository")

    def test_moving_tags_can_replace_other_digests(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        source = evidence["images"]["core"]
        prefix = "ghcr.io/org/luminusos:"
        targets = [
            prefix + "testing-45.20261105",
            prefix + "testing-45",
            prefix + "testing",
        ]
        registry = {targets[1]: "sha256:" + "f" * 64, targets[2]: "sha256:" + "f" * 64}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_artifacts(root, evidence)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "sig"
            signature.touch()

            def command(argv, **kwargs):
                if argv[:2] == ["skopeo", "inspect"]:
                    ref = argv[-1].removeprefix("docker://")
                    if ref == source:
                        return subprocess.CompletedProcess(argv, 0, stdout=digest)
                    if ref not in registry:
                        raise subprocess.CalledProcessError(
                            1, argv, stderr="manifest unknown"
                        )
                    return subprocess.CompletedProcess(argv, 0, stdout=registry[ref])
                if argv[:2] == ["skopeo", "copy"]:
                    registry[argv[-1].removeprefix("docker://")] = digest
                return subprocess.CompletedProcess(argv, 0, stdout="")

            with (
                patch.object(
                    promote_images, "inspect_version", self.real_inspect_version
                ),
                patch.object(promote_images.subprocess, "run", side_effect=command),
            ):
                promote_images.promote(
                    source,
                    digest,
                    targets,
                    promote_images.CANDIDATE_KEY,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            self.assertEqual([registry[target] for target in targets], [digest] * 3)

    def test_failed_official_signature_verification_never_moves_floating_tags(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_artifacts(root, evidence)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "sig"
            signature.touch()
            commands = [
                None,
                subprocess.CompletedProcess([], 0, stdout=digest),
                None,
                None,
                subprocess.CompletedProcess([], 0, stdout=digest),
                None,
                subprocess.CalledProcessError(1, "cosign"),
            ]
            with (
                patch.object(
                    promote_images.subprocess, "run", side_effect=commands
                ) as run,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                promote_images.promote(
                    evidence["images"]["core"],
                    digest,
                    [
                        "ghcr.io/org/luminusos:testing-45.20261105",
                        "ghcr.io/org/luminusos:testing",
                    ],
                    promote_images.CANDIDATE_KEY,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            copies = [
                c.args[0][-1]
                for c in run.call_args_list
                if c.args[0][:2] == ["skopeo", "copy"]
            ]
            self.assertEqual(
                copies, ["docker://ghcr.io/org/luminusos:testing-45.20261105"]
            )

    def test_missing_candidate_key_and_foreign_source_owner_are_rejected(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "sig"
            signature.touch()
            missing = root / "missing.pub"
            for source, key in (
                (evidence["images"]["core"], missing),
                (
                    "ghcr.io/other/luminusos-candidates@" + digest,
                    promote_images.CANDIDATE_KEY,
                ),
            ):
                with (
                    self.subTest(source=source, key=key),
                    patch.object(
                        promote_images,
                        "CANDIDATE_KEY",
                        missing if key == missing else promote_images.CANDIDATE_KEY,
                    ),
                    patch.object(promote_images.subprocess, "run") as run,
                    self.assertRaises(ValueError),
                ):
                    promote_images.promote(
                        source,
                        digest,
                        ["ghcr.io/org/luminusos:testing-45.20261105"],
                        key,
                        manifest,
                        signature,
                        "org/repository",
                        "c" * 40,
                        "core",
                    )
                run.assert_not_called()
            foreign = root / "foreign.pub"
            foreign.write_text("-----BEGIN PUBLIC KEY-----\n")
            for key in (foreign, promote_images.OFFICIAL_KEY):
                with (
                    self.subTest(trusted_key=key.name),
                    patch.object(promote_images.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "candidate key required"),
                ):
                    promote_images.promote(
                        evidence["images"]["core"],
                        digest,
                        ["ghcr.io/org/luminusos:testing-45.20261105"],
                        key,
                        manifest,
                        signature,
                        "org/repository",
                        "c" * 40,
                        "core",
                    )
                run.assert_not_called()

    def test_rejects_wrong_destinations_and_digests_before_registry_access(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        source = evidence["images"]["core"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            for bad_source, expected, destinations in (
                (
                    source,
                    "sha256:" + "f" * 64,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
                ),
                (
                    source,
                    digest,
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                ),
                (source, digest, ["ghcr.io/other/luminusos:testing-45.20261105"]),
                (source, digest, ["ghcr.io/org/luminusos:latest"]),
                (source, digest, ["ghcr.io/org/luminusos:testing-45.20261105-iso"]),
            ):
                with (
                    self.subTest(source=bad_source, destinations=destinations),
                    patch.object(promote_images.subprocess, "run") as run,
                    self.assertRaises(ValueError),
                ):
                    promote_images.promote(
                        bad_source,
                        expected,
                        destinations,
                        promote_images.CANDIDATE_KEY,
                        manifest,
                        root / "signature",
                        "org/repository",
                        "c" * 40,
                        "core",
                    )
                run.assert_not_called()

    def test_post_copy_digest_change_prevents_official_signing(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_artifacts(root, evidence)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "sig"
            signature.touch()
            commands = [
                None,
                subprocess.CompletedProcess([], 0, stdout=digest),
                None,
                None,
                subprocess.CompletedProcess([], 0, stdout="sha256:" + "f" * 64),
            ]
            with (
                patch.object(
                    promote_images.subprocess, "run", side_effect=commands
                ) as run,
                self.assertRaisesRegex(ValueError, "changed digest"),
            ):
                promote_images.promote(
                    evidence["images"]["core"],
                    digest,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
                    promote_images.CANDIDATE_KEY,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            self.assertFalse(
                any(c.args[0][:2] == ["cosign", "sign"] for c in run.call_args_list)
            )

    def test_final_tag_recheck_detects_change_after_copy(self):
        evidence = ReleasePolicyTests().evidence()
        digest = evidence["candidate_digest"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_artifacts(root, evidence)
            manifest = root / "evidence.json"
            manifest.write_text(json.dumps(evidence))
            signature = root / "sig"
            signature.touch()
            commands = [
                None,
                subprocess.CompletedProcess([], 0, stdout=digest),
                None,
                None,
                subprocess.CompletedProcess([], 0, stdout=digest),
                None,
                None,
                subprocess.CompletedProcess([], 0, stdout="sha256:" + "f" * 64),
            ]
            with (
                patch.object(
                    promote_images.subprocess, "run", side_effect=commands
                ) as run,
                self.assertRaisesRegex(ValueError, "changed after promotion"),
            ):
                promote_images.promote(
                    evidence["images"]["core"],
                    digest,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
                    promote_images.CANDIDATE_KEY,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            self.assertTrue(
                any(c.args[0][:2] == ["cosign", "sign"] for c in run.call_args_list)
            )

    def test_missing_evidence_refuses_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "evidence"),
            ):
                promote_images.promote(
                    "ghcr.io/org/luminusos-candidates@sha256:" + "a" * 64,
                    "sha256:" + "a" * 64,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
                    promote_images.CANDIDATE_KEY,
                    Path(temporary) / "absent",
                    Path(temporary) / "sig",
                    "org/repository",
                    "c" * 40,
                    "core",
                )
            run.assert_not_called()

    def write_artifacts(self, root, evidence):
        for name, entry in evidence["evidence"].items():
            data = ("evidence:" + name).encode()
            (root / entry["artifact"]).write_bytes(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()

    def test_unbound_core_and_installer_never_contact_registry(self):
        evidence = ReleasePolicyTests().evidence()
        digest = "sha256:" + "a" * 64
        evidence["images"] = {
            "core": "ghcr.io/org/luminusos-candidates@" + digest,
            "workstation": "ghcr.io/org/luminusos-candidates@" + digest,
            "installer": "ghcr.io/org/luminusos-candidates@sha256:" + "b" * 64,
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
                        ["ghcr.io/org/luminusos:testing-45.20261105"],
                        promote_images.CANDIDATE_KEY,
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
        core = "ghcr.io/org/luminusos-candidates@" + core_digest
        evidence["images"] = {
            "core": core,
            "workstation": "ghcr.io/org/luminusos-candidates@"
            + evidence["candidate_digest"],
            "installer": "ghcr.io/org/luminusos-candidates@sha256:" + "e" * 64,
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
            key = promote_images.CANDIDATE_KEY
            inspect = subprocess.CompletedProcess([], 0, stdout=core_digest)
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                ],
            ) as run:
                promote_images.promote(
                    core,
                    core_digest,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
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
                    "ghcr.io/org/luminusos-candidates@sha256:" + "f" * 64,
                    core_digest,
                    ["ghcr.io/org/luminusos:testing-45.20261105"],
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
            key = promote_images.CANDIDATE_KEY
            inspect = subprocess.CompletedProcess(
                [], 0, stdout=evidence["candidate_digest"]
            )
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                ],
            ) as run:
                promote_images.promote(
                    evidence["images"]["workstation"],
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "workstation",
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
            key = promote_images.CANDIDATE_KEY
            inspect = subprocess.CompletedProcess(
                [], 0, stdout=evidence["candidate_digest"]
            )
            source = evidence["images"]["workstation"]
            with patch.object(
                promote_images.subprocess,
                "run",
                side_effect=[
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                    None,
                    None,
                    inspect,
                ],
            ) as run:
                promote_images.promote(
                    source,
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "workstation",
                )
            self.assertEqual(run.call_args_list[2].args[0][-1], source)
            self.assertEqual(run.call_args_list[3].args[0][4], "docker://" + source)

    def test_missing_gate_blocks_all_registry_mutations(self):
        evidence = ReleasePolicyTests().evidence()
        evidence["gates"]["installation"] = False
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            key = promote_images.CANDIDATE_KEY
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "installation"),
            ):
                promote_images.promote(
                    evidence["images"]["workstation"],
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    evidence_path,
                    Path(directory) / "signature",
                    "org/repository",
                    "c" * 40,
                    "workstation",
                )
            run.assert_not_called()

    def test_foreign_signature_key_blocks_copy(self):
        evidence = ReleasePolicyTests().evidence()
        with tempfile.TemporaryDirectory() as directory:
            self.write_artifacts(Path(directory), evidence)
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            key = promote_images.CANDIDATE_KEY
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
                    evidence["images"]["workstation"],
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    evidence_path,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "workstation",
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
            key = promote_images.CANDIDATE_KEY
            with (
                patch.object(
                    promote_images.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "cosign"),
                ) as run,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                promote_images.promote(
                    evidence["images"]["workstation"],
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "workstation",
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
            key = promote_images.CANDIDATE_KEY
            (root / evidence["evidence"]["installation"]["artifact"]).write_text(
                "tampered"
            )
            with (
                patch.object(promote_images.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "checksum mismatch"),
            ):
                promote_images.promote(
                    evidence["images"]["workstation"],
                    evidence["candidate_digest"],
                    ["ghcr.io/org/luminusos-workstation:testing-45.20261105"],
                    key,
                    manifest,
                    signature,
                    "org/repository",
                    "c" * 40,
                    "workstation",
                )
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:2], ["cosign", "verify-blob"])


class ContainerWorkflowTests(unittest.TestCase):
    def load_workflow(self, name):
        return yaml.load(
            (ROOT / ".github/workflows" / name).read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )

    def assert_container_security_contract(self, workflow, private=False):
        jobs = workflow["jobs"]
        permissions = {
            "metadata": {"contents": "read"},
            "core": {"contents": "read", "packages": "read"},
            "workstation": {"contents": "read", "packages": "read", "actions": "read"},
            "installer": {"contents": "read", "packages": "read", "actions": "read"},
        }
        private_permissions = {
            "private-core": {"contents": "read"},
            "private-core-attest": {
                "contents": "read",
                "actions": "read",
                "id-token": "write",
                "attestations": "write",
            },
        }
        if private:
            permissions = private_permissions
            self.assertEqual(
                workflow["on"]["workflow_call"].get("secrets"),
                {
                    "CORE_R2_WRITER_ACCESS_KEY_ID": {"required": "true"},
                    "CORE_R2_WRITER_SECRET_ACCESS_KEY": {"required": "true"},
                    "CORE_R2_READER_ACCESS_KEY_ID": {"required": "true"},
                    "CORE_R2_READER_SECRET_ACCESS_KEY": {"required": "true"},
                },
            )
        self.assertEqual(set(jobs), set(permissions))
        if not private:
            for name in ("metadata", "core", "workstation"):
                self.assertNotIn("if", jobs[name], name)
            self.assertNotIn("private_core", str(workflow))
            self.assertEqual(
                jobs["installer"]["if"],
                "always() && inputs.build_installer && needs.metadata.result == 'success' && needs.workstation.result == 'success'",
            )
        else:
            self.assert_private_job_contract(jobs)

        secret_steps = (
            {
                ("private-core", "Transport private producer archive"): {
                    "R2_ACCESS_KEY_ID": "${{ secrets.CORE_R2_WRITER_ACCESS_KEY_ID }}",
                    "R2_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_WRITER_SECRET_ACCESS_KEY }}",
                },
                ("private-core-attest", "Check actual private producer object"): {
                    "R2_ACCESS_KEY_ID": "${{ secrets.CORE_R2_READER_ACCESS_KEY_ID }}",
                    "R2_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_READER_SECRET_ACCESS_KEY }}",
                    "GH_TOKEN": "${{ github.token }}",
                },
            }
            if private
            else {}
        )
        self.assertNotIn("secrets.", str(workflow.get("env", {})))
        self.assertNotIn("R2_", str(workflow.get("env", {})))
        seen = []
        for name, job in jobs.items():
            self.assertEqual(job["permissions"], permissions[name], name)
            self.assertNotIn("secrets", job, name)
            job_settings = {k: v for k, v in job.items() if k != "steps"}
            self.assertNotIn("secrets.", str(job_settings), name)
            self.assertNotIn("R2_", str(job_settings), name)
            self.assertNotIn("GH_TOKEN", job.get("env", {}), name)
            for step in job.get("steps", []):
                if "docker/build-push-action" in step.get("uses", ""):
                    self.assertEqual(step["with"].get("push"), "false")
                key = (name, step.get("name"))
                if key in secret_steps:
                    seen.append(key)
                    credentials = secret_steps[key]
                    self.assertEqual(
                        set(step["env"]), {*credentials, "CORE_HANDOFF_FACTS"}
                    )
                    for variable, reference in credentials.items():
                        self.assertEqual(step["env"][variable], reference)
                    remaining = copy.deepcopy(step)
                    for variable in credentials:
                        del remaining["env"][variable]
                    self.assertNotIn("secrets.", str(remaining))
                    self.assertNotIn("R2_", str(remaining))
                else:
                    self.assertNotIn("secrets.", str(step), key)
                    self.assertNotIn("R2_", str(step), key)
        self.assertCountEqual(seen, secret_steps)

    def assert_private_job_contract(self, jobs):
        steps = {
            "private-core": [
                "Validate independent operator policy",
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "Install trusted OCI tooling",
                "Build and export private core",
                "Pack checked producer output",
                "Terminate builder before credential transport",
                "Transport private producer archive",
            ],
            "private-core-attest": [
                "Validate independent operator policy",
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "Check actual private producer object",
                "Attest checked local archive with native provenance",
            ],
        }
        context = '{"repository":${{ toJSON(github.repository) }},"repository_id":${{ toJSON(github.repository_id) }},"sha":${{ toJSON(github.sha) }},"ref":${{ toJSON(github.ref) }},"event_name":${{ toJSON(github.event_name) }},"workflow_ref":${{ toJSON(github.workflow_ref) }},"run_id":${{ toJSON(github.run_id) }},"run_attempt":${{ toJSON(github.run_attempt) }}}'
        for name, job in jobs.items():
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
            self.assertEqual(
                job["timeout-minutes"], "150" if name == "private-core" else "30"
            )
            self.assertEqual(
                job["env"],
                {
                    "CORE_HANDOFF_POLICY": "${{ vars.CORE_HANDOFF_POLICY }}",
                    "CORE_HANDOFF_CONTEXT": context,
                },
            )
            self.assertEqual(
                [step.get("name", step.get("uses")) for step in job["steps"]],
                steps[name],
            )
            for step in job["steps"]:
                if step.get("id") == "policy":
                    self.assertEqual(
                        step["env"],
                        {
                            "CORE_HANDOFF_JOB": "${{ toJSON(job) }}",
                            "CORE_RUNNER_ENVIRONMENT": "${{ runner.environment }}",
                            "ACTION_CLOSURE": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\nactions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
                        },
                    )
                elif step.get("name") not in (
                    "Transport private producer archive",
                    "Check actual private producer object",
                ):
                    self.assertNotIn("env", step)
        self.assertEqual(
            jobs["private-core"]["if"],
            "inputs.private_core_handoff && github.event_name == 'workflow_dispatch' && github.repository == 'luminusOS/images' && !inputs.publish && !inputs.build_installer && inputs.channel == 'testing'",
        )
        self.assertNotIn("needs", jobs["private-core"])
        self.assertEqual(jobs["private-core"]["environment"], "core-candidate-writer")
        self.assertEqual(jobs["private-core-attest"]["needs"], ["private-core"])
        self.assertEqual(
            jobs["private-core-attest"]["if"],
            "inputs.private_core_handoff && github.event_name == 'workflow_dispatch' && needs.private-core.result == 'success'",
        )
        self.assertEqual(
            jobs["private-core-attest"]["environment"], "core-candidate-reader"
        )

    def test_private_core_security_contract_rejects_mutations(self):
        originals = {
            False: self.load_workflow("containers.yml"),
            True: self.load_workflow("private-core-producer.yml"),
        }
        for private, original in originals.items():
            self.assert_container_security_contract(original, private)
        mutations = [
            (
                "legacy build credential",
                "core",
                "Build core",
                "env",
                {
                    "R2_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_WRITER_SECRET_ACCESS_KEY }}"
                },
            ),
            (
                "private host build credential",
                "private-core",
                "Build and export private core",
                "env",
                {
                    "R2_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_WRITER_SECRET_ACCESS_KEY }}"
                },
            ),
            (
                "wrong writer environment",
                "private-core",
                None,
                "environment",
                "unprotected",
            ),
            (
                "wrong reader environment",
                "private-core-attest",
                None,
                "environment",
                "unprotected",
            ),
            (
                "changed legacy core condition",
                "core",
                None,
                "if",
                "inputs.private_core_handoff",
            ),
            ("changed legacy metadata condition", "metadata", None, "if", "true"),
            (
                "writer token escalation",
                "private-core",
                None,
                "permissions",
                {"contents": "read", "id-token": "write"},
            ),
            (
                "legacy token escalation",
                "core",
                None,
                "permissions",
                {"contents": "read", "packages": "read", "id-token": "write"},
            ),
            (
                "attester package escalation",
                "private-core-attest",
                None,
                "permissions",
                {
                    "contents": "read",
                    "actions": "read",
                    "id-token": "write",
                    "attestations": "write",
                    "packages": "write",
                },
            ),
            ("inherited job secrets", "private-core", None, "secrets", "inherit"),
            (
                "job-level credential",
                "private-core",
                None,
                "env",
                {"R2_ACCESS_KEY_ID": "${{ secrets.CORE_R2_WRITER_ACCESS_KEY_ID }}"},
            ),
            (
                "unapproved transport env",
                "private-core",
                "Transport private producer archive",
                "env",
                {
                    "R2_ACCESS_KEY_ID": "${{ secrets.CORE_R2_READER_ACCESS_KEY_ID }}",
                    "R2_SECRET_ACCESS_KEY": "${{ secrets.CORE_R2_READER_SECRET_ACCESS_KEY }}",
                    "CORE_HANDOFF_FACTS": "{}",
                },
            ),
            (
                "missing writer success dependency",
                "private-core-attest",
                None,
                "needs",
                [],
            ),
            (
                "private PR gate",
                "private-core",
                None,
                "if",
                "inputs.private_core_handoff",
            ),
        ]
        for label, job_name, step_name, field, value in mutations:
            with self.subTest(mutation=label):
                private = job_name.startswith("private-core")
                mutated = copy.deepcopy(originals[private])
                target = mutated["jobs"][job_name]
                if step_name:
                    target = next(
                        s for s in target["steps"] if s.get("name") == step_name
                    )
                target[field] = value
                with self.assertRaises(AssertionError):
                    self.assert_container_security_contract(mutated, private)
        mutated = copy.deepcopy(originals[True])
        mutated["jobs"]["private-core-extra"] = copy.deepcopy(
            mutated["jobs"]["private-core"]
        )
        with self.assertRaises(AssertionError):
            self.assert_container_security_contract(mutated, True)

    def test_private_core_requires_exact_named_secrets_from_caller(self):
        self.assert_container_security_contract(
            self.load_workflow("private-core-producer.yml"), True
        )

    def test_private_core_rejects_missing_optional_and_extra_secrets(self):
        original = self.load_workflow("private-core-producer.yml")
        self.assert_container_security_contract(original, True)
        mutated = copy.deepcopy(original)
        del mutated["on"]["workflow_call"]["secrets"]
        with self.assertRaises(AssertionError):
            self.assert_container_security_contract(mutated, True)
        for name in original["on"]["workflow_call"]["secrets"]:
            for declaration in (None, {}, {"required": "false"}):
                with self.subTest(secret=name, declaration=declaration):
                    mutated = copy.deepcopy(original)
                    secrets = mutated["on"]["workflow_call"]["secrets"]
                    if declaration is None:
                        del secrets[name]
                    else:
                        secrets[name] = declaration
                    with self.assertRaises(AssertionError):
                        self.assert_container_security_contract(mutated, True)
        mutated = copy.deepcopy(original)
        mutated["on"]["workflow_call"]["secrets"]["UNEXPECTED_SECRET"] = {
            "required": "true"
        }
        with self.assertRaises(AssertionError):
            self.assert_container_security_contract(mutated, True)

    def test_private_opt_in_defaults_off_without_changing_legacy_caller_routes(self):
        private = self.load_workflow("private-core-producer.yml")
        self.assertEqual(set(private["on"]), {"workflow_call"})
        call = private["on"]["workflow_call"]
        inputs = call["inputs"]
        self.assertEqual(
            set(inputs),
            {"channel", "build_installer", "publish", "private_core_handoff"},
        )
        self.assertEqual(
            set(call["outputs"]),
            {
                "private_core_key",
                "private_core_policy_sha256",
                "private_core_archive_sha256",
                "private_core_archive_size",
                "private_core_manifest_digest",
            },
        )
        self.assertEqual(
            inputs["private_core_handoff"], {"type": "boolean", "default": "false"}
        )
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path.name not in (
                "private-core-producer.yml",
                "private-core-handoff.yml",
            ):
                self.assertNotIn("private-core-producer.yml", path.read_text())
        self.assertNotIn(
            "private_core_handoff",
            self.load_workflow("containers.yml")["on"]["workflow_call"]["inputs"],
        )
        for name in ("build-containers.yml", "auto-testing.yml", "publish.yml"):
            for job in self.load_workflow(name)["jobs"].values():
                if job.get("uses") == "./.github/workflows/containers.yml":
                    self.assertEqual(
                        job["with"].get("private_core_handoff", "false"), "false"
                    )
                    self.assertEqual(job["with"]["publish"], "false")
                    self.assertNotIn("secrets", job)
                    self.assertEqual(
                        job["permissions"],
                        {"contents": "read", "packages": "read", "actions": "read"},
                    )

    def test_resume_imports_original_candidate_without_rebuilding(self):
        workflow = self.load_workflow("publish.yml")
        jobs = workflow["jobs"]
        self.assertIn("inputs.candidate_run_id == ''", jobs["containers"]["if"])
        resume = jobs["release"]
        self.assertEqual(resume["needs"], ["quality", "inputs", "release-evidence"])
        self.assertIn("inputs.candidate_run_id != ''", resume["if"])
        self.assertIn("inputs.validation_run_id != ''", resume["if"])
        commands = "\n".join(step.get("run", "") for step in resume["steps"])
        self.assertIn("fetch-candidate", commands)
        evidence_commands = "\n".join(
            step.get("run", "") for step in jobs["release-evidence"]["steps"]
        )
        self.assertIn("fetch-validation", evidence_commands)
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
            caller["permissions"],
            {"contents": "read", "packages": "read", "actions": "read"},
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
        self.assert_container_security_contract(workflow)

    def test_reusable_installer_workflow_is_read_only_and_uses_approved_payload(self):
        workflow = self.load_workflow("installer.yml")
        build = workflow["jobs"]["build"]
        self.assertEqual(
            build["permissions"],
            {"contents": "read", "packages": "read", "actions": "read"},
        )
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
        self.assertNotIn("if", load)
        self.assertEqual(
            load["env"]["ARCHIVE_SHA256"], "${{ inputs.workstation_archive_sha256 }}"
        )
        self.assertEqual(load["env"]["IMAGE_ID"], "${{ inputs.workstation_image_id }}")
        self.assertFalse(
            any(step.get("name") == "Export installer payload" for step in steps)
        )
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
                            "prepare",
                            "release",
                            "release-stable",
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

    def test_every_channel_builds_core_and_workstation_from_source(self):
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
        self.assertNotIn("if", workflow["jobs"]["core"])
        self.assertNotIn("if", workflow["jobs"]["workstation"])
        self.assertNotIn("promote_version", workflow["on"]["workflow_call"]["inputs"])
        self.assertEqual(workflow["jobs"]["workstation"]["needs"], ["metadata", "core"])

    def test_packaging_waits_for_staged_candidates_of_either_channel(self):
        workflow = self.load_workflow("publish.yml")
        for name in ("iso", "qcow2"):
            with self.subTest(job=name):
                job = workflow["jobs"][name]
                self.assertEqual(job["needs"], ["containers", "publish-images"])
                self.assertIn("needs.publish-images.result == 'success'", job["if"])
                self.assertNotIn("inputs.channel", job["if"])

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
