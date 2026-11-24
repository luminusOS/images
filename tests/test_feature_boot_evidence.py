import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / ".github/scripts/workflow")
)

import feature_boot_evidence as evidence


class FeatureBootEvidenceTests(unittest.TestCase):
    def test_promotion_verifier_does_not_consume_isolated_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "feature-boot.json").write_text(
                json.dumps(
                    {"schema": 1, "scope": "isolated-testing; not promotion evidence"}
                )
            )
            with (
                patch.object(
                    evidence.pipeline,
                    "binding",
                    return_value={"candidate_digest": "sha256:" + "b" * 64},
                ),
                patch.object(
                    evidence, "platform_manifest", return_value="sha256:" + "a" * 64
                ),
                patch.object(evidence.pipeline, "verify"),
                self.assertRaisesRegex(
                    ValueError, "feature boot receipt does not match candidate"
                ),
            ):
                evidence.validate(root, {}, "dummy")

    def test_observation_requires_a_real_reboot_exact_digest_and_enforcing_activation(
        self,
    ):
        manifest = "sha256:" + "a" * 64
        raw = "b" * 64
        version = "45.20261118.2"
        observation = {
            "before_boot_id": "12345678-1234-1234-1234-123456789abc",
            "after_boot_id": "12345678-1234-1234-1234-123456789abd",
            "platform_manifest_digest": manifest,
            "raw_sha256": raw,
            "fetched": [
                f"/{version}/luminusos-dummy_{version}.raw.xz",
                f"/{version}/release.json.gpg",
            ],
            "discovered_features": ["dummy"],
            "selinux": "Enforcing",
            "service": "active",
            "merge": "provisioned",
        }
        evidence.validate_observation(observation, version, manifest, raw)
        for name, wrong in (
            ("after_boot_id", observation["before_boot_id"]),
            ("platform_manifest_digest", "sha256:" + "0" * 64),
            ("raw_sha256", "c" * 64),
            ("fetched", []),
            ("discovered_features", ["dummy", "unknown"]),
            ("selinux", "Permissive"),
            ("service", "inactive"),
            ("merge", "pending"),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.validate_observation(
                    observation | {name: wrong}, version, manifest, raw
                )

    def test_platform_manifest_uses_the_raw_index_hash_and_one_amd64_entry(self):
        manifest = "sha256:" + "a" * 64
        entry = {
            "platform": {"os": "linux", "architecture": "amd64"},
            "digest": manifest,
            "mediaType": evidence.MANIFEST_TYPES[0],
        }
        index = {
            "schemaVersion": 2,
            "mediaType": evidence.INDEX_TYPES[0],
            "manifests": [entry],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_index = root / "workstation-oci.json"
            raw_index.write_text(json.dumps(index))
            binding = "sha256:" + hashlib.sha256(raw_index.read_bytes()).hexdigest()
            self.assertEqual(evidence.platform_manifest(root, binding), manifest)
            with self.assertRaises(ValueError):
                evidence.platform_manifest(root, "sha256:" + "0" * 64)
            raw_index.write_text(json.dumps(index | {"manifests": [entry, entry]}))
            with self.assertRaises(ValueError):
                evidence.platform_manifest(
                    root, "sha256:" + hashlib.sha256(raw_index.read_bytes()).hexdigest()
                )
