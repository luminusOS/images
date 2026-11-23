import copy
import importlib.util
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_policy_base_risk", ROOT / ".github/scripts/workflow/release_policy.py"
)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)

RECORD = json.loads((ROOT / "shared/release/base-trust-risk.json").read_text())
BASE = "quay.io/fedora/fedora-bootc@sha256:" + "a" * 64
NOW = datetime(2026, 11, 20, tzinfo=UTC)


def errors(record=RECORD, base=BASE, version="45", now=NOW):
    return policy.validate_base_risk(record, base, version, now)


class BaseTrustRiskTests(unittest.TestCase):
    def test_recorded_risk_accepts_digest_pinned_fedora_base(self):
        self.assertEqual(errors(), [])

    def test_risk_is_owned_and_expires_within_thirty_days(self):
        accepted = datetime.fromisoformat(RECORD["accepted_at"])
        expires = datetime.fromisoformat(RECORD["expires_at"])
        self.assertTrue(RECORD["owner"])
        self.assertLess(accepted, expires)
        self.assertLessEqual(expires - accepted, timedelta(days=30))

    def test_expired_or_not_yet_accepted_risk_is_rejected(self):
        expires = datetime.fromisoformat(RECORD["expires_at"])
        accepted = datetime.fromisoformat(RECORD["accepted_at"])
        self.assertTrue(errors(now=expires))
        self.assertTrue(errors(now=accepted - timedelta(seconds=1)))

    def test_floating_foreign_or_other_release_base_is_rejected(self):
        for base, version in (
            ("quay.io/fedora/fedora-bootc:45", "45"),
            ("quay.io/fedora/fedora-bootc@sha256:" + "A" * 64, "45"),
            ("quay.io/evil/fedora-bootc@sha256:" + "a" * 64, "45"),
            ("quay.io/fedora/fedora-bootc@sha256:" + "a" * 64 + "x", "45"),
            (BASE, "44"),
            (BASE, 45),
        ):
            with self.subTest(base=base, version=version):
                self.assertTrue(errors(base=base, version=version))

    def test_incomplete_or_overlong_records_are_rejected(self):
        for change in (
            lambda r: r.update(owner=""),
            lambda r: r.pop("expires_at"),
            lambda r: r.update(expires_at="2026-12-17T00:00:00Z"),
            lambda r: r.update(expires_at="2026-12-01T00:00:00"),
            lambda r: r.update(kind="other"),
            lambda r: r.update(schema_version=2),
            lambda r: r.update(mitigations=[]),
            lambda r: r.update(mitigations=[""]),
            lambda r: r.update(mitigations="digest pin"),
            lambda r: r.update(schema_version=True),
            lambda r: r.update(fedora_version=45),
        ):
            record = copy.deepcopy(RECORD)
            change(record)
            with self.subTest(record=record):
                self.assertTrue(errors(record=record))
        self.assertTrue(errors(record=[]))

    def test_repository_must_be_a_registry_path(self):
        digest = "@sha256:" + "a" * 64
        for repository, base in (
            ("", digest),
            ("fedora-bootc", "fedora-bootc" + digest),
            (
                "quay.io/fedora/fedora-bootc:45",
                "quay.io/fedora/fedora-bootc:45" + digest,
            ),
            ("quay.io/Fedora/fedora-bootc", "quay.io/Fedora/fedora-bootc" + digest),
        ):
            record = {**RECORD, "repository": repository}
            with self.subTest(repository=repository):
                self.assertTrue(errors(record=record, base=base))

    def test_integer_release_on_both_sides_is_rejected(self):
        self.assertTrue(errors(record={**RECORD, "fedora_version": 45}, version=45))

    def test_naive_evaluation_clock_is_rejected(self):
        self.assertTrue(errors(now=NOW.replace(tzinfo=None)))


if __name__ == "__main__":
    unittest.main()


class StableRecordsTests(unittest.TestCase):
    def test_stable_base_risk_is_in_force_for_fedora_45_only(self):
        record = json.loads(
            (ROOT / "shared/release/base-trust-risk-stable.json").read_text()
        )
        self.assertEqual(errors(record), [])
        self.assertTrue(errors(record, version="46"))
        self.assertTrue(
            errors(record, base="quay.io/other/fedora-bootc@sha256:" + "a" * 64)
        )

    def test_stable_flatpak_exclusion_is_valid_for_workstation_only(self):
        spec = importlib.util.spec_from_file_location(
            "supply_chain_stable_records",
            ROOT / ".github/scripts/workflow/supply_chain.py",
        )
        chain = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(chain)
        path = ROOT / "shared/release/flatpak-scan-risk-stable.json"
        for scope in ("workstation_payload", "installer_live"):
            context = {
                "edition": "workstation",
                "component_scope": scope,
                "channel": "stable",
                "fedora": "45",
            }
            self.assertEqual(
                chain._scan_exclusion(path, context, NOW)["path"], "/var/lib/flatpak"
            )
        with self.assertRaises(chain.SupplyChainError):
            chain._scan_exclusion(
                path,
                {
                    "edition": "core",
                    "component_scope": "core_payload",
                    "channel": "stable",
                    "fedora": "45",
                },
                NOW,
            )
