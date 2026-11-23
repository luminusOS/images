import copy
import datetime as dt
import hashlib
import json
import re
import tomllib
import unittest
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def fixture_utc_timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",
        value,
    ):
        return False
    dt.datetime.fromisoformat(value)
    return True


def fixture_https_uri(value):
    if not isinstance(value, str) or any(c.isspace() for c in value):
        return False
    parsed = urlsplit(value)
    port = parsed.port
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and (port is None or port > 0)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def fixture_bytes(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def fixture_hash(value):
    return hashlib.sha256(fixture_bytes(value)).hexdigest()


def fixture_exception_matches(exception, finding):
    fields = (
        "advisory",
        "package",
        "package_version",
        "edition",
        "component_scope",
        "channel",
        "fedora",
        "component_type",
    )
    return all(exception[field] == finding[field] for field in fields) and (
        exception["component_type"] != "embedded_go"
        or exception["binary"] == finding["binary"]
    )


def rebind_fixture_candidate(bundle):
    candidate = bundle["candidate"]
    binding = {
        "identity": candidate["identity"],
        "candidate_sha256": fixture_hash(candidate),
    }
    validation = bundle["validation"]
    validation["binding"] = copy.deepcopy(binding)
    validation["signature"]["subject_sha256"] = binding["candidate_sha256"]
    for receipt in validation["receipts"]:
        receipt["binding"] = copy.deepcopy(binding)
    for receipt in validation["receipts"]:
        if receipt["control"] in ("sirius_install", "update", "rollback", "final_boot"):
            phase = "live" if receipt["control"] == "sirius_install" else "installed"
            channel = next(
                r
                for r in validation["receipts"]
                if r["edition"] == receipt["edition"]
                and r["control"] == "control_channel"
                and r["phase"] == phase
            )
            receipt["observations"]["channel_receipt_sha256"] = fixture_hash(channel)


def example_bundle(fixtures, profile):
    candidate = copy.deepcopy(fixtures["candidate"])
    identity = candidate["identity"]
    identity.update(profile["identity"])
    policy = copy.deepcopy(fixtures["policy"])
    for exception in policy["exceptions"]:
        exception["channel"] = identity["channel"]
        exception["fedora"] = identity["fedora"]
        exception["edition"] = (
            "workstation" if identity["selection"] == "workstation" else "core"
        )
        exception["component_scope"] = (
            "workstation_payload"
            if exception["edition"] == "workstation"
            else "core_payload"
        )
    identity["policy_sha256"] = fixture_hash(policy)
    selection = identity["selection"]
    editions = ["core", "workstation"] if selection == "all" else [selection]
    candidate["components"] = {
        name: copy.deepcopy(fixtures["components"][name])
        for name in editions + (["installer"] if "workstation" in editions else [])
    }
    candidate["artifacts"] = (
        copy.deepcopy(fixtures["artifacts"]) if "workstation" in editions else {}
    )
    for format_name, artifact in candidate["artifacts"].items():
        prefix = "testing-" if identity["channel"] == "testing" else ""
        artifact["path"] = (
            f"luminusos-workstation-{prefix}{identity['build_version']}.{format_name}"
        )
    candidate["installed"] = {
        edition: {
            "edition": edition,
            "channel": identity["channel"],
            "fedora": identity["fedora"],
            "reference": (
                f"ghcr.io/example/{'luminusos' if edition == 'core' else 'luminusos-workstation'}:"
                f"{'testing-' if identity['channel'] == 'testing' else ''}{identity['fedora']}"
            ),
            "digest": candidate["components"][edition]["digest"],
        }
        for edition in editions
    }
    candidate["core_dependency"] = copy.deepcopy(fixtures["core_dependency"])
    candidate["core_dependency"].update(
        channel=identity["channel"],
        fedora=identity["fedora"],
        source_ref=identity["source_ref"],
        policy_sha256=identity["policy_sha256"],
    )
    if profile.get("reuse_core"):
        candidate["core_dependency"].update(mode="reused", source_sha="c" * 40)
    candidate["validation_images"] = {}
    for edition in editions:
        images = copy.deepcopy(fixtures["validation_images"])
        for role, image in images.items():
            image["logical_reference"] = (
                f"{candidate['components'][edition]['repository']}@{image['digest']}"
            )
            if role == "update":
                image["derived_from"] = candidate["components"][edition]["digest"]
        candidate["validation_images"][edition] = images
    binding = {"candidate_sha256": fixture_hash(candidate), "identity": identity}
    receipts = []
    for edition in editions:
        controls = [
            (control, phase)
            for control in fixtures["editions"][edition]["controls"]
            for phase in (
                ["live", "installed"]
                if edition == "workstation" and control == "control_channel"
                else ["live"]
                if control in ("sirius_install", "live_isolation")
                else ["installed"]
            )
        ]
        for control, phase in controls:
            receipt = copy.deepcopy(fixtures["receipt"])
            receipt.update(
                edition=edition,
                control=control,
                phase=phase,
                binding=copy.deepcopy(binding),
                observations=copy.deepcopy(fixtures["observations"][control]),
            )
            if control == "control_channel":
                receipt["observations"].update(
                    vm_id=f"synthetic-{edition}-{phase}",
                    cid=43
                    if phase == "live"
                    else 44
                    if edition == "workstation"
                    else 42,
                    selinux_mode="Permissive" if phase == "live" else "Enforcing",
                )
            if control in ("first_boot", "final_boot"):
                receipt["observations"]["installed"] = candidate["installed"][edition]
                receipt["observations"]["iso_detached"] = (
                    True if edition == "workstation" else "not_applicable"
                )
            if control in ("update", "rollback"):
                observation = receipt["observations"]
                observation["reference"] = candidate["installed"][edition]["reference"]
                observation["from_digest" if control == "update" else "to_digest"] = (
                    candidate["components"][edition]["digest"]
                )
                observation["to_digest" if control == "update" else "from_digest"] = (
                    candidate["validation_images"][edition]["update"]["digest"]
                )
            if control in ("expected_key", "unsigned_rejected", "foreign_key_rejected"):
                observation = receipt["observations"]
                role = {
                    "expected_key": "signed",
                    "unsigned_rejected": "unsigned",
                    "foreign_key_rejected": "foreign",
                }[control]
                declared = candidate["validation_images"][edition][role]
                observation.update(
                    logical_reference=declared["logical_reference"],
                    fixture_digest=declared["digest"],
                )
                observation["key_fingerprint"] = fixtures["trusted_runner"][
                    "official_key_fingerprint"
                ]
                observation["signer_fingerprint"] = declared["signing_key_fingerprint"]
            receipts.append(receipt)
        channels = {
            r["phase"]: r
            for r in receipts
            if r["edition"] == edition and r["control"] == "control_channel"
        }
        for receipt in [r for r in receipts if r["edition"] == edition]:
            control = receipt["control"]
            if control in ("sirius_install", "update", "rollback", "final_boot"):
                channel = channels[
                    "live" if control == "sirius_install" else "installed"
                ]
                receipt["observations"].update(
                    channel_receipt_sha256=fixture_hash(channel),
                    vm_id=channel["observations"]["vm_id"],
                )
                if control != "sirius_install":
                    receipt["observations"]["host_key_fingerprint"] = channel[
                        "observations"
                    ]["host_key_fingerprint"]
    validation = copy.deepcopy(fixtures["validation"])
    validation.update(binding=copy.deepcopy(binding), receipts=receipts)
    validation["signature"]["subject_sha256"] = fixture_hash(candidate)
    if profile.get("accepted_risk"):
        validation["scan"].update(
            decision="accepted_risk",
            applied_exceptions=[fixture_hash(policy["exceptions"][0])],
        )
    return {"candidate": candidate, "validation": validation, "policy": policy}


def check_fixture_relations(bundle, editions, now, trusted_runner):
    candidate, validation, policy = (
        bundle[name] for name in ("candidate", "validation", "policy")
    )
    identity = candidate["identity"]
    expected_ref = (
        "refs/heads/main"
        if identity["channel"] == "testing"
        else f"refs/heads/release/{identity['fedora']}"
    )
    if identity["source_ref"] != expected_ref:
        raise ValueError("source_ref")
    if identity["policy_sha256"] != fixture_hash(policy):
        raise ValueError("policy_sha256")
    expected_binding = {
        "candidate_sha256": fixture_hash(candidate),
        "identity": identity,
    }
    if validation["binding"] != expected_binding:
        raise ValueError("validation_binding")
    if (
        validation["signature"]["subject_sha256"]
        != expected_binding["candidate_sha256"]
    ):
        raise ValueError("signature_subject")
    dependency = candidate["core_dependency"]
    for field in ("fedora", "channel", "source_ref", "architecture"):
        if dependency[field] != identity[field]:
            raise ValueError("core_scope")
    if dependency["digest"] != identity["core_digest"]:
        raise ValueError("core_digest")
    if (
        dependency["base_digest"] != identity["base_digest"]
        or dependency["policy_sha256"] != identity["policy_sha256"]
    ):
        raise ValueError("core_evidence_binding")
    if (
        dependency["mode"] == "built"
        and dependency["source_sha"] != identity["source_sha"]
    ):
        raise ValueError("built_core_source")
    if (
        "core" in candidate["components"]
        and candidate["components"]["core"]["digest"] != identity["core_digest"]
    ):
        raise ValueError("core_output")
    selection = identity["selection"]
    selected = {"core", "workstation"} if selection == "all" else {selection}
    components = selected | ({"installer"} if "workstation" in selected else set())
    if set(candidate["components"]) != components:
        raise ValueError("components")
    if set(candidate["installed"]) != selected:
        raise ValueError("installed_selection")
    if set(candidate["validation_images"]) != selected:
        raise ValueError("validation_image_selection")
    for edition, images in candidate["validation_images"].items():
        official = trusted_runner["official_key_fingerprint"]
        if (
            images["update"]["signing_key_fingerprint"] != official
            or images["signed"]["signing_key_fingerprint"] != official
            or images["foreign"]["signing_key_fingerprint"] in (None, official)
            or images["unsigned"]["signing_key_fingerprint"] is not None
        ):
            raise ValueError("fixture_signing_key")
        b_digest = images["update"]["digest"]
        if (
            b_digest == candidate["components"][edition]["digest"]
            or images["update"]["derived_from"]
            != candidate["components"][edition]["digest"]
            or images["signed"]["digest"] != b_digest
            or any(
                images[role]["derived_from"] != b_digest
                for role in ("signed", "unsigned", "foreign")
            )
        ):
            raise ValueError("declared_update_binding")
        if (
            len({images[role]["digest"] for role in ("signed", "unsigned", "foreign")})
            != 3
        ):
            raise ValueError("declared_fixture_digests")
        for image in images.values():
            if image["producer"] != trusted_runner["technical_signer"]:
                raise ValueError("fixture_producer")
            if (
                image["logical_reference"]
                != f"{candidate['components'][edition]['repository']}@{image['digest']}"
            ):
                raise ValueError("declared_logical_reference")
    if set(candidate["artifacts"]) != (
        {"iso", "qcow2"} if "workstation" in selected else set()
    ):
        raise ValueError("artifacts")
    for edition, installed in candidate["installed"].items():
        image = "luminusos" if edition == "core" else "luminusos-workstation"
        tag = ("testing-" if identity["channel"] == "testing" else "") + identity[
            "fedora"
        ]
        if (
            installed["edition"] != edition
            or installed["channel"] != identity["channel"]
            or installed["fedora"] != identity["fedora"]
            or installed["reference"] != f"ghcr.io/example/{image}:{tag}"
            or installed["digest"] != candidate["components"][edition]["digest"]
        ):
            raise ValueError("installed_identity")
    expected = {
        (edition, control, phase)
        for edition in selected
        for control in editions[edition]["controls"]
        for phase in (
            ["live", "installed"]
            if edition == "workstation" and control == "control_channel"
            else ["live"]
            if control in ("sirius_install", "live_isolation")
            else ["installed"]
        )
    }
    actual = [(r["edition"], r["control"], r["phase"]) for r in validation["receipts"]]
    if set(actual) != expected or len(actual) != len(expected):
        raise ValueError("receipt_set")
    for receipt in validation["receipts"]:
        if receipt["executor"] != validation["executor"]:
            raise ValueError("receipt_executor")
        if receipt["binding"] != expected_binding:
            raise ValueError("receipt_binding")
        if (
            receipt["deadline_seconds"]
            != trusted_runner["deadlines"][receipt["control"]]
        ):
            raise ValueError("trusted_deadline")
        start, end = (
            dt.datetime.fromisoformat(receipt[key])
            for key in ("started_at", "finished_at")
        )
        if (
            not start
            <= end
            <= start + dt.timedelta(seconds=receipt["deadline_seconds"])
        ):
            raise ValueError("receipt_deadline")
        if (
            receipt["control"] in ("first_boot", "final_boot")
            and receipt["observations"]["installed"]
            != candidate["installed"][receipt["edition"]]
        ):
            raise ValueError("observed_installation")
        observation = receipt["observations"]
        if receipt["control"] in ("sirius_install", "update", "rollback", "final_boot"):
            phase = "live" if receipt["control"] == "sirius_install" else "installed"
            channel = next(
                r
                for r in validation["receipts"]
                if r["edition"] == receipt["edition"]
                and r["control"] == "control_channel"
                and r["phase"] == phase
            )
            if (
                observation["channel_receipt_sha256"] != fixture_hash(channel)
                or observation["vm_id"] != channel["observations"]["vm_id"]
                or (
                    receipt["control"] != "sirius_install"
                    and observation["host_key_fingerprint"]
                    != channel["observations"]["host_key_fingerprint"]
                )
            ):
                raise ValueError("phase_channel_binding")
        if receipt["control"] in (
            "expected_key",
            "unsigned_rejected",
            "foreign_key_rejected",
        ):
            role = {
                "expected_key": "signed",
                "unsigned_rejected": "unsigned",
                "foreign_key_rejected": "foreign",
            }[receipt["control"]]
            image = candidate["validation_images"][receipt["edition"]][role]
            if (
                observation["key_fingerprint"]
                != trusted_runner["official_key_fingerprint"]
                or observation["signer_fingerprint"] != image["signing_key_fingerprint"]
                or observation["logical_reference"] != image["logical_reference"]
                or observation["fixture_digest"] != image["digest"]
            ):
                raise ValueError("mirror_declared_binding")
        if receipt["control"] == "preflight" and (
            observation["available_bytes"] < observation["required_bytes"]
            or observation["required_bytes"] < sum(observation["budget_terms"].values())
            or observation["budget_terms"]["disk"]
            < observation["disk_fully_allocated_bytes"]
            or observation["budget_terms"]["reserve"] < observation["reserve_bytes"]
        ):
            raise ValueError("disk_budget")
        if receipt["control"] == "sirius_install" and (
            observation["iso_sha256"] != candidate["artifacts"]["iso"]["sha256"]
            or observation["payload_digest"]
            != candidate["components"]["workstation"]["digest"]
        ):
            raise ValueError("installation_binding")
        if receipt["control"] in ("update", "rollback") and (
            observation["from_digest"] == observation["to_digest"]
            or observation["before_boot_id"] == observation["after_boot_id"]
            or observation["reference"]
            != candidate["installed"][receipt["edition"]]["reference"]
        ):
            raise ValueError("transition")
    for edition in selected:
        by_control = {
            r["control"]: r["observations"]
            for r in validation["receipts"]
            if r["edition"] == edition
        }
        update, rollback = (by_control[c] for c in ("update", "rollback"))
        if (
            update["from_digest"] != candidate["components"][edition]["digest"]
            or update["to_digest"]
            != candidate["validation_images"][edition]["update"]["digest"]
            or rollback["from_digest"] != update["to_digest"]
            or rollback["to_digest"] != update["from_digest"]
        ):
            raise ValueError("rollback_binding")
        mirror_controls = ("expected_key", "unsigned_rejected", "foreign_key_rejected")
        if len({by_control[c]["fixture_digest"] for c in mirror_controls}) != 3:
            raise ValueError("mirror_fixture_digests")
        if edition == "workstation" and (
            by_control["sirius_install"]["disk_id"]
            != by_control["first_boot"]["disk_id"]
            or by_control["sirius_install"]["disk_id"]
            != by_control["final_boot"]["disk_id"]
        ):
            raise ValueError("installed_disk_binding")
    seen = set()
    for exception in policy["exceptions"]:
        issued, expires = (
            dt.datetime.fromisoformat(exception[key])
            for key in ("issued_at", "expires_at")
        )
        if not issued <= now < expires <= issued + dt.timedelta(days=30):
            raise ValueError("exception_expiry")
        if (
            exception["channel"] != identity["channel"]
            or exception["fedora"] != identity["fedora"]
            or exception["edition"] not in selected
        ):
            raise ValueError("exception_scope")
        key = tuple(
            exception[field]
            for field in (
                "advisory",
                "package",
                "package_version",
                "edition",
                "component_scope",
                "channel",
                "fedora",
            )
        )
        if key in seen:
            raise ValueError("duplicate_exception")
        seen.add(key)
    known_exceptions = {fixture_hash(e) for e in policy["exceptions"]}
    if not set(validation["scan"]["applied_exceptions"]) <= known_exceptions:
        raise ValueError("applied_exceptions")


class ReleaseContractTests(unittest.TestCase):
    def check_relations(self, bundle):
        check_fixture_relations(
            bundle, self.fixtures["editions"], self.now, self.fixtures["trusted_runner"]
        )

    def assert_fixture_semantic_rejection(self, bundle, error):
        for document in bundle.values():
            self.validator.validate(document)
        with self.assertRaisesRegex(ValueError, error):
            self.check_relations(bundle)

    def test_declared_derivation_and_producer_after_rebinding(self):
        for role, field, value, error in (
            (
                "foreign",
                "derived_from",
                "sha256:" + "f" * 64,
                "declared_update_binding",
            ),
            ("signed", "digest", "sha256:" + "f" * 64, "declared_update_binding"),
            ("unsigned", "digest", "sha256:" + "e" * 64, "declared_fixture_digests"),
            ("foreign", "signing_key_fingerprint", "9" * 64, "fixture_signing_key"),
            (
                "update",
                "logical_reference",
                "ghcr.io/example/luminusos@sha256:" + "f" * 64,
                "declared_logical_reference",
            ),
        ):
            with self.subTest(role=role, field=field):
                bundle = example_bundle(
                    self.fixtures, self.fixtures["valid_profiles"][0]
                )
                bundle["candidate"]["validation_images"]["core"][role][field] = value
                rebind_fixture_candidate(bundle)
                self.assert_fixture_semantic_rejection(bundle, error)
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][0])
        bundle["candidate"]["validation_images"]["core"]["update"]["producer"][
            "run_id"
        ] = 999
        rebind_fixture_candidate(bundle)
        self.assert_fixture_semantic_rejection(bundle, "fixture_producer")
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][0])
        for role in ("update", "signed"):
            bundle["candidate"]["validation_images"]["core"][role][
                "signing_key_fingerprint"
            ] = "d" * 64
        for receipt in bundle["validation"]["receipts"]:
            if receipt["control"] in (
                "expected_key",
                "unsigned_rejected",
                "foreign_key_rejected",
            ):
                receipt["observations"]["key_fingerprint"] = "d" * 64
            if receipt["control"] == "expected_key":
                receipt["observations"]["signer_fingerprint"] = "d" * 64
        rebind_fixture_candidate(bundle)
        self.assert_fixture_semantic_rejection(bundle, "fixture_signing_key")

    def test_mirror_and_reboot_observations_match_declared_inputs(self):
        for control, field, value, error in (
            ("expected_key", "key_fingerprint", "f" * 64, "mirror_declared_binding"),
            (
                "foreign_key_rejected",
                "signer_fingerprint",
                "9" * 64,
                "mirror_declared_binding",
            ),
            (
                "expected_key",
                "logical_reference",
                "ghcr.io/example/luminusos@sha256:" + "f" * 64,
                "mirror_declared_binding",
            ),
            ("update", "to_digest", "sha256:" + "f" * 64, "rollback_binding"),
            ("rollback", "to_digest", "sha256:" + "f" * 64, "rollback_binding"),
            (
                "update",
                "host_key_fingerprint",
                "SHA256:" + "B" * 43,
                "phase_channel_binding",
            ),
            ("rollback", "channel_receipt_sha256", "f" * 64, "phase_channel_binding"),
            (
                "final_boot",
                "host_key_fingerprint",
                "SHA256:" + "B" * 43,
                "phase_channel_binding",
            ),
            ("final_boot", "vm_id", "another-vm", "phase_channel_binding"),
        ):
            with self.subTest(control=control, field=field):
                bundle = example_bundle(
                    self.fixtures, self.fixtures["valid_profiles"][0]
                )
                receipt = next(
                    r
                    for r in bundle["validation"]["receipts"]
                    if r["control"] == control
                )
                receipt["observations"][field] = value
                self.assert_fixture_semantic_rejection(bundle, error)

    def test_workstation_phase_identity_and_live_selinux(self):
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][1])
        receipts = bundle["validation"]["receipts"]
        channels = {
            r["phase"]: r for r in receipts if r["control"] == "control_channel"
        }
        channels["live"]["observations"]["host_key_fingerprint"] = "SHA256:" + "C" * 43
        rebind_fixture_candidate(bundle)
        self.validator.validate(bundle["validation"])
        self.check_relations(bundle)
        self.assertEqual(channels["live"]["observations"]["selinux_mode"], "Permissive")
        channels["installed"]["observations"]["selinux_mode"] = "Permissive"
        self.assertTrue(list(self.validator.iter_errors(bundle["validation"])))
        channels["installed"]["observations"]["selinux_mode"] = "Enforcing"
        install = next(r for r in receipts if r["control"] == "sirius_install")
        install["observations"]["channel_receipt_sha256"] = fixture_hash(
            channels["installed"]
        )
        self.assert_fixture_semantic_rejection(bundle, "phase_channel_binding")
        rebind_fixture_candidate(bundle)
        receipts.remove(channels["installed"])
        self.assert_fixture_semantic_rejection(bundle, "receipt_set")
        receipts.extend((channels["installed"], copy.deepcopy(channels["live"])))
        self.assert_fixture_semantic_rejection(bundle, "receipt_set")

    def test_trusted_deadline_and_final_no_channel(self):
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][0])
        bundle["validation"]["receipts"][0]["deadline_seconds"] = 99999
        self.assert_fixture_semantic_rejection(bundle, "trusted_deadline")
        final = next(
            r for r in bundle["validation"]["receipts"] if r["control"] == "final_boot"
        )
        final["observations"]["observation_method"] = "ssh"
        self.assertTrue(list(self.validator.iter_errors(bundle["validation"])))

    def test_https_format_check_does_not_depend_on_optional_packages(self):
        for value in (
            "https://",
            "https://user:password@example.com",
            "https://example.com:99999",
            "https://exam ple.com",
        ):
            with self.subTest(value=value):
                bundle = example_bundle(
                    self.fixtures, self.fixtures["valid_profiles"][0]
                )
                receipt = next(
                    r
                    for r in bundle["validation"]["receipts"]
                    if r["control"] == "expected_key"
                )
                receipt["observations"]["physical_endpoint"] = value
                self.assertTrue(list(self.validator.iter_errors(bundle["validation"])))

    def test_phase_channels_and_declared_update_inputs(self):
        for profile in self.fixtures["valid_profiles"]:
            with self.subTest(profile=profile["name"]):
                bundle = example_bundle(self.fixtures, profile)
                candidate = bundle["candidate"]
                self.assertEqual(
                    set(candidate["validation_images"]), set(candidate["installed"])
                )
                for edition in candidate["installed"]:
                    channels = [
                        r
                        for r in bundle["validation"]["receipts"]
                        if r["edition"] == edition and r["control"] == "control_channel"
                    ]
                    self.assertEqual(
                        {r["phase"] for r in channels},
                        {"installed", "live"}
                        if edition == "workstation"
                        else {"installed"},
                    )
                    self.assertTrue(
                        all(
                            r["observations"]["host_key_binding"]
                            == "first_contact_cid_bound"
                            for r in channels
                        )
                    )
                self.check_relations(bundle)

    def test_rebound_candidate_does_not_authorize_alternate_update_or_key(self):
        for field, value in (
            ("digest", "sha256:" + "f" * 64),
            ("signing_key_fingerprint", "f" * 64),
        ):
            with self.subTest(field=field):
                bundle = example_bundle(
                    self.fixtures, self.fixtures["valid_profiles"][0]
                )
                bundle["candidate"]["validation_images"]["core"]["update"][field] = (
                    value
                )
                rebind_fixture_candidate(bundle)
                with self.assertRaises(ValueError):
                    self.check_relations(bundle)

    def test_ci_installs_pinned_schema_validator(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = next(
            dependency
            for dependency in project["dependency-groups"]["dev"]
            if dependency.startswith("jsonschema==")
        )
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn(pin, workflow)

    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (ROOT / "shared/release/contract.schema.json").read_text()
        )
        cls.fixtures = json.loads(
            (ROOT / "tests/fixtures/release-contract-cases.json").read_text()
        )
        from jsonschema import Draft202012Validator, FormatChecker

        Draft202012Validator.check_schema(cls.schema)
        checker = FormatChecker()
        checker.checks("date-time", raises=ValueError)(fixture_utc_timestamp)
        checker.checks("uri", raises=ValueError)(fixture_https_uri)
        cls.validator = Draft202012Validator(cls.schema, format_checker=checker)
        cls.now = dt.datetime.fromisoformat(cls.fixtures["evaluation_time"])

    def test_schema_and_closed_objects(self):
        def visit(value):
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.schema)

    def test_synthetic_valid_bundles(self):
        self.assertEqual(
            self.fixtures["evidence_notice"], "SYNTHETIC: NOT ATTESTATIONS"
        )
        for name, edition in self.fixtures["editions"].items():
            with self.subTest(edition=name):
                self.validator.validate(edition)
        for profile in self.fixtures["valid_profiles"]:
            with self.subTest(profile=profile["name"]):
                bundle = example_bundle(self.fixtures, profile)
                for document in bundle.values():
                    self.validator.validate(document)
                    self.assertEqual(document["evidence_class"], "synthetic")
                self.check_relations(bundle)

    def test_negative_examples(self):
        for case in self.fixtures["invalid_cases"]:
            with self.subTest(case=case["name"]):
                profile = next(
                    p
                    for p in self.fixtures["valid_profiles"]
                    if p["name"] == case["profile"]
                )
                bundle = example_bundle(self.fixtures, profile)
                target = bundle
                for part in case["path"][:-1]:
                    target = target[part]
                last = case["path"][-1]
                if case.get("remove"):
                    del target[last]
                else:
                    target[last] = copy.deepcopy(case["value"])
                if case.get("rebind_candidate"):
                    rebind_fixture_candidate(bundle)
                if case["stage"] == "schema":
                    self.assertTrue(
                        any(
                            list(self.validator.iter_errors(document))
                            for document in bundle.values()
                        )
                    )
                else:
                    for document in bundle.values():
                        self.validator.validate(document)
                    with self.assertRaisesRegex(ValueError, case["error"]):
                        self.check_relations(bundle)

    def test_expiry_and_scope_after_rebinding(self):
        for field, value, error in (
            ("expires_at", "2026-11-08T00:00:00Z", "exception_expiry"),
            ("expires_at", "2026-12-02T00:00:00Z", "exception_expiry"),
            ("package_version", "*", "schema"),
            ("channel", "stable", "exception_scope"),
        ):
            with self.subTest(field=field, value=value):
                bundle = example_bundle(
                    self.fixtures, self.fixtures["valid_profiles"][0]
                )
                bundle["policy"]["exceptions"][0][field] = value
                candidate = bundle["candidate"]
                candidate["identity"]["policy_sha256"] = fixture_hash(bundle["policy"])
                candidate["core_dependency"]["policy_sha256"] = candidate["identity"][
                    "policy_sha256"
                ]
                rebind_fixture_candidate(bundle)
                if error == "schema":
                    self.assertTrue(list(self.validator.iter_errors(bundle["policy"])))
                else:
                    for document in bundle.values():
                        self.validator.validate(document)
                    with self.assertRaisesRegex(ValueError, error):
                        self.check_relations(bundle)

    def test_exact_finding_match_does_not_transfer_acceptance(self):
        exception = self.fixtures["policy"]["exceptions"][0]
        finding = copy.deepcopy(exception)
        self.assertTrue(fixture_exception_matches(exception, finding))
        for field, value in (
            ("advisory", "CVE-2026-54321"),
            ("package", "another-package"),
            ("package_version", "1.1-1.fc45"),
            ("edition", "workstation"),
            ("component_scope", "installer_live"),
            ("channel", "stable"),
            ("fedora", "44"),
        ):
            with self.subTest(field=field):
                changed = finding | {field: value}
                self.assertFalse(fixture_exception_matches(exception, changed))

    def test_advisory_families_and_embedded_binary(self):
        policy = copy.deepcopy(self.fixtures["policy"])
        exception = policy["exceptions"][0]
        for advisory in ("CVE-2026-12345", "GHSA-2345-6789-cfgh", "GO-2026-1234"):
            with self.subTest(advisory=advisory):
                exception["advisory"] = advisory
                self.validator.validate(policy)
        exception.update(
            component_type="embedded_go",
            binary={
                "path": "/usr/bin/example",
                "sha256": "f" * 64,
                "rpm_nevra": "example-1.0-1.fc45.x86_64",
            },
        )
        self.validator.validate(policy)
        different_binary = copy.deepcopy(exception)
        different_binary["binary"]["sha256"] = "e" * 64
        self.assertFalse(fixture_exception_matches(exception, different_binary))

    def test_duplicate_receipt_rejected(self):
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][0])
        receipts = bundle["validation"]["receipts"]
        receipts.append(copy.deepcopy(receipts[0]))
        self.validator.validate(bundle["validation"])
        with self.assertRaisesRegex(ValueError, "receipt_set"):
            self.check_relations(bundle)

    def test_legacy_consumer_rejects_new_candidate(self):
        import runpy

        legacy = runpy.run_path(
            str(ROOT / ".github/scripts/workflow/release_pipeline.py")
        )
        bundle = example_bundle(self.fixtures, self.fixtures["valid_profiles"][0])
        with self.assertRaisesRegex(ValueError, "invalid candidate version"):
            legacy["validate_candidate"](bundle["candidate"], ROOT)
