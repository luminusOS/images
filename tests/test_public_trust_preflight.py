import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/public-trust-preflight.py"
PAYLOAD = b"synthetic snapshot verifier commissioning control\n"


@dataclass(frozen=True)
class OpenPgpFixtures:
    primary: str
    primary_only: bytes
    signing_subkey: str
    signing_keyring: bytes
    signature: bytes
    non_signing_keyring: bytes
    expired_keyring: bytes
    expired_primary: str
    expired_subkey: str
    other_primary_only: bytes


def make_openpgp_fixtures() -> OpenPgpFixtures:
    with tempfile.TemporaryDirectory(prefix="preflight-fixtures-") as home:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": home,
            "GNUPGHOME": home,
            "LC_ALL": "C",
        }

        def gpg(*args: str, data: bytes = b"") -> bytes:
            return subprocess.run(
                [
                    "gpg",
                    "--no-options",
                    "--homedir",
                    home,
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--faked-system-time",
                    "20200101T000000!",
                    *args,
                ],
                input=data,
                capture_output=True,
                timeout=15,
                check=True,
                env=env,
            ).stdout

        def fingerprints(keyring: bytes) -> list[str]:
            output = gpg(
                "--with-colons",
                "--with-fingerprint",
                "--with-subkey-fingerprint",
                "--show-keys",
                data=keyring,
            )
            return [
                entry.split(":")[9]
                for entry in output.decode("utf-8").split("\n")
                if entry.startswith("fpr:")
            ]

        try:
            first = "Snapshot Fixture <snapshot-fixture@example.invalid>"
            gpg("--quick-generate-key", first, "ed25519", "cert,sign", "0")
            primary_only = gpg("--export", first)
            (primary,) = fingerprints(primary_only)
            gpg("--quick-add-key", primary, "ed25519", "sign", "0")
            signing_keyring = gpg("--export", first)
            _, signing_subkey = fingerprints(signing_keyring)
            signature = gpg(
                "--local-user",
                f"{signing_subkey}!",
                "--output",
                "-",
                "--detach-sign",
                data=PAYLOAD,
            )
            gpg("--quick-add-key", primary, "cv25519", "encr", "0")
            non_signing_keyring = gpg("--export", first)

            other = "Expired Fixture <expired-fixture@example.invalid>"
            gpg("--quick-generate-key", other, "ed25519", "cert,sign", "0")
            other_primary_only = gpg("--export", other)
            (expired_primary,) = fingerprints(other_primary_only)
            gpg("--quick-add-key", expired_primary, "ed25519", "sign", "1d")
            expired_keyring = gpg("--export", other)
            _, expired_subkey = fingerprints(expired_keyring)
            return OpenPgpFixtures(
                primary,
                primary_only,
                signing_subkey,
                signing_keyring,
                signature,
                non_signing_keyring,
                expired_keyring,
                expired_primary,
                expired_subkey,
                other_primary_only,
            )
        finally:
            subprocess.run(
                ["gpgconf", "--homedir", home, "--kill", "all"],
                capture_output=True,
                timeout=15,
                check=True,
                env=env,
            )


def pem(der: bytes, width: int = 64, newline: bytes = b"\n") -> bytes:
    encoded = base64.b64encode(der)
    lines = [encoded[i : i + width] for i in range(0, len(encoded), width)]
    return newline.join(
        [b"-----BEGIN PUBLIC KEY-----", *lines, b"-----END PUBLIC KEY-----", b""]
    )


def ec_points() -> list[tuple[bytes, bytes]]:
    modulus = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    algorithm = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    results = []
    for x in range(12):
        square = (x**3 - 3 * x + b) % modulus
        y = pow(square, (modulus + 1) // 4, modulus)
        if y * y % modulus == square:
            coord = x.to_bytes(32)
            results.append(
                (
                    b"\x30\x59"
                    + algorithm
                    + b"\x03\x42\x00\x04"
                    + coord
                    + y.to_bytes(32),
                    b"\x30\x39"
                    + algorithm
                    + b"\x03\x22\x00"
                    + bytes([2 + y % 2])
                    + coord,
                )
            )
    return results


class PublicTrustPreflightTests(unittest.TestCase):
    openpgp: OpenPgpFixtures

    @classmethod
    def setUpClass(cls) -> None:
        cls.openpgp = make_openpgp_fixtures()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.user_home = self.directory / "user-profile"
        self.user_home.mkdir()
        self.snapshot = self.write("proposed.pgp", self.openpgp.primary_only)
        self.points = ec_points()
        self.proposed = self.write("proposed.pub", pem(self.points[0][0]))
        self.candidate = self.write("candidate.pub", pem(self.points[1][0]))
        self.official = self.write("official.pub", pem(self.points[2][0]))
        self.validation = self.write("validation.pub", pem(self.points[3][0]))
        self.digest = hashlib.sha256(self.points[0][0]).hexdigest()

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path

    def run_preflight(
        self, subkeys: tuple[str, ...] = (), *, primary: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--snapshot-keyring",
                str(self.snapshot),
                "--snapshot-primary-fingerprint",
                self.openpgp.primary if primary is None else primary,
                "--snapshot-signing-subkeys",
                *subkeys,
                "--receipt-key",
                str(self.proposed),
                "--receipt-key-sha256",
                self.digest,
                "--candidate-key",
                str(self.candidate),
                "--official-key",
                str(self.official),
                "--validation-only-receipt-key",
                str(self.validation),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ
            | {
                "HOME": str(self.user_home),
                "GNUPGHOME": str(self.user_home),
            },
            check=False,
        )

    def assert_rejected(
        self, result: subprocess.CompletedProcess[str], reason: str
    ) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(reason, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_approved_snapshot_and_distinct_receipt_leave_user_profile_untouched(
        self,
    ) -> None:
        result = self.run_preflight(primary=self.openpgp.primary.lower())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("preflight passed", result.stdout)
        self.assertEqual(list(self.user_home.iterdir()), [])

    def test_missing_empty_malformed_and_mixed_snapshot_roots_fail(self) -> None:
        valid = self.openpgp.primary_only
        corrupted_signature = valid[:-8] + bytes([valid[-8] ^ 1]) + valid[-7:]
        for label, data in {
            "missing": None,
            "empty": b"",
            "text": b"not a keyring",
            "trailing-garbage": valid + b"extra",
            "foreign-packet": valid + b"\xc5\x01\x04",
            "truncated": valid[:-1],
            "corrupted-self-signature": corrupted_signature,
            "second-primary": valid + self.openpgp.other_primary_only,
            "duplicate-primary": valid * 2,
            "malformed-allowed-trailing-signature": valid + b"\xc2\x01\x04",
        }.items():
            with self.subTest(label=label):
                self.snapshot.unlink(missing_ok=True)
                if data is not None:
                    self.snapshot.write_bytes(data)
                self.assert_rejected(self.run_preflight(), "snapshot keyring")

    def test_snapshot_requires_matching_full_primary_and_signing_subkeys(self) -> None:
        for primary in ("1" * 40, self.openpgp.primary[-16:]):
            with self.subTest(primary=primary):
                self.assert_rejected(
                    self.run_preflight(primary=primary), "primary fingerprint"
                )
        self.assert_rejected(self.run_preflight(("2" * 40,)), "signing subkey")

    def test_signing_subkey_matches_approved_set_and_gpgv_validsig(self) -> None:
        self.snapshot.write_bytes(self.openpgp.signing_keyring)
        signature = self.write("payload.sig", self.openpgp.signature)
        payload = self.write("payload", PAYLOAD)
        verifier_home = self.directory / "gpgv"
        verifier_home.mkdir(mode=0o700)
        proof = subprocess.run(
            [
                "gpgv",
                "--homedir",
                str(verifier_home),
                "--keyring",
                str(self.snapshot),
                "--status-fd",
                "1",
                str(signature),
                str(payload),
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": str(verifier_home),
                "GNUPGHOME": str(verifier_home),
                "LC_ALL": "C",
            },
        )
        validsig = [
            line.split()
            for line in proof.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        self.assertEqual(len(validsig), 1, proof.stdout)
        self.assertEqual(validsig[0][2], self.openpgp.signing_subkey)
        self.assertEqual(validsig[0][11], self.openpgp.primary)
        self.assertNotEqual(validsig[0][2], validsig[0][11])

        checked = self.run_preflight((self.openpgp.signing_subkey,))
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assert_rejected(self.run_preflight(), "signing subkey")
        self.assertIn("not a signing-usability proof", checked.stdout)

    def test_expired_signing_subkey_is_rejected_even_when_approved(self) -> None:
        self.snapshot.write_bytes(self.openpgp.expired_keyring)
        self.assert_rejected(
            self.run_preflight(
                (self.openpgp.expired_subkey,), primary=self.openpgp.expired_primary
            ),
            "GnuPG lists an unusable key",
        )

    def test_valid_encryption_subkey_is_not_an_approved_signer(self) -> None:
        self.snapshot.write_bytes(self.openpgp.non_signing_keyring)
        self.assert_rejected(
            self.run_preflight((self.openpgp.signing_subkey,)), "non-signing"
        )

    def test_help_separates_preflight_from_commissioning(self) -> None:
        help_text = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout
        self.assertIn(
            "gpgv proof for every intended production signer through the actual verifier",
            " ".join(help_text.split()),
        )

    def test_receipt_rejects_reencoded_candidate_official_and_validation_keys(
        self,
    ) -> None:
        for i, role in enumerate(("candidate", "official", "validation-only"), 1):
            with self.subTest(role=role):
                self.proposed.write_bytes(
                    pem(self.points[i][1], width=24, newline=b"\r\n")
                )
                self.digest = hashlib.sha256(self.points[i][0]).hexdigest()
                self.assert_rejected(self.run_preflight(), f"matches {role}")

    def test_receipt_requires_explicit_matching_digest(self) -> None:
        self.digest = "0" * 64
        self.assert_rejected(self.run_preflight(), "approved receipt key SHA-256")

    def test_distinct_compressed_key_is_not_the_proposed_cosign_format(self) -> None:
        self.proposed.write_bytes(pem(self.points[0][1]))
        self.assert_rejected(self.run_preflight(), "named P-256")

    def test_receipt_rejects_mixed_or_missing_pem_inputs(self) -> None:
        self.proposed.write_bytes(
            self.proposed.read_bytes() + self.candidate.read_bytes()
        )
        self.assert_rejected(self.run_preflight(), "receipt key")
        self.proposed.write_bytes(pem(self.points[0][0]))
        self.validation.unlink()
        self.assert_rejected(self.run_preflight(), "validation-only")
