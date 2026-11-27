import argparse
import base64
import binascii
import hashlib
import os
import re
import stat
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MAX_KEYRING_BYTES = 64 * 1024
MAX_PEM_BYTES = 16 * 1024
FINGERPRINT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
PUBLIC_PEM = re.compile(
    rb"-----BEGIN PUBLIC KEY-----\r?\n"
    rb"((?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----(?:\r?\n)?"
)
P256_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


class PreflightError(ValueError):
    pass


@dataclass(frozen=True)
class SnapshotIdentity:
    primary: str
    signing_subkeys: frozenset[str]


def read_public_file(path: Path, limit: int, role: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                data = stream.read(limit + 1)
                if 0 < len(data) <= limit:
                    return data
    except OSError:
        pass
    raise PreflightError(f"{role} must be a nonempty bounded regular file")


def run_tool(command: list[str], data: bytes, home: str, failure: str) -> bytes:
    try:
        result = subprocess.run(
            command,
            input=data,
            capture_output=True,
            check=True,
            timeout=10,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": home,
                "GNUPGHOME": home,
                "LC_ALL": "C",
                "OPENSSL_CONF": "/dev/null",
            },
        )
    except (OSError, subprocess.SubprocessError):
        raise PreflightError(failure) from None
    if result.stderr:
        raise PreflightError(failure)
    return result.stdout


def snapshot_packets(data: bytes) -> Counter[int]:
    # Count packet envelopes before GnuPG lists keys; this does not validate packet semantics.
    counts: Counter[int] = Counter()
    offset = 0
    error = PreflightError("snapshot keyring is not a single binary public key export")
    while offset < len(data):
        header = data[offset]
        offset += 1
        if header < 0x80 or offset == len(data):
            raise error
        if header & 0x40:
            tag = header & 0x3F
            first = data[offset]
            offset += 1
            if first < 192:
                length = first
            elif first < 224 and offset < len(data):
                length = ((first - 192) << 8) + data[offset] + 192
                offset += 1
            elif first == 255 and offset + 4 <= len(data):
                length = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            else:
                raise error
        else:
            tag = (header >> 2) & 0x0F
            length_type = header & 3
            width = 1 << length_type
            if length_type == 3 or offset + width > len(data):
                raise error
            length = int.from_bytes(data[offset : offset + width], "big")
            offset += width
        if (
            tag not in {2, 6, 13, 14, 17}
            or (not counts and tag != 6)
            or (tag == 6 and counts[6])
            or not 0 < length <= len(data) - offset
        ):
            raise error
        counts[tag] += 1
        offset += length
    return counts


def snapshot_identity(data: bytes, home: str) -> SnapshotIdentity:
    packets = snapshot_packets(data)
    gpg = [
        "gpg",
        "--no-options",
        "--batch",
        "--no-keyring",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--trust-model",
        "always",
    ]
    error = "snapshot keyring could not be parsed by GnuPG"
    run_tool([*gpg, "--list-packets"], data, home, error)
    listing = run_tool(
        [
            *gpg,
            "--with-colons",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--show-keys",
        ],
        data,
        home,
        error,
    )
    try:
        records = [line.split(":") for line in listing.decode("utf-8").split("\n")]
    except UnicodeDecodeError:
        raise PreflightError(error) from None
    parsed: dict[str, list[tuple[str, str]]] = {"pub": [], "sub": []}
    for index, record in enumerate(records):
        kind = record[0]
        if kind not in parsed:
            continue
        if (
            len(record) < 12
            or record[1] in {"e", "r", "d", "i", "n", "w"}
            or "D" in record[11]
            or index + 1 >= len(records)
        ):
            raise PreflightError("snapshot keyring: GnuPG lists an unusable key")
        next_record = records[index + 1]
        if (
            len(next_record) < 10
            or next_record[0] != "fpr"
            or not FINGERPRINT.fullmatch(next_record[9])
        ):
            raise PreflightError(error)
        parsed[kind].append((next_record[9].upper(), record[11]))
    if len(parsed["pub"]) != 1 or len(parsed["sub"]) != packets[14]:
        raise PreflightError("snapshot keyring contains missing or unrecognized keys")
    primary, capabilities = parsed["pub"][0]
    subkeys = frozenset(
        fingerprint for fingerprint, caps in parsed["sub"] if "s" in caps
    )
    if len(subkeys) != packets[14] or primary in subkeys:
        raise PreflightError(
            "snapshot keyring contains a non-signing or duplicate subkey"
        )
    if not subkeys and "s" not in capabilities:
        raise PreflightError("snapshot keyring: GnuPG lists no signing capability")
    return SnapshotIdentity(primary, subkeys)


def read_spki(path: Path, role: str) -> bytes:
    data = read_public_file(path, MAX_PEM_BYTES, role)
    match = PUBLIC_PEM.fullmatch(data)
    if match:
        try:
            der = base64.b64decode(b"".join(match[1].splitlines()), validate=True)
        except binascii.Error:
            der = b""
        if len(der) >= 2 and der[0] == 0x30:
            size = der[1]
            if size < 128 and len(der) == 2 + size:
                return der
            if size in {0x81, 0x82}:
                end = 2 + (size & 0x7F)
                if len(der) == end + int.from_bytes(der[2:end], "big"):
                    return der
    raise PreflightError(f"{role} must contain exactly one PEM public key")


def canonical_spki(der: bytes, home: str, role: str) -> bytes:
    command = ["openssl", "pkey", "-pubin", "-inform", "DER"]
    failure = f"{role} could not be validated by OpenSSL"
    run_tool([*command, "-pubcheck", "-noout"], der, home, failure)
    public_der = run_tool(
        [
            *command,
            "-ec_conv_form",
            "uncompressed",
            "-ec_param_enc",
            "named_curve",
            "-outform",
            "DER",
        ],
        der,
        home,
        failure,
    )
    if not public_der:
        raise PreflightError(failure)
    return public_der


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=(
            "Offline public trust preflight for identities and GnuPG-listed capabilities; "
            "not a signing-usability proof. Does not approve or install trust."
        ),
        epilog="Use independently approved fingerprints and comparison keys. "
        "Do not derive approval values from the proposal. "
        "Commissioning separately requires gpgv proof for every intended production signer "
        "through the actual verifier.",
    )
    parser.add_argument(
        "--snapshot-keyring",
        required=True,
        type=Path,
        help="Binary OpenPGP export with one public primary and only subkeys listed as signing; no armor or keybox",
    )
    parser.add_argument(
        "--snapshot-primary-fingerprint",
        required=True,
        help="Approved full OpenPGP fingerprint",
    )
    parser.add_argument(
        "--snapshot-signing-subkeys",
        required=True,
        nargs="*",
        metavar="FINGERPRINT",
        help="Exact approved set of subkeys listed as signing; specify no values for a listed signing primary alone",
    )
    parser.add_argument(
        "--receipt-key",
        required=True,
        type=Path,
        help="Proposed Cosign P-256 public PEM",
    )
    parser.add_argument(
        "--receipt-key-sha256",
        required=True,
        help="Approved SHA-256 of canonical SPKI DER",
    )
    parser.add_argument(
        "--candidate-key",
        required=True,
        type=Path,
        help="Approved candidate public comparison PEM",
    )
    parser.add_argument(
        "--official-key",
        required=True,
        type=Path,
        help="Approved official public comparison PEM",
    )
    parser.add_argument(
        "--validation-only-receipt-key",
        required=True,
        action="append",
        type=Path,
        help="Approved public comparison PEM; repeat for every validation-only receipt identity",
    )
    args = parser.parse_args()

    try:
        primary = args.snapshot_primary_fingerprint.upper()
        if not FINGERPRINT.fullmatch(primary):
            raise PreflightError("expected full snapshot primary fingerprint")
        subkeys = [value.upper() for value in args.snapshot_signing_subkeys]
        if (
            any(not FINGERPRINT.fullmatch(value) for value in subkeys)
            or len(set(subkeys)) != len(subkeys)
            or primary in subkeys
        ):
            raise PreflightError(
                "expected distinct full snapshot signing subkey fingerprints"
            )
        if not re.fullmatch(r"[0-9a-fA-F]{64}", args.receipt_key_sha256):
            raise PreflightError("expected approved receipt key SHA-256")

        with tempfile.TemporaryDirectory(prefix="public-trust-preflight-") as home:
            snapshot = snapshot_identity(
                read_public_file(
                    args.snapshot_keyring, MAX_KEYRING_BYTES, "snapshot keyring"
                ),
                home,
            )
            if snapshot.primary != primary:
                raise PreflightError(
                    "snapshot primary fingerprint differs from approved identity"
                )
            if snapshot.signing_subkeys != frozenset(subkeys):
                raise PreflightError(
                    "snapshot signing subkey fingerprints differ from approved identities"
                )

            proposal = read_spki(args.receipt_key, "receipt key")
            canonical = canonical_spki(proposal, home, "receipt key")
            for role, path in [
                ("candidate", args.candidate_key),
                ("official", args.official_key),
                *(
                    ("validation-only", path)
                    for path in args.validation_only_receipt_key
                ),
            ]:
                label = f"{role} receipt comparison key"
                if canonical_spki(read_spki(path, label), home, label) == canonical:
                    raise PreflightError(f"receipt key matches {role} identity")
            if proposal != canonical or not canonical.startswith(P256_SPKI):
                raise PreflightError(
                    "receipt key must use named P-256 with an uncompressed point"
                )
            if hashlib.sha256(canonical).hexdigest() != args.receipt_key_sha256.lower():
                raise PreflightError("approved receipt key SHA-256 does not match")
    except PreflightError as exc:
        parser.exit(1, f"public trust preflight: {exc}\n")
    print(
        "Public trust preflight passed (identity and listed capability only; "
        "not a signing-usability proof)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
