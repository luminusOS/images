import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "testing-45.20261031"
OLD = "testing-45.20261030"

AWS = """#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
store = pathlib.Path(os.environ["STORE"])
command = args[1]
if command == "cp":
    src, dst = args[2:4]
    if os.getenv("FAIL_QCOW") and src.endswith(".qcow2"):
        sys.exit(1)
    target = store / dst.removeprefix("s3://bucket/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, target)
elif command == "ls":
    for path in (store / "testing").iterdir():
        if path.is_dir(): print(" PRE " + path.name + "/")
elif command == "rm":
    shutil.rmtree(store / args[2].removeprefix("s3://bucket/"))
else:
    raise SystemExit("unexpected aws command")
"""
CURL = """#!/usr/bin/env python3
import os, pathlib, sys
url = sys.argv[-1]
if os.getenv("FAIL_DOWNLOAD"): sys.exit(22)
if os.getenv("CORRUPT_QCOW") and url.endswith(".qcow2"):
    sys.stdout.buffer.write(b"corrupt")
else:
    path = pathlib.Path(os.environ["STORE"]) / url.removeprefix("https://download.luminusos.org/")
    sys.stdout.buffer.write(path.read_bytes())
"""
COSIGN = """#!/usr/bin/env python3
import sys
if sys.argv[1] != "verify-blob": raise SystemExit(2)
"""


class PublicationIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.dist = self.root / "dist"
        self.store = self.root / "store"
        self.bin.mkdir()
        self.dist.mkdir()
        for name, body in (("aws", AWS), ("curl", CURL), ("cosign", COSIGN)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        for fmt, data in (("iso", b"iso"), ("qcow2", b"qcow")):
            (self.dist / f"luminusos-workstation-{VERSION}.{fmt}").write_bytes(data)
        (self.store / "testing" / OLD).mkdir(parents=True)
        (self.store / "testing" / OLD / "old.iso").write_bytes(b"old")
        (self.store / "stable" / "keep").mkdir(parents=True)
        (self.store / "stable" / "keep" / "keep.iso").write_bytes(b"keep")
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STORE": str(self.store),
            "R2_BUCKET": "bucket",
            "R2_ENDPOINT": "https://example.invalid",
        }

    def invoke(self, *arguments, **overrides):
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / ".github/scripts/publish-r2.py"),
                "testing",
                VERSION,
                str(self.dist),
                *arguments,
            ],
            env={**self.env, **overrides},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_success_keeps_other_channel_and_prunes_old_version(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        for fmt in ("iso", "qcow2"):
            self.assertTrue(
                (
                    self.store
                    / "testing"
                    / VERSION
                    / f"luminusos-workstation-{VERSION}.{fmt}"
                ).is_file()
            )
        self.assertFalse((self.store / "testing" / OLD).exists())
        self.assertTrue((self.store / "stable/keep/keep.iso").is_file())
        latest = json.loads((self.store / "testing/latest.json").read_text())
        self.assertEqual(latest["version"], VERSION)
        self.assertTrue(
            latest["assets"]["iso"].startswith(
                "https://download.luminusos.org/testing/"
            )
        )
        self.assertTrue(latest["assets"]["qcow2"].endswith(".qcow2"))

    def test_failure_never_updates_latest_or_removes_old(self):
        for failure in ("FAIL_QCOW", "FAIL_DOWNLOAD", "CORRUPT_QCOW"):
            with self.subTest(failure=failure):
                result = self.invoke(**{failure: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((self.store / "testing" / OLD / "old.iso").is_file())
                self.assertFalse((self.store / "testing/latest.json").exists())

    def test_required_evidence_publishes_json_and_signed_manifest(self):
        import hashlib

        evidence = self.dist / "workstation" / "sbom.spdx.json"
        evidence.parent.mkdir()
        evidence.write_text('{"spdxVersion":"SPDX-2.3","packages":[]}')
        (self.dist / "workstation" / "provenance.json").write_text("{}")
        entries = {
            path.relative_to(self.dist).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.dist.rglob("*")
            if path.is_file()
        }
        (self.dist / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items()))
        )
        (self.dist / "SHA256SUMS.sig").write_text("signature")
        result = self.invoke("--require-evidence")
        self.assertEqual(result.returncode, 0, result.stderr)
        latest = json.loads((self.store / "testing/latest.json").read_text())
        self.assertIn("workstation/sbom.spdx.json", latest["evidence"])
        self.assertTrue((self.store / "testing" / VERSION / "SHA256SUMS.sig").is_file())

    def test_required_evidence_bad_manifest_preserves_previous_release(self):
        (self.dist / "SHA256SUMS").write_text("0" * 64 + "  nonexistent.json\n")
        (self.dist / "SHA256SUMS.sig").write_text("signature")
        result = self.invoke("--require-evidence")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.store / "testing" / OLD / "old.iso").is_file())
        self.assertFalse((self.store / "testing/latest.json").exists())
