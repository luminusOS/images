import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "published_base", ROOT / ".github/scripts/workflow/published_base.py"
)
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

REPOSITORY = "luminusOS/images"
OFFICIAL_SHA = hashlib.sha256(base.OFFICIAL_KEY.read_bytes()).hexdigest()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Registry:
    """Line tags of a published release, as skopeo would serve them."""

    def __init__(self, line: str, version: str):
        self.blobs = {}
        self.tags = {}
        for edition, name in base.EDITIONS.items():
            repository = f"ghcr.io/luminusos/{name}"
            config = json.dumps(
                {
                    "config": {
                        "Labels": {
                            "org.opencontainers.image.version": version.removeprefix(
                                "testing-"
                            )
                        }
                    },
                    "edition": edition,
                }
            ).encode()
            manifest = json.dumps(
                {"config": {"digest": digest(config)}, "edition": edition}
            ).encode()
            index = json.dumps(
                {
                    "manifests": [
                        {
                            "digest": digest(manifest),
                            "platform": {
                                "architecture": "amd64",
                                "os": "linux",
                                "variant": "v1",
                            },
                        },
                        {
                            "digest": "sha256:" + "0" * 64,
                            "platform": {"architecture": "unknown", "os": "unknown"},
                        },
                    ]
                }
            ).encode()
            self.tags[f"{repository}:{line}"] = index
            self.blobs[f"{repository}@{digest(manifest)}"] = manifest
            self.blobs[f"config:{repository}@{digest(manifest)}"] = config

    def index_digest(self, edition: str) -> str:
        return digest(
            next(v for k, v in self.tags.items() if base.EDITIONS[edition] + ":" in k)
        )


class World:
    def __init__(self, channel="testing", fedora="45", version=None):
        self.channel = channel
        self.fedora = fedora
        prefix = "testing-" if channel == "testing" else ""
        self.version = version or f"{prefix}{fedora}.20261118.1"
        self.registry = Registry(prefix + fedora, self.version)
        self.evidence = {
            "repository": REPOSITORY,
            "source": {
                "repository": REPOSITORY,
                "ref": "refs/heads/main"
                if channel == "testing"
                else f"refs/heads/release/{fedora}",
                "commit": "a" * 40,
                "run_id": 1,
            },
            "images": {
                edition: "ghcr.io/luminusos/luminusos-candidates@"
                + self.registry.index_digest(edition)
                for edition in base.EDITIONS
            }
            | {
                "installer": "ghcr.io/luminusos/luminusos-candidates@sha256:" + "9" * 64
            },
        }
        self.releases = [
            self.release(self.version),
            self.release(f"{prefix}{fedora}.20261117.3"),
            self.release(f"{prefix}{fedora}.20261118"),
        ]
        self.failures = set()
        self.calls = []
        self.sums_extra = ""

    def release(self, tag, **extra):
        return {
            "tag_name": tag,
            "draft": False,
            "prerelease": self.channel == "testing",
            "author": {"login": "github-actions[bot]"},
            "url": f"https://api.github.com/repos/{REPOSITORY}/releases/1",
            "assets": [{"name": name, "size": None} for name in base.ASSETS],
        } | extra

    def assets(self, evidence_bytes=None):
        evidence_bytes = evidence_bytes or json.dumps(self.evidence).encode()
        bundle = io.BytesIO()
        with tarfile.open(fileobj=bundle, mode="w:gz") as tar:
            for name, data in (
                ("candidate.json", b"{}"),
                ("release-evidence.json", self.bundled or evidence_bytes),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        sums = (
            f"{hashlib.sha256(b'{}').hexdigest()}  candidate.json\n"
            f"{hashlib.sha256(evidence_bytes).hexdigest()}  release-evidence.json\n"
            + self.sums_extra
        )
        return {
            "SHA256SUMS": sums.encode(),
            "SHA256SUMS.sig": b"signature",
            "evidence.tar.gz": bundle.getvalue(),
        }

    bundled = None

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        tool = argv[0]
        if tool == "gh" and argv[1] == "api":
            assert "--paginate" in argv and "--slurp" in argv, argv
            data = self.assets()
            for release in self.releases:
                for asset in release["assets"]:
                    if asset["size"] is None:
                        asset["size"] = len(data[asset["name"]])
            return mock.Mock(
                stdout=json.dumps([self.releases[::2], self.releases[1::2]])
            )
        if tool == "gh" and argv[1:3] == ["release", "download"]:
            self.downloaded = argv[3]
            name = argv[argv.index("--pattern") + 1]
            directory = Path(argv[argv.index("--dir") + 1])
            (directory / name).write_bytes(self.assets()[name])
            return mock.Mock(stdout="")
        if argv[:2] == ["cosign", "verify-blob"]:
            if "verify-blob" in self.failures:
                raise subprocess.CalledProcessError(1, argv)
            return mock.Mock(stdout="")
        if argv[:2] == ["cosign", "verify"]:
            if "verify" in self.failures:
                raise subprocess.CalledProcessError(1, argv)
            return mock.Mock(stdout="")
        if tool == "skopeo":
            reference = argv[-1].removeprefix("docker://")
            if "--config" in argv:
                return mock.Mock(stdout=self.registry.blobs[f"config:{reference}"])
            if reference in self.registry.tags:
                return mock.Mock(stdout=self.registry.tags[reference])
            return mock.Mock(stdout=self.registry.blobs[reference])
        raise AssertionError(argv)

    def resolve(self):
        with mock.patch.object(base.subprocess, "run", side_effect=self.run):
            return base.resolve(REPOSITORY, self.channel, self.fedora)


class PublishedBaseTests(unittest.TestCase):
    def assert_rejected(self, world, message):
        with self.assertRaisesRegex(
            (ValueError, subprocess.CalledProcessError), message
        ):
            world.resolve()

    def test_resolves_both_editions_from_the_newest_signed_release(self):
        for channel in ("testing", "stable"):
            with self.subTest(channel=channel):
                world = World(channel)
                result = world.resolve()
                self.assertEqual(world.downloaded, world.version)
                prefix = "testing-" if channel == "testing" else ""
                evidence = hashlib.sha256(
                    json.dumps(world.evidence).encode()
                ).hexdigest()
                for edition, name in base.EDITIONS.items():
                    item = result[edition]
                    self.assertEqual(
                        item["reference"], f"ghcr.io/luminusos/{name}:{prefix}45"
                    )
                    self.assertEqual(
                        item["index_digest"], world.registry.index_digest(edition)
                    )
                    self.assertEqual(item["version"], world.version)
                    self.assertEqual(item["release_evidence_sha256"], evidence)
                    self.assertEqual(item["official_key_sha256"], OFFICIAL_SHA)
                    self.assertEqual(
                        set(item),
                        {
                            "reference",
                            "index_digest",
                            "manifest_digest",
                            "config_digest",
                            "version",
                            "release_evidence_sha256",
                            "official_key_sha256",
                        },
                    )
                blob = next(
                    c for c in world.calls if c[:2] == ["cosign", "verify-blob"]
                )
                self.assertEqual(blob[blob.index("--key") + 1], str(base.OFFICIAL_KEY))
                verified = [c[-1] for c in world.calls if c[:2] == ["cosign", "verify"]]
                self.assertEqual(
                    verified,
                    [
                        f"ghcr.io/luminusos/{name}@{world.registry.index_digest(e)}"
                        for e, name in base.EDITIONS.items()
                    ],
                )

    def test_newest_release_uses_numeric_sequence_order(self):
        world = World(version="testing-45.20261118.10")
        world.releases.insert(0, world.release("testing-45.20261118.9"))
        world.resolve()
        self.assertEqual(world.downloaded, "testing-45.20261118.10")

    def test_untrusted_newest_release_never_falls_back(self) -> None:
        for fields in (
            {"author": {"login": "someone"}},
            {"author": ["github-actions[bot]"]},
            {"url": "https://api.github.com/repos/fork/images/releases/1"},
        ):
            with self.subTest(fields=fields):
                world = World()
                world.releases.insert(
                    1, world.release("testing-45.20261119.1", **fields)
                )
                self.assert_rejected(
                    world,
                    "newest release on line testing/Fedora 45 was not published by the release workflow",
                )
                self.assertFalse(
                    any(call[:2] == ["gh", "release"] for call in world.calls)
                )

    def test_no_release_of_the_line_fails_closed(self):
        for releases in (
            [],
            [World().release("testing-44.20261118.1")],
            [World().release("testing-45.20261118.1", draft=True)],
            [World().release("testing-45.20261118.1", prerelease=False)],
            [World().release("testing-45.20261118.1-rc")],
        ):
            with self.subTest(releases=releases):
                world = World()
                world.releases = releases
                self.assert_rejected(world, "manual full release")

    def test_stable_never_resolves_a_testing_release_or_tag(self):
        world = World("stable")
        world.releases = [
            World("testing").release("testing-45.20261118.1") | {"prerelease": False},
            world.release("45.20261118"),
        ]
        self.assert_rejected(world, "manual full release")
        world = World("stable")
        world.resolve()
        inspected = [c[-1] for c in world.calls if c[0] == "skopeo"]
        self.assertTrue(all("testing" not in ref for ref in inspected))
        world = World("stable")
        world.evidence["source"]["ref"] = "refs/heads/main"
        self.assert_rejected(world, "stable line")

    def test_single_manifest_line_tag_is_rejected(self) -> None:
        world = World()
        world.registry.tags["ghcr.io/luminusos/luminusos:testing-45"] = json.dumps(
            {"schemaVersion": 2, "config": {"digest": "sha256:" + "0" * 64}}
        ).encode()
        self.assert_rejected(
            world, "must point to an image index, not a single manifest"
        )

    def test_multiple_linux_amd64_descriptors_are_rejected(self) -> None:
        world = World()
        tag = "ghcr.io/luminusos/luminusos:testing-45"
        index = json.loads(world.registry.tags[tag])
        descriptor = index["manifests"][0]
        index["manifests"].append(
            descriptor | {"platform": descriptor["platform"] | {"variant": "v2"}}
        )
        world.registry.tags[tag] = json.dumps(index).encode()
        self.assert_rejected(world, "needs one linux/amd64 manifest")

    def test_signature_failure_is_rejected(self):
        world = World()
        world.failures.add("verify-blob")
        self.assert_rejected(world, "cosign")
        self.assertFalse(any(c[0] == "skopeo" for c in world.calls))

    def test_evidence_must_be_covered_by_the_signed_sums(self):
        world = World()
        world.bundled = json.dumps(world.evidence | {"tampered": True}).encode()
        self.assert_rejected(world, "differs from the signed SHA256SUMS")
        world = World()
        world.sums_extra = f"{'1' * 64}  release-evidence.json\n"
        self.assert_rejected(world, "duplicate SHA256SUMS")

    def test_missing_assets_fail_closed(self):
        world = World()
        world.releases[0]["assets"] = world.releases[0]["assets"][:2]
        self.assert_rejected(world, "lacks signed evidence")

    def test_line_tag_must_serve_the_released_digest(self):
        world = World()
        world.evidence["images"]["workstation"] = (
            "ghcr.io/luminusos/luminusos-candidates@sha256:" + "8" * 64
        )
        self.assert_rejected(world, "not the workstation image")
        world = World()
        tag = "ghcr.io/luminusos/luminusos:testing-45"
        world.registry.tags[tag] = world.registry.tags[tag] + b" "
        self.assert_rejected(world, "not the core image")

    def test_version_label_and_config_must_match(self):
        world = World()
        world.releases[0]["tag_name"] = "testing-45.20261119.1"
        world.version = "testing-45.20261119.1"
        self.assert_rejected(world, "version label")
        world = World()
        key = next(k for k in world.registry.blobs if k.startswith("config:"))
        world.registry.blobs[key] += b" "
        self.assert_rejected(world, "config digest mismatch")

    def test_official_image_signature_failure_is_rejected(self):
        world = World()
        world.failures.add("verify")
        self.assert_rejected(world, "cosign")

    def test_cli_writes_the_base_and_reports_rejections(self):
        world = World()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "base.json"
            argv = [
                "published_base",
                "--repository",
                REPOSITORY,
                "--channel",
                "testing",
                "--fedora",
                "45",
                "--output",
                str(output),
            ]
            with (
                mock.patch.object(base.sys, "argv", argv),
                mock.patch.object(base.subprocess, "run", side_effect=world.run),
                mock.patch.object(base.sys, "stdout", new_callable=io.StringIO),
            ):
                self.assertEqual(base.main(), 0)
            self.assertEqual(set(json.loads(output.read_text())), set(base.EDITIONS))
            output.unlink()
            world.releases = []
            with (
                mock.patch.object(base.sys, "argv", argv),
                mock.patch.object(base.subprocess, "run", side_effect=world.run),
                mock.patch.object(
                    base.sys, "stderr", new_callable=io.StringIO
                ) as stderr,
            ):
                self.assertEqual(base.main(), 1)
            self.assertIn("manual full release", stderr.getvalue())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
