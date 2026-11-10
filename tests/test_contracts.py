import json
import re
import shlex
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


class RepositoryContracts(unittest.TestCase):
    def test_python_sources_compile(self):
        for directory in (
            "shared/scripts",
            "tools",
            "tests",
            ".github/scripts",
            "editions/workstation",
        ):
            for path in (ROOT / directory).rglob("*.py"):
                with self.subTest(path=path):
                    compile(path.read_bytes(), str(path), "exec")

    def test_just_recipes_render(self):
        subprocess.run(
            ["just", "--justfile", str(ROOT / "Justfile"), "--list"],
            check=True,
            capture_output=True,
            text=True,
        )
        for module, recipe in (
            ("build", "core"),
            ("build", "workstation"),
            ("build", "workstation-iso"),
            ("package", "workstation"),
            ("qemu", "install"),
        ):
            with self.subTest(module=module, recipe=recipe):
                result = subprocess.run(
                    [
                        "just",
                        "--justfile",
                        str(ROOT / "Justfile"),
                        "--dry-run",
                        module,
                        recipe,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                for command in result.stdout.splitlines():
                    shlex.split(command)
        self.assertIn('"rpmdb-repair.py"', read("tools/core-stamp.py"))

    def test_version_and_digest_contracts(self):
        digest = read("tools/fedora-bootc-digest.py")
        self.assertIn("quay.io/v2/fedora/fedora-bootc/manifests/", digest)
        for path in (
            ".github/scripts/workflow/build_metadata.py",
            ".github/workflows/auto-testing.yml",
        ):
            self.assertIn("tools/fedora-bootc-digest.py", read(path))
        self.assertIn(
            ".github/scripts/workflow/build_metadata.py",
            read(".github/workflows/containers.yml"),
        )
        self.assertIn(
            'org.opencontainers.image.base.digest="${fedora_bootc_digest}"',
            read("editions/workstation/Containerfile"),
        )
        compile(read("tools/release-notes.py"), "tools/release-notes.py", "exec")
        config = read("config/releases.env")
        values = {}
        for line in config.splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = shlex.split(value)[0]
        self.assertIn(values["LATEST_RELEASE"], values["SUPPORTED_RELEASES"].split())
        self.assertIn("UPDATE_CHANNEL=testing", read("config/versions.env"))

    def test_trust_and_system_security(self):
        self.assertIn("install firewalld", read("editions/core/Containerfile"))
        helper = read("editions/workstation/build.py")
        self.assertIn('["systemctl", "disable", "sshd.service"]', helper)
        self.assertIn("--remove-service-from-zone=ssh", helper)
        self.assertIn(
            '["systemctl", "enable", "bootc-fetch-apply-updates.timer"]', helper
        )
        stage = read(
            "editions/workstation/files/system/usr/lib/systemd/system/bootc-fetch-apply-updates.service.d/10-luminusos-stage.conf"
        )
        self.assertIn("ExecStart=", stage.splitlines())
        self.assertIn("ExecStart=/usr/bin/bootc upgrade --quiet", stage.splitlines())
        self.assertNotIn("--apply", stage)
        policy = json.loads(read("shared/trust/etc/containers/policy.json"))
        self.assertTrue(
            (ROOT / "shared/trust/etc/pki/containers/luminusos.pub").stat().st_size
        )
        for image in ("luminusos", "luminusos-workstation"):
            rule = policy["transports"]["docker"][f"ghcr.io/luminusos/{image}"][0]
            self.assertEqual(rule["type"], "sigstoreSigned")
            self.assertEqual(rule["keyPath"], "/etc/pki/containers/luminusos.pub")
        self.assertIn(
            "sha256sum -c", read("editions/workstation/Containerfile.installer")
        )

    def test_workflow_security_and_contracts(self):
        publish = read(".github/workflows/publish.yml")
        metadata = read(".github/scripts/workflow/build_metadata.py")
        publisher = read(".github/scripts/workflow/release_publish.py")
        auto = read(".github/workflows/auto-testing.yml")
        build = read(".github/workflows/build-containers.yml")
        self.assertNotIn("needs.version", publish)
        self.assertIn("SHA256:209BDmH3jsRyO9UeGPPgLWPSegKmYCBIya0nR/AWWCY", publisher)
        self.assertIn("release_publish.py publish --candidate", publish)
        self.assertIn("if: github.ref == 'refs/heads/main'", publish)
        self.assertIn("uses: ./.github/workflows/containers.yml", publish)
        self.assertIn("uses: ./.github/workflows/containers.yml", build)
        for value in (
            "uses: ./.github/workflows/publish.yml",
            "build_sequence: true",
            "org.opencontainers.image.base.digest",
            "needs.check.outputs.build",
        ):
            self.assertIn(value, auto)
        for key in ("fedora_version", "sirius_version"):
            self.assertRegex(
                publish, re.compile(rf'{key}:\n(?:.*\n){{0,3}}\s*default: ""')
            )
        self.assertIn(
            '"sirius_rpm_version": override.replace("-rc.", "~rc.")', metadata
        )
        self.assertIn("sirius_version override requires sirius_sha256", metadata)
        self.assertIn("publish: false", build)
        self.assertNotIn("inputs.publish", build)
        self.assertIn('env.get("PUBLISH") == "true"', metadata)
        self.assertIn("reusable build is read-only", metadata)
        self.assertIn(
            "workstation_target_image=ghcr.io/${{ inputs.image_namespace }}/luminusos-workstation:${{ inputs.target_tag }}",
            read(".github/workflows/installer.yml"),
        )
        self.assertIn(
            '"cosign", "sign", "--yes", "--key", "env://COSIGN_PRIVATE_KEY"',
            read(".github/scripts/workflow/sign_candidates.py"),
        )
        self.assertIn("cosign-release: v2.", publish)
        self.assertIn('"FETCH_HEAD:config/releases.env"', metadata)
        self.assertNotIn(
            "channel_policy",
            "\n".join(
                read(str(path.relative_to(ROOT)))
                for path in (ROOT / ".github/workflows").glob("*.yml")
            ),
        )
        self.assertIn('fedora == supported["LATEST_RELEASE"]', metadata)
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            for line in path.read_text().splitlines():
                match = re.match(r"\s*(?:- )?uses: (\S+)", line)
                if match:
                    value = match.group(1)
                    self.assertTrue(
                        value.startswith("./")
                        or re.fullmatch(r"[^ ]+@[0-9a-f]{40}", value)
                        or re.fullmatch(r"docker://[^ ]+@sha256:[0-9a-f]{64}", value),
                        (path, line),
                    )

    def test_stable_promotion_and_tag_order(self):
        workflow = read(".github/workflows/containers.yml")
        publish = read(".github/workflows/publish.yml")
        promotion = read(".github/scripts/workflow/promote_images.py")
        orchestration = read(".github/scripts/workflow/release_publish.py")
        with self.subTest("preserve digest"):
            for argument in ('"skopeo"', '"copy"', '"--all"', '"--preserve-digests"'):
                self.assertIn(argument, promotion)
            self.assertIn("promotion.promote(", orchestration)
            self.assertIn("release_publish.py promote", publish)
        with self.subTest("testing source"):
            self.assertIn(
                'candidate["version_tag"] != f"testing-{version}"', orchestration
            )
            self.assertIn('candidate["channel"] != "testing"', orchestration)
            self.assertIn("release_publish.py verify-source", publish)
        with self.subTest("Fedora stable release check"):
            self.assertIn("docker://quay.io/fedora/fedora-bootc:latest", orchestration)
            self.assertIn('"SUPPORTED_RELEASES"', orchestration)
            self.assertIn("candidate Fedora release is not yet GA", orchestration)
        with self.subTest("signing before tags"):
            sign = publish.find("sign_candidates.py")
            move = publish.find("release_publish.py promote")
            self.assertGreaterEqual(sign, 0)
            self.assertGreater(move, sign)
            self.assertLess(
                orchestration.index(
                    "candidate = verify_release(candidate_path, evidence_path, key)",
                    orchestration.index("def promote("),
                ),
                orchestration.index(
                    "promotion.promote(", orchestration.index("def promote(")
                ),
            )
            self.assertLess(
                promotion.index('["cosign", "verify"'),
                promotion.index('"--preserve-digests"'),
            )
        with self.subTest("no early tag push"):
            self.assertNotRegex(workflow, r"docker push.*(?:branch_tag|channel_tag)")
            self.assertNotIn("steps.version.outputs.channel_core_image }}", workflow)
            self.assertNotIn(
                "steps.version.outputs.channel_workstation_image }}", workflow
            )

    def test_published_images_are_signed(self):
        publish = read(".github/workflows/publish.yml")
        signing = read(".github/scripts/workflow/sign_candidates.py")
        self.assertIn(
            '"cosign", "sign", "--yes", "--key", "env://COSIGN_PRIVATE_KEY"', signing
        )
        self.assertIn('["cosign", "verify", "--key", str(KEY), immutable]', signing)
        self.assertIn("sign_candidates.py", publish)
        self.assertIn("cosign-release: v2.", publish)
