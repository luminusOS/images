import hashlib
import re
import unittest
from pathlib import Path

import yaml


class CIToolingTests(unittest.TestCase):
    def test_actionlint_build_pins_reviewed_source_and_builder(self):
        root = Path(__file__).resolve().parents[1]
        containerfile = (
            root / ".github/containers/actionlint/Containerfile"
        ).read_text()
        self.assertIn(
            "FROM docker.io/library/golang:1.26.11-bookworm@sha256:"
            "79ecd0a7157c7a4cf3b281ced8465350591bf54fedab540e75374a003e1fde7e"
            " AS builder",
            containerfile,
        )
        self.assertIn(
            "https://codeload.github.com/rhysd/actionlint/tar.gz/"
            "914e7df21a07ef503a81201c76d2b11c789d3fca",
            containerfile,
        )
        self.assertIn(
            "30a9b942aa2a9c5246d8434d3ad9ff010969d1d4510281c4d395e18665192e6e",
            containerfile,
        )
        self.assertLess(
            containerfile.index("sha256sum --check"), containerfile.index("tar -x")
        )
        self.assertIn("git apply --check /tmp/native26.patch", containerfile)
        self.assertIn("git apply --whitespace=error /tmp/native26.patch", containerfile)

    def test_actionlint_patch_matches_reviewed_artifact(self):
        root = Path(__file__).resolve().parents[1]
        patch = (root / ".github/containers/actionlint/native26.patch").read_bytes()
        digest = "fc7c822a3bcdf299da41206205f38d172c615e4caa692f2ce1de5af1854094bd"
        self.assertEqual(hashlib.sha256(patch).hexdigest(), digest)
        containerfile = (
            root / ".github/containers/actionlint/Containerfile"
        ).read_text()
        self.assertIn(digest, containerfile)
        self.assertLess(containerfile.index(digest), containerfile.index("git apply"))

    def test_actionlint_fetch_inventory_is_limited_to_reviewed_versions(self):
        root = Path(__file__).resolve().parents[1]
        containerfile = (
            root / ".github/containers/actionlint/Containerfile"
        ).read_text()
        selected = re.findall(r"^\s+([^\s]+@v[^\s;]+)", containerfile, re.MULTILINE)
        self.assertCountEqual(
            selected,
            [
                "github.com/bmatcuk/doublestar/v4@v4.10.0",
                "github.com/fatih/color@v1.19.0",
                "github.com/google/go-cmp@v0.7.0",
                "github.com/mattn/go-colorable@v0.1.14",
                "github.com/mattn/go-runewidth@v0.0.21",
                "github.com/mattn/go-shellwords@v1.0.12",
                "github.com/robfig/cron/v3@v3.0.1",
                "github.com/yuin/goldmark@v1.7.17",
                "go.yaml.in/yaml/v4@v4.0.0-rc.3",
                "golang.org/x/net@v0.52.0",
                "golang.org/x/sync@v0.20.0",
                "golang.org/x/sys@v0.42.0",
                "github.com/clipperhouse/uax29/v2@v2.7.0",
                "github.com/mattn/go-isatty@v0.0.20",
            ],
        )

    def test_actionlint_build_authenticates_modules_before_offline_execution(self):
        root = Path(__file__).resolve().parents[1]
        containerfile = (
            root / ".github/containers/actionlint/Containerfile"
        ).read_text()
        self.assertIn("GOTOOLCHAIN=local", containerfile)
        self.assertIn("GOWORK=off", containerfile)
        self.assertIn("GOENV=off", containerfile)
        self.assertIn("CGO_ENABLED=0", containerfile)
        self.assertIn("GOFLAGS=-mod=readonly", containerfile)
        self.assertIn("GOPROXY=https://proxy.golang.org", containerfile)
        self.assertIn("GOSUMDB=sum.golang.org", containerfile)
        self.assertIn('go mod download -json "$module"', containerfile)
        checksum_guard = 'grep -Fq "$module_path $module_version/go.mod h1:" go.sum'
        self.assertIn(checksum_guard, containerfile)
        self.assertLess(
            containerfile.index(checksum_guard), containerfile.index("go mod download")
        )
        self.assertIn(
            "sha256sum go.mod go.sum > /tmp/module-files.sha256", containerfile
        )
        self.assertEqual(
            containerfile.count("sha256sum --check /tmp/module-files.sha256"), 2
        )
        offline = containerfile.split("RUN --network=none", 1)[1]
        self.assertIn("export GOPROXY=off GOSUMDB=off", offline)
        self.assertIn(
            "go test -mod=readonly ./ -run '^TestRuleRunnerLabel' -count=1", offline
        )
        self.assertIn("go build -trimpath -buildvcs=false -mod=readonly", offline)
        for forbidden in [
            "go mod tidy",
            "go generate",
            "go mod download all",
            "apt-get",
            "apk add",
            "--mount=type=cache",
            "--mount=type=secret",
        ]:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, containerfile)

    def test_actionlint_final_stage_only_replaces_binary(self):
        root = Path(__file__).resolve().parents[1]
        containerfile = (
            root / ".github/containers/actionlint/Containerfile"
        ).read_text()
        final = containerfile.rsplit("\nFROM ", 1)[1].splitlines()
        self.assertEqual(
            final,
            [
                (
                    "docker.io/rhysd/actionlint@sha256:"
                    "887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9"
                ),
                "COPY --from=builder /out/actionlint /usr/local/bin/actionlint",
            ],
        )

    def test_actionlint_ci_builds_minimal_context_and_checks_all_workflows(self):
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        self.assertEqual(workflow["jobs"]["quality"]["runs-on"], "ubuntu-26.04")
        step = next(
            s
            for s in workflow["jobs"]["actionlint"]["steps"]
            if s.get("name") == "actionlint"
        )
        self.assertEqual(step["timeout-minutes"], 10)
        run = step["run"]
        self.assertIn("docker build --platform linux/amd64", run)
        self.assertIn("--file .github/containers/actionlint/Containerfile", run)
        self.assertIn(
            "--tag luminus-actionlint:native26 .github/containers/actionlint", run
        )
        self.assertIn("docker run --rm --network=none --read-only", run)
        self.assertIn("--workdir /work", run)
        self.assertIn('src="$GITHUB_WORKSPACE",dst=/work,readonly', run)
        self.assertIn("-shellcheck=/usr/local/bin/shellcheck", run)
        self.assertIn("-pyflakes=/usr/bin/pyflakes", run)
        self.assertNotIn(".github/workflows/", run)
        self.assertNotIn("-ignore", run)
        self.assertNotIn("push", run)

    def test_quality_installs_verified_just_before_checks(self):
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
        steps = workflow["jobs"]["quality"]["steps"]
        system = next(
            step for step in steps if step.get("name") == "Install system tooling"
        )
        self.assertNotIn(" just ", f" {system['run'].splitlines()[-1]} ")
        install_index = next(
            i for i, step in enumerate(steps) if step.get("name") == "Install just"
        )
        check_index = next(
            i for i, step in enumerate(steps) if step.get("name") == "Check tooling"
        )
        install = steps[install_index]["run"]
        self.assertLess(install_index, check_index)
        self.assertIn("just-1.46.0-x86_64-unknown-linux-musl.tar.gz", install)
        self.assertIn(
            "79966e6e353f535ee7d1c6221641bcc8e3381c55b0d0a6dc6e54b34f9db36eaa", install
        )
        self.assertLess(install.index("sha256sum --check"), install.index("tar -x"))
        self.assertIn("GITHUB_PATH", install)
