import re
import tomllib
import unittest
from pathlib import Path


class DevDependencyTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        project = tomllib.loads((root / "pyproject.toml").read_text())
        lock = tomllib.loads((root / "uv.lock").read_text())
        self.declared = {}
        for requirement in project["dependency-groups"]["dev"]:
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s,;*]+)", requirement)
            self.assertIsNotNone(match, f"Expected an exact dev pin: {requirement}")
            name, version = match.groups()
            name = re.sub(r"[-_.]+", "-", name).lower()
            self.assertNotIn(name, self.declared)
            self.declared[name] = version
        self.packages = lock["package"]
        roots = [
            package
            for package in self.packages
            if package["source"] == {"virtual": "."}
        ]
        self.assertEqual(len(roots), 1)
        self.root_package = roots[0]

    def test_root_dev_references_match_declared_dependencies(self):
        references = self.root_package["dev-dependencies"]["dev"]
        self.assertCountEqual(
            [reference["name"] for reference in references], self.declared
        )

    def test_root_dev_metadata_matches_declared_pins(self):
        metadata = self.root_package["metadata"]["requires-dev"]["dev"]
        self.assertCountEqual(
            [(entry["name"], entry["specifier"]) for entry in metadata],
            [(name, f"=={version}") for name, version in self.declared.items()],
        )

    def test_declared_dev_versions_are_locked(self):
        for name, version in self.declared.items():
            with self.subTest(package=name):
                self.assertEqual(
                    [
                        package["version"]
                        for package in self.packages
                        if package["name"] == name
                    ],
                    [version],
                )


if __name__ == "__main__":
    unittest.main()
