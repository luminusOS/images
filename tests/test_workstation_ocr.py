import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTAINERFILE = ROOT / "editions/workstation/Containerfile"


class WorkstationOcrTests(unittest.TestCase):
    def test_ocr_packages_are_installed_with_gnome_in_final_image(self):
        source = CONTAINERFILE.read_text()
        desktop = source.split("# GNOME desktop environment packages", 1)[1]
        install = desktop.split("dnf clean all", 1)[0]
        for package in (
            "tesseract",
            "tesseract-langpack-eng",
            "tesseract-langpack-por",
        ):
            with self.subTest(package=package):
                self.assertIn(package, install.split())
        self.assertNotIn("FROM ", desktop)

    def test_build_validation_requires_both_exact_languages_and_success(self):
        source = CONTAINERFILE.read_text()
        self.assertIn('ocr_languages="$(tesseract --list-langs)"', source)
        validation = source.split('ocr_languages="$(tesseract --list-langs)"', 1)[1]
        validation = (
            'ocr_languages="$(tesseract --list-langs)"'
            + validation.split("rpm -q", 1)[0]
        )
        validation = validation.replace("\\\n", "").strip().removesuffix("&&")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "tesseract"
            executable.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$OCR_LANGUAGES"\nexit "$OCR_STATUS"\n'
            )
            executable.chmod(0o755)
            for languages, status, passes in (
                ("List of available languages (2):\neng\npor", "0", True),
                ("eng", "0", False),
                ("por", "0", False),
                ("eng_extra\npor_extra", "0", False),
                ("eng\npor", "1", False),
            ):
                with self.subTest(languages=languages, status=status):
                    result = subprocess.run(
                        ["/bin/sh", "-c", validation],
                        env={
                            **os.environ,
                            "PATH": directory + os.pathsep + os.defpath,
                            "OCR_LANGUAGES": languages,
                            "OCR_STATUS": status,
                        },
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, passes, result.stderr)


if __name__ == "__main__":
    unittest.main()
