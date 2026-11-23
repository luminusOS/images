import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "squash_image", ROOT / "tools/squash-image.py"
)
squash = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(squash)


class SquashTests(unittest.TestCase):
    def metadata(self, layers=1, labels=None):
        return json.dumps(
            {
                "OCIv1": {
                    "rootfs": {
                        "type": "layers",
                        "diff_ids": ["sha256:" + "a" * 64] * layers,
                    },
                    "config": {"Labels": {} if labels is None else labels},
                }
            }
        )

    def test_single_layer_without_ostree_labels_is_noop(self):
        with (
            patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
            patch.object(squash, "run", return_value=self.metadata()) as run,
            patch.object(squash.subprocess, "run") as cleanup,
        ):
            squash.main()
        run.assert_called_once_with(
            ["sudo", "buildah", "inspect", "--type", "image", "localhost/image:tag"],
            capture=True,
        )
        cleanup.assert_not_called()

    def test_multilayer_or_present_labels_squashes(self):
        for metadata in (
            self.metadata(layers=2),
            self.metadata(labels={"ostree.final-diffid": ""}),
            self.metadata(labels={"ostree.commit": "value"}),
        ):
            with (
                self.subTest(metadata=metadata),
                patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
                patch.object(
                    squash, "run", side_effect=[metadata, "container123\n", None, None]
                ) as run,
                patch.object(squash.subprocess, "run") as cleanup,
            ):
                squash.main()
            self.assertEqual(
                run.call_args_list[1].args[0],
                ["sudo", "buildah", "from", "--pull=never", "localhost/image:tag"],
            )
            self.assertEqual(
                run.call_args_list[2].args[0],
                [
                    "sudo",
                    "buildah",
                    "config",
                    "--unsetlabel",
                    "ostree.final-diffid",
                    "--unsetlabel",
                    "ostree.commit",
                    "container123",
                ],
            )
            self.assertEqual(
                run.call_args_list[3].args[0],
                [
                    "sudo",
                    "buildah",
                    "commit",
                    "--squash",
                    "container123",
                    "localhost/image:tag",
                ],
            )
            self.assertEqual(
                cleanup.call_args.args[0], ["sudo", "buildah", "rm", "container123"]
            )

    def test_malformed_inspect_fails_before_from(self):
        bad = ["not json", "null", "{}", json.dumps({"OCIv1": {}})]
        bad.append(
            json.dumps(
                {
                    "OCIv1": {
                        "rootfs": {
                            "type": "layers",
                            "diff_ids": ["sha256:" + "a" * 64],
                        },
                        "config": {},
                    }
                }
            )
        )
        for rootfs, labels in (
            (None, {}),
            ({"type": "layers", "diff_ids": []}, {}),
            ({"type": "layers", "diff_ids": [None]}, {}),
            ({"type": "layers", "diff_ids": ["bad"]}, {}),
            ({"type": "other", "diff_ids": ["sha256:" + "a" * 64]}, {}),
            ({"type": "layers", "diff_ids": ["sha256:" + "a" * 64]}, None),
            ({"type": "layers", "diff_ids": ["sha256:" + "a" * 64]}, {"x": 1}),
        ):
            bad.append(
                json.dumps({"OCIv1": {"rootfs": rootfs, "config": {"Labels": labels}}})
            )
        for metadata in bad:
            with (
                self.subTest(metadata=metadata),
                patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
                patch.object(squash, "run", return_value=metadata) as run,
                patch.object(squash.subprocess, "run") as cleanup,
                self.assertRaises(ValueError),
            ):
                squash.main()
            self.assertEqual(run.call_count, 1)
            cleanup.assert_not_called()

    def test_inspect_failure_propagates_without_cleanup(self):
        with (
            patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
            patch.object(
                squash, "run", side_effect=subprocess.CalledProcessError(1, "inspect")
            ) as run,
            patch.object(squash.subprocess, "run") as cleanup,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            squash.main()
        self.assertEqual(run.call_count, 1)
        cleanup.assert_not_called()

    def test_config_failure_still_removes_temporary_container(self):
        def fake(command, **kwargs):
            if command[2] == "inspect":
                return self.metadata(layers=2)
            if command[2] == "from":
                return "container123\n"
            if command[2] == "config":
                raise subprocess.CalledProcessError(1, command)
            return None

        with (
            patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
            patch.object(squash, "run", side_effect=fake),
            patch.object(squash.subprocess, "run") as cleanup,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            squash.main()
        self.assertEqual(
            cleanup.call_args_list[-1].args[0],
            ["sudo", "buildah", "rm", "container123"],
        )

    def test_commit_failure_still_removes_temporary_container(self):
        with (
            patch.object(sys, "argv", ["squash-image.py", "localhost/image:tag"]),
            patch.object(
                squash,
                "run",
                side_effect=[
                    self.metadata(layers=2),
                    "container123\n",
                    None,
                    subprocess.CalledProcessError(1, "commit"),
                ],
            ),
            patch.object(squash.subprocess, "run") as cleanup,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            squash.main()
        self.assertEqual(
            cleanup.call_args.args[0], ["sudo", "buildah", "rm", "container123"]
        )


if __name__ == "__main__":
    unittest.main()
