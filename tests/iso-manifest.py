import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY = "etc/selinux/targeted/contexts/files/file_contexts"


def stage(name, **fields):
    return {"type": f"org.osbuild.{name}", **fields}


def pipeline(name, *stages):
    return {"name": name, "stages": list(stages)}


def tree_input(name, alias="tree"):
    return {
        alias: {
            "type": "org.osbuild.tree",
            "origin": "org.osbuild.pipeline",
            "references": [f"name:{name}"],
        }
    }


def manifest():
    options = {
        "kernel": {"opts": ["root=live:CDLABEL=LUMINUSOS", "enforcing=0", "quiet"]},
        "custom": [{"linux": "/images/pxeboot/vmlinuz enforcing=1 rd.live.image"}],
    }
    return {
        "version": "2",
        "pipelines": [
            pipeline("build", stage("selinux", options={"file_contexts": POLICY})),
            pipeline("os-tree", stage("container-deploy")),
            pipeline("efiboot-tree", stage("grub2.iso", options=copy.deepcopy(options))),
            pipeline(
                "bootiso-tree",
                stage("mkdir"),
                stage("copy", inputs=tree_input("os-tree"), options={"paths": [
                    {"from": "input://tree/lib/modules/k/vmlinuz", "to": "tree:///images/pxeboot/vmlinuz"},
                    {"from": "input://tree/lib/modules/k/initramfs.img", "to": "tree:///images/pxeboot/initrd.img"},
                ]}),
                stage("chmod"),
                stage("squashfs", inputs=tree_input("os-tree"), options={"filename": "LiveOS/squashfs.img"}),
                stage("grub2.iso.legacy", options=copy.deepcopy(options)),
                stage("grub2.inst", options={"filename": "images/eltorito.img", "prefix": {"path": "/boot/grub2"}}),
                stage("truncate", options={"filename": "images/efiboot.img"}),
                stage("mkfs.fat", devices={"device": {"type": "org.osbuild.loopback", "options": {"filename": "images/efiboot.img"}}}),
                stage("copy", inputs=tree_input("efiboot-tree", "root-tree"),
                      options={"paths": [{"from": "input://root-tree/", "to": "mount://-/"}]},
                      devices={"-": {"type": "org.osbuild.loopback", "options": {"filename": "images/efiboot.img"}}},
                      mounts=[{"name": "-", "type": "org.osbuild.fat", "source": "-", "target": "/"}]),
                stage("copy", inputs=tree_input("efiboot-tree", "root-tree"),
                      options={"paths": [{"from": "input://root-tree/EFI", "to": "tree:///"}]}),
                stage("discinfo"),
            ),
            pipeline(
                "bootiso",
                stage("xorrisofs", inputs=tree_input("bootiso-tree"), options={
                    "filename": "install.iso", "efi": "images/efiboot.img", "boot": {"image": "images/eltorito.img"},
                }),
                stage("implantisomd5", options={"filename": "install.iso"}),
            ),
        ],
    }


class IsoManifestTest(unittest.TestCase):
    def transform(self, data):
        return subprocess.run(
            [sys.executable, "-B", ROOT / "tools/enforce-live-iso.py"],
            input=json.dumps(data), capture_output=True, text=True, check=False,
        )

    def test_labels_the_compressed_tree_and_sanitizes_both_menus(self):
        data = manifest()
        result = self.transform(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = copy.deepcopy(data)
        expected["pipelines"][1]["stages"].append(stage(
            "selinux", options={"file_contexts": POLICY, "exclude_paths": ["/sysroot"]},
        ))
        for idx, stage_index in ((2, 0), (3, 4)):
            expected["pipelines"][idx]["stages"][stage_index]["options"]["kernel"]["opts"].remove("enforcing=0")
        self.assertEqual(json.loads(result.stdout), expected)

    def test_refuses_unknown_pipeline_and_unsafe_boot_options(self):
        mutations = (
            lambda data: data.update(version="3"),
            lambda data: data["pipelines"].append(copy.deepcopy(data["pipelines"][1])),
            lambda data: data["pipelines"][1]["stages"].append(stage("copy")),
            lambda data: data["pipelines"][3]["stages"][3].update(inputs=tree_input("build")),
            lambda data: data["pipelines"][4]["stages"][0].update(inputs=tree_input("build")),
            lambda data: data["pipelines"][3]["stages"].pop(4),
            lambda data: data["pipelines"][2]["stages"][0]["options"]["kernel"]["opts"].append("selinux=0"),
            lambda data: data["pipelines"][2]["stages"][0]["options"]["custom"][0].update(linux="/vmlinuz enforcing=0"),
            lambda data: data["pipelines"][3]["stages"][8].update(inputs=tree_input("build", "root-tree")),
            lambda data: data["pipelines"][3]["stages"][9].update(inputs=tree_input("build", "root-tree")),
            lambda data: data["pipelines"][3]["stages"][3]["options"].update(filename="unused.img"),
            lambda data: data["pipelines"][3]["stages"].append(stage("copy", options={"paths": [
                {"from": "input://tree/stock.img", "to": "tree:///LiveOS/squashfs.img"},
            ]})),
            lambda data: data["pipelines"][3]["stages"][8]["options"]["paths"][0].update(to="tree:///"),
            lambda data: data["pipelines"][4]["stages"][0]["options"].update(efi="images/stock-efi.img"),
            lambda data: data["pipelines"][4]["stages"][0]["options"]["boot"].update(image="images/other.img"),
        )
        for idx, mutate in enumerate(mutations):
            with self.subTest(idx=idx):
                data = manifest()
                mutate(data)
                result = self.transform(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("live ISO manifest:", result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
