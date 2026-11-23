import json
import shlex
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_stages(stages, *kinds):
    require(
        [stage["type"] for stage in stages] == [f"org.osbuild.{kind}" for kind in kinds],
        f"expected stage sequence: {', '.join(kinds)}",
    )
    return stages


def require_tree_input(stage, name, alias="tree"):
    tree = stage["inputs"][alias]
    require(
        tree["type"] == "org.osbuild.tree"
        and tree["origin"] == "org.osbuild.pipeline"
        and tree["references"] == [f"name:{name}"],
        f"{stage['type']} must consume {name}",
    )


def require_safe_boot_options(tokens, explicit=False):
    for option in ("selinux", "enforcing"):
        values = [token for token in tokens if token.split("=", 1)[0] == option]
        require(
            values in ([], [f"{option}=1"]) and (not explicit or option != "enforcing" or values),
            f"unexpected {option} boot arguments: {values}",
        )


def require_efi_copy(copy, source, destination):
    require_tree_input(copy, "efiboot-tree", "root-tree")
    require(
        copy["options"]["paths"] == [{"from": source, "to": destination}],
        f"unexpected EFI copy to {destination}",
    )


def require_efi_device(stage, alias):
    device = stage["devices"][alias]
    require(
        device["type"] == "org.osbuild.loopback"
        and device["options"]["filename"] == "images/efiboot.img",
        "expected the EFI image as the loop device",
    )


def enforce_live_iso(manifest):
    require(manifest["version"] == "2", "expected an OSBuild v2 manifest")
    pipelines = {pipeline["name"]: pipeline["stages"] for pipeline in manifest["pipelines"]}
    require(len(pipelines) == len(manifest["pipelines"]), "duplicate pipeline name")
    live = pipelines["os-tree"]
    require_stages(live, "container-deploy")
    (uefi,) = require_stages(pipelines["efiboot-tree"], "grub2.iso")
    _, kernel_copy, _, squashfs, bios, grub, truncate, fat, efi_copy, efi_fallback, _ = require_stages(
        pipelines["bootiso-tree"], "mkdir", "copy", "chmod", "squashfs",
        "grub2.iso.legacy", "grub2.inst", "truncate", "mkfs.fat", "copy", "copy", "discinfo",
    )
    iso, checksum = require_stages(pipelines["bootiso"], "xorrisofs", "implantisomd5")
    require_tree_input(kernel_copy, "os-tree")
    require_tree_input(squashfs, "os-tree")
    require(squashfs["options"]["filename"] == "LiveOS/squashfs.img", "unexpected live root path")
    require_tree_input(iso, "bootiso-tree")
    require_efi_copy(efi_copy, "input://root-tree/", "mount://-/")
    require_efi_copy(efi_fallback, "input://root-tree/EFI", "tree:///")
    require_efi_device(efi_copy, "-")
    require_efi_device(fat, "device")
    require(
        efi_copy["mounts"] == [{"name": "-", "type": "org.osbuild.fat", "source": "-", "target": "/"}],
        "unexpected EFI copy mount",
    )
    require(
        truncate["options"]["filename"] == iso["options"]["efi"] == "images/efiboot.img"
        and grub["options"]["filename"] == iso["options"]["boot"]["image"] == "images/eltorito.img"
        and grub["options"]["prefix"]["path"] == "/boot/grub2",
        "unexpected EFI or BIOS boot image wiring",
    )
    require(
        iso["options"]["filename"] == checksum["options"]["filename"] == "install.iso",
        "expected install.iso as the checksummed export",
    )

    for menu in (uefi, bios):
        kind = menu["type"]
        options = menu["options"]
        kernel = options["kernel"]
        require(
            isinstance(kernel["opts"], list)
            and all(isinstance(token, str) and shlex.split(token) == [token] for token in kernel["opts"]),
            f"unexpected {kind} kernel option format",
        )
        kernel["opts"] = [token for token in kernel["opts"] if token != "enforcing=0"]
        require_safe_boot_options(kernel["opts"])
        require(len(options["custom"]) == 1, f"expected one custom {kind} boot entry")
        require_safe_boot_options(shlex.split(options["custom"][0]["linux"])[1:], explicit=True)

    live.append({
        "type": "org.osbuild.selinux",
        "options": {
            "file_contexts": "etc/selinux/targeted/contexts/files/file_contexts",
            "exclude_paths": ["/sysroot"],
        },
    })
    return manifest


if __name__ == "__main__":
    try:
        result = enforce_live_iso(json.load(sys.stdin))
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        sys.exit(f"live ISO manifest: {error}")
    json.dump(result, sys.stdout)
    print()
