#!/usr/bin/env python3
import argparse
import os
import shlex
import shutil
import sys
from pathlib import Path

from qemu_common import (
    disk_format,
    is_owned_file,
    load_environment,
    record_owned_file,
    resolve_artifact,
    resolve_ovmf,
)

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", default="disk", choices=("disk", "iso"))
    args = parser.parse_args()
    test_dir = ROOT / ".test"
    if test_dir.is_symlink():
        raise ValueError("refusing to use symlinked .test directory")
    test_dir.mkdir(exist_ok=True)
    env = load_environment(ROOT, os.environ)
    dry = env.get("QEMU_DRY_RUN", "0") == "1"
    display = env.get("QEMU_DISPLAY") or "auto"
    command = [
        env.get("QEMU_BINARY") or "qemu-kvm",
        "-machine",
        "type=q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        env.get("QEMU_MEM") or "4G",
        "-smp",
        env.get("QEMU_CPU") or "4",
        "-display",
        "gtk" if display == "auto" else display,
        "-netdev",
        "user,id=net0,hostfwd=tcp::2222-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]
    bus = env.get("QEMU_DISK_BUS") or "ahci"
    if bus not in ("ahci", "sata", "virtio"):
        raise ValueError(f"Unknown QEMU_DISK_BUS: {bus}")

    def add_disk(path, name, index):
        command.extend(
            ["-drive", f"file={path},format={disk_format(path)},if=none,id={name}"]
        )
        if bus in ("ahci", "sata"):
            command.extend(
                [
                    "-device",
                    "ich9-ahci,id=ahci",
                    "-device",
                    f"ide-hd,drive={name},bus=ahci.{index - 1},bootindex={index}",
                ]
            )
        else:
            command.extend(
                ["-device", f"virtio-blk-pci,drive={name},bootindex={index}"]
            )

    if args.mode == "disk":
        path = resolve_artifact(
            ROOT,
            env.get("QEMU_DISK_PATH"),
            test_dir / "last-qcow2",
            "*.qcow2",
            test_dir / "disk.qcow2",
        )
        print(f"Booting disk: {path}", flush=True)
        add_disk(path, "system_disk", 1)
        command.extend(["-boot", "order=c,menu=on"])
    else:
        path = resolve_artifact(
            ROOT, env.get("QEMU_ISO_PATH"), test_dir / "last-iso", "*.iso"
        )
        print(f"Booting ISO: {path}", flush=True)
        command.extend(["-cdrom", str(path), "-boot", "once=d,order=c,menu=on"])
        disk = Path(
            env.get("QEMU_INSTALL_DISK_PATH") or test_dir / "install-disk.qcow2"
        )
        if disk.is_symlink() and not disk.is_file():
            raise ValueError("refusing broken install disk symlink")
        disk_marker = test_dir / ".install-disk-owned"
        if disk_marker.is_symlink():
            raise ValueError("refusing symlinked disk ownership marker")
        if env.get("QEMU_RESET_DISK", "0") != "0" and not dry and disk.exists():
            if (
                disk.is_symlink()
                or disk.resolve().parent != test_dir.resolve()
                or disk.name != "install-disk.qcow2"
                or not is_owned_file(disk, disk_marker, "luminusos-install-disk")
            ):
                raise ValueError("refusing to reset an unowned install disk")
            disk.unlink()
        if not disk.is_file() and not dry:
            import subprocess

            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    str(disk),
                    env.get("QEMU_INSTALL_DISK_SIZE") or "64G",
                ],
                check=True,
                env=env,
            )
            if (
                disk.resolve().parent == test_dir.resolve()
                and disk.name == "install-disk.qcow2"
            ):
                record_owned_file(disk, disk_marker, "luminusos-install-disk")
        add_disk(disk, "install_disk", 2)
    if env.get("QEMU_BOOT", "uefi") == "uefi":
        code, template = resolve_ovmf(env)
        variables = Path(env.get("QEMU_OVMF_VARS") or test_dir / "OVMF_VARS.fd")
        if variables.is_symlink() and not variables.is_file():
            raise ValueError("refusing broken NVRAM symlink")
        vars_marker = test_dir / ".ovmf-vars-owned"
        if vars_marker.is_symlink():
            raise ValueError("refusing symlinked NVRAM ownership marker")
        if env.get("QEMU_RESET_NVRAM", "0") != "0" and not dry and variables.exists():
            if (
                variables.is_symlink()
                or variables.resolve().parent != test_dir.resolve()
                or variables.name != "OVMF_VARS.fd"
                or not is_owned_file(variables, vars_marker, "luminusos-ovmf-vars")
            ):
                raise ValueError("refusing to reset unowned NVRAM")
            variables.unlink()
        if not variables.is_file() and not dry:
            shutil.copyfile(template, variables)
            if (
                variables.resolve().parent == test_dir.resolve()
                and variables.name == "OVMF_VARS.fd"
            ):
                record_owned_file(variables, vars_marker, "luminusos-ovmf-vars")
        command.extend(
            [
                "-drive",
                f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive",
                f"if=pflash,format=raw,file={variables}",
            ]
        )
    if env.get("QEMU_DEBUG", "1") != "0":
        log = test_dir / "qemu.log"
        command.extend(
            [
                "-d",
                "guest_errors",
                "-D",
                str(log),
                "-serial",
                "mon:stdio",
                "-monitor",
                "none",
            ]
        )
        print(f"Debug logging enabled: {log}", flush=True)
    if env.get("QEMU_NO_REBOOT", "0") != "0":
        command.append("-no-reboot")
    if dry:
        print(shlex.join(command))
    else:
        os.execvpe(command[0], command, env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"qemu: {error}", file=sys.stderr)
        sys.exit(1)
