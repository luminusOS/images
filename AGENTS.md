# AGENTS.md

## Scope

This repository currently maintains two active editions:

- `core`: shared Fedora bootc base image.
- `workstation`: GNOME desktop image packaged as ISO and qcow2 artifacts.

The core source remains under `editions/core`, but its image name is `luminusos:<tag>` rather than a core-specific image name.

Do not add other edition scaffolding unless the package set, target devices, installer flow, and test matrix are part of the change.

## Build Commands

- Build the base image: `just build core`
- Build the workstation image: `just build workstation`
- Package all workstation artifacts: `just package workstation`
- Package one format: `just package workstation iso` or `just package workstation qcow2`
- Boot the latest ISO in QEMU: `just qemu iso`
- Install to a QEMU disk: `just qemu install`
- Boot the installed QEMU disk: `just qemu run`

Use `QEMU_RESET_DISK=1 just qemu iso` when the installer test needs a fresh disk.

## Script Conventions

- Build helper scripts use `.sh` extensions.
- Shared scripts live in `common/`.
- Desktop scripts live under their desktop module, for example `desktops/gnome/build.sh`.
- Containerfiles should call scripts through the `/ctx` bind mount, for example `/ctx/common/recover-rpmdb.sh`.

## Installer Notes

The workstation ISO uses ReadyMade with `copy_mode = "bootc"` and installs the embedded workstation image from container storage. The live ISO itself is not booted as a bootc deployment.

Installed Linux filesystems should be Btrfs. Keep `--bootc-default-fs btrfs`, ReadyMade repart templates, and `/usr/lib/image-builder/bootc/disk.yaml` aligned when changing storage layout. The ISO boot menu is configured through `/usr/lib/image-builder/bootc/iso.yaml`.

The local wrappers under `desktops/gnome/files/usr/libexec/luminusos/` are intentional:

- `bootc-wrapper` moves bootc image import temp data onto the target disk, removes installer artifacts from the target deployment, and writes final target GRUB configs after `bootc install to-filesystem`.
- `bootupctl-wrapper` filters bootupd flags that fail during the live ISO install path.
- `readymade-wrapper` keeps ReadyMade temp files out of the live ISO root and forces UTF-8 locale.

Keep those wrappers in sync with `editions/workstation/Containerfile`, which installs them over the corresponding system binaries during image build.

## Cleanup Rules

Avoid reintroducing unused placeholders, compatibility aliases, or CI workflows. If a command is replaced, update README, architecture docs, and this file in the same change.
