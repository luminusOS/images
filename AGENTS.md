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
- Build only the workstation ISO root image for debugging: `just build workstation-iso`

Use `QEMU_RESET_DISK=1 just qemu iso` when the installer test needs a fresh disk.

## Script Conventions

- Build helper scripts use `.sh` extensions.
- Shared data/config inputs live in `shared/`.
- Do not add shared shell scripts unless there is a concrete cross-edition need that cannot live in `core`.
- Edition scripts live under their edition, for example `editions/workstation/build.sh`.
- Containerfiles may call edition scripts through a `/ctx` bind mount.

## Installer Notes

The workstation ISO uses Sirius (the LuminusOS installer, consumed as a prebuilt RPM from its GitHub release) and installs the embedded workstation image from container storage. ISO packaging uses `luminusos-workstation:<tag>-iso` as the live root and `luminusos-workstation:<tag>` as the installed payload. The live ISO itself is not booted as a bootc deployment.

Installed Linux filesystems should be Btrfs in the Sirius ISO install path. Keep `/usr/lib/image-builder/bootc/disk.yaml` (which image-builder uses for the filesystem layout, overriding `--bootc-default-fs`) and the Sirius repart templates (`files/usr/share/sirius/repart.d/`) aligned when changing that storage layout: root/home/var stay Btrfs, but `/boot` must remain ext4 because image-builder qcow2 generation does not support Btrfs for `/boot`. The ISO boot menu is configured through `/usr/lib/image-builder/bootc/iso.yaml`.

Sirius is configured through `/etc/sirius/distro.toml` and `/etc/sirius/sirius.toml`, installed only into the ISO live root by `editions/workstation/Containerfile.installer`. The installed workstation payload should not ship Sirius.

## Cleanup Rules

Avoid reintroducing unused placeholders, compatibility aliases, or CI workflows. If a command is replaced, update README, architecture docs, and this file in the same change.

Do not commit changes or create pull requests from this agent workflow. Reviewing the diff, choosing what belongs in git history, committing, and opening PRs are entirely the developer's responsibility.
