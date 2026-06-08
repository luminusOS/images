# Contributing

This repository builds Luminus OS bootc images. Keep local development focused on the two active editions:

- `core`: shared Fedora bootc base image, published locally as `luminusos:<tag>`.
- `workstation`: GNOME desktop image, packaged as ISO and qcow2 artifacts.

## Local Development Builds

Use the normal build when you need an image that is close to a packageable artifact:

```bash
just build workstation
```

For fast iteration on workstation image changes that do not need Flatpaks or immediate ISO/qcow2 packaging, use:

```bash
LOS_TAG=44.dev LOS_SKIP_FLATPAKS=1 LOS_SQUASH=0 just build workstation
```

What each variable does:

- `LOS_TAG=44.dev` keeps the local image tag stable across days, avoiding rebuilds caused only by the date-based default tag changing.
- `LOS_SKIP_FLATPAKS=1` skips Flatpak installation, which avoids network and install time while testing image/package/session changes.
- `LOS_SQUASH=0` skips the post-build squash step, keeping the fastest local build path.

Do not use `LOS_SQUASH=0` as the final packaging path. `just package workstation` squashes local images before running image-builder so OCI whiteouts from lower layers are processed.

## Packaging

Build the workstation image first, then package the desired artifact:

```bash
just build workstation
just package workstation
just package workstation iso
just package workstation qcow2
```

The ISO path automatically builds a separate live installer root image tagged as `luminusos-workstation:<tag>-iso`, then embeds the normal `luminusos-workstation:<tag>` image as the ReadyMade install payload. The qcow2 path creates a directly bootable disk image from the normal workstation image and does not exercise the ReadyMade UI.

## QEMU Testing

Boot the latest ISO:

```bash
just qemu iso
```

Use a fresh install disk for installer tests:

```bash
QEMU_RESET_DISK=1 just qemu iso
```

Install directly to a QEMU disk and boot it:

```bash
just qemu install
just qemu run
```

## Shared Inputs

Shared data and config live in `shared/`:

- `shared/flatpaks`
- `shared/bootc-image-builder.toml`

Do not reintroduce shared shell scripts unless there is a concrete cross-edition need that cannot live in `core` or an edition-local script.
