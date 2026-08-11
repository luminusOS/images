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
LOS_TAG=44.dev LOS_SKIP_FLATPAKS=1 just build workstation
```

What each variable does:

- `LOS_TAG=testing-44.dev` keeps the local image tag stable across days, avoiding rebuilds caused only by the date-based default tag changing.
- `LOS_SKIP_FLATPAKS=1` skips Flatpak installation, which avoids network and install time while testing image/package/session changes.

Builds squash the local core and workstation payload images by default so OCI whiteouts from lower layers are processed before packaging. The `luminusos-workstation:<tag>-iso` live root squashes itself in `Containerfile.installer` (a final `FROM scratch` + `COPY --from=live / /` stage) because image-builder/osbuild deploys the ISO live root without applying OCI whiteout semantics; leftover `.wh.*` files in the live rootfs break services such as dbus-broker.

## Validation and Tests

Run the same checks CI runs on `main` before pushing:

```bash
just check   # verifies bash, jq, just, Python/PyYAML, shellcheck and shfmt
just lint    # shellcheck over every script
just test    # tests/run.sh: script unit tests + config validation
```

`tests/run.sh` tests the `shared/scripts/` helpers and validates the config files shipped in the images: TOML, JSON, systemd units, repart definitions, YAML, overlays, version defaults, and artifact/QEMU resolution. CI also lints the workflows with actionlint and smoke-builds the core image. The Publish workflow boots the finished qcow2 and ISO under QEMU/KVM, then `.github/scripts/boot-test.sh` checks that a graphical screen appeared.

## Packaging

Build the workstation image first, then package the desired artifact:

```bash
just build workstation
just package workstation
just package workstation iso
just package workstation qcow2
```

The ISO path automatically builds a separate live installer root image tagged as `luminusos-workstation:<tag>-iso`, then embeds the normal `luminusos-workstation:<tag>` image as the Sirius install payload. The qcow2 path creates a directly bootable disk image from the normal workstation image and does not exercise the Sirius UI.

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

## AI-Assisted Contributions

Contributions made with AI assistance are welcome, but the contributor remains responsible for the change. Do not submit code you do not understand. You must be able to explain what the code does, why it is correct, and what tradeoffs or risks it introduces.

AI-assisted changes must be tested thoroughly. Maintainers may ask for evidence that the functionality works and was tested, such as test output, screenshots, screen recordings, logs, or clear reproduction steps.

## Shared Inputs

Shared data and config live in `shared/`:

- `shared/flatpaks`
- `shared/bootc-image-builder.toml.example` (copy to `shared/bootc-image-builder.toml`, gitignored, for local `just qemu install`)
- `shared/scripts/` (build-time helpers bind-mounted into every edition build)

Only add a script to `shared/scripts/` when it is genuinely used by more than one edition Containerfile; edition-specific logic stays in the edition's own script.

Tracked release defaults live in `config/versions.env`; local environment variables still override them. Installed-system files live under `editions/workstation/files/system/`, while files used only by the live installer live under `editions/workstation/files/installer/`.
