<div align="center">
  <img src="editions/workstation/assets/logo.png" width="128" alt="Luminus OS logo" />

# Luminus OS

An immutable Fedora bootc desktop with GNOME, atomic updates, and rollback.

[Downloads](https://github.com/luminusOS/images/releases) · [Build locally](#build-locally) · [Documentation](#documentation)

</div>

## Images

- **Workstation** — GNOME desktop for PCs and notebooks, available as an installer ISO, qcow2 disk, and OCI image (`ghcr.io/luminusos/luminusos-workstation`). The ISO uses the Sirius installer.
- **Core** — shared base for Luminus OS images (`ghcr.io/luminusos/luminusos`).

> [!IMPORTANT]
> Testing releases are pre-releases. Use a disposable VM to evaluate them before installing on hardware, and back up your data.

## Build locally

Use a Linux host with Buildah and sudo access; QEMU/KVM is needed for VM testing. Install `just` (CI uses 1.46.0), Python 3.11+, and `jq`. See the [development guide](CONTRIBUTING.md) for Python dependencies and build options.

```bash
git clone https://github.com/luminusOS/images.git
cd images
just build workstation
just package workstation iso
just qemu iso
```

For a directly bootable VM disk, use `just package workstation qcow2`. To build only the shared base, use `just build core`.

## Updates and trust

Images are delivered through OCI registries; releases require cosign signatures and validation evidence before promotion. Installed systems support atomic updates and rollback.

See the [release strategy](docs/release-strategy.md) for channels, signature verification, download checksums, and installation acceptance criteria. Shipping a trust policy alone does not establish that an installed system rejects untrusted updates.

## Documentation

- [Architecture](ARCHITECTURE.md) — image layers, Sirius installation, and storage layout.
- [Development guide](CONTRIBUTING.md) — local builds, packaging, tests, and QEMU workflows.
- [Release strategy](docs/release-strategy.md) — candidate validation and promotion without rebuilding approved payloads.
