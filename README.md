<div align="center">
  <img src="editions/workstation/files/usr/share/sirius/logo.png" width="160" />
</div>

# Luminus OS

An immutable operating system built on [Fedora bootc](https://containers.github.io/bootc/), with atomic updates, OCI container delivery, and a GNOME workstation packaged as installable artifacts.

## Editions

| Edition | Description | Output |
|---------|-------------|--------|
| **core** | Minimal base for downstream Luminus images | `luminusos:<tag>` container image |
| **workstation** | GNOME desktop for PCs and notebooks | Container image, installable ISO (Sirius), qcow2 |

Planned editions (not active build targets yet): **mobile**, **cast**, **play**, **education**. Planning notes live under `editions/`.

## Quick Start

```bash
just build workstation        # build the desktop image
just package workstation iso  # produce the installer ISO
just qemu iso                 # boot it in QEMU/KVM
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, faster iteration flags, packaging, and QEMU testing.

## Versioning

Releases follow the Fedora base version plus a build date:

```
{FEDORA_VERSION}.{YYYYMMDD}   →   44.20260322
```

Container images use the Fedora version as a floating tag:

```
ghcr.io/luminusos/luminusos:44
ghcr.io/luminusos/luminusos-workstation:44
```

## Rebasing to Luminus OS

Rebase an existing bootc-capable Fedora Atomic system:

```bash
bootc switch ghcr.io/luminusos/luminusos-workstation:44
```

## CI & Releases

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci` | Push to `main` | Lint, unit/config tests, core smoke build |
| `build-containers` | Push/PR on `main` and `f*` | Builds `core` and `workstation` containers → GHCR |
| `publish` | Manual | Builds containers, packages ISO + qcow2, boot smoke test, GitHub Release |

ISO and qcow2 downloads are hosted on [SourceForge](https://sourceforge.net/projects/luminusos/files/) (mirrored worldwide); GitHub Releases carry the notes with direct links and a SHA256 table per edition.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): image layering, installer flow, storage layout, CI internals
- [CONTRIBUTING.md](CONTRIBUTING.md): local builds, tests, packaging, contribution policies
