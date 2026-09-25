<div align="center">
  <img src="editions/workstation/assets/logo.png" width="160" />
</div>

# Luminus OS

An immutable operating system built on [Fedora bootc](https://containers.github.io/bootc/), with atomic updates, OCI container delivery, and a GNOME workstation packaged as installable artifacts.

## Editions

| Edition | Description | Output |
| --- | --- | --- |
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

Every build has a channel-neutral version, `{FEDORA_VERSION}.{YYYYMMDD}`, written to `/usr/lib/os-release`. The channel only appears in image tags:

| Channel | Dated tag | Fedora tag | Channel tag | GitHub release |
| --- | --- | --- | --- | --- |
| testing | `testing-45.20260923` | `testing-45` | `testing` | `testing-45.20260923` (pre-release) |
| stable | `45.20260923` | `45` | `latest` | `v45.20260923` |

Tags apply to both `ghcr.io/luminusos/luminusos` and `ghcr.io/luminusos/luminusos-workstation`.

Published images are signed with cosign and installed systems refuse unsigned updates. Verify manually with:

```bash
cosign verify --key editions/workstation/files/system/etc/pki/containers/luminusos.pub ghcr.io/luminusos/luminusos-workstation:testing
```

### Release pipeline

1. **Testing**: run the `publish` workflow with `channel=testing`. It builds new images, packages and boot-tests the ISO/qcow2, and publishes a pre-release.
2. **Stable**: after validating a testing build, run `publish` with `channel=stable` and `promote_version=45.20260923`. Stable never rebuilds; it copies the `testing-45.20260923` images to the stable tags with identical digests, then repackages, boot-tests and publishes a normal release.

Installed systems follow `UPDATE_CHANNEL` in `config/versions.env` (it sets the Sirius `target_imgref`), independent of which channel an ISO was published on. It stays `testing` until the first stable release exists; switch it to `stable` to make new installs track `luminusos-workstation:{FEDORA_VERSION}`.

## Rebasing to Luminus OS

Rebase an existing bootc-capable Fedora Atomic system:

```bash
bootc switch ghcr.io/luminusos/luminusos-workstation:testing
```

## CI & Releases

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci` | Push to `main` | Lint, unit/config tests, core smoke build |
| `build-containers` | Push/PR on `main` and `f*`, or manual | Validation build of `core` and `workstation`. A manual run with `publish` checked pushes signed testing containers (no ISO/qcow2) |
| `publish` | Manual | `testing`: builds, pushes, packages and boot-tests ISO/qcow2, publishes a pre-release. `stable`: promotes an existing testing build, repackages, boot-tests, publishes a release |

ISO and qcow2 downloads are hosted on [SourceForge](https://sourceforge.net/projects/luminusos/files/) (mirrored worldwide); GitHub Releases carry the notes with direct links and a SHA256 table per edition.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): image layering, installer flow, storage layout, CI internals
- [CONTRIBUTING.md](CONTRIBUTING.md): local builds, tests, packaging, contribution policies
