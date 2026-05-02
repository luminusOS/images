# Luminus OS

An immutable, GNOME-only operating system built on [Fedora bootc](https://containers.github.io/bootc/). Atomic updates, OCI container delivery, and three distinct editions for different form factors.

## Editions

| Edition | Description | Output |
|---------|-------------|--------|
| **core** | Minimal CLI base — containers, servers, terminal | Container image |
| **workstation** | GNOME desktop for PCs and notebooks | Container image + ISO |
| **mobile-phosh** | [Phosh](https://gitlab.gnome.org/World/Phosh/phosh) shell for phones and tablets | Container image + 7z disk image |
| **mobile-gnome** | GNOME Mobile shell for phones and tablets | Container image + 7z disk image |

## Versioning

Releases follow the Fedora base version with a build date suffix:

```
{FEDORA_VERSION}.{YYYYMMDD}   →   44.20260322
```

## Project Structure

```
.
├── common/            # Shared base packages (all editions)
│   ├── build
│   ├── cleanup
│   └── finalize
├── desktops/          # Desktop environment modules
│   ├── gnome/         # GNOME desktop (workstation)
│   ├── gnome-mobile/  # GNOME Mobile shell
│   └── phosh/         # Phosh shell
├── editions/          # Bootable image definitions
│   ├── core/          # CLI-only edition
│   ├── workstation/   # Desktop edition
│   └── mobile/        # Mobile editions (phosh + gnome-mobile)
└── tools/             # Local development helpers (QEMU)
```

## Building Locally

### Prerequisites

- [`buildah`](https://buildah.io/)
- [`just`](https://just.systems/)
- [`podman`](https://podman.io/) — for bootc-image-builder (ISO and disk image generation)
- `qemu-kvm` and `OVMF` — for QEMU testing

### Build a container image

```bash
# Build a specific edition
just build core
just build workstation
just build mobile-phosh
just build mobile-gnome
```

### Build the workstation ISO

Uses bootc-image-builder to generate a bootable ISO (no Anaconda). Requires the workstation container image to be available locally first.

```bash
just build workstation
just iso
```

### Build a mobile disk image (7z)

```bash
just build mobile-phosh
just mobile-disk phosh

just build mobile-gnome
just mobile-disk gnome
```

### Test with QEMU

```bash
# Build, install to a virtual disk, and boot
just qemu-install
just qemu-run

# Or boot an ISO directly
just qemu-iso
```

### Configuration

Variables can be overridden via environment or a `.env` file at the project root:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOS_FEDORA_VERSION` | `44` | Fedora base version |
| `LOS_BASE` | `quay.io/fedora/fedora-bootc:44` | Base bootc image |
| `LOS_REGISTRY` | `localhost` | Container registry for local builds |
| `LOS_TAG` | `44.YYYYMMDD` | Image tag (auto-generated) |
| `LOS_NAME` | `LuminusOS` | OS name |
| `LOS_PRETTY_NAME` | `Luminus OS` | OS pretty name |
| `QEMU_MEM` | `4G` | QEMU memory |
| `QEMU_CPU` | `4` | QEMU CPU cores |

## CI / Releases

GitHub Actions automatically builds and publishes all editions on every push to `main`.

| Workflow | Trigger | Output |
|----------|---------|--------|
| `build-containers` | Push to `main`, PRs | Container images → GHCR |
| `build-iso` | Tag `v*` or manual | Workstation ISO → release |
| `build-mobile-images` | Tag `v*` or manual | Mobile 7z disk images → release |

Container images are published at:

```
ghcr.io/OWNER/luminusos-core:latest
ghcr.io/OWNER/luminusos-workstation:latest
ghcr.io/OWNER/luminusos-mobile-phosh:latest
ghcr.io/OWNER/luminusos-mobile-gnome:latest
```

To create a release with ISO and mobile disk images, push a version tag:

```bash
git tag v44.20260322
git push origin v44.20260322
```

## Rebasing to Luminus OS

Once the workstation image is published, rebase any existing Fedora Atomic system:

```bash
bootc switch ghcr.io/luminusos/luminusos-workstation:latest
```

## License

MIT — see [LICENSE](LICENSE).
