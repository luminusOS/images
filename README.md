# Luminus OS

An immutable operating system built on [Fedora bootc](https://containers.github.io/bootc/). Atomic updates, OCI container delivery, and a workstation image packaged as installable artifacts.

## Editions

| Edition | Description | Output |
|---------|-------------|--------|
| **core** | Minimal base for containers and downstream Luminus images | `luminusos:<tag>` container image |
| **workstation** | GNOME desktop for PCs and notebooks | Container image + ISO + qcow2 |

## Planned Editions

These names are reserved for future planning only. They are not active build targets yet.

| Planned edition | Target |
|-----------------|--------|
| **mobile** | Phones and touch-first mobile devices |
| **cast** | TVs and living-room displays |
| **play** | Gaming handhelds |

Planning notes live in each planned edition directory under `editions/`. These directories should only become active build targets after their package set, target devices, installer flow, and test matrix are defined.

## Versioning

Releases follow the Fedora base version with a build date suffix:

```
{FEDORA_VERSION}.{YYYYMMDD}   →   44.20260322
```

## Project Structure

```
.
├── common/            # Shared base packages (all editions)
│   ├── build.sh
│   ├── cleanup.sh
│   └── finalize.sh
├── desktops/          # Desktop environment modules
│   └── gnome/         # GNOME desktop (workstation)
├── editions/          # Bootable image definitions
│   ├── cast/          # Planned TV/living-room edition
│   ├── core/          # Shared base edition
│   ├── mobile/        # Planned mobile edition
│   ├── play/          # Planned gaming handheld edition
│   └── workstation/   # Desktop edition
└── tools/             # Local development helpers (QEMU)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed image layering, installer, QEMU, and runtime model.

## Building Locally

### Prerequisites

- [`buildah`](https://buildah.io/)
- [`just`](https://just.systems/)
- [`image-builder`](https://github.com/osbuild/bootc-image-builder) — for ISO and qcow2 generation
- [`podman`](https://podman.io/) — for QEMU disk install helper
- `qemu-kvm` and `OVMF` — for QEMU testing

### Build a container image

```bash
# Build a specific active edition
just build core
just build workstation
```

### Package workstation artifacts

Requires the workstation container image to be available locally first.

```bash
just build workstation
just package workstation        # ISO and qcow2
just package workstation iso
just package workstation qcow2
```

Workstation artifacts use Btrfs for installed Linux filesystems. The UEFI ESP remains vfat.

### Test with QEMU

```bash
# Build, install to a virtual disk, and boot
just qemu install
just qemu run

# Or boot an ISO directly
just qemu iso

# Recreate the install disk before booting the ISO
QEMU_RESET_DISK=1 just qemu iso
```

`just qemu run` boots `.test/install-disk.qcow2`, resets the local OVMF
NVRAM by default, and uses AHCI/SATA for firmware compatibility. To test the
same disk through virtio, use:

```bash
QEMU_DISK_BUS=virtio just qemu run
```

Inside the live ISO or installed system, check the current mode with:

```bash
cat /etc/luminusos/system-mode
```

Expected values are `live` in the ISO session and `installed` after booting the installed system.
`bootc status` is expected to work after installation; the live ISO session
itself is not booted as a bootc deployment.

To verify that the live ISO contains the bootc payload image ReadyMade will
install:

```bash
grep bootc_imgref /etc/readymade.toml
sudo podman images
```

If ReadyMade fails during installation, collect the full bootc error with:

```bash
sudo cat /tmp/readymade-logs*/readymade.log
```

### Configuration

Variables can be overridden via environment or a `.env` file at the project root:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOS_FEDORA_VERSION` | `44` | Fedora base version |
| `LOS_BASE` | `quay.io/fedora/fedora-bootc:44` | Base bootc image |
| `LOS_REGISTRY` | `localhost` | Container registry for local builds |
| `LOS_TAG` | `44.YYYYMMDD` | Image tag (auto-generated) |
| `LOS_WORKSTATION_TARGET_IMAGE` | local workstation tag | Installed system update reference; set to `ghcr.io/OWNER/luminusos-workstation:44` for release ISOs |
| `LOS_NAME` | `LuminusOS` | OS name |
| `LOS_PRETTY_NAME` | `Luminus OS` | OS pretty name |
| `AURORA_SHELL_VERSION` | `v50.3` | Aurora Shell release tag |
| `LOS_FORCE_CORE` | `0` | Rebuild `core` before `workstation` even when the local tag already exists |
| `LOS_SKIP_FLATPAKS` | `0` | Skip Flatpak installation during local workstation builds |
| `QEMU_MEM` | `4G` | QEMU memory |
| `QEMU_CPU` | `4` | QEMU CPU cores |
| `QEMU_INSTALL_DISK_SIZE` | `64G` | Empty disk size attached when booting the ISO |
| `QEMU_RESET_DISK` | `0` | Recreate the QEMU install disk before booting the ISO when set to `1` |
| `QEMU_DISK_BUS` | `ahci` | Disk bus for QEMU testing: `ahci`, `sata`, or `virtio` |
| `QEMU_NO_REBOOT` | `0` | Exit QEMU instead of rebooting the guest when set to `1` |
| `QEMU_RESET_NVRAM` | `0` | Recreate the QEMU UEFI NVRAM file before boot when set to `1` |

## CI / Releases

GitHub Actions builds active editions from Fedora release branches. Branch names follow Fedora versions: `f44`, `f45`, `f46`, and so on.

| Workflow | Trigger | Output |
|----------|---------|--------|
| `build-containers` | Push/PR on `f*` | `core` and `workstation` container images → GHCR |

Container images use the Fedora version number as the floating tag, without the branch `f` prefix:

```
ghcr.io/OWNER/luminusos:44
ghcr.io/OWNER/luminusos-workstation:44
```

## Rebasing to Luminus OS

Once the workstation image is published, rebase any existing Fedora Atomic system:

```bash
bootc switch ghcr.io/OWNER/luminusos-workstation:44
```

## License

MIT — see [LICENSE](LICENSE).
