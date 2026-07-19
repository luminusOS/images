# Luminus OS

An immutable operating system built on [Fedora bootc](https://containers.github.io/bootc/). Atomic updates, OCI container delivery, and a workstation image packaged as installable artifacts.

## Editions

| Edition | Description | Output |
|---------|-------------|--------|
| **core** | Minimal base for containers and downstream Luminus images | `luminusos:<tag>` container image |
| **workstation** | GNOME desktop for PCs and notebooks | Container image + ISO + qcow2; ISO packaging also creates a local `luminusos-workstation:<tag>-iso` installer root image |

## Planned Editions

These names are reserved for future planning only. They are not active build targets yet.

| Planned edition | Target |
|-----------------|--------|
| **mobile** | Phones and touch-first mobile devices |
| **cast** | TVs and living-room displays |
| **play** | Gaming handhelds |
| **education** | Classrooms, labs, and student learning devices |

Planning notes live in each planned edition directory under `editions/`. These directories should only become active build targets after their package set, target devices, installer flow, and test matrix are defined.

## Versioning

Releases follow the Fedora base version with a build date suffix:

```
{FEDORA_VERSION}.{YYYYMMDD}   →   44.20260322
```

## Project Structure

```
.
├── editions/          # Bootable image definitions
│   ├── cast/          # Planned TV/living-room edition
│   ├── core/          # Shared base edition
│   ├── education/     # Planned education edition
│   ├── mobile/        # Planned mobile edition
│   ├── play/          # Planned gaming handheld edition
│   └── workstation/   # Desktop edition
├── shared/            # Shared data/config inputs
│   ├── bootc-image-builder.toml.example
│   ├── flatpaks
│   └── scripts/       # Build-time helpers shared by the Containerfiles
└── tools/             # Local development helpers (QEMU)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed image layering, installer, QEMU, and runtime model.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, cache-friendly build commands, packaging, QEMU testing, and environment variables.

## CI / Releases

GitHub Actions builds active editions from Fedora release branches. Branch names follow Fedora versions: `f44`, `f45`, `f46`, and so on.

| Workflow | Trigger | Output |
|----------|---------|--------|
| `build-containers` | Push/PR on `f*` | `core` and `workstation` container images → GHCR |

Container images use the Fedora version number as the floating tag, without the branch `f` prefix:

```
ghcr.io/luminusos/luminusos:44
ghcr.io/luminusos/luminusos-workstation:44
```

## Rebasing to Luminus OS

Once the workstation image is published, rebase an existing bootc-capable Fedora
Atomic system into Luminus OS:

```bash
bootc switch ghcr.io/luminusos/luminusos-workstation:44
```

## License

MIT — see [LICENSE](LICENSE).
