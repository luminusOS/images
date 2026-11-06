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

`config/releases.env` on `main` lists the Fedora releases LuminusOS builds (`SUPPORTED_RELEASES`) and the newest one (`LATEST_RELEASE`). Every branch reads it from `main`. Builds of unsupported releases fail. Only `LATEST_RELEASE` moves the floating `testing` and `latest` tags, so they never go back to an older release. Stable promotion is refused until Fedora itself has released that version, i.e. until `quay.io/fedora/fedora-bootc:latest` reaches it.

Release images require cosign signatures. Verify a specific image digest with the repository's public key:

```bash
cosign verify --key shared/trust/etc/pki/containers/luminusos.pub 'ghcr.io/luminusos/luminusos-workstation@sha256:<digest>'
```

The shared core installs the trust policy and public key. This configuration alone does not prove that an installed system enforces signature verification: acceptance of the expected key and rejection of unsigned and foreign-signed updates must also be tested after Sirius installation.

### Release pipeline

1. **Prepare**: build candidates, capture and verify their signed image digests, scan them, and package and boot-test ISO/qcow2 artifacts. Candidate creation does not advance update channels or imply installation approval.
2. **Validate**: install the exact candidate ISO through Sirius in a disposable VM. Retain signed, run-bound evidence for first boot, live isolation, signed-update acceptance and rejection, update/rollback, and host security state.
3. **Promote**: resume the original candidate run and verify its manifest, signatures, digests, artifact hashes, and installation evidence. Only then advance release/channel tags and publish downloads. Do not rebuild a different candidate during this step.
4. **Stable**: promote approved testing core/workstation digests without rebuilding those payloads. A separately rebuilt live installer needs its own packaging, boot, and installation evidence before release.

See [the release strategy](docs/release-strategy.md) for the acceptance contract. A missing validation runner or missing evidence blocks promotion; it is not a reason to bypass a gate.

Installed systems follow `UPDATE_CHANNEL` in `config/versions.env` (it sets the Sirius `target_imgref`), independent of which channel an ISO was published on. It stays `testing` until the first stable release exists; switch it to `stable` to make new installs track `luminusos-workstation:{FEDORA_VERSION}`.

## Rebasing to Luminus OS

Rebase an existing bootc-capable Fedora Atomic system:

```bash
bootc switch ghcr.io/luminusos/luminusos-workstation:testing
```

## CI & Releases

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci` | Push to `main`, PRs | Lint, unit/config tests, workflow lint |
| `build-containers` | Push/PR on `main` and `f*`, or manual | Validation build of `core` and `workstation`. It never publishes |
| `auto-testing` | Daily, or manual | Checks the Fedora base and prepares signed candidates; does not bypass release approval or advance update channels |
| `publish` | Manual | Prepares candidates and resumes their promotion after validating evidence; stable retains approved payload digests |
| `installation-validation` | Manual, protected runner | Runs the provisioned installation test driver against an existing candidate and records signed validation evidence |

ISO and qcow2 downloads are hosted at `download.luminusos.org` on Cloudflare R2. Each channel retains its latest published artifact release; previous R2 versions are removed after the new files and metadata are published. SourceForge remains a backup, and GitHub Releases carry download links and SHA256 checksums. Older GitHub release links to R2 expire when that channel is updated.

The publish workflow requires GitHub Actions secrets `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` for an R2 API token with object read and write access to the `luminus-downloads` bucket. The scheduled container-only releases do not change downloadable artifacts.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): image layering, installer flow, storage layout, CI internals
- [CONTRIBUTING.md](CONTRIBUTING.md): local builds, tests, packaging, contribution policies
