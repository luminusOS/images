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
LOS_TAG=testing-dev LOS_SKIP_FLATPAKS=1 just build workstation
```

What each variable does:

- `LOS_TAG=testing-dev` keeps the local image tag stable across days, avoiding rebuilds caused only by the date-based default tag changing.
- `LOS_SKIP_FLATPAKS=1` skips Flatpak installation, which avoids network and install time while testing image/package/session changes.

Builds squash the local core and workstation payload images by default so OCI whiteouts from lower layers are processed before packaging. The `luminusos-workstation:<tag>-iso` live root squashes itself in `Containerfile.installer` (a final `FROM scratch` + `COPY --from=live / /` stage) because image-builder/osbuild deploys the ISO live root without applying OCI whiteout semantics; leftover `.wh.*` files in the live rootfs break services such as dbus-broker.

## Validation and Tests

Run the same checks CI runs on `main` before pushing:

```bash
just check   # verifies jq, just, Python/PyYAML and the pinned Ruff version
just lint    # Ruff lint and formatting checks
just test    # Python unittest discovery and config validation
```

The Python tests under `tests/` exercise the automation and validate the config files shipped in the images: TOML, JSON, systemd units, repart definitions, YAML, overlays, version defaults, and artifact/QEMU resolution. CI also lints the workflows with actionlint, and `build-containers` build-checks `core` and `workstation`. Packaging validation uses `.github/scripts/boot-test.py` to check for a graphical screen under QEMU/KVM; it does not replace installation and first-boot evidence.

### Workflow lint

Use Docker with BuildKit to build and run the same workflow checker as CI:

```bash
docker build --platform linux/amd64 --file .github/containers/actionlint/Containerfile \
  --tag luminus-actionlint:native26 .github/containers/actionlint
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --mount type=bind,src="$PWD",dst=/work,readonly --workdir /work \
  luminus-actionlint:native26 -shellcheck=/usr/local/bin/shellcheck -pyflakes=/usr/bin/pyflakes
```

The Containerfile pins the Go builder, actionlint source archive, patch and original runtime image. Dependency fetching authenticates the selected versions against the unchanged upstream checksums; tests and compilation then run without network access. Only the actionlint binary is replaced, preserving ShellCheck and Pyflakes.

The local patch adds native Ubuntu 26.04 runner recognition and compatibility checks. Remove it when adopting an upstream release with equivalent support, and retain tests for unknown labels, incompatible runners and both external checkers. Source or dependency updates require reviewing the pins and checksums rather than accepting newly generated lock entries.

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

### Optional TPM 2.0 and Secure Boot

The local QEMU launcher accepts independent `QEMU_TPM=0|1` and `QEMU_SECURE_BOOT=0|1` options, both disabled by default. They do not become installation requirements in Sirius.

```bash
QEMU_TPM=1 just qemu iso
QEMU_SECURE_BOOT=1 just qemu iso
QEMU_TPM=1 QEMU_SECURE_BOOT=1 just qemu iso
QEMU_TPM=1 QEMU_SECURE_BOOT=1 just qemu run
```

TPM emulation requires `swtpm` with TPM 2.0 support on the machine running QEMU. Secure Boot requires UEFI and a QEMU firmware descriptor advertising a raw q35 firmware pair with `secure-boot`, `enrolled-keys`, and `requires-smm` features, normally supplied by `edk2-ovmf` or `ovmf`. Missing requested capabilities fail explicitly; the launcher does not silently fall back to an unsecured profile. `QEMU_DRY_RUN=1` prints arguments without creating VM state or starting processes, but still checks requested prerequisites.

TPM and firmware state are private and persistent under `.test/qemu-vms/`, keyed by the canonical disk path. ISO installation and installed boot must use the same disk path to retain their identity. With either option enabled, `just qemu run` preserves NVRAM; nonzero `QEMU_RESET_NVRAM` values and `QEMU_OVMF_VARS` overrides are rejected. Resetting the install disk does not clear TPM or firmware state. Do not delete this state if it protects data or is needed to reproduce a test.

`QEMU_SECURE_BOOT=1` selects enrolled firmware; it does not prove the current contents of persistent NVRAM still enable Secure Boot. Confirm the state inside the guest, for example with `mokutil --sb-state`, and inspect SecureBoot/SetupMode and kernel logs. Confirm TPM version 2.0 and a successful capability query when guest tools are available. Emulated TPM and Secure Boot tests do not establish EAC Linux v2 compliance, measured boot, or attestation accepted by Epic.

## Automation and Verification

Repository-owned automation uses Python with explicit `python3` entrypoints. Keep configuration as data and invoke external tools with subprocess argument lists, not `shell=True`. Edition-specific helpers stay under their edition; shared helpers need concrete consumers.

Use Python 3.11 or newer, `just`, and `jq`. Install the pinned development dependencies into an isolated environment with `uv sync --frozen --group dev`, then activate it with `source .venv/bin/activate`.

Run the public quality gates before submitting changes:

```bash
just check
just lint
just test
```

Python tests use `unittest`; Ruff checks Python style and formatting. Workflow changes also require actionlint. These checks do not replace image builds, ISO/qcow2 packaging, or VM tests.

For installer changes, exercise Sirius from the ISO on a disposable disk and inspect the installed system after first boot. Booting a prebuilt qcow2 does not establish that Sirius works. Claims about signed updates require tests with the expected key, an incorrect key, and an unsigned image, plus update and rollback evidence. Report unavailable runtime checks as blocked, not passed.

Keep runtime evidence tied to the exact source commit, candidate image digests, and SHA256 hashes of the tested ISO/qcow2. Retain the installation and first-boot logs, bootc state before and after update/rollback, signature rejection results, and observed SELinux, firewall, and Secure Boot state. Confirm that the installed system has the intended update reference and contains no Sirius or live-session configuration. A screenshot or an asserted JSON boolean alone is not installation evidence.

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
