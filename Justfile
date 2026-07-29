set dotenv-load := true

registry := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag := env("LOS_TAG", fedora_ver + "." + build_date)
core_image := registry + "/luminusos:" + tag
workstation_image := registry + "/luminusos-workstation:" + tag
workstation_iso_image := registry + "/luminusos-workstation:" + tag + "-iso"

# Build core, workstation, and workstation ISO root images.
mod build '.just/build.just'
# Package workstation ISO and qcow2 artifacts.
mod package '.just/package.just'
# Run local ISO, disk, and installer flows in QEMU.
mod qemu '.just/qemu.just'

# List the available command groups.
default:
    @just --list

# Clean generated build artifacts.
clean:
    rm -rf .test/ *.iso *.qcow2 *.7z

# Clean generated artifacts and local container images.
clean-all: clean
    -sudo buildah rmi {{ core_image }} 2>/dev/null || true
    -sudo buildah rmi {{ workstation_image }} 2>/dev/null || true
    -sudo buildah rmi {{ workstation_iso_image }} 2>/dev/null || true

# Verify lint and formatting tools are available.
check:
    @command -v shellcheck || (echo "shellcheck not found"; exit 1)
    @command -v shfmt      || (echo "shfmt not found"; exit 1)

# Run script unit tests and configuration validation.
test:
    tests/run.sh

# Lint all shell scripts.
lint:
    find editions shared tools tests .github/scripts -name '*.sh' | xargs shellcheck -S warning
    shellcheck *.sh 2>/dev/null || true

# Format all shell scripts in place.
format:
    find editions shared tools tests .github/scripts -name '*.sh' | xargs shfmt -w -i 2 -ci
    shfmt -w -i 2 -ci *.sh 2>/dev/null || true
