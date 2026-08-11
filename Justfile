set dotenv-load := true

import '.just/common.just'

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
    @command -v bash       || (echo "bash not found"; exit 1)
    @command -v jq         || (echo "jq not found"; exit 1)
    @command -v just       || (echo "just not found"; exit 1)
    @command -v python3    || (echo "python3 not found"; exit 1)
    @command -v shellcheck || (echo "shellcheck not found"; exit 1)
    @command -v shfmt      || (echo "shfmt not found"; exit 1)
    @python3 -c 'import yaml' || (echo "PyYAML not found"; exit 1)

# Run script unit tests and configuration validation.
test:
    tests/run.sh

# Lint all shell scripts.
lint:
    find editions shared tools tests .github/scripts -name '*.sh' -print0 | xargs -0 shellcheck -S warning
    shellcheck *.sh 2>/dev/null || true

# Format all shell scripts in place.
format:
    find editions shared tools tests .github/scripts -name '*.sh' -print0 | xargs -0 shfmt -w -i 2 -ci
    shfmt -w -i 2 -ci *.sh 2>/dev/null || true
