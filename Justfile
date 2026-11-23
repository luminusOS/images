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
    @command -v jq         || (echo "jq not found"; exit 1)
    @command -v just       || (echo "just not found"; exit 1)
    @command -v python3    || (echo "python3 not found"; exit 1)
    @python3 -c 'import sys; assert sys.version_info >= (3, 11)' || (echo "Python 3.11 or newer required"; exit 1)
    @ruff --version | grep -Fx 'ruff 0.16.2' || (echo "ruff 0.16.2 required"; exit 1)
    @python3 -c 'import yaml' || (echo "PyYAML not found"; exit 1)

# Run script unit tests and configuration validation.
test:
    python3 -m unittest discover -s tests -p 'test_*.py'

# Lint and check formatting.
lint:
    ruff check .
    ruff format --check .

# Format Python scripts in place.
format:
    ruff format .
