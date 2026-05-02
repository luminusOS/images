set dotenv-load

# ── Configuration ────────────────────────────────────────────────────────
base       := env("LOS_BASE", "quay.io/fedora/fedora-bootc:44")
name       := env("LOS_NAME", "LuminusOS")
pretty     := env("LOS_PRETTY_NAME", "Luminus OS")
registry   := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag        := env("LOS_TAG", fedora_ver + "." + build_date)


# QEMU settings
qemu_mem       := env("QEMU_MEM", "4G")
qemu_cpu       := env("QEMU_CPU", "4")
qemu_display   := env("QEMU_DISPLAY", "gtk")
qemu_disk_size := env("QEMU_INSTALL_DISK_SIZE", "20G")

# Container runtime auto-detection
_runtime := if `command -v podman >/dev/null 2>&1; echo $?` == "0" { "podman" } else if `command -v docker >/dev/null 2>&1; echo $?` == "0" { "docker" } else { "" }

# ── Recipes ──────────────────────────────────────────────────────────────

# Default recipe: show available commands
default:
    @just --list

# Build an edition: just build core | workstation | mobile-phosh | mobile-gnome
build edition="workstation":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ edition }}" in
      core)
        sudo buildah bud \
          --build-arg base={{ base }} \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}" \
          --tag {{ registry }}/luminusos-core:{{ tag }} \
          --file editions/core/Containerfile \
          .
        ;;
      workstation)
        just build core
        sudo buildah bud \
          --cap-add sys_admin \
          --security-opt label=disable \
          --build-arg core_image={{ registry }}/luminusos-core:{{ tag }} \
          --build-arg desktop=gnome \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}" \
          --tag {{ registry }}/luminusos-workstation:{{ tag }} \
          --file editions/workstation/Containerfile \
          .
        ;;
      mobile-phosh)
        just build core
        sudo buildah bud \
          --build-arg core_image={{ registry }}/luminusos-core:{{ tag }} \
          --build-arg mobile_desktop=phosh \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}" \
          --tag {{ registry }}/luminusos-mobile-phosh:{{ tag }} \
          --file editions/mobile/Containerfile \
          .
        ;;
      mobile-gnome)
        just build core
        sudo buildah bud \
          --build-arg core_image={{ registry }}/luminusos-core:{{ tag }} \
          --build-arg mobile_desktop=gnome-mobile \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}" \
          --tag {{ registry }}/luminusos-mobile-gnome:{{ tag }} \
          --file editions/mobile/Containerfile \
          .
        ;;
      *)
        echo "Unknown edition: {{ edition }}"
        echo "Valid editions: core, workstation, mobile-phosh, mobile-gnome"
        exit 1
        ;;
    esac

# Package an edition (iso, mobile-phosh, or mobile-gnome)
package target="iso":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ target }}" in
      iso)
        mkdir -p .test
        sudo image-builder build \
          --bootc-default-fs ext4 \
          --output-dir . \
          --output-name luminusos-workstation-{{ tag }}.iso \
          --bootc-ref {{ registry }}/luminusos-workstation:{{ tag }} \
          bootc-generic-iso
        ;;
      mobile-phosh)
        mkdir -p .test
        sudo podman run --rm --privileged \
          --security-opt label=type:unconfined_t \
          -v $(pwd)/.test:/output \
          -v $(pwd)/common/bootc-image-builder.toml:/config.toml:ro \
          -v /var/lib/containers/storage:/var/lib/containers/storage \
          quay.io/centos-bootc/bootc-image-builder:latest \
          --type raw \
          --config /config.toml \
          {{ registry }}/luminusos-mobile-phosh:{{ tag }}
        7z a -t7z -m0=lzma2 -mx=9 \
          .test/luminusos-mobile-phosh-{{ tag }}.7z \
          .test/raw/disk.raw
        ;;
      mobile-gnome)
        mkdir -p .test
        sudo podman run --rm --privileged \
          --security-opt label=type:unconfined_t \
          -v $(pwd)/.test:/output \
          -v $(pwd)/common/bootc-image-builder.toml:/config.toml:ro \
          -v /var/lib/containers/storage:/var/lib/containers/storage \
          quay.io/centos-bootc/bootc-image-builder:latest \
          --type raw \
          --config /config.toml \
          {{ registry }}/luminusos-mobile-gnome:{{ tag }}
        7z a -t7z -m0=lzma2 -mx=9 \
          .test/luminusos-mobile-gnome-{{ tag }}.7z \
          .test/raw/disk.raw
        ;;
      *)
        echo "Unknown package target: {{ target }}"
        echo "Valid targets: iso, mobile-phosh, mobile-gnome"
        exit 1
        ;;
    esac

# Run QEMU for a specific target (iso, disk, install, run, mobile-phosh, mobile-gnome)
qemu target="disk":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ target }}" in
      iso)
        ./tools/qemu.sh qemu-iso
        ;;
      disk)
        ./tools/qemu.sh qemu-disk
        ;;
      install)
        just build workstation
        ./tools/install-qemu.sh {{ registry }}/luminusos-workstation:{{ tag }} {{ qemu_disk_size }}
        ;;
      run)
        QEMU_DISK_PATH=".test/disk.qcow2" ./tools/qemu.sh qemu-disk
        ;;
      mobile-phosh|mobile-gnome)
        if [ ! -f ".test/raw/disk.raw" ]; then
          echo "Error: .test/raw/disk.raw not found. Run 'just package {{ target }}' first."
          exit 1
        fi
        # Phosh/GNOME Mobile work best in portrait (720x1280)
        QEMU_DISK_PATH=".test/raw/disk.raw" ./tools/qemu.sh qemu-disk
        ;;
      *)
        echo "Unknown qemu target: {{ target }}"
        echo "Valid targets: iso, disk, install, run, mobile-phosh, mobile-gnome"
        exit 1
        ;;
    esac

# Clean build artifacts
clean:
    rm -rf .test/ *.iso *.7z

# Clean everything including container images
clean-all: clean
    -sudo buildah rmi {{ registry }}/luminusos-core:{{ tag }} || true
    -sudo buildah rmi {{ registry }}/luminusos-workstation:{{ tag }} || true
    -sudo buildah rmi {{ registry }}/luminusos-mobile-phosh:{{ tag }} || true
    -sudo buildah rmi {{ registry }}/luminusos-mobile-gnome:{{ tag }} || true
