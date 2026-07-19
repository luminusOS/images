set dotenv-load

# ── Configuration ────────────────────────────────────────────────────────
base       := env("LOS_BASE", "quay.io/fedora/fedora-bootc:44")
name       := env("LOS_NAME", "LuminusOS")
pretty     := env("LOS_PRETTY_NAME", "Luminus OS")
registry   := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag        := env("LOS_TAG", fedora_ver + "." + build_date)
core_image := registry + "/luminusos:" + tag
workstation_image := registry + "/luminusos-workstation:" + tag
workstation_iso_image := registry + "/luminusos-workstation:" + tag + "-iso"
workstation_target_image := env("LOS_WORKSTATION_TARGET_IMAGE", "ghcr.io/luminusos/luminusos-workstation:" + fedora_ver)
aurora_shell_version := env("AURORA_SHELL_VERSION", "v50.3")
sirius_version := env("SIRIUS_VERSION", "0.1.0")
force_core := env("LOS_FORCE_CORE", "0")
skip_flatpaks := env("LOS_SKIP_FLATPAKS", "0")
sudo_keepalive := '''
keep_sudo_alive() {
  sudo -v
  while true; do
    sudo -n true
    sleep 60
  done &
  sudo_keepalive_pid="$!"
  trap 'kill "${sudo_keepalive_pid}" 2>/dev/null || true' EXIT
}
'''


# QEMU settings
qemu_disk_size := env("QEMU_INSTALL_DISK_SIZE", "64G")

# ── Recipes ──────────────────────────────────────────────────────────────

# Default recipe: show available commands
default:
    @just --list

# Build an active edition or workstation ISO root: just build core | workstation | workstation-iso
build edition="workstation":
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    core_stamp() {
      {
        printf '%s\n' "{{ base }}" "{{ fedora_ver }}" "{{ tag }}" "{{ name }}" "{{ pretty }}"
        find editions/core -type f -print0 | sort -z | xargs -0 sha256sum
      } | sha256sum | awk '{print $1}'
    }
    keep_sudo_alive
    case "{{ edition }}" in
      core)
        sudo buildah bud \
          --layers \
          --build-arg base={{ base }} \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg distro_version={{ tag }} \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}" \
          --tag {{ core_image }} \
          --file editions/core/Containerfile \
          .
        ./tools/squash-image.sh {{ core_image }}
        mkdir -p .test
        printf '%s\n' "{{ tag }}" > .test/last-core-tag
        core_stamp > .test/last-core-stamp
        ;;
      workstation)
        current_core_stamp="$(core_stamp)"
        previous_core_stamp=""
        if [ -f .test/last-core-stamp ]; then
          previous_core_stamp="$(cat .test/last-core-stamp)"
        fi
        if [ "{{ force_core }}" = "1" ] || \
           [ "$current_core_stamp" != "$previous_core_stamp" ] || \
           ! sudo buildah inspect {{ core_image }} >/dev/null 2>&1; then
          just build core
        else
          echo "Using existing core image: {{ core_image }}"
        fi
        sudo buildah bud \
          --layers \
          --cap-add sys_admin \
          --security-opt label=disable \
          --build-arg core_image={{ core_image }} \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg image_version={{ tag }} \
          --build-arg edition_name="Workstation" \
          --build-arg edition_id="workstation" \
          --build-arg aurora_shell_version={{ aurora_shell_version }} \
          --build-arg skip_flatpaks={{ skip_flatpaks }} \
          --tag {{ workstation_image }} \
          --file editions/workstation/Containerfile \
          .
        ./tools/squash-image.sh {{ workstation_image }}
        mkdir -p .test
        printf '%s\n' "{{ tag }}" > .test/last-workstation-tag
        ;;
      workstation-iso)
        if ! sudo buildah inspect {{ workstation_image }} >/dev/null 2>&1; then
          echo "Workstation image not found in local buildah storage: {{ workstation_image }}"
          echo "Run 'just build workstation' first."
          exit 1
        fi
        sudo buildah bud \
          --layers \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg sirius_version={{ sirius_version }} \
          --build-arg workstation_image={{ workstation_image }} \
          --build-arg workstation_target_image={{ workstation_target_image }} \
          --build-arg image_version={{ tag }} \
          --tag {{ workstation_iso_image }} \
          --file editions/workstation/Containerfile.installer \
          .
        echo "Skipping squash for {{ workstation_iso_image }} because the ISO live root is packaged as layered container input"
        ;;
      *)
        echo "Unknown edition: {{ edition }}"
        echo "Valid editions: core, workstation, workstation-iso"
        exit 1
        ;;
    esac

# Package workstation artifacts: all, iso, or qcow2
package edition="workstation" format="all":
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}

    if [ "{{ edition }}" != "workstation" ]; then
      echo "Unknown package edition: {{ edition }}"
      echo "Valid editions: workstation"
      exit 1
    fi

    keep_sudo_alive

    mkdir -p .test
    package_tag="${LOS_TAG:-}"
    if [ -z "$package_tag" ] && [ -f .test/last-workstation-tag ]; then
      package_tag="$(cat .test/last-workstation-tag)"
    fi
    if [ -z "$package_tag" ]; then
      package_tag="{{ tag }}"
    fi
    image_ref="{{ registry }}/luminusos-workstation:${package_tag}"
    iso_image_ref="{{ registry }}/luminusos-workstation:${package_tag}-iso"

    if [[ "$image_ref" == localhost/* ]] && ! sudo buildah inspect "$image_ref" >/dev/null 2>&1; then
      echo "Workstation image not found in local buildah storage: $image_ref"
      echo "Run 'just build workstation' or set LOS_TAG to the tag you already built."
      exit 1
    fi

    build_iso_image() {
      if [[ "$iso_image_ref" != localhost/* ]]; then
        return 0
      fi

      echo "Building workstation ISO image from $image_ref"
      LOS_TAG="${package_tag}" just build workstation-iso
    }

    check_qcow2_disk_layout() {
      local image="$1"
      local ctr=""
      local rootfs=""
      local disk_yaml="/usr/lib/image-builder/bootc/disk.yaml"
      local status=0

      [[ "$image" == localhost/* ]] || return 0

      ctr="$(sudo buildah from --pull=never "${image}")"
      rootfs="$(sudo buildah mount "${ctr}")"

      if [ ! -f "${rootfs}${disk_yaml}" ]; then
        echo "Missing ${disk_yaml} inside ${image}" >&2
        status=1
      else
        set +e
        sudo awk '
        BEGIN {
          code = 12
        }
        /payload:/ {
          in_payload = 1
          fs = ""
        }
        in_payload && /^[[:space:]]+type:/ {
          fs = $2
          gsub(/"/, "", fs)
        }
        in_payload && /^[[:space:]]+mountpoint:[[:space:]]+"\/boot"$/ {
          if (fs == "ext4") {
            code = 0
            exit 0
          }
          if (fs == "btrfs") {
            code = 10
            exit 10
          }
          code = 11
          exit 11
        }
        END {
          exit code
        }
      ' "${rootfs}${disk_yaml}"
        status=$?
        set -e
      fi

      if [ "${status}" != "0" ]; then
        if [ "${status}" = "10" ]; then
          echo "${image} still has /boot as btrfs in ${disk_yaml}." >&2
          echo "Rebuild the workstation image before packaging qcow2:" >&2
          echo "  LOS_TAG=${package_tag} just build workstation" >&2
        else
          echo "Unable to validate /boot ext4 in ${image}:${disk_yaml}" >&2
        fi
      fi

      sudo buildah umount "${ctr}" >/dev/null 2>&1 || true
      sudo buildah rm "${ctr}" >/dev/null 2>&1 || true
      return "${status}"
    }

    case "{{ format }}" in
      all|qcow2)
        check_qcow2_disk_layout "$image_ref"
        ;;
    esac

    if [[ "$image_ref" == localhost/* ]]; then
      echo "Ensuring local workstation image is squashed before packaging"
      ./tools/squash-image.sh "$image_ref"
    fi

    # run_image_builder <image-builder-type> <output-name> <pointer-file> [extra args...]
    run_image_builder() {
      local type="$1" output="$2" pointer="$3"
      shift 3

      sudo image-builder build \
        --bootc-default-fs btrfs \
        --output-dir . \
        --output-name "$output" \
        "$@" \
        "$type"

      local path="$(pwd)/$output"
      if [ ! -f "$path" ]; then
        echo "Expected artifact was not created: $path"
        exit 1
      fi
      printf '%s\n' "$path" > "$pointer"
      echo "Wrote artifact pointer: $pointer -> $path"
    }

    package_iso() {
      build_iso_image
      if [[ "$iso_image_ref" == localhost/* ]]; then
        echo "Skipping squash for workstation ISO image because the ISO live root is packaged as layered container input"
      fi

      echo "Building workstation ISO from $iso_image_ref with payload $image_ref"
      run_image_builder bootc-generic-iso \
        "luminusos-workstation-${package_tag}.iso" .test/last-iso \
        --bootc-ref "$iso_image_ref" \
        --bootc-installer-payload-ref "$image_ref"
    }

    package_qcow2() {
      echo "Building workstation qcow2 from $image_ref"
      run_image_builder qcow2 \
        "luminusos-workstation-${package_tag}.qcow2" .test/last-qcow2 \
        --bootc-ref "$image_ref"
    }

    case "{{ format }}" in
      all)
        package_iso
        package_qcow2
        ;;
      iso|sirius-iso)
        package_iso
        ;;
      qcow2)
        package_qcow2
        ;;
      *)
        echo "Unknown package format: {{ format }}"
        echo "Valid formats: all, iso, sirius-iso, qcow2"
        exit 1
        ;;
    esac

# Run QEMU for a target: just qemu iso | disk | install | run
qemu target="disk":
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    case "{{ target }}" in
      iso)
        QEMU_INSTALL_DISK_SIZE="{{ qemu_disk_size }}" ./tools/qemu.sh iso
        ;;
      disk)
        ./tools/qemu.sh disk
        ;;
      install)
        keep_sudo_alive
        just build workstation
        ./tools/install-qemu.sh {{ workstation_image }} {{ qemu_disk_size }}
        ;;
      run)
        QEMU_RESET_NVRAM="${QEMU_RESET_NVRAM:-1}" QEMU_DISK_PATH=".test/install-disk.qcow2" ./tools/qemu.sh disk
        ;;
      *)
        echo "Unknown qemu target: {{ target }}"
        echo "Valid targets: iso, disk, install, run"
        exit 1
        ;;
    esac

# Clean build artifacts
clean:
    rm -rf .test/ *.iso *.qcow2 *.7z

# Clean everything including container images
clean-all: clean
    -sudo buildah rmi {{ core_image }} 2>/dev/null || true
    -sudo buildah rmi {{ workstation_image }} 2>/dev/null || true
    -sudo buildah rmi {{ workstation_iso_image }} 2>/dev/null || true

# Verify lint/format tools are available
check:
	@command -v shellcheck || (echo "shellcheck not found"; exit 1)
	@command -v shfmt      || (echo "shfmt not found"; exit 1)

# Lint all shell scripts
lint:
	find editions shared tools -name '*.sh' | xargs shellcheck -S warning
	shellcheck *.sh 2>/dev/null || true

# Format all shell scripts in-place
format:
	find editions shared tools -name '*.sh' | xargs shfmt -w -i 2 -ci
	shfmt -w -i 2 -ci *.sh 2>/dev/null || true
