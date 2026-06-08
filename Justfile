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
force_core := env("LOS_FORCE_CORE", "0")
skip_flatpaks := env("LOS_SKIP_FLATPAKS", "0")
squash := env("LOS_SQUASH", "1")
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
    squash_image() {
      local image="$1"
      local ctr=""

      if [ "{{ squash }}" != "1" ]; then
        echo "Skipping squash for ${image} because LOS_SQUASH={{ squash }}"
        return 0
      fi

      ctr="$(sudo buildah from --pull=never "${image}")"
      if ! sudo buildah config \
        --unsetlabel ostree.final-diffid \
        --unsetlabel ostree.commit \
        "${ctr}" || \
        ! sudo buildah commit --squash "${ctr}" "${image}"; then
        sudo buildah rm "${ctr}" >/dev/null 2>&1 || true
        return 1
      fi
      sudo buildah rm "${ctr}"
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
        squash_image {{ core_image }}
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
        squash_image {{ workstation_image }}
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
          --build-arg workstation_image={{ workstation_image }} \
          --build-arg workstation_target_image={{ workstation_target_image }} \
          --build-arg image_version={{ tag }} \
          --tag {{ workstation_iso_image }} \
          --file editions/workstation/Containerfile.installer \
          .
        squash_image {{ workstation_iso_image }}
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
      LOS_TAG="${package_tag}" LOS_SQUASH=0 just build workstation-iso
    }

    squash_local_image() {
      local image="$1"
      local ctr=""

      ctr="$(sudo buildah from --pull=never "${image}")"
      if ! sudo buildah config \
        --unsetlabel ostree.final-diffid \
        --unsetlabel ostree.commit \
        "${ctr}" || \
        ! sudo buildah commit --squash "${ctr}" "${image}"; then
        sudo buildah rm "${ctr}" >/dev/null 2>&1 || true
        return 1
      fi
      sudo buildah rm "${ctr}"
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
      squash_local_image "$image_ref"
    fi

    package_iso() {
      build_iso_image
      if [[ "$iso_image_ref" == localhost/* ]]; then
        echo "Ensuring local workstation ISO image is squashed before packaging"
        squash_local_image "$iso_image_ref"
      fi

      echo "Building workstation ISO from $iso_image_ref with payload $image_ref"
      sudo image-builder build \
        --bootc-default-fs btrfs \
        --output-dir . \
        --output-name "luminusos-workstation-${package_tag}.iso" \
        --bootc-ref "$iso_image_ref" \
        --bootc-installer-payload-ref "$image_ref" \
        bootc-generic-iso

      iso_path="$(pwd)/luminusos-workstation-${package_tag}.iso"
      if [ ! -f "$iso_path" ]; then
        echo "Expected ISO was not created: $iso_path"
        exit 1
      fi
      printf '%s\n' "$iso_path" > .test/last-iso
      echo "Wrote ISO pointer: .test/last-iso -> $iso_path"
    }

    package_qcow2() {
      echo "Building workstation qcow2 from $image_ref"
      sudo image-builder build \
        --bootc-default-fs btrfs \
        --output-dir . \
        --output-name "luminusos-workstation-${package_tag}.qcow2" \
        --bootc-ref "$image_ref" \
        qcow2

      qcow2_path="$(pwd)/luminusos-workstation-${package_tag}.qcow2"
      if [ ! -f "$qcow2_path" ]; then
        echo "Expected qcow2 was not created: $qcow2_path"
        exit 1
      fi
      printf '%s\n' "$qcow2_path" > .test/last-qcow2
      echo "Wrote qcow2 pointer: .test/last-qcow2 -> $qcow2_path"
    }

    case "{{ format }}" in
      all)
        package_iso
        package_qcow2
        ;;
      iso)
        package_iso
        ;;
      qcow2)
        package_qcow2
        ;;
      *)
        echo "Unknown package format: {{ format }}"
        echo "Valid formats: all, iso, qcow2"
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
	find editions tools -name '*.sh' | xargs shellcheck -S warning
	shellcheck *.sh 2>/dev/null || true

# Format all shell scripts in-place
format:
	find editions tools -name '*.sh' | xargs shfmt -w -i 2 -ci
	shfmt -w -i 2 -ci *.sh 2>/dev/null || true
