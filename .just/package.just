set dotenv-load := true

registry := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag := env("LOS_TAG", "testing-" + fedora_ver + "." + build_date)
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

# Package all workstation artifact formats by default.
default: workstation

# Package workstation artifacts: all, iso, sirius-iso, or qcow2.
workstation format="all": (_workstation format)

[no-cd]
_workstation format:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}

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
      local image="$1" ctr rootfs boot_fstype
      local disk_yaml="/usr/lib/image-builder/bootc/disk.yaml"

      [[ "$image" == localhost/* ]] || return 0

      ctr="$(sudo buildah from --pull=never "${image}")"
      rootfs="$(sudo buildah mount "${ctr}")"

      # /boot must stay ext4: image-builder qcow2 generation rejects btrfs there.
      boot_fstype="$(sudo awk '
        /^[[:space:]]+type: "(ext4|btrfs)"$/ { t = $2; gsub(/"/, "", t) }
        /mountpoint:[[:space:]]+"\/boot"/    { print t; exit }
      ' "${rootfs}${disk_yaml}" 2>/dev/null || true)"

      sudo buildah umount "${ctr}" >/dev/null 2>&1 || true
      sudo buildah rm "${ctr}" >/dev/null 2>&1 || true

      if [ "${boot_fstype}" != "ext4" ]; then
        echo "${image} does not have /boot as ext4 in ${disk_yaml} (found: '${boot_fstype:-missing}')." >&2
        echo "Rebuild the workstation image before packaging qcow2:" >&2
        echo "  LOS_TAG=${package_tag} just build workstation" >&2
        return 1
      fi
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

      # The installer payload is already embedded in the live root as an OCI
      # layout (see Containerfile.installer), so no --bootc-installer-payload-ref
      # here: image-builder only needs the live root image.
      echo "Building workstation ISO from $iso_image_ref"
      run_image_builder bootc-generic-iso \
        "luminusos-workstation-${package_tag}.iso" .test/last-iso \
        --bootc-ref "$iso_image_ref"
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
