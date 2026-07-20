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
aurora_shell_sha256 := env("AURORA_SHELL_SHA256", "0fcfa7933872184831a80da6521d8535cf4dc1e2f367a45643332cfe7eba111f")
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
          --build-arg aurora_shell_sha256={{ aurora_shell_sha256 }} \
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
        echo "No post-build squash needed for {{ workstation_iso_image }}: Containerfile.installer squashes itself into a single layer"
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

    # bootc-generic-iso embeds the installer payload as a containers-storage
    # blob, which forces `bootc install` to re-diff/tar each layer into
    # /var/tmp at install time (~2.5 GiB, hence the tmpfs var-tmp.mount and
    # the 5 GiB RAM gate). osbuild's skopeo stage also supports an "oci"
    # destination, which stores ready-made layer blobs — no re-tar, no
    # large staging area — matching how Anaconda embeds ostree-native
    # container payloads. image-builder-cli has no flag for this, so we
    # generate the manifest, patch that one stage, and run osbuild directly.
    patch_iso_payload_to_oci() {
      local manifest_json="$1" patched_manifest="$2"
      local skopeo_count
      skopeo_count="$(jq '[.pipelines[] | select(.name == "os-tree") | .stages[] | select(.type == "org.osbuild.skopeo")] | length' "$manifest_json")"
      if [ "$skopeo_count" != "1" ]; then
        echo "Expected exactly 1 org.osbuild.skopeo stage in the 'os-tree' pipeline, found $skopeo_count" >&2
        echo "osbuild/images changed the bootc-generic-iso manifest shape; update patch_iso_payload_to_oci() in the Justfile" >&2
        exit 1
      fi
      jq '
        (.pipelines[] | select(.name == "os-tree") | .stages[] | select(.type == "org.osbuild.skopeo") | .options.destination)
          = {"type": "oci", "path": "/usr/lib/luminusos/payload.oci"}
      ' "$manifest_json" > "$patched_manifest"
    }

    package_iso() {
      build_iso_image
      if [[ "$iso_image_ref" == localhost/* ]]; then
        echo "No post-build squash needed for the workstation ISO image: Containerfile.installer squashes itself into a single layer"
      fi

      local out_name="luminusos-workstation-${package_tag}.iso"
      local ib_cache="$(pwd)/.test/image-builder-cache"
      local manifest_json=".test/${package_tag}.osbuild-manifest.json"
      local patched_manifest=".test/${package_tag}.osbuild-manifest.oci.json"
      mkdir -p "$ib_cache"

      echo "Generating osbuild manifest for bootc-generic-iso (payload: $image_ref)"
      sudo image-builder build \
        --bootc-default-fs btrfs \
        --output-dir . \
        --output-name "$out_name" \
        --cache "$ib_cache" \
        --with-manifest \
        --bootc-ref "$iso_image_ref" \
        --bootc-installer-payload-ref "$image_ref" \
        bootc-generic-iso

      local generated_manifest="${out_name%.iso}.osbuild-manifest.json"
      if [ ! -f "$generated_manifest" ]; then
        echo "Expected osbuild manifest was not generated: $generated_manifest"
        exit 1
      fi
      mv "$generated_manifest" "$manifest_json"

      echo "Patching installer payload embed: containers-storage -> oci"
      patch_iso_payload_to_oci "$manifest_json" "$patched_manifest"

      echo "Rebuilding ISO from the patched manifest (payload embedded as OCI layout)"
      sudo rm -rf bootiso
      sudo osbuild \
        --store "$ib_cache" \
        --output-directory . \
        --export bootiso \
        "$patched_manifest"

      if [ ! -f bootiso/install.iso ]; then
        echo "Expected osbuild export not found: bootiso/install.iso"
        exit 1
      fi
      sudo mv bootiso/install.iso "$out_name"
      sudo rm -rf bootiso
      sudo chown "$(id -u):$(id -g)" "$out_name"

      local iso_path="$(pwd)/$out_name"
      printf '%s\n' "$iso_path" > .test/last-iso
      echo "Wrote artifact pointer: .test/last-iso -> $iso_path"
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
        ./tools/install-qemu.sh {{ workstation_image }}
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

# Run the repo test suite (script unit tests + config validation)
test:
	tests/run.sh

# Lint all shell scripts
lint:
	find editions shared tools tests .github/scripts -name '*.sh' | xargs shellcheck -S warning
	shellcheck *.sh 2>/dev/null || true

# Format all shell scripts in-place
format:
	find editions shared tools tests .github/scripts -name '*.sh' | xargs shfmt -w -i 2 -ci
	shfmt -w -i 2 -ci *.sh 2>/dev/null || true
