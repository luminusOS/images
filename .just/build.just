set dotenv-load := true

base := env("LOS_BASE", "quay.io/fedora/fedora-bootc:44")
name := env("LOS_NAME", "LuminusOS")
pretty := env("LOS_PRETTY_NAME", "Luminus OS")
registry := env("LOS_REGISTRY", "localhost")
fedora_ver := env("LOS_FEDORA_VERSION", "44")
build_date := `date +%Y%m%d`
tag := env("LOS_TAG", fedora_ver + "." + build_date)
core_image := registry + "/luminusos:" + tag
workstation_image := registry + "/luminusos-workstation:" + tag
workstation_iso_image := registry + "/luminusos-workstation:" + tag + "-iso"
workstation_target_image := env("LOS_WORKSTATION_TARGET_IMAGE", "ghcr.io/luminusos/luminusos-workstation:" + fedora_ver)
aurora_shell_version := env("AURORA_SHELL_VERSION", "v50.3")
aurora_shell_sha256 := env("AURORA_SHELL_SHA256", "0fcfa7933872184831a80da6521d8535cf4dc1e2f367a45643332cfe7eba111f")
sirius_version := env("SIRIUS_VERSION", "1.0.3")
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

# Build the workstation image by default.
default: workstation

# Build the shared Fedora bootc base image.
core: (_edition "core")

# Build the GNOME workstation image.
workstation: (_edition "workstation")

# Build the workstation live ISO root image.
workstation-iso: (_edition "workstation-iso")

[no-cd]
_edition edition:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    core_stamp() {
      {
        printf '%s\n' "{{ base }}" "{{ fedora_ver }}" "{{ tag }}" "{{ name }}" "{{ pretty }}"
        find editions/core -type f -print0 | sort -z | xargs -0 sha256sum
      } | sha256sum | awk '{print $1}'
    }
    build_image() { # build_image <tag> <containerfile> [extra buildah bud args...]
      local image_tag="$1" file="$2"
      shift 2
      sudo buildah bud --layers "$@" --tag "$image_tag" --file "$file" .
    }
    keep_sudo_alive
    case "{{ edition }}" in
      core)
        build_image {{ core_image }} editions/core/Containerfile \
          --build-arg base={{ base }} \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg distro_version={{ tag }} \
          --build-arg distro_name="{{ name }}" \
          --build-arg distro_pretty_name="{{ pretty }}"
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
        build_image {{ workstation_image }} editions/workstation/Containerfile \
          --cap-add sys_admin \
          --security-opt label=disable \
          --build-arg core_image={{ core_image }} \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg image_version={{ tag }} \
          --build-arg edition_name="Workstation" \
          --build-arg edition_id="workstation" \
          --build-arg aurora_shell_version={{ aurora_shell_version }} \
          --build-arg aurora_shell_sha256={{ aurora_shell_sha256 }} \
          --build-arg skip_flatpaks={{ skip_flatpaks }}
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
        echo "Exporting installer payload as OCI layout to .test/payload.oci"
        mkdir -p .test
        sudo rm -rf .test/payload.oci
        sudo skopeo copy "containers-storage:{{ workstation_image }}" "oci:.test/payload.oci:latest"
        sudo chown -R "$(id -u):$(id -g)" .test/payload.oci
        build_image {{ workstation_iso_image }} editions/workstation/Containerfile.installer \
          --build-arg fedora_version={{ fedora_ver }} \
          --build-arg sirius_version={{ sirius_version }} \
          --build-arg workstation_image={{ workstation_image }} \
          --build-arg workstation_target_image={{ workstation_target_image }} \
          --build-arg image_version={{ tag }}
        echo "No post-build squash needed for {{ workstation_iso_image }}: Containerfile.installer squashes itself into a single layer"
        ;;
      *)
        echo "Unknown edition: {{ edition }}"
        echo "Valid editions: core, workstation, workstation-iso"
        exit 1
        ;;
    esac
