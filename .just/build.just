set dotenv-load := true

import 'common.just'

# Build the workstation image by default.
default: workstation

# Hash every input that can change the core image.
[private]
[no-cd]
_core-stamp:
    #!/usr/bin/env bash
    set -euo pipefail
    {
      printf '%s\n' "{{ base }}" "{{ fedora_ver }}" "{{ tag }}" "{{ name }}" "{{ pretty }}"
      find \
        editions/core \
        shared/scripts/dnf-releasever.sh \
        shared/scripts/os-release-set.sh \
        shared/scripts/rpmdb-repair.sh \
        -type f -print0 | sort -z | xargs -0 sha256sum
    } | sha256sum | awk '{print $1}'

# Build the shared Fedora bootc base image.
[no-cd]
core:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    keep_sudo_alive
    sudo buildah bud --layers \
      --tag {{ core_image }} \
      --file editions/core/Containerfile \
      --build-arg base={{ base }} \
      --build-arg fedora_version={{ fedora_ver }} \
      --build-arg distro_version={{ tag }} \
      --build-arg distro_name="{{ name }}" \
      --build-arg distro_pretty_name="{{ pretty }}" \
      .
    ./tools/squash-image.sh {{ core_image }}
    mkdir -p .test
    just build::_core-stamp > .test/last-core-stamp

# Build the GNOME workstation image.
[no-cd]
workstation:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    keep_sudo_alive
    current_core_stamp="$(just build::_core-stamp)"
    previous_core_stamp=""
    if [ -f .test/last-core-stamp ]; then
      previous_core_stamp="$(cat .test/last-core-stamp)"
    fi
    if [ "{{ force_core }}" = "1" ] || \
       [ "${current_core_stamp}" != "${previous_core_stamp}" ] || \
       ! sudo buildah inspect {{ core_image }} >/dev/null 2>&1; then
      just build core
    else
      echo "Using existing core image: {{ core_image }}"
    fi
    sudo buildah bud --layers \
      --cap-add sys_admin \
      --security-opt label=disable \
      --tag {{ workstation_image }} \
      --file editions/workstation/Containerfile \
      --build-arg core_image={{ core_image }} \
      --build-arg fedora_version={{ fedora_ver }} \
      --build-arg image_version={{ tag }} \
      --build-arg edition_name="Workstation" \
      --build-arg edition_id="workstation" \
      --build-arg aurora_shell_version={{ aurora_shell_version }} \
      --build-arg aurora_shell_sha256={{ aurora_shell_sha256 }} \
      --build-arg skip_flatpaks={{ skip_flatpaks }} \
      .
    ./tools/squash-image.sh {{ workstation_image }}
    mkdir -p .test
    printf '%s\n' "{{ tag }}" > .test/last-workstation-tag

# Build the workstation live ISO root image.
[no-cd]
workstation-iso:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    keep_sudo_alive
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
    sudo buildah bud --layers \
      --tag {{ workstation_iso_image }} \
      --file editions/workstation/Containerfile.installer \
      --build-arg fedora_version={{ fedora_ver }} \
      --build-arg sirius_version={{ sirius_version }} \
      --build-arg workstation_image={{ workstation_image }} \
      --build-arg workstation_target_image={{ workstation_target_image }} \
      --build-arg image_version={{ tag }} \
      .
    echo "No post-build squash needed for {{ workstation_iso_image }}: Containerfile.installer squashes itself into a single layer"
