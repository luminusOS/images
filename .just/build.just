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
      printf '%s\n' "{{ base }}" "{{ fedora_ver }}" "{{ tag }}" "{{ version }}" "{{ name }}" "{{ pretty }}"
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
      --build-arg distro_version={{ version }} \
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
      --build-arg fedora_bootc_base={{ base }} \
      --build-arg fedora_version={{ fedora_ver }} \
      --build-arg image_version={{ version }} \
      --build-arg edition_name="Workstation" \
      --build-arg edition_id="workstation" \
      --build-arg aurora_shell_version={{ aurora_shell_version }} \
      --build-arg aurora_shell_sha256={{ aurora_shell_sha256 }} \
      --build-arg elastic_swap_version={{ elastic_swap_version }} \
      --build-arg elastic_swap_sha256={{ elastic_swap_sha256 }} \
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
    if [ "${INSTALLER_FEATURES:-0}" = 1 ]; then
      test -f .test/payload.oci/index.json || {
        echo "Stage the exact signed OCI payload at .test/payload.oci first." >&2
        exit 1
      }
    else
      echo "Exporting installer payload as OCI layout to .test/payload.oci"
      mkdir -p .test
      sudo rm -rf .test/payload.oci
      sudo skopeo copy "containers-storage:{{ workstation_image }}" "oci:.test/payload.oci:latest"
      sudo chown -R "$(id -u):$(id -g)" .test/payload.oci
    fi
    sudo buildah bud --layers \
      --tag {{ workstation_iso_image }} \
      --file editions/workstation/Containerfile.installer \
      --build-arg fedora_version={{ fedora_ver }} \
      --build-arg sirius_version={{ sirius_version }} \
      --build-arg sirius_rpm_version={{ sirius_rpm_version }} \
      --build-arg sirius_sha256={{ sirius_sha256 }} \
      --build-arg installer_features="${INSTALLER_FEATURES:-0}" \
      --build-arg sirius_local_rpm="${SIRIUS_LOCAL_RPM:-0}" \
      --build-arg workstation_image={{ workstation_image }} \
      --build-arg workstation_target_image={{ workstation_target_image }} \
      --build-arg image_version={{ version }} \
      .
    echo "No post-build squash needed for {{ workstation_iso_image }}: Containerfile.installer squashes itself into a single layer"

# Build one hardware feature extension (name or directory) for the local workstation image.
[no-cd]
sysext feature:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ sudo_keepalive }}
    keep_sudo_alive
    feature="{{ feature }}"
    [ -d "${feature}" ] || feature="editions/workstation/features/${feature}"
    [ -f "${feature}/feature.env" ] || { echo "No feature manifest at ${feature}/feature.env"; exit 1; }
    image="${LOS_SYSEXT_IMAGE:-{{ workstation_image }}}"
    if ! sudo podman image inspect "${image}" >/dev/null 2>&1; then
      echo "Workstation image not found in local storage: ${image}"
      echo "Run 'just build workstation' first."
      exit 1
    fi
    digest="$(sudo podman image inspect --format '{{{{.Digest}}' "${image}")"
    version="$(sudo podman image inspect --format '{{{{index .Labels "org.opencontainers.image.version"}}' "${image}")"
    name="${image%@*}"
    [[ "${name##*/}" == *:* ]] && name="${name%:*}"
    out=".test/sysext/${version}"
    mkdir -p "${out}"
    sudo ./editions/workstation/build-sysext.sh "${feature}" "${name}@${digest}" "${out}"
    sudo podman run --rm --network none --security-opt label=disable \
      --volume "$PWD/editions/workstation/sysext:/run/sysext/bin:ro" \
      --volume "$PWD/${out}:/run/sysext/out" \
      "localhost/luminusos-sysext-builder:{{ fedora_ver }}" \
      python3 /run/sysext/bin/release.py assemble /run/sysext/out \
        --version "${version}" --image-digest "${digest}"
    if [ -n "${SYSEXT_SIGNING_KEY:-}" ]; then
      sudo chown -R "$(id -u):$(id -g)" "${out}"
      python3 editions/workstation/sysext/release.py sign "${out}" --key "${SYSEXT_SIGNING_KEY}"
    fi
    sudo chown -R "$(id -u):$(id -g)" "${out}"
    echo "Feature artifacts for ${version} (${digest}) in ${out}"
