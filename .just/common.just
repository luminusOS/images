default_fedora_version := shell('"$1" "$2"', justfile_directory() / "tools/config-value.sh", "DEFAULT_FEDORA_VERSION")
default_aurora_shell_version := shell('"$1" "$2"', justfile_directory() / "tools/config-value.sh", "AURORA_SHELL_VERSION")
default_aurora_shell_sha256 := shell('"$1" "$2"', justfile_directory() / "tools/config-value.sh", "AURORA_SHELL_SHA256")
default_sirius_version := shell('"$1" "$2"', justfile_directory() / "tools/config-value.sh", "SIRIUS_VERSION")

fedora_ver := env("LOS_FEDORA_VERSION", default_fedora_version)
base := env("LOS_BASE", "quay.io/fedora/fedora-bootc:" + fedora_ver)
name := env("LOS_NAME", "LuminusOS")
pretty := env("LOS_PRETTY_NAME", "Luminus OS")
registry := env("LOS_REGISTRY", "localhost")
build_date := `date +%Y%m%d`
tag := env("LOS_TAG", "testing-" + fedora_ver + "." + build_date)
core_image := registry + "/luminusos:" + tag
workstation_image := registry + "/luminusos-workstation:" + tag
workstation_iso_image := registry + "/luminusos-workstation:" + tag + "-iso"
workstation_target_image := env("LOS_WORKSTATION_TARGET_IMAGE", "ghcr.io/luminusos/luminusos-workstation:testing-" + fedora_ver)
aurora_shell_version := env("AURORA_SHELL_VERSION", default_aurora_shell_version)
aurora_shell_sha256 := env("AURORA_SHELL_SHA256", default_aurora_shell_sha256)
sirius_version := env("SIRIUS_VERSION", default_sirius_version)
force_core := env("LOS_FORCE_CORE", "0")
skip_flatpaks := env("LOS_SKIP_FLATPAKS", "0")
qemu_disk_size := env("QEMU_INSTALL_DISK_SIZE", "64G")

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
