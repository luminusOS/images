#!/usr/bin/env python3
import os
import shutil
import subprocess
from pathlib import Path


def run_system(command):
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("LD_LIBRARY_PATH", None)
    subprocess.run(command, check=True, env=env)


for path in (Path("/boot/efi"), Path("/boot/loader/entries")):
    path.mkdir(parents=True, exist_ok=True)
for path in (
    Path("/usr/share/applications/liveinst.desktop"),
    Path("/etc/xdg/autostart/org.gnome.Software.desktop"),
):
    path.unlink(missing_ok=True)
run_system(["glib-compile-schemas", "/usr/share/glib-2.0/schemas/"])
if shutil.which("dconf"):
    run_system(["dconf", "update"])
icon_cache = shutil.which("gtk4-update-icon-cache") or shutil.which(
    "gtk-update-icon-cache"
)
if icon_cache:
    run_system([icon_cache, "-f", "-t", "/usr/share/icons/hicolor"])
for name, target in (
    ("default.target", "graphical.target"),
    ("display-manager.service", "gdm.service"),
):
    link = Path("/etc/systemd/system") / name
    link.unlink(missing_ok=True)
    link.symlink_to(f"/usr/lib/systemd/system/{target}")
for command in (
    ["systemctl", "disable", "sshd.service"],
    ["firewall-offline-cmd", "--zone=public", "--remove-service-from-zone=ssh"],
    ["systemctl", "enable", "bootc-fetch-apply-updates.timer"],
    ["systemctl", "enable", "elastic-swap.service"],
    ["systemctl", "enable", "systemd-oomd.service"],
    ["systemctl", "enable", "luminus-flatpak-remotes.service"],
):
    run_system(command)
