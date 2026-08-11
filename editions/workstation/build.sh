#!/usr/bin/env bash
set -uexo pipefail

mkdir -p /boot/efi /boot/loader/entries

rm -f /usr/share/applications/liveinst.desktop
rm -f /etc/xdg/autostart/org.gnome.Software.desktop

glib-compile-schemas /usr/share/glib-2.0/schemas/
if command -v dconf >/dev/null 2>&1; then
  dconf update
fi

# The overlay ships luminusos-logo-icon.svg after the last dnf transaction, so
# the hicolor cache written by rpm file triggers would not list it.
if command -v gtk4-update-icon-cache >/dev/null 2>&1; then
  gtk4-update-icon-cache -f -t /usr/share/icons/hicolor
elif command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t /usr/share/icons/hicolor
fi

if [ -f /usr/share/gnome-shell/modes/initial-setup.json ]; then
  tmp="$(mktemp)"
  jq '.enabledExtensions = (((.enabledExtensions // []) + ["aurora-shell@luminusos.github.io"]) | unique)' \
    /usr/share/gnome-shell/modes/initial-setup.json >"${tmp}"
  install -m 0644 "${tmp}" /usr/share/gnome-shell/modes/initial-setup.json
  rm -f "${tmp}"
fi

ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
ln -sf /usr/lib/systemd/system/gdm.service /etc/systemd/system/display-manager.service
