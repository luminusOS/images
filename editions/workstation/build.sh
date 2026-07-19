#!/usr/bin/env bash
set -uexo pipefail

mkdir -p /boot/efi /boot/loader/entries

rm -f /usr/share/applications/liveinst.desktop
rm -f /etc/xdg/autostart/org.gnome.Software.desktop
mkdir -p /usr/share/gnome-shell/search-providers
cat > /usr/share/gnome-shell/search-providers/org.gnome.Software-search-provider.ini <<'EOF'
DefaultDisabled=true
EOF

# Compile GNOME schema overrides
glib-compile-schemas /usr/share/glib-2.0/schemas/
if command -v dconf >/dev/null 2>&1; then
  dconf update
fi

if [ -f /usr/share/gnome-shell/modes/initial-setup.json ]; then
  tmp="$(mktemp)"
  jq '.enabledExtensions = (((.enabledExtensions // []) + ["aurora-shell@luminusos.github.io"]) | unique)' \
    /usr/share/gnome-shell/modes/initial-setup.json > "${tmp}"
  install -m 0644 "${tmp}" /usr/share/gnome-shell/modes/initial-setup.json
  rm -f "${tmp}"
fi

# Ensure graphical boot and GDM as display manager
ln -sf /usr/lib/systemd/system/graphical.target /etc/systemd/system/default.target
ln -sf /usr/lib/systemd/system/gdm.service /etc/systemd/system/display-manager.service

mkdir -p /etc/gdm
cat > /etc/gdm/custom.conf <<'EOF'
[daemon]
InitialSetupEnable=true
EOF
