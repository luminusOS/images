#!/usr/bin/env bash
set -uexo pipefail

# GNOME Desktop module
releasever="$(cat /etc/dnf/vars/releasever 2>/dev/null || true)"
dnf_args=()
if [ -n "${releasever}" ]; then
  dnf_args+=(--releasever="${releasever}")
fi
dnf_args+=(--disablerepo="terra*")

# Copy static files into the image
if [ -d files ]; then
  find files -mindepth 1 -maxdepth 1 -exec cp -arf {} / \;
fi

if [ -x /ctx/common/recover-rpmdb.sh ]; then
  /ctx/common/recover-rpmdb.sh
else
  rpm --rebuilddb
fi

dnf -y "${dnf_args[@]}" install --setopt=install_weak_deps=False \
  accountsservice \
  gdm \
  gnome-initial-setup \
  gnome-shell \
  gnome-backgrounds

dnf -y "${dnf_args[@]}" install --setopt=install_weak_deps=False gnome-software

# ReadyMade's CleanupBoot postinstall module expects a BLS entry directory.
# The live root can boot without it, but the installed target needs the path.
mkdir -p /boot/efi /boot/loader/entries

# ReadyMade replaces the legacy live installer entry in the live session.
rm -f /usr/share/applications/liveinst.desktop
if [ -f /usr/share/applications/com.fyralabs.Readymade.desktop ]; then
  mkdir -p /etc/xdg/autostart /usr/local/share/applications
  sed -i '/^NoDisplay=/d' /usr/share/applications/com.fyralabs.Readymade.desktop
  sed -i '/^Hidden=/d' /usr/share/applications/com.fyralabs.Readymade.desktop
  sed -i 's|^Exec=.*|Exec=/usr/libexec/luminusos/readymade-wrapper|' /usr/share/applications/com.fyralabs.Readymade.desktop
  cp -f /usr/share/applications/com.fyralabs.Readymade.desktop /usr/local/share/applications/com.fyralabs.Readymade.desktop
  cp -f /usr/local/share/applications/com.fyralabs.Readymade.desktop /etc/xdg/autostart/com.fyralabs.Readymade.desktop
  sed -i '/^NoDisplay=/d' /usr/share/applications/com.fyralabs.Readymade.desktop
  sed -i '/^Hidden=/d' /usr/share/applications/com.fyralabs.Readymade.desktop
  printf '\nNoDisplay=true\nHidden=true\n' >> /usr/share/applications/com.fyralabs.Readymade.desktop
fi
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

# Mask services that fail in live environment
systemctl mask bootloader-update.service
systemctl enable luminusos-installed-firstboot-cleanup.service
printf 'luminus\n' > /etc/hostname

# Create a live user with autologin in locked mode
useradd -m -G wheel liveuser || true
passwd -d liveuser
mkdir -p /etc/gdm
cat > /etc/gdm/custom.conf <<'EOF'
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=liveuser
DefaultSession=live-installer.desktop
EOF
mkdir -p /var/lib/AccountsService/users
cat > /var/lib/AccountsService/users/liveuser <<'EOF'
[User]
Session=live-installer
XSession=live-installer
SystemAccount=false
EOF
