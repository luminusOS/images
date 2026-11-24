# Tools to check, pack, sign and test hardware feature extensions. Never part
# of the workstation image: erofs-utils is a build-time dependency only.
ARG fedora_version
FROM quay.io/fedora/fedora:${fedora_version}

RUN dnf -y install --setopt=install_weak_deps=False \
      erofs-utils \
      gnupg2 \
      jq \
      python3 \
      systemd-container \
      systemd-udev \
      xz \
    && dnf clean all
