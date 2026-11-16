# Triage: workstation workstation_payload, testing, Fedora 45

Base image: quay.io/fedora/fedora-bootc:45 sha256:d70fb477a35612f651fcfa397f41e2945514374d3fdaaa64b0e75a3ca1da2bbc. Reviewed 2026-11-16 by leandromqrs.
Binary paths and owning RPMs were resolved in the cosign-verified candidate image
with `find /usr -samefile <ostree object>` and `rpm -qf`; hashes are the SBOM SHA-256.
Fedora status from Bodhi on 2026-11-16.

## Default exposure (checked in the verified image with rpm, systemctl and getcap)

- `/usr/bin/podman`: CLI run on user invocation; podman.socket, podman.service and the other podman units are disabled system-wide and for users.
- `/usr/libexec/podman/rootlessport`: helper started only by a rootless podman container with published ports; podman units are disabled.
- `/usr/libexec/podman/quadlet`: DEFAULT-EXPOSED: runs at every boot and user login as podman-system-generator/podman-user-generator, parsing local quadlet unit files (no network input).
- `/usr/bin/skopeo`: CLI run on user invocation; the RPM ships no systemd units.
- `/usr/bin/toolbox`: CLI run on user invocation; the RPM ships no systemd units.
- `/usr/bin/kl2tpd`: go-l2tp ships no systemd units; required only by NetworkManager-l2tp-1.52.6-1.fc45 and started only when a user activates an L2TP VPN.
- `/usr/bin/kpppoed`: go-l2tp ships no systemd units; required only by NetworkManager-l2tp-1.52.6-1.fc45 and not started by default.
- `/usr/bin/ql2tpd`: go-l2tp ships no systemd units; required only by NetworkManager-l2tp-1.52.6-1.fc45 and not started by default.
- `/usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz`: running kernel of every installed system.
- No flagged binary has a setuid bit or file capabilities.
- Kernel matches come from NVD CPE `linux_kernel` entries with no usable version bound
  (16 with version `-`, CVE-2020-27815 fixed in 5.10.4, CVE-2021-20194 from 5.2);
  applicability to 7.3.3 was not verified and blocks stable.
- These exceptions are scoped to the testing channel and expire on 2026-12-16T00:00:00Z.

| Advisory | Severity | Package | Version | Binary | RPM | Fixed upstream |
|---|---|---|---|---|---|---|
| CVE-2016-3699 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2017-6264 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2018-10902 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2018-14625 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2019-14899 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2020-16119 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2020-1749 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2020-27815 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | 4.9.249, 4.14.213, 4.19.164, 5.4.86, 5.10.4 |
| CVE-2021-20194 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2021-3864 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2022-0400 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2022-1247 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2022-3636 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2023-3640 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2023-39179 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2023-39180 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2023-6535 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2023-6610 | High | linux-kernel | 7.3.3-300.fc45.x86_64 | /usr/lib/modules/7.3.3-300.fc45.x86_64/vmlinuz | kernel-core-7.3.3-300.fc45.x86_64 | unknown |
| CVE-2026-56866 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-56866 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78659 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78660 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78663 | Critical | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78667 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-78669 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94439 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94440 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94444 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-94447 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97031 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27.1-X:nodwarf5 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| CVE-2026-97032 | High | stdlib | go1.27rc2-X:nodwarf5 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 1.26.9, 1.27.2 |
| GHSA-2v4p-qf9q-27wj | High | google.golang.org/grpc | v1.82.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.82.2 |
| GHSA-2v4p-qf9q-27wj | High | google.golang.org/grpc | v1.82.1 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.82.2 |
| GHSA-4374-p667-p6c8 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.17.0 |
| GHSA-4374-p667-p6c8 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.17.0 |
| GHSA-4374-p667-p6c8 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.17.0 |
| GHSA-4hq8-gpf5-8p68 | High | go.podman.io/podman/v6 | v6.0.0-20260929000000-b3b4b2d4f590+dirty | /usr/libexec/podman/rootlessport | podman-5:6.1.3-1.fc45.x86_64 | 6.0.0 |
| GHSA-4hq8-gpf5-8p68 | High | go.podman.io/podman/v6 | v6.0.0-20260929000000-b3b4b2d4f590+dirty | /usr/libexec/podman/quadlet | podman-5:6.1.3-1.fc45.x86_64 | 6.0.0 |
| GHSA-4hq8-gpf5-8p68 | High | go.podman.io/podman/v6 | v6.0.0-20260929000000-b3b4b2d4f590+dirty | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 6.0.0 |
| GHSA-hrxh-6v49-42gf | High | google.golang.org/grpc | v1.82.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.82.1 |
| GHSA-mgcc-cww5-fp2q | High | github.com/go-jose/go-jose/v4 | v4.1.4 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 4.1.6 |
| GHSA-mgcc-cww5-fp2q | High | github.com/go-jose/go-jose/v4 | v4.1.4 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 4.1.6 |
| GHSA-vp52-pcj8-j9qc | High | google.golang.org/grpc | v1.82.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.83.1 |
| GHSA-vp52-pcj8-j9qc | High | google.golang.org/grpc | v1.82.1 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.83.1 |
| GO-2026-4918 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.53.0 |
| GO-2026-4918 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.53.0 |
| GO-2026-4918 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.53.0 |
| GO-2026-5026 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.55.0 |
| GO-2026-5026 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.55.0 |
| GO-2026-5026 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.55.0 |
| GO-2026-5932 | Unknown | golang.org/x/crypto | v0.54.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.58.1-0.20261009181718-2f1f834330b2 |
| GO-2026-5932 | Unknown | golang.org/x/crypto | v0.56.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.58.1-0.20261009181718-2f1f834330b2 |
| GO-2026-5942 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.56.0 |
| GO-2026-5942 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.56.0 |
| GO-2026-5942 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.56.0 |
| GO-2026-5970 | High | golang.org/x/text | v0.21.0 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 0.39.0 |
| GO-2026-6179 | High | golang.org/x/mod | v0.20.0 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 0.40.0 |
| GO-2026-6179 | High | golang.org/x/mod | v0.38.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.40.0 |
| GO-2026-6180 | High | golang.org/x/mod | v0.20.0 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 0.40.0 |
| GO-2026-6180 | High | golang.org/x/mod | v0.38.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.40.0 |
| GO-2026-6303 | High | golang.org/x/crypto | v0.54.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.55.0 |
| GO-2026-6354 | High | golang.org/x/crypto | v0.54.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.56.0 |
| GO-2026-6355 | High | golang.org/x/crypto | v0.54.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.56.0 |
| GO-2026-6603 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6603 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6603 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6603 | High | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6603 | High | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6610 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6610 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6610 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6610 | High | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6610 | High | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6611 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6611 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6611 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6611 | High | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6611 | High | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6612 | Critical | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6612 | Critical | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6612 | Critical | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6612 | Critical | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6612 | Critical | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6617 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6617 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6617 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.60.0 |
| GO-2026-6617 | High | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6617 | High | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.60.0 |
| GO-2026-6629 | High | golang.org/x/text | v0.21.0 | /usr/bin/toolbox | toolbox-0.3-7.fc45.x86_64 | 0.41.0 |
| GO-2026-6629 | High | golang.org/x/text | v0.40.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.41.0 |
| GO-2026-6860 | High | golang.org/x/net | v0.15.0 | /usr/bin/kl2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.62.0 |
| GO-2026-6860 | High | golang.org/x/net | v0.15.0 | /usr/bin/kpppoed | go-l2tp-0.1.8-5.fc45.x86_64 | 0.62.0 |
| GO-2026-6860 | High | golang.org/x/net | v0.15.0 | /usr/bin/ql2tpd | go-l2tp-0.1.8-5.fc45.x86_64 | 0.62.0 |
| GO-2026-6860 | High | golang.org/x/net | v0.56.0 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 0.62.0 |
| GO-2026-6860 | High | golang.org/x/net | v0.57.0 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 0.62.0 |
| GO-2026-6865 | High | github.com/klauspost/compress | v1.19.1 | /usr/bin/skopeo | skopeo-1:1.24.1-1.fc45.x86_64 | 1.20.2 |
| GO-2026-6865 | High | github.com/klauspost/compress | v1.19.1 | /usr/bin/podman | podman-5:6.1.3-1.fc45.x86_64 | 1.20.2 |
