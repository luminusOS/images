# Stable 45 exception evidence

Owner: leandromqrs. Built from the owner's decision table of 2026-11-17 and the scan of the first stable candidate (publish.yml run 44229426822 on release/45, commit e046a1a). Findings outside the table are not excepted and block.

## ksmbd module absence (CVE-2023-39179, CVE-2023-39180)

The candidate SBOMs (syft, from the image RPM database) list kernel, kernel-core, kernel-modules and kernel-modules-core 7.3.4-300.fc45.x86_64 (core), plus kernel-modules-extra (workstation, installer), supplier Fedora Project. Koji builds are unique per NEVRA, so these are the packages of Koji build kernel-7.3.4-300.fc45.

On 2026-11-18 the Fedora-signed copies of those four RPMs were downloaded from https://kojipkgs.fedoraproject.org/packages/kernel/7.3.4/300.fc45/data/signed/f577861e/x86_64/. They were verified with `rpmkeys --dbpath <empty db> -Kv` against a database holding only the Fedora 45 primary key, 4F50 A611 4CD5 C697 6A7F 1179 655A 4B02 F577 861E (taken from https://fedoraproject.org/fedora.gpg and matching the fingerprint listed on https://fedoraproject.org/security/). Every package reports a valid RSA/SHA256 header signature by that key, plus valid header and payload digests.

In the signed packages, `rpm -qlp` lists no file matching ksmbd, and /lib/modules/7.3.4-300.fc45.x86_64/config in kernel-core contains `# CONFIG_SMB_SERVER is not set`. ksmbd is therefore neither built nor shipped by any kernel package the candidate installs.

Limitation: the SBOM does not list the kernel module files themselves, because the image stores them as ostree objects. The link between the image and these packages therefore rests on the RPM database's NEVRA and Fedora supplier.

Signed RPMs (sha256):

```
fe8e66965978c8ee0c557959817bb3df6ac1540a5912bbb76f94d3bd269bacd6  kernel-core-7.3.4-300.fc45.x86_64.rpm
cf55e4539fdfd39da91772c4656f1a0103ed3ed3630056d49c69b3f2807230ef  kernel-modules-7.3.4-300.fc45.x86_64.rpm
487c5eccb519d06b8171bbeccf746b927fe0ab2f99d7ae1d855771f503e8767d  kernel-modules-core-7.3.4-300.fc45.x86_64.rpm
4b2e2cd66d0efb8cc39f31ea8843f63acd05320a2aa78cdc396b2ede76ff6e2b  kernel-modules-extra-7.3.4-300.fc45.x86_64.rpm
```

## podman 6.2.0 and GHSA-4hq8-gpf5-8p68

Scan of the second stable candidate (publish.yml run 44296172348 on release/45, base sha256:69b66da0839f186f799addae6620aae19a6998b3fd4d2def00168c8dab50c486) reports GHSA-4hq8-gpf5-8p68 (CVE-2026-57231, image environment entries without a value leak host variables) on /usr/bin/podman, /usr/libexec/podman/quadlet and /usr/libexec/podman/rootlessport. The advisory covers `go.podman.io/podman/v6 < 6.0.0`. Go records the main module of these binaries as the pseudo-version `v6.0.0-20261110000000-d3ee8c5e6fec+dirty`, which orders before 6.0.0.

- The candidate SBOMs list podman 5:6.2.0-1.fc45 and skopeo 1:1.25.1-2.fc45. Their Fedora-signed RPMs were downloaded from kojipkgs (data/signed/f577861e) on 2026-11-18. `rpmkeys -K`, run against a database holding only the Fedora 45 primary key, reports `digests signatures OK`. The RPM file digests equal the sha256 of the scanned ostree objects: c7c17121… /usr/bin/podman, 0639f268… /usr/libexec/podman/quadlet, 376de782… /usr/libexec/podman/rootlessport and 0e6ca9bf… /usr/bin/skopeo. Those digests set the binary identities in the policies.
- The Fedora f45 podman.spec has `Version: 6.2.0` and `Source0: https://github.com/containers/%{name}/archive/v%{version_no_tilde}.tar.gz`, and its `sources` file names v6.2.0.tar.gz.
- The advisory names the fix commit 6c431b73dbf8e4b20b778644d7a80caebdb75050, "fix image host env leak". The GitHub compare API between that commit and v6.2.0 returns `ahead`, behind 0, so the fix is an ancestor of the tag the binaries are built from.
- The Fedora-signed source package podman-6.2.0-1.fc45.src.rpm (sha256 a3271ece6301e5d6c6d7d3f8ce7eeb9f79dc633a9d7eaf30d6a3cd10ebf6484c, from kojipkgs data/signed/f577861e/src) passes `rpmkeys -K` with only the Fedora 45 key. It contains only podman.spec and v6.2.0.tar.gz (sha256 cb182273c5c5e3ea079f8f88a9a30a574d247f80e0b9dd9c02df1d2e6f6f3705). The tarball's sha512 (10b1559e9e34…) equals both the dist-git `sources` entry and a fresh download of https://github.com/containers/podman/archive/v6.2.0.tar.gz.
- The spec declares no `Patch` lines. `%prep` runs `%autosetup -Sgit` and changes only the Makefile (the `@@PODMAN@@` bindir substitution; the cgroups-v1 edit applies only on RHEL 9). That edited working tree explains the `+dirty` suffix. `%build` sets only compiler and linker flags and build tags, and stamps GIT_COMMIT 055de046937d29450f310fce0fe3071485d8bed9, the commit that tag v6.2.0 points to.
- In the unpacked v6.2.0 source, pkg/specgen/generate/container.go:130 defines `ParseImageEnvs`, which rejects an image env entry without `=` or with an empty key. It is called on the image config in container.go:192 and pkg/specgen/generate/kube/kube.go:493: the change commit 6c431b73dbf8 makes.
- Owner decision of 2026-11-18: classify this finding as `proven_false_positive` for these three podman-6.2.0-1.fc45 binaries, for 30 days.

```
2e401364d53b98fedc4d04a957c3937ad4e987e3029dd3b960fceb6fe1265188  podman-6.2.0-1.fc45.x86_64.rpm
d3ed4f5d207fd107a870d74ebe79eec8a2288a30fb4d1e266da678ece885c3fb  skopeo-1.25.1-2.fc45.x86_64.rpm
```

## Decision table


Dono: leandromqrs. Escopo: `channel=stable`, Fedora 45, edições e escopos em que cada achado aparece. Validade: no máximo 30 dias a partir da emissão da política stable. Evidência: `kernel-triage.md` e `go-triage.md`, neste diretório.

| Grupo | Achados | Decisão | Classificação na política |
|---|---|---|---|
| Kernel corrigido antes do 7.3 | CVE-2018-10902, CVE-2018-14625, CVE-2020-27815, CVE-2022-3636, CVE-2023-6610 | Não aplicável | `proven_false_positive`, citando commit e tag |
| Kernel com lockdown | CVE-2016-3699 | Escolha do dono: não aplicável com recibo de lockdown. Luna rejeitou a prova: nenhum registro liga `6ea0e815fc5e` ao CVE. O dono aceitou o risco em 2026-11-17 | `accepted_risk` |
| Kernel fora da config | CVE-2023-39179, CVE-2023-39180 | Não aplicável | `proven_false_positive`, citando `# CONFIG_SMB_SERVER is not set`, só depois de S4 provar que não há módulo ksmbd no candidato |
| Kernel sem correção upstream | CVE-2019-14899 | Risco aceito | `accepted_risk` |
| Kernel sem informação | CVE-2017-6264, CVE-2020-16119, CVE-2020-1749, CVE-2021-20194, CVE-2021-3864, CVE-2022-0400, CVE-2022-1247, CVE-2023-3640, CVE-2023-6535 | Risco aceito, 30 dias | `accepted_risk` |
| Go: podman/quadlet/rootlessport/skopeo | stdlib e módulos | Usar a base com podman 6.2.0 e skopeo 1.25.1. Aceitar os 3 restantes: GO-2026-6860, GHSA-mgcc-cww5-fp2q e GO-2026-5932 | sem classificação favorável. O scan do candidato stable decide, e só os 3 restantes podem virar `accepted_risk`; qualquer outro achado bloqueia |
| Go: toolbox | 16 advisories, incluindo o Critical CVE-2026-78663 de servidor HTTP/2 | Risco aceito | `accepted_risk` |
| Go: go-l2tp (workstation) | 22 advisories por binário | Risco aceito | `accepted_risk` |
| Exclusão do Flatpak no scan | `/var/lib/flatpak` | Aceita na stable, 30 dias | registro de exclusão próprio para a stable |
| Base fedora-bootc sem assinatura | `quay.io/fedora/fedora-bootc` | Aceita | registro de risco da base para a stable |

Pendências que decorrem das decisões:

- Criar um recibo de lockdown do kernel (`/sys/kernel/security/lockdown`) na validação, antes de classificar CVE-2016-3699.
- Gerar a política stable contra o scan do primeiro candidato stable (S4). Achados que não estiverem nesta tabela bloqueiam.
- Luna revisa todas as classificações `proven_false_positive` antes de a política ser gravada.

## Kernel triage


Scope: the 18 High advisories Grype 0.101.1 flags against `kernel-core-7.3.4-300.fc45.x86_64`. Research only. No repository files were edited and no GitHub writes were made.

Rule applied: a `not-applicable-fixed` verdict needs a fetched fix commit and a fetched first-containing tag. A `not-applicable-config` verdict needs an exact quoted `CONFIG_` line from a fetched config. Anything else is `unknown`. Nothing below rests on memory.

Tag proof method: `https://api.github.com/repos/torvalds/linux/compare/<tag>...<sha>` returns `behind` when the commit is an ancestor of the tag, which means the tag contains it, and `ahead` or `diverged` when it is not. The first containing tag is the first one that returns `behind`, with the previous tag returning `ahead` or `diverged`. The GitHub unauthenticated rate limit (60 requests per hour) ran out partway through, so any check that needed more calls is marked unknown.

## Summary table

| CVE | Subsystem | Fix commit | First containing tag | Verdict | Sources fetched | Recommendation |
|---|---|---|---|---|---|---|
| CVE-2016-3699 | ACPI table override, Secure Boot | cited fix `a4a5ed2835e8` is an out-of-tree securelevel patch; lockdown equivalent `6ea0e815fc5e` (v5.4) is not tied to the CVE by any record | not established | unknown | CVE Services, gh commit/compare API | accept risk |
| CVE-2017-6264 | NVIDIA Android GPU driver | none | none | unknown | CVE Services, CIRCL, Red Hat CVE page | accept risk |
| CVE-2018-10902 | ALSA rawmidi double free | `39675f7a7c7e` "ALSA: rawmidi: Change resized buffers atomically" | v4.18 (v4.17 ahead, v4.18 behind) | not-applicable-fixed | torvalds commit page, compare API | not applicable |
| CVE-2018-14625 | vhost/vsock use-after-free | `834e772c8db0` "vhost/vsock: fix use-after-free in network stack callers" (message: "This is CVE-2018-14625") | v4.20 (compare: ahead) | not-applicable-fixed | gh commit + compare API (Commander) | not applicable |
| CVE-2019-14899 | VPN TCP injection via loose rp_filter | none ("No current fix from upstream") | n/a | applicable-unfixed | Ubuntu tracker | accept risk |
| CVE-2020-16119 | DCCP use-after-free | none identified | none | unknown | Fedora config (no `CONFIG_IP_DCCP` line quotable) | accept risk |
| CVE-2020-1749 | IPv6 tunnels bypass IPsec | none identified | none | unknown | NVD, Red Hat CVE page | accept risk |
| CVE-2020-27815 | JFS dbAdjTree array index | `c61b3e4839007668360ed8b87d7da96d2e59fc6c` "jfs: Fix array index bounds check in dbAdjTree" | v5.11 (v5.10 diverged, v5.11 behind) | not-applicable-fixed | stable commit page, compare API | not applicable |
| CVE-2021-20194 | BPF getsockopt heap overflow | none identified | none | unknown | NVD, Red Hat CVE page | accept risk |
| CVE-2021-3864 | dumpable flag after SUID exec | none identified (only lore submissions in NVD) | none | unknown | Ubuntu tracker, NVD | accept risk |
| CVE-2022-0400 | SMC out-of-bounds read | none; contested | none | unknown | Red Hat hydra JSON | accept risk |
| CVE-2022-1247 | ROSE race in rose_connect | none identified | none | unknown | Ubuntu tracker, CVE Services | accept risk |
| CVE-2022-3636 | MediaTek PPE use-after-free | `17a5f6a78dc7` "net: ethernet: mtk_eth_soc: use after free in __mtk_ppe_check_skb()" | v5.19 (v5.18 diverged, v5.19 behind) | not-applicable-fixed | CVE Services (VulDB CNA), stable commit page, compare API | not applicable |
| CVE-2023-3640 | x86 cpu_entry_area leak | none identified | none | unknown | Ubuntu tracker, CVE Services | accept risk |
| CVE-2023-39179 | ksmbd SMB2 read OOB | ksmbd not built | n/a | not-applicable-config | Fedora f45 config | not applicable |
| CVE-2023-39180 | ksmbd SMB2_READ memory leak | ksmbd not built | n/a | not-applicable-config | Fedora f45 config | not applicable |
| CVE-2023-6535 | NVMe/TCP target NULL deref | none identified | none | unknown | Red Hat CVE page, CVE Services | accept risk |
| CVE-2023-6610 | CIFS client smb2_dump_detail OOB read | `567320c46a60` "smb: client: fix potential OOB in smb2_dump_detail()" (message: "This fixes CVE-2023-6610") | v6.7 (compare ...v6.6: behind, ...v6.7: ahead) | not-applicable-fixed | gh commit + compare API (Commander) | not applicable |

Verdict counts: not-applicable-fixed 3; not-applicable-config 2; applicable-unfixed 1; unknown 12. Total 18.

Blocking: none. No CVE is confirmed applicable and unfixed with real exposure.

## Sources fetched

- Red Hat CVE JSON: https://access.redhat.com/hydra/rest/securitydata/cve/<CVE-ID>.json
- Red Hat CVE page: https://access.redhat.com/security/cve/<cve-id-lowercase>
- CVE Services: https://cveawg.mitre.org/api/cve/<CVE-ID>
- CIRCL CVE mirror: https://cve.circl.lu/api/cve/<CVE-ID>
- NVD: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>
- Ubuntu tracker: https://ubuntu.com/security/<CVE-ID>
- Kernel CNA: https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/<year>/<CVE-ID>.json (HTTP 404 for all seven original unknowns checked)
- Torvalds commit page: https://git.kernel.org/torvalds/c/39675f7a7c7e7702f7d5341f1e0d01db746543a0
- Stable commit pages: https://git.kernel.org/stable/c/c61b3e4839007668360ed8b87d7da96d2e59fc6c and https://git.kernel.org/stable/c/17a5f6a78dc7b8db385de346092d7d9f9dc24df6 (used for the commit subject only; their branch lists are an index, not containment)
- GitHub compare API: https://api.github.com/repos/torvalds/linux/compare/<tag>...<sha>
- Fedora kernel config (f45): https://src.fedoraproject.org/rpms/kernel/raw/f45/f/kernel-x86_64-fedora.config

## Per-CVE notes

**CVE-2016-3699.** Fetched: the CVE Services record cites `https://github.com/mjg59/linux/commit/a4a5ed2835e8ea042868b7401dced3f517cafa76`. The SHA exists on torvalds/linux, but the compare API says `ahead` for v4.5 and `diverged` for v4.6 and v4.7, so it is not in those tags. Later tag checks hit the rate limit. First containing tag not found. Verdict unknown. Red Hat rates it Low. Superseded 2026-11-17: the cited CVE fix `a4a5ed2835e8` is an out-of-tree securelevel patch and is not in mainline (`compare/v5.4...a4a5ed2835e8` diverged). `6ea0e815fc5e` ("acpi: Disable ACPI table override if the kernel is locked down", contained in v5.4 and v7.0) is the lockdown-based equivalent, but no fetched record names it as the fix for this CVE. Luna's review rejected the favorable classification; verdict unknown, handled as accepted risk until a record ties the fix to the CVE.

**CVE-2017-6264.** Fetched: CIRCL and CVE Services show the CNA is NVIDIA with product "Android", and the record does not name a mainline Linux function fix. No fix commit found. Verdict unknown.

**CVE-2018-10902.** Fetched: commit `39675f7a7c7e` is titled "ALSA: rawmidi: Change resized buffers atomically" (torvalds commit page). Compare API: `v4.17...39675f7a` returns `ahead`, `v4.18...39675f7a` returns `behind`. First containing tag: v4.18. Verdict not-applicable-fixed.

**CVE-2018-14625.** Fetched: Red Hat and NVD describe the AF_VSOCK connect/close race. Red Hat's data lists fixed RHSA errata but no upstream commit. No upstream commit identified. Verdict unknown. Superseded 2026-11-17: `gh api repos/torvalds/linux/commits/834e772c8db0` shows "vhost/vsock: fix use-after-free in network stack callers" with the message line "This is CVE-2018-14625"; `compare/834e772c8db0...v7.0` returns `ahead` (contained), and `...v4.20` also `ahead`. Verdict not-applicable-fixed.

**CVE-2019-14899.** Fetched: Ubuntu tracker says "No current fix from upstream as of 2019-12-13". Verdict applicable-unfixed. The exposure depends on the `rp_filter` sysctl, which is a configuration default, not a code defect. Recommendation accept risk.

**CVE-2020-16119.** Red Hat's CVE data names kernel-rt on MRG 2 as affected. No fix commit identified. Verdict unknown. The Fedora config does not contain a quotable `CONFIG_IP_DCCP` line, so no config verdict can be made.

**CVE-2020-1749.** Fetched: NVD and Red Hat CVE pages describe the IPsec-over-IPv6 tunnel issue. Neither names an upstream commit. Verdict unknown.

**CVE-2020-27815.** Fetched: commit `c61b3e4839007668360ed8b87d7da96d2e59fc6c` is titled "jfs: Fix array index bounds check in dbAdjTree" (stable commit page). Compare API: `v5.10...c61b3e48` returns `diverged`, `v5.11...c61b3e48` returns `behind`. First containing tag: v5.11. Verdict not-applicable-fixed.

**CVE-2021-20194.** Fetched: NVD and Red Hat describe the bug and its precondition (`CONFIG_HARDENED_USERCOPY` not set). The Fedora config sets `CONFIG_HARDENED_USERCOPY=y`, but that is a mitigation, not a fix, and it does not remove the bug. No upstream fix commit identified. Verdict unknown.

**CVE-2021-3864.** Fetched: Ubuntu tracker says "upstream as of 2022-01-27". The NVD references are only lore.kernel.org patch submissions, not a merged commit. No commit SHA identified, so the verdict cannot be not-applicable-fixed. Verdict unknown.

**CVE-2022-0400.** Fetched: Red Hat says "These files are not built in our source code". This is a Red Hat statement, not a config proof for Fedora. The Fedora f45 config does not give a quotable `CONFIG_SMC` line. The contested status came from a search snippet of a Yocto commit whose page returned HTTP 403, so it is not used for the verdict. Verdict unknown.

**CVE-2022-1247.** Fetched: Ubuntu tracker says "upstream as of 2023.01.10", but the tracker page gives no commit SHA. No fix commit, so no not-applicable-fixed verdict. The Fedora f45 config has no quotable `CONFIG_ROSE` line. Verdict unknown.

**CVE-2022-3636.** Fetched: the CVE Services record (VulDB CNA) names fix commit `17a5f6a78dc7` as the patch and states "No released Linux Kernel version was ever affected". Commit title "net: ethernet: mtk_eth_soc: use after free in __mtk_ppe_check_skb()" (stable commit page). Compare API: `v5.18...17a5f6a7` returns `diverged`, `v5.19...17a5f6a7` returns `behind`. First containing tag: v5.19. Verdict not-applicable-fixed.

**CVE-2023-3640.** Fetched: Ubuntu tracker says "upstream as of 2023-09-01"; Red Hat says the CVE-2023-0597 fix already covers the vector. No commit SHA identified. Verdict unknown.

**CVE-2023-39179 and CVE-2023-39180.** The fetched Fedora f45 config (https://src.fedoraproject.org/rpms/kernel/raw/f45/f/kernel-x86_64-fedora.config) contains the exact line `# CONFIG_SMB_SERVER is not set`. ksmbd is therefore not built, and the flaws are in ksmbd. Verdict not-applicable-config for both.

**CVE-2023-6535.** Fetched: Red Hat CVE page and CVE Services record do not name an upstream commit. No fix commit identified. Verdict unknown.

**CVE-2023-6610.** Fetched: Red Hat CVE page and CVE Services record do not name an upstream commit. No fix commit identified. Verdict unknown. Superseded 2026-11-17: `commits/567320c46a60` is "smb: client: fix potential OOB in smb2_dump_detail()" with "This fixes CVE-2023-6610"; `compare/567320c46a60...v7.0` and `...v6.7` return `ahead`, `...v6.6` returns `behind`. Verdict not-applicable-fixed.

## Caveats

- The fetched Fedora f45 config file does not contain every symbol. For example, it has no `CONFIG_X86_64=y` line. Absence of a line is therefore not used as config proof; only quoted lines are.
- No CVE was marked REJECTED. CVE-2019-14899 is contested upstream, but its verdict rests on the Ubuntu tracker only.
- The kernel CNA JSON path returned 404 for all seven original unknowns. These CVEs were assigned by Red Hat or NVIDIA, so the kernel CNA may not hold a record for them. This is unverified.
- 12 unknowns remain. Resolving them needs an upstream commit SHA and a containment check through the GitHub compare API after the rate limit resets.

Commander follow-up 2026-11-17: CVE-2016-3699, CVE-2018-14625 and CVE-2023-6610 resolved with authenticated GitHub commit/compare API calls (the analyst hit the unauthenticated rate limit). Revised counts: not-applicable-fixed 6 (one conditional on lockdown), not-applicable-config 2, applicable-unfixed 1, unknown 9.

Containment check 2026-11-17 (Commander, authenticated `gh api repos/torvalds/linux/compare/<sha>...v7.0 --jq .status`, `ahead` means contained):

| Commit | v7.0 | Subject |
|---|---|---|
| 39675f7a7c7e | ahead | ALSA: rawmidi: Change resized buffers atomically (CVE-2018-10902) |
| 834e772c8db0 | ahead | vhost/vsock: fix use-after-free in network stack callers (CVE-2018-14625) |
| c61b3e4839007668360ed8b87d7da96d2e59fc6c | ahead | jfs: Fix array index bounds check in dbAdjTree (CVE-2020-27815) |
| 17a5f6a78dc7 | ahead | net: ethernet: mtk_eth_soc: use after free in __mtk_ppe_check_skb() (CVE-2022-3636) |
| 567320c46a60 | ahead | smb: client: fix potential OOB in smb2_dump_detail() (CVE-2023-6610) |

ksmbd (CVE-2023-39179, CVE-2023-39180): `# CONFIG_SMB_SERVER is not set` proves the Fedora kernel does not build ksmbd. The SBOMs list no kernel module files for core and workstation, so the absence of a ksmbd module in the shipped image was not yet proven at triage time; the signed-RPM inspection above supplies that proof. S4 must inspect the stable candidate (`find /usr/lib/modules -name 'ksmbd*'` empty) before these are recorded as `proven_false_positive`.


## Go triage


Research-only analysis. Sources: the three exception policies and their `*.triage.md`
files under `images-stable-plan/shared/release/exceptions/`, Fedora Bodhi API, Fedora KOJI,
pkg.go.dev/vuln. Reviewed 2026-11-17.

## 1. Scope and deduplication

| Policy | embedded_go entries |
|---|---|
| `core-core_payload-testing-45.json` | 96 |
| `workstation-installer_live-testing-45.json` | 162 |
| `workstation-workstation_payload-testing-45.json` | 162 |

- The installer_live and workstation_payload entry sets are **identical** (verified set equality).
- The core set is a strict **subset** of the workstation sets (same advisory/binary/module tuples).
  Core only lacks the three `go-l2tp` binaries, which are workstation-only.
- Deduplicated universe: **162 unique (advisory, binary, module@version) tuples** covering
  **36 unique advisories** across **8 (rpm_nevra, binary path) groups** and **28 (binary → module@version) subgroups**.

Group membership across policies:

| RPM (nevra) | Binary | Policies | Module subgroups | Advisories |
|---|---|---|---|---|
| `podman-5:6.1.3-1.fc45.x86_64` | `/usr/bin/podman` | core, installer_live, workstation_payload | 8 | 26 |
| `podman-5:6.1.3-1.fc45.x86_64` | `/usr/libexec/podman/quadlet` | all 3 | 2 | 13 |
| `podman-5:6.1.3-1.fc45.x86_64` | `/usr/libexec/podman/rootlessport` | all 3 | 2 | 13 |
| `skopeo-1:1.24.1-1.fc45.x86_64` | `/usr/bin/skopeo` | all 3 | 7 | 28 |
| `toolbox-0.3-7.fc45.x86_64` | `/usr/bin/toolbox` | all 3 | 3 | 16 |
| `go-l2tp-0.1.8-5.fc45.x86_64` | `/usr/bin/kl2tpd` | installer_live, workstation_payload | 2 | 22 |
| `go-l2tp-0.1.8-5.fc45.x86_64` | `/usr/bin/kpppoed` | installer_live, workstation_payload | 2 | 22 |
| `go-l2tp-0.1.8-5.fc45.x86_64` | `/usr/bin/ql2tpd` | installer_live, workstation_payload | 2 | 22 |

Advisory families (deduplicated, 36 total): 12 stdlib CVEs (CVE-2026-56866, -78659, -78660,
-78663, -78667, -78669, -94439, -94440, -94444, -94447, -97031, -97032; fixed in go 1.26.9 / 1.27.2),
10 x/net (GHSA-4374-p667-p6c8 + GO-2026-4918/-5026/-5942/-6603/-6610/-6611/-6612/-6617/-6860),
4 x/crypto (GO-2026-5932/-6303/-6354/-6355), 3 grpc (GHSA-2v4p-qf9q-27wj, -hrxh-6v49-42gf, -vp52-pcj8-j9qc),
2 x/mod (GO-2026-6179/-6180), 2 x/text (GO-2026-5970/-6629), 1 go-jose (GHSA-mgcc-cww5-fp2q),
1 klauspost/compress (GO-2026-6865), 1 podman self-module (GHSA-4hq8-gpf5-8p68).

## 2. Fedora 45 package status (Bodhi + KOJI, checked 2026-11-17)

The triage notes flagged Bodhi `FEDORA-2026-9b209999d0` as "pending, fix unverified".
**It went stable on 2026-11-18** (Bodhi status: `stable`, test gating passed):
`buildah-1.46.1-1.fc45, containers-common-0.70.0-1.fc45, podman-6.2.0-1.fc45, skopeo-1.25.1-2.fc45`.

Toolchain availability: `golang-1.27.3-1.fc45` stable 2026-10-31; `golang-1.27.4-2.fc45`
stable 2026-11-14 (both ≥ 1.27.2, so past the stdlib fix line). `golang-1.27.2-1.fc45` was
obsoleted in candidate.

| RPM | Shipped in images | Newest Fedora 45 build (Bodhi) | Built with | Fixes stdlib CVEs? | Vendored module fixes (upstream go.mod) |
|---|---|---|---|---|---|
| podman | `5:6.1.3-1.fc45` (embeds go1.27.1) | `6.2.0-1.fc45` **stable 2026-11-18** | KOJI build done 2026-11-11 → golang-1.27.3 | Yes (≥1.27.2) | x/net v0.61.0, x/crypto v0.58.0, x/mod v0.42.0, x/text v0.43.0, grpc v1.84.0, go-jose **v4.1.5**, klauspost/compress v1.20.3 |
| skopeo | `1:1.24.1-1.fc45` (embeds go1.27.1) | `1.25.1-2.fc45` **stable 2026-11-18** (same update) | KOJI build done 2026-11-15 → golang-1.27.4 | Yes | x/net v0.60.0, x/crypto v0.58.0, x/text v0.43.0, grpc v1.83.2, go-jose **v4.1.5**, compress v1.20.3 |
| toolbox | `0.3-7.fc45` (embeds go1.27rc2) | none newer (0.3-7 itself is the latest, stable 2026-08-05) | built 2026-08-05 → golang-1.27~rc2 | No fix available | n/a |
| go-l2tp | `0.1.8-5.fc45` (embeds go1.27rc2) | **zero Fedora 45 updates in Bodhi** | built with golang-1.27~rc2 | No fix available | n/a |

KOJI buildroot RPM lists are not queryable anonymously; the toolchain column infers the
build-time stable `golang` from KOJI task timestamps, which is consistent with every
embedded stdlib string in the SBOMs (go1.27.1 for the September/October podman/skopeo
builds, go1.27rc2 for the July toolbox/go-l2tp builds). Treat as high-confidence pending a
re-scan of the next base image.

## 3. Critical advisories (2 IDs, 1 root bug)

Verified on pkg.go.dev/vuln:

- **GO-2026-6612** (x/net) and **CVE-2026-78663** (stdlib) are **aliases of the same bug**:
  the HTTP/**2 server** refunds connection-level flow control twice (stream reset + handler
  read), letting a malicious **client** bypass `MaxReceiveBufferPerConnection`. Total
  buffering still bounded by the concurrent-stream limit and per-stream flow control.
  Fixed in go 1.26.9 / 1.27.2 and `golang.org/x/net/http2` v0.60.0.
- Reachability: exploitation requires the binary to **serve HTTP/2 to an attacker-controlled
  client**. None of the eight binaries do so in the shipped configuration: podman's REST
  service is socket-activated and the units are disabled; skopeo and toolbox are HTTP
  *clients* only; quadlet parses local unit files with no network input; the go-l2tp daemons
  are L2TP/PPPoE control daemons, not HTTP servers. **Not blocking on reachability**, but
  podman could serve its API over TCP if a user enables `podman.socket` (HTTP/1.1, not h2c —
  unverified for 6.1.3; worth confirming if TCP API use is ever supported on stable).

Both Criticals hit all 8 binaries (stdlib family) or the 5 podman/skopeo/go-l2tp binaries
(x/net family), and both are covered by the recommendations below.

## 4. Per-group recommendations

Reachability quotes are from the `reason` fields / triage MD "Default exposure" section;
none of the flagged binaries has a setuid bit or file capabilities (checked with `rpm`,
`systemctl`, `getcap` in the verified image).

### G1–G3. podman `/usr/bin/podman`, `/usr/libexec/podman/quadlet`, `/usr/libexec/podman/rootlessport` — **update package**

- Highest severity: **Critical** (CVE-2026-78663 stdlib; podman binary also GO-2026-6612 via x/net).
- Fixed build `podman-6.2.0-1.fc45` is in Fedora 45 **stable**; the next base-image pick clears
  the 12 stdlib CVEs, the x/net family (v0.61.0 ≥ 0.60.0 — except GO-2026-6860, see below),
  x/mod, x/text, grpc and klauspost/compress advisories, and GHSA-4hq8-gpf5-8p68
  (self-module fixed at 6.0.0; shipped pseudo-version predates the 6.0.0 tag).
- Reachability notes: podman is a CLI on user invocation with all systemd units disabled;
  rootlessport starts only for rootless containers with published ports; **quadlet is
  DEFAULT-EXPOSED** (runs every boot/login as a system/user generator, parsing local quadlet
  files, no network input). Quadlet's 13 advisories are stdlib + self-module: cleared by the
  update; generator input is local files, so the pre-update exposure was accepted-risk-grade.
- **Residual after update (re-scan before stable):** GO-2026-6860 (x/net, High, fix 0.62.0 >
  vendored 0.61.0), GHSA-mgcc-cww5-fp2q (go-jose, High, fix 4.1.6 > vendored 4.1.5), and
  GO-2026-5932 (x/crypto, severity Unknown, fix is a trunk pseudo-version > v0.58.0).
  These need a Fedora maintainer bump or an explicit accepted-risk entry on stable.

### G4. skopeo `/usr/bin/skopeo` — **update package**

- Highest severity: **Critical** (same stdlib + x/net 6612/6603/6610/6611/6617 set).
- Fixed build `skopeo-1.25.1-2.fc45` stable (same Bodhi update as podman); x/crypto 0.58.0
  clears GO-2026-6303/-6354/-6355, x/text 0.43.0 clears GO-2026-6629, grpc 1.83.2 clears all
  three grpc GHSAs. Same residuals as podman (x/net GO-2026-6860, go-jose, GO-2026-5932).
- Reachability note: "CLI run on user invocation; the RPM ships no systemd units." skopeo is
  an HTTP/2 *client* against registries; the Critical is server-side. Acceptable until the
  base picks the new build.

### G5. toolbox `/usr/bin/toolbox` — **accept risk (with a rebuild request; see caveats)**

- Highest severity: **Critical** (CVE-2026-78663 stdlib via go1.27rc2 toolchain).
- **No newer Fedora 45 build exists** (0.3-7.fc45 is current), so `update package` is not
  available. The Critical requires an HTTP/2 server role; toolbox is a CLI with no systemd
  units and no setuid/caps, so there is no attacker path that clears the advisory's
  precondition → accept risk.
- Residual Highs (x/mod 0.20.0, x/text 0.21.0, stdlib×11) are also accept-risk on the same
  reachability logic, but every one of them disappears with a plain **rebuild against
  golang-1.27.4** (vendored x/mod/x/text come from the module cache at build time; a
  packager re-release would likely also refresh them — unverified). Recommend opening a
  Fedora rebuild request rather than carrying a Critical into stable indefinitely.
  **Uncertainty:** if stable policy forbids shipping any unfixable Critical, this group
  escalates to block-by-policy, not block-by-exploit.

### G6–G8. go-l2tp `/usr/bin/kl2tpd`, `/usr/bin/kpppoed`, `/usr/bin/ql2tpd` — **accept risk (rebuild request; weakest evidence)**

- Highest severity: **Critical** (stdlib CVE-2026-78663 on go1.27rc2; x/net GO-2026-6612 on
  the very old vendored v0.15.0, which additionally carries 9 High x/net advisories
  including GHSA-4374-p667-p6c8 and GO-2026-4918/-5026/-5942 — some of which predate
  0.17.0/0.53.0/0.55.0/0.56.0 fix lines, i.e. the daemon vendors a two-year-old x/net).
- **Bodhi has zero Fedora 45 go-l2tp updates**; no `update package` path exists.
- Reachability notes (from triage): "go-l2tp ships no systemd units; required only by
  NetworkManager-l2tp-1.52.6-1.fc45"; kl2tpd is "started only when a user activates an L2TP
  VPN"; kpppoed and ql2tpd are "not started by default". No setuid/caps. The VPN connection
  itself is user-initiated to a configured gateway.
- **Why accept risk and not block:** the Critical is HTTP/2-server-only and these daemons do
  not terminate HTTP. **Explicit uncertainty:** the older High x/net advisories (0.15.0
  vendored) were not individually checked for client-side/parser reachability from the L2TP
  control channel; go-l2tp's x/net use is expected to be limited to context/idna on dial
  paths. If any of GO-2026-4918/-5026/-5942/GHSA-4374 turns out to hit `http2`/`html` code
  these daemons load, kl2tpd (user-activated, parses peer messages) would deserve a rebuild
  request treated as a stable gate. Also note: stable images that install NetworkManager-l2tp
  carry this permanently — filing a go-l2tp FTBFS-style rebuild bug upstream is the real fix.

## 5. Recommendation tally (per group)

| Recommendation | Groups |
|---|---|
| update package | 4 (podman×3, skopeo) |
| accept risk | 4 (toolbox, kl2tpd, kpppoed, ql2tpd) |
| block | 0 |

No group meets the block definition (network-facing or privileged **and** exploitable): no
flagged binary is setuid/cap-raised, none listens on the network by default, and the single
Critical is an HTTP/2-server bug unreachable in all eight binaries' shipped roles.

## 6. Caveats and follow-ups for the stable gate

1. Re-scan the candidate built on the `podman-6.2.0-1.fc45` / `skopeo-1.25.1-2.fc45` base: the
   toolchain/module inference above is timestamp+go.mod based, not buildroot-verified.
   Expected survivors: GO-2026-6860 (x/net High), GHSA-mgcc-cww5-fp2q (go-jose High),
   GO-2026-5932 (x/crypto Unknown) — decide accepted-risk entries for those on stable now.
2. The toolbox and go-l2tp Criticals are accepted on **role reachability**, not absence of a
   fix, and have no Bodhi path; open Fedora rebuild requests so the stable exception
   (expiry 2026-12-16) is not simply re-issued forever.
3. Exceptions expire 2026-12-16 and were scoped to testing; every recommendation here needs
   re-affirmation with per-CVE language for the stable policy (the kernel `linux_kernel_any`
   entries are out of scope of this analysis and still block stable per their own triage).
4. Severity strings, fixed versions and exposure notes come from the two triage MD tables;
   installer_live and workstation_payload MDs are identical apart from the title, and core's
   table is the workstation table minus the go-l2tp rows (verified).
