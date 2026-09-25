# Release Strategy: Fedora Versions and Updates

Status: **decided, not implemented**. Written 2026-09-25 to decide how LuminusOS handles Fedora major versions (e.g. 45 → 46) and how updates reach installed systems.

## Current state

- One branch (`main`); `DEFAULT_FEDORA_VERSION` in `config/versions.env` selects the Fedora release.
- Channels: `testing` (`testing-45.X`, `testing-45`, `testing`) and `stable` (`45.X`, `45`, `latest`), published manually through the `publish` workflow. Stable promotes an existing testing build without rebuilding.
- Installed systems follow `UPDATE_CHANNEL` (currently `testing`), through a Fedora-pinned tag (`testing-45`).
- Nothing applies updates automatically: `bootc-fetch-apply-updates.timer` is disabled and nothing replaces it.

## How Universal Blue (Bluefin) does it

Checked against `ublue-os/bluefin` workflows and Justfile, September 2026:

- **Single branch.** No branch per Fedora version. The Fedora version is derived from upstream (the `fedora-coreos:stable` image label), not hard-coded.
- **Streams:**
  - `latest`: built daily; jumps to Fedora N+1 as soon as it ships.
  - `stable` (default): rebuilt automatically every Tuesday; moves to N+1 only when Fedora CoreOS does, about two weeks after release.
  - `gts`: formerly N-1, now only an alias of `stable`.
- **No N-1 maintenance.** Users migrate automatically. Safety comes from the upgrade delay plus `bootc rollback`.
- **Automatic updates:** checked every 6 hours, staged, applied on the next reboot.

## How Fedora itself does it

Checked September 2026, when Fedora 44 is the current release, 45 is Branched (prerelease) and 46 is Rawhide.

- **Lifecycle:** a release roughly every six months. Each release is maintained until four weeks after release N+2 (about 13 months), so two stable releases are always supported at once.
- **Image tags on quay:**
  - `fedora-bootc` and `fedora-silverblue` publish per-version tags (`40` … `46`), `latest` (currently **44**, the current GA release) and `rawhide`.
  - `fedora-coreos` publishes only streams (`stable`, `testing`, `next`).
- **Atomic desktops (Silverblue), the model closest to LuminusOS:**
  - Systems follow a version-pinned ref.
  - Major upgrades are user-initiated: GNOME Software shows "Fedora N+1 available" with Download and Restart & Upgrade, or the user runs `rpm-ostree rebase`.
  - The old release keeps receiving updates until EOL; rollback happens from GRUB or `rpm-ostree rollback`.
  - The desktop configuration keeps one branch per release (`main` = Rawhide).
- **Fedora CoreOS (servers):**
  - Systems follow a stream and auto-update through Zincati phased rollouts.
  - Major rebases are automatic and staggered: `next` at the Go decision, `testing` at GA (week 0), `stable` two weeks later.
  - Bluefin copies this model.

Implications for LuminusOS:

- **The current base is Fedora 45 Prerelease.** A LuminusOS stable release should not exist before Fedora 45 GA; until then testing is effectively "branched".
- **The Atomic desktop model fits a desktop OS best.** The version-pinned targets (`testing-45`, `45`) already match it.
- **What LuminusOS lacks to complete that model:**
  - A new-version notification. GNOME Software detects major upgrades from ostree refs, not OCI tags, so LuminusOS needs its own prompt that runs `bootc switch …:<N+1>`.
  - An EOL bridge, so users who ignore the prompt still move on.
  - Scheduled rebuilds for every supported version.
  - Staged background updates.

## Options considered

- **Stream model (CoreOS/Bluefin):** systems follow `testing`/`latest` and migrate automatically when a new major version is promoted. Simpler to run, but users cannot choose when to migrate. Rejected.
- **Matrix on one branch:** one pipeline builds every supported version. Cheaper, but version-specific differences pile up as conditionals. Rejected in favour of Fedora's own layout.

## Decision

LuminusOS follows the **Fedora Atomic desktop model** with **one branch per Fedora release**, like Fedora's own Atomic desktop configuration.

### Branches

| Branch | Role | Publishes |
| --- | --- | --- |
| `main` | Next Fedora release (Branched/Rawhide) | `testing-<next>` only; never stable |
| `f45`, `f46`, … | One per supported Fedora release | `testing-<N>`, and `<N>` after stable promotion |

- Create `fNN` from `main` when Fedora NN reaches GA; `main` then moves to NN+1.
- Fixes land on `main` and are backported with `git cherry-pick -x`.
- A branch is retired at Fedora NN EOL, four weeks after NN+2 GA.

### Release metadata

`config/releases.env` on `main` is the single source of truth:
- `SUPPORTED_RELEASES="45 46"`
- `LATEST_RELEASE=46`, the newest GA release

Branch workflows read it from `origin/main`.

### Rules

- Installed systems follow their version tag (`testing-<N>` or `<N>`), as today.
- The floating tags `latest` and `testing` move only when publishing `LATEST_RELEASE`, so they never go backwards.
- Stable promotion is refused while the Fedora base is still a prerelease (`fedora-bootc:latest` older than N). The first LuminusOS stable ships with Fedora 45 GA.

## Implementation phases (one commit each)

1. **Staged automatic updates:** a timer runs `bootc upgrade` every 6 hours without `--apply`. The update is ready for the next boot and the machine is never rebooted by it.
2. **Release metadata and guards:** `config/releases.env`, the floating-tag guard and the stable-after-GA guard.
3. **Scheduled rebuilds:**
   - A weekly workflow on `main` dispatches a signed container publish (no ISO) for every supported branch.
   - `update-fedora.yml` is removed; the live digest made it obsolete.
4. **Branch plumbing:**
   - CI and Dependabot (`target-branch`) cover `f*`, with branch protection for `main` and `f*`.
   - A `docs/release-lifecycle.md` runbook covers branching at GA, backports and EOL.
   - `f45` is created at Fedora 45 GA.
5. **New-version notification:** a user timer checks whether `<N+1>` is supported and offers `bootc switch` to it. This replaces what GNOME Software does from ostree refs on Silverblue.
6. **EOL bridge:** a manual workflow that, at Fedora N EOL, copies the N+1 images onto the `<N>` and `testing-<N>` tags, so remaining systems move on at their next update.
