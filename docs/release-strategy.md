# Release Strategy: Fedora Versions and Updates

This document separates the current release contract from the longer-term branch lifecycle decision recorded on 2026-09-25. Proposed branch automation below is not a claim that it has been deployed.

- [Current state](#current-state)
- [Candidate approval contract](#candidate-approval-contract)
- [Stable release runbook](#stable-release-runbook)
- [Release models: Bluefin](#how-universal-blue-bluefin-does-it) and [Fedora](#how-fedora-itself-does-it)
- [Options considered](#options-considered)
- [Longer-term lifecycle decision](#longer-term-lifecycle-decision)
- [Lifecycle implementation phases](#lifecycle-implementation-phases)

## Current state

- Testing builds on `main`; stable builds on protected `release/<Fedora>` branches listed in `STABLE_LINES` in `config/releases.env` on `main`.
- Channels: `testing` (`testing-45.X`, `testing-45`, `testing`) and `stable` (`45.X`, `45`, `latest`). See the [stable release runbook](#stable-release-runbook) for the approval gate and tag rules.
- Installed systems follow the image's `UPDATE_CHANNEL` through a Fedora-pinned tag (`testing-45` or `45`).
- The image enables `bootc-fetch-apply-updates.timer` with a drop-in that runs `bootc upgrade` without `--apply`. Updates are staged for the next reboot, not applied through a forced restart. Metered connections are excluded. Runtime behavior still needs confirmation on the installed system.

## Candidate approval contract

- Validation builds have read-only permissions, require no publishing secrets, and transfer images between jobs as artifacts rather than assuming runner-local storage is shared.
- Privileged publication is restricted to authorized repository runs. Candidate identities must distinguish retries; subsequent operations use the captured image digest, not a mutable tag lookup.
- Verify the staged candidate against `shared/release/candidate.pub`. Public images and download checksums use the separate official key, `shared/trust/etc/pki/containers/luminusos.pub`. Cosign 2 is retained for compatibility with containers/image.
- Bind SBOM, vulnerability results, provenance, boot logs, and installer evidence to the source commit, image digests, and artifact hashes. Exceptions to the vulnerability policy require a specific package/finding, justification, and expiry.
- Generate and sign a checksum manifest for downloadable artifacts. Publish the detached signature alongside the manifest; an unsigned checksum table in release notes is insufficient.
- Require real Sirius installation and first-boot evidence. qcow2 boot screenshots alone do not satisfy this gate. Verify expected-key updates, unsigned and incorrect-key rejection, update and rollback, live/installed separation, and observed host security state.
- Fedora does not publish a verifiable signature for `fedora-bootc`. Building on it is an accepted risk recorded in `shared/release/base-trust-risk.json`, with an owner and an expiry at most 30 days after acceptance. `release_policy.validate_base_risk` accepts only a digest-pinned reference from the recorded repository and Fedora release while the record is in force. The scope is the repository and release, not one digest, so every digest the detector picks in that window is covered; renewal is a reviewed edit, never automatic. The record does not replace verification of LuminusOS image signatures.
- Missing, failed, untrusted, mismatched, or stale evidence blocks promotion. Local mocks validate control flow, not the runtime guarantees represented by that evidence.
- Only after approval may branch and channel tags move using digest-preserving copies. Stable must retain the approved payload digests. Installer and artifact evidence must describe the exact live root and bytes being released.

Detached blob signatures use the pinned public key without a transparency-log dependency. They are created with `cosign sign-blob --tlog-upload=false` and verified with `--insecure-ignore-tlog` **and the expected `--key`**. This skips Rekor inclusion checking, not cryptographic signature or key verification. It avoids treating private installation evidence as a transparency-log publication requirement. Image-signature verification is a separate operation.

After downloading the checksum manifest, its signature, and the referenced files while preserving their relative paths, verify them with Cosign 2 and GNU coreutils:

```bash
cosign verify-blob --key shared/trust/etc/pki/containers/luminusos.pub \
  --signature SHA256SUMS.sig --insecure-ignore-tlog SHA256SUMS
sha256sum --check SHA256SUMS
```

Do not replace the public key with one supplied alongside an untrusted download. Obtain it through the trusted repository or an already trusted installation.

The local implementation environment has not demonstrated installation, update/rollback, signature enforcement, SELinux, firewall, or Secure Boot. These remain release acceptance requirements, not implied successes. Do not bypass them to make a workflow complete.

### Installation validation runner

`installation-validation.yml` runs through `workflow_dispatch`, either from a release chain or by hand, on the line that produced the candidate (`main` for testing, `release/<Fedora>` for stable), on a GitHub-hosted `ubuntu-26.04` runner with KVM and vhost-vsock, in the `candidate-staging` environment.

For a full candidate, the driver boots the verified ISO with Secure Boot enforced (OVMF with the Microsoft keys enrolled), installs it with `sirius run-playbook`, and boots the installed disk without the ISO. For an image candidate, validation builds a disposable disk from the newest signed published release of the line, switches it to the candidate with bootc, and runs the installed-system checks. The disposable disk is never published. The validation run records the checkout commit as `runner_sha`.

Trust and update checks use a disposable fixture: images derived from the candidate workstation image with one marker layer, served by a local registry and signed with an ephemeral key that exists only for the run. The fixture proves that signature policy is enforced and that bootc can update and roll back; it does not prove official signing, which promotion verifies. Full validation must not replace installation with a qcow2 boot. For full candidates, the qcow2 boot smoke test logs into the booted disk over vsock and requires a running system with no failed units, `/var` as the bootc stateroot, a successful `systemd-random-seed.service` and no relabel from `restorecon -n`. Neither path disables signature checking or reuses VM state between runs. A missing prerequisite fails the run.

Both kinds require `first_boot`, `expected_key`, `unsigned_rejected`, `foreign_key_rejected`, `update`, `rollback`, `selinux_enforcing`, `firewall`, `no_tcp_ssh`, and `secure_boot`. Full adds `sirius_install` and `live_isolation`; image adds `base_boot` and `upgrade_from_published`. `no_tcp_ssh` fails when the installed system listens on any non-loopback TCP address, through a process or a systemd socket unit, or offers SSH on TCP at all, including loopback; the harness itself connects over vsock. Each JSON receipt records `name`, the observed `command` argument list, `exit_code`, timezone-aware `started_at`/`finished_at`, a relative nonempty `log`, its `sha256`, and `binding` matching `release_pipeline.binding(candidate)`. Do not execute command strings read from receipts. A successful rejection test records the test harness's success after observing rejection, not the unsigned update command's exit status as if the update should succeed.

Dispatch the installation workflow with the successful preparation run's `candidate_run_id`. It verifies the signed candidate, invokes the driver without signing secrets, checks all receipts and log hashes, and only then signs `validation.json`. The uploaded `installation-validation` artifact contains that document, its detached signature, and the receipts/logs. Promotion checks the GitHub run identity as well as the signature and exact candidate binding.

### Preparing and resuming a testing release

Scheduled testing and stable releases publish the signed core and workstation OCI images consumed by `bootc upgrade`, plus an evidence-only GitHub release. They do not build the installer, ISO or qcow2, write to R2 or SourceForge, or change `<channel>/latest.json`. The download index and installation media stay at the last full release. Prepare new full releases only by manually dispatching `publish.yml` with `artifacts=full`.

`testing-release-chain.yml` follows successful Auto Testing runs on `main`. For a scheduled candidate it verifies the signed `release-candidate` and requires `release_kind=image` before dispatching validation. After successful validation it resumes `publish.yml` with both run IDs and waits for publication. A failure in either workflow fails the chain. No candidate, a newer candidate, or an already published version can leave the chain with nothing to publish. The chain checks the exact version tag before validation and again before publication: overlapping builds can choose the same sequence, but promotion cannot overwrite an immutable version tag.

Manual **Auto Testing** still invokes the same chain when it produces a candidate, but new runs also prepare images only. The scheduled kind check does not change how the chain handles a candidate from an older manual Auto Testing run. A direct `publish.yml` preparation does not trigger this chain; use the following steps to validate and resume it yourself.

1. Dispatch `publish.yml` on `main` with `channel=testing` and leave `candidate_run_id` and `validation_run_id` empty. Select `artifacts=full` for installation media or leave `artifacts=auto` for images only. Preparation produces a signed `release-candidate` without moving public tags.
2. Run `installation-validation.yml` with that preparation's `candidate_run_id`. Retain the successful validation run ID.
3. Resume `publish.yml` with the same channel and both `candidate_run_id` and `validation_run_id`. Leave `artifacts` at `auto` to use the signed kind. The workflow verifies the original candidate and matching validation instead of rebuilding them. Only a full release publishes downloads.

The official publishing credentials (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `SF_USER` and `SF_SSH_KEY`) are Environment secrets, not repository secrets. The testing `release` job reads them from `testing-publish`, which deploys only from `main`. `release-stable` reads them from `stable`, which deploys only from `release/<Fedora>` and requires a reviewer. No other job and no other workflow reads them, so a testing run cannot sign or publish stable content, and candidate preparation only ever has the isolated candidate key.

### Diagnostic Auto Testing builds

The manual Auto Testing dispatch offers an opt-in diagnostic bypass, disabled by default. Use it only to investigate container builds while waiting for upstream package fixes. Scheduled runs and ordinary publication remain strict. This option is restricted to a fresh testing build from Auto Testing on `main`; it is not available for stable preparation or resumption.

A bypassed execution cannot push candidate images or sign them with the official key. The publishing job is skipped, along with its candidate scans and the ISO/qcow2 and boot jobs that require its registry digests. Container builds and their Actions artifacts remain available; those artifacts are not private staging or successful scan evidence. Diagnostic scanning and packaging without public image writes require a separate artifact transport.

A bypassed execution never produces a signed `release-candidate`. It cannot be used for installation approval, channel promotion, stable preparation, or release publication through this workflow. To obtain a promotable candidate, run a new strict preparation and satisfy all ordinary gates; clearing a checkbox during resumption cannot rehabilitate a bypassed build.

Full publication requires the SourceForge and R2 credentials as well as the official signing key. GitHub release assets contain `SHA256SUMS`, its signature, and `evidence.tar.gz`; the full release's ISO and qcow2 are published through R2 and SourceForge. Publication spans external services and is not an atomic transaction: inspect completed steps before retrying an interrupted release.

## Stable release runbook

[Prepare and validate](#prepare-and-validate) · [Approve](#approve) · [Reject](#reject) · [Resume](#resume) · [Revert](#revert) · [Risk exceptions](#risk-exceptions)

### Prepare and validate

**Scheduled.** Daily [Auto Stable](../.github/workflows/auto-stable.yml) runs on `main` and checks each active `release/<Fedora>` line independently. A line without a published stable release fails before a build, with a command to prepare its first full release. Other line jobs continue. The [branch detector](../.github/scripts/workflow/stable_detect.py) compares the live Fedora bootc digest with the base label on the public workstation line tag. It requests image-only preparation if the digests differ or the image version lacks a Git tag, unless another run is already in flight. The `main` run verifies that the scheduled candidate is signed and image-only, dispatches validation and publication on the same branch, and stops at the `stable` Environment for approval.

Auto Stable on `main` dispatches the workflows of each `release/<Fedora>` branch, so a release line only gets image-only updates once its branch carries the same `publish.yml`, `installation-validation.yml`, detector and release scripts as `main`. Backport every change to these files to each active release branch before relying on its schedule. Until then the line fails closed: a full candidate from an older branch is refused by the image-kind check on `main`, and nothing is published.

**Manual.** The first stable release of a Fedora line must be a full release. In **Image Publication** (`publish.yml`), select the active `release/<Fedora>` branch, set `channel=stable` and `artifacts=full`, and leave both run IDs blank. For Fedora 45:

```sh
gh workflow run publish.yml --repo luminusOS/images --ref release/45 \
  -f channel=stable -f artifacts=full
```

On an established line, leave `artifacts=auto` to prepare images only. A manual dispatch of **Auto Stable** on `main` still runs the chain for all active lines; dispatching it directly on a release branch still only runs detection and preparation. Both now request images only. Leave `orchestrator_run_id` blank when dispatching directly.

1. Find the successful preparation run that uploaded `release-candidate`. Both kinds stage and scan core and workstation; full also stages and scans the installer and records ISO, qcow2 and boot-smoke evidence.
2. Dispatch **Installation Validation** (`installation-validation.yml`) on the same branch with that `candidate_run_id`. Wait for it to succeed. Full validation installs the candidate ISO with Sirius; image validation switches a disposable disk built from the newest signed published release to the candidate. Keep the validation run ID and its signed `installation-validation` artifact.
3. [Resume publication](#resume) with those two IDs. The `release-evidence` job verifies their binding and uploads the approval summary. `release-stable` waits for a required reviewer in the `stable` GitHub Environment. Do not dispatch another publication for the same line while one is waiting.

If installation validation fails, stop without dispatching publication. If a step in `release-evidence` fails, the publication run ends before approval. In either case, do not resume the failed candidate: fix the cause, prepare a new candidate, and validate it.

### Approve

Only the repository owner approves stable deployments. Agents must never approve or publish stable, accept risks, or read secret values. Check that the `stable` Environment requires the owner as reviewer, allows only the active release branches and disallows admin bypass. These are GitHub settings, not implied by the workflow YAML.

Before choosing **Review deployments** → **stable** → **Approve and deploy** in the publication run:

1. Read `approval-summary.json` in the `stable-approval-summary` artifact and compare it with the run summary. Confirm the candidate run and source commit, version, Fedora base digest, and exact image digests. For full, confirm the installer digest; for image, confirm the published base.
2. Check the preparation run's `candidate-scans` against the summary. Confirm each scan decision and policy SHA-256, and review all applied exceptions (advisory, package and version, classification, owner and UTC expiry), exclusions and the unsigned-base risk record. Do not approve missing, mismatched or expired evidence.
3. Open the matching **Installation Validation** run. Confirm it ran on the same release line for that candidate, succeeded without skipping the required job, and produced signed `validation.json` and receipts in `installation-validation`. A boot smoke test is not installation validation.

After approval, [`release-stable`](../.github/workflows/publish.yml) re-verifies the candidate evidence and regenerates the summary using the current branch tip's policy and risk records. A changed summary or an expired record blocks publication before public writes. Promotion copies the approved digests without rebuilding: core and workstation get version and Fedora-line tags, and only `LATEST_RELEASE` moves `latest`. Image publication rechecks the pinned base and creates an evidence-only GitHub release. Full publication also moves installer tags with the `-iso` suffix and publishes downloads to R2 and SourceForge. Both use the exact version as the GitHub release tag (no `v` prefix).

### Reject

Use `gh` authenticated with repository read access, `skopeo`, and `curl`.

1. Run the read-only checks below, including the **Before rejection** index request, and record the results.
2. In the waiting publication run, choose **Review deployments** → **stable** → **Reject**, and record why. In the `release-stable` job (**Promote approved stable candidate**), confirm that **Verify and promote immutable images** and **Publish verified downloads and release** are skipped or not started.
3. Repeat the read-only checks, this time using the **After rejection** index request, and compare the results. Rejecting a pending deployment does not undo writes from an earlier attempt.

Set `version` to the candidate's build version from the summary (the value below is an example), and `fedora` to its Fedora line.

```bash
repo=luminusOS/images
fedora=45
version=45.20261118.1
for image in luminusos luminusos-workstation; do
  for tag in "$version" "$fedora" latest; do
    printf '%s:%s\n' "$image" "$tag"
    skopeo inspect --format '{{.Digest}}' "docker://ghcr.io/luminusos/$image:$tag"
  done
done
for tag in "$version-iso" "$fedora-iso"; do
  printf 'luminusos-workstation:%s\n' "$tag"
  skopeo inspect --format '{{.Digest}}' \
    "docker://ghcr.io/luminusos/luminusos-workstation:$tag"
done
gh release view "$version" --repo "$repo" --json tagName,isDraft
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://download.luminusos.org/stable/$version/SHA256SUMS"
```

For a previously unpublished candidate, expect missing version tags, no GitHub release (including a draft when checked with repository access), and HTTP `404` for the checksum manifest. The Fedora-line and `latest` tag digests must be unchanged, or still absent. Authentication, networking and server errors do not prove absence.

```bash
# Before rejection:
curl -sS -o stable-latest.before.json -w '%{http_code}\n' \
  https://download.luminusos.org/stable/latest.json
# After rejection:
curl -sS -o stable-latest.after.json -w '%{http_code}\n' \
  https://download.luminusos.org/stable/latest.json
```

Expect `404` both times if there was no index. If both responses are `200`, `cmp stable-latest.before.json stable-latest.after.json` should find no difference. A change in HTTP status (for example, `200` → `404`) also counts as a change. If anything has changed, check for another publication or a previous partial attempt before attributing the change to this run.

### Resume

If validation succeeded but publication did not start or needs another attempt, first check that no `publish.yml` run on the same release branch is active. Substitute the candidate's branch for `release/45`:

```bash
gh api --paginate 'repos/luminusOS/images/actions/workflows/publish.yml/runs?branch=release%2F45&per_page=100' \
  --jq '.workflow_runs[] | select(.status == "queued" or .status == "in_progress" or .status == "waiting" or .status == "pending" or .status == "requested") | .html_url'
```

If the check returns a run URL, wait for that run to finish or resolve its waiting deployment before dispatching another run. If the check fails, do not dispatch. Otherwise, dispatch `publish.yml` on the same release branch with both original run IDs. This fetches and verifies existing evidence rather than rebuilding; the new publication run still needs approval. Substitute the original numeric IDs:

```bash
gh workflow run publish.yml --repo luminusOS/images --ref release/45 \
  -f channel=stable -f candidate_run_id=123456789 -f validation_run_id=123456790
```

- The scheduled chain checks the exact Git tag for the version before validation and again before publication, and skips candidates superseded by a newer successful Auto Stable candidate on that line. Builds choose their sequence number from existing Git tags, so overlapping builds can pick the same version. The publisher separately refuses to overwrite an OCI version tag with a different digest. If another candidate owns the version, prepare and validate a fresh candidate; do not delete tags to make room.
- After a partial publication, inspect which destinations changed. Retry only the same candidate with its matching validation, and do not resume an older candidate after a newer release has advanced channel tags. Publication is not atomic across GHCR, SourceForge, R2 and GitHub.
- Before moving image tags, the publisher preflights an existing GitHub release (its target commit, title, draft state and assets) and the public versioned `SHA256SUMS`; conflicts detected by those checks fail before public writes.
- [`gh release create` with assets](https://cli.github.com/manual/gh_release_create) creates a draft, uploads the assets, then publishes it. An ordinary upload error deletes the draft, but a runner cancellation or a killed process before the last step can leave one. On retry, the [publisher](../.github/scripts/workflow/release_publish.py#L1215) checks that the draft matches the candidate, uploads only missing assets and then publishes it; a draft with other contents stops the retry before any write.

### Revert

On an affected installed system with a previous deployment available, run `sudo bootc rollback` and reboot into that deployment. This is local recovery; it does not change the public stable channel or prevent it offering the bad version again.

There is no automated withdrawal or channel rollback. The maintainer should identify the bad version and digests, warn users in the GitHub release notes not to install or update to that version, and provide the local rollback instructions. A warning or a GitHub-only withdrawal does not remove GHCR tags or mirrored downloads. Prepare a fixed release on the same release line, validate it and publish it as a new version through the normal approval gate. Check the Fedora-line tags and, where applicable, `latest`. For a full replacement on `LATEST_RELEASE`, also check `stable/latest.json`. Do not move or delete tags by hand.

### Risk exceptions

- **Testing:** renew still-needed exceptions before **2026-12-16 00:00 UTC**. See `shared/release/exceptions/*-testing-45.json`, `shared/release/base-trust-risk.json` and `shared/release/flatpak-scan-risk.json`.
- **Stable:** the current records expire **2026-12-18 00:00 UTC**. See `shared/release/exceptions/*-stable-45.json`, `shared/release/base-trust-risk-stable.json` and `shared/release/flatpak-scan-risk-stable.json`.

Review renewals on the appropriate branch; do not carry testing exceptions into stable or extend records automatically. Update workflow policy hash pins when policy bytes change. If refreshed records change the signed scan evidence or approval summary, do not reuse the old approval; prepare and validate against the new policy.

### Existing qcow2 installs with separate `var` or `home` subvolumes

New qcow2 disks have a single Btrfs `root` subvolume; `/var` and `/var/home` are the ostree stateroot directories inside it, as on Sirius installs. Older published disks mounted separate subvolumes, and their mount units live in `/etc`, so updating the image neither removes them nor migrates data:

- Disks built before the `/var/home` fix mount a `var` subvolume at `/var` and try to mount a `home` subvolume at `/home`, a symlink to `var/home`. `home.mount` fails on every boot.
- Disks built after it mount `var` at `/var` and `home` at `/var/home`. The `var` subvolume starts empty with an unlabeled root, and `systemd-random-seed.service` can fail on SELinux denials.

Diagnose on a clone of the disk before touching the original:

```sh
systemctl is-system-running; systemctl --failed
systemctl show home.mount var.mount var-home.mount -p FragmentPath -p ActiveState
findmnt --target /var; findmnt --target /var/home
restorecon -n -v /var /var/lib /var/home        # prints labels that differ from policy
```

Back up the active `/var` and all home data before changing mounts. That means the `/var/home` you see now and every subvolume, which you can reach read-only by mounting the top level, for example `sudo mount -o ro,subvolid=5 "$(findmnt -no SOURCE --target /var | sed 's/\[.*//')" /mnt`.

Do not disable `var.mount`. It would show the stateroot's own, different `/var` and hide the state that lives on the `var` subvolume.

For the failed `home.mount` on disks built before the `/var/home` fix, the conservative repair removes only that unit and leaves the visible data in `/var/home`:

```sh
sudo systemctl disable home.mount
sudo mv /etc/systemd/system/home.mount /root/home.mount.disabled
sudo find /etc/systemd/system -name home.mount -type l -delete   # leftover enablement links
sudo systemctl daemon-reload
sudo systemctl reset-failed home.mount
```

Never delete `/var/home`, the `var` subvolume or the `home` subvolume. None of these steps has been tested on a clone of an affected install yet.

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

## Longer-term lifecycle decision

This is the historical design, not the stable release procedure. The implemented branch names and scheduled workflow are described in the [stable release runbook](#stable-release-runbook).

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
- The floating tags `latest` and `testing` move only when publishing `LATEST_RELEASE`. The download index `<channel>/latest.json` moves only for a full release on `LATEST_RELEASE`. A full release on an older supported line uploads its downloads and prunes only that line's previous versions.
- Stable promotion is refused while the Fedora base is still a prerelease (`fedora-bootc:latest` older than N). The first LuminusOS stable ships with Fedora 45 GA.

## Lifecycle implementation phases

1. **Staged automatic updates:** a timer runs `bootc upgrade` every 6 hours without `--apply`. The update is ready for the next boot and the machine is never rebooted by it.
2. **Release metadata and guards:** `config/releases.env`, the floating-tag guard and the stable-after-GA guard.
3. **Scheduled rebuilds:**
   - A weekly workflow on `main` dispatches a signed container publish (no ISO) for every supported branch.
   - `update-fedora.yml` is removed; the live digest made it obsolete (done for `main` by `auto-testing.yml`).
4. **Branch plumbing:**
   - CI and Dependabot (`target-branch`) cover `f*`, with branch protection for `main` and `f*`.
   - A `docs/release-lifecycle.md` runbook covers branching at GA, backports and EOL.
   - `f45` is created at Fedora 45 GA.
5. **New-version notification:** a user timer checks whether `<N+1>` is supported and offers `bootc switch` to it. This replaces what GNOME Software does from ostree refs on Silverblue.
6. **EOL bridge:** a manual workflow that, at Fedora N EOL, copies the N+1 images onto the `<N>` and `testing-<N>` tags, so remaining systems move on at their next update.
