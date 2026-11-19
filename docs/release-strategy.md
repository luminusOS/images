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

`installation-validation.yml` runs only through manual dispatch on `main` or a `release/<Fedora>` branch, and only on the line that produced the candidate (`main` for testing, `release/<Fedora>` for stable), on a GitHub-hosted `ubuntu-26.04` runner with KVM and vhost-vsock, in the `candidate-staging` environment. The job token gets `packages: read` so it can pull the private candidate; it is used only in the staging step, through a temporary authfile that is removed before the VM starts, and the driver and signing steps never see it.

The driver is `.github/scripts/workflow/validation_driver.py`, reviewed like any other repository code and run from the checkout of the dispatching commit on that line, which is recorded as `runner_sha`. It boots the verified candidate ISO with Secure Boot enforced (OVMF with the Microsoft keys enrolled), installs it with `sirius run-playbook`, boots the installed disk without the ISO and runs every check over SSH on AF_VSOCK, with a per-run key passed as the `ssh.authorized_keys.root` SMBIOS credential. Neither image changes for this.

Trust and update checks use a disposable fixture: images derived from the candidate workstation image with one marker layer, served by a local registry and signed with an ephemeral key that exists only for the run. Only the disposable VM learns that key, under its own repository scope, after `expected_key` has confirmed that the official policy, registry configuration and public key match the repository. The fixture proves that signature policy is enforced and that bootc can update and roll back; it does not prove official signing, which promotion verifies. The driver must not replace installation with a qcow2 boot, disable signature checking or reuse VM state between runs. A missing prerequisite fails the run.

The required receipt names are `sirius_install`, `first_boot`, `live_isolation`, `expected_key`, `unsigned_rejected`, `foreign_key_rejected`, `update`, `rollback`, `selinux_enforcing`, `firewall`, `no_tcp_ssh`, and `secure_boot`. `no_tcp_ssh` fails when the installed system listens on any non-loopback TCP address, through a process or a systemd socket unit, or offers SSH on TCP at all, including loopback; the harness itself connects over vsock. Each JSON receipt records `name`, the observed `command` argument list, `exit_code`, timezone-aware `started_at`/`finished_at`, a relative nonempty `log`, its `sha256`, and `binding` matching `release_pipeline.binding(candidate)`. Do not execute command strings read from receipts. A successful rejection test records the test harness's success after observing rejection, not the unsigned update command's exit status as if the update should succeed.

Dispatch the installation workflow with the successful preparation run's `candidate_run_id`. It verifies the signed candidate, invokes the driver without signing secrets, checks all receipts and log hashes, and only then signs `validation.json`. The uploaded `installation-validation` artifact contains that document, its detached signature, and the receipts/logs. Promotion checks the GitHub run identity as well as the signature and exact candidate binding.

### Preparing and resuming a testing release

Testing releases run without a person once Auto Testing produces a candidate. `testing-release-chain.yml` runs when Auto Testing succeeds on `main`. If that run uploaded a signed `release-candidate`, it dispatches `installation-validation.yml` for it, waits for that exact run, and on success dispatches `publish.yml` with both run IDs and waits for the publication as well. A failed validation or publication fails the chain run. A chain run also succeeds without publishing when Auto Testing produced no candidate, or when a newer Auto Testing candidate appeared in the meantime; that newer candidate goes through its own chain. A candidate is also skipped when the testing tag for its version already exists. A build numbers its version from the tags present when it starts, so two overlapping same-day builds can share a number; once one is released, promotion would refuse to move that tag to the other's bytes. The chain reads the version from the candidate's scanned image label, checks the exact tag before validation and again before publication, and the next build takes the following number. The run log states which of these happened. A chain that runs out of time fails and names the `publish.yml` command that resumes the release by hand. The chain only decides when to continue: the dispatched workflows verify the candidate, the validation and their runs exactly as they do for a manual release. The manual steps below remain available for reruns and for candidates prepared through `publish.yml`.

1. Dispatch `publish.yml` on `main` with `channel=testing` and leave `candidate_run_id` and `validation_run_id` empty. A successful preparation produces the signed `release-candidate` artifact; it does not move channel tags or publish downloads. Scheduled testing follows the same preparation path.
2. Run `installation-validation.yml` with that preparation's `candidate_run_id`. Retain the successful validation run ID.
3. Resume `publish.yml` with the same channel and both `candidate_run_id` and `validation_run_id`. The workflow downloads and verifies the original candidate and matching validation instead of rebuilding them. It stages signed download evidence, preflights all three image references, promotes tags, and publishes downloads.

The official publishing credentials (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `SF_USER` and `SF_SSH_KEY`) are Environment secrets, not repository secrets. The testing `release` job reads them from `testing-publish`, which deploys only from `main`. `release-stable` reads them from `stable`, which deploys only from `release/<Fedora>` and requires a reviewer. No other job and no other workflow reads them, so a testing run cannot sign or publish stable content, and candidate preparation only ever has the isolated candidate key.

### Diagnostic Auto Testing builds

The manual Auto Testing dispatch offers an opt-in diagnostic bypass, disabled by default. Use it only to investigate container builds while waiting for upstream package fixes. Scheduled runs and ordinary publication remain strict. This option is restricted to a fresh testing build from Auto Testing on `main`; it is not available for stable preparation or resumption.

A bypassed execution cannot push candidate images or sign them with the official key. The publishing job is skipped, along with its candidate scans and the ISO/qcow2 and boot jobs that require its registry digests. Container builds and their Actions artifacts remain available; those artifacts are not private staging or successful scan evidence. Diagnostic scanning and packaging without public image writes require a separate artifact transport.

A bypassed execution never produces a signed `release-candidate`. It cannot be used for installation approval, channel promotion, stable preparation, or release publication through this workflow. To obtain a promotable candidate, run a new strict preparation and satisfy all ordinary gates; clearing a checkbox during resumption cannot rehabilitate a bypassed build.

Configure the publication signing key, SourceForge credentials, and R2 credentials before resumption. GitHub release assets contain `SHA256SUMS`, its signature, and `evidence.tar.gz`; ISO and qcow2 downloads are published through R2 and SourceForge. Promotion and download publication span external services and are not an atomic transaction: inspect completed steps before retrying an interrupted release.

## Stable release runbook

[Prepare and validate](#prepare-and-validate) · [Approve](#approve) · [Reject](#reject) · [Resume](#resume) · [Revert](#revert) · [Risk exceptions](#risk-exceptions)

### Prepare and validate

**Scheduled.** Daily [Auto Stable](../.github/workflows/auto-stable.yml#L1-L59) runs on `main` and dispatches `auto-stable.yml` on each active `release/<Fedora>` branch. The [branch detector](../.github/scripts/workflow/stable_detect.py#L58-L106) compares the live `fedora-bootc:<Fedora>` digest with the base label on the public `luminusos-workstation:<Fedora>` tag. It requests preparation when those digests differ or the published image has no matching Git tag, unless a run that could carry a candidate is already in flight. Preparation pins the detected base digest. The [`main` run](../.github/scripts/workflow/stable_chain.py#L91-L145) waits for preparation, dispatches installation validation and then publication on the same branch, and stops when publication reaches the `stable` Environment. The schedule currently builds full releases, including ISO and qcow2; scheduled image-only updates are a later change.

**Manual.** In Actions, choose **Image Publication** (`publish.yml`), select the active `release/<Fedora>` branch, set `channel=stable`, and leave `candidate_run_id` and `validation_run_id` blank. To run detection instead, dispatch **Auto Stable** on `main` to run the chain for all active lines. Dispatching Auto Stable directly on a release branch runs only detection and preparation; leave `orchestrator_run_id` blank and continue manually if it produces a candidate.

1. Find the successful preparation run that uploaded `release-candidate`. Preparation signs core, workstation and installer images in the private `luminusos-candidates` package, scans them under stable policy, and binds the ISO, qcow2 and boot smoke evidence into the signed candidate.
2. Dispatch **Installation Validation** (`installation-validation.yml`) on the same branch with `candidate_run_id` set to that preparation run ID. Wait for the `installation` job and run to succeed. It installs the candidate ISO with Sirius, boots the installed disk, and checks update, rollback and trust. Keep the validation run ID and its signed `installation-validation` artifact.
3. [Resume publication](#resume) with those two IDs. The `release-evidence` job verifies their binding and uploads the approval summary. `release-stable` waits for a required reviewer in the `stable` GitHub Environment. Do not dispatch another publication for the same line while one is waiting.

If installation validation fails, stop without dispatching publication. If a step in `release-evidence` fails, the publication run ends before approval. In either case, do not resume the failed candidate: fix the cause, prepare a new candidate, and validate it.

### Approve

Only the repository owner approves stable deployments. Agents must never approve or publish stable, accept risks, or read secret values. Check that the `stable` Environment requires the owner as reviewer, allows only the active release branches and disallows admin bypass. These are GitHub settings, not implied by the workflow YAML.

Before choosing **Review deployments** → **stable** → **Approve and deploy** in the publication run:

1. Read `approval-summary.json` in the `stable-approval-summary` artifact and compare it with the run summary. Confirm the candidate run and source commit, version, Fedora base digest, and exact core, workstation and installer digests.
2. Check the preparation run's `candidate-scans` against the summary. Confirm each scan decision and policy SHA-256, and review all applied exceptions (advisory, package and version, classification, owner and UTC expiry), exclusions and the unsigned-base risk record. Do not approve missing, mismatched or expired evidence.
3. Open the matching **Installation Validation** run. Confirm it ran on the same release line for that candidate, succeeded without skipping the required job, and produced signed `validation.json` and receipts in `installation-validation`. A boot smoke test is not installation validation.

After approval, [`release-stable`](../.github/workflows/publish.yml#L635-L694) re-verifies the candidate evidence and regenerates the summary using the current branch tip's policy and risk records. A changed summary or an expired record blocks publication before public writes. Promotion copies the approved digests without rebuilding: core and workstation get version and Fedora-line tags, installer tags append `-iso`, and only `LATEST_RELEASE` moves `latest` on core and workstation. It publishes downloads to R2 and SourceForge and creates a normal GitHub release using the exact version as its tag (no `v` prefix).

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

If validation succeeded but publication did not start or needs another attempt, first check that no publication is waiting on the same release branch. Substitute the candidate's branch for `release/45`:

```bash
gh api --paginate 'repos/luminusOS/images/actions/workflows/publish.yml/runs?branch=release%2F45&per_page=100' \
  --jq '.workflow_runs[] | select(.status == "waiting") | .html_url'
```

If the check returns a run URL, resolve the waiting deployment before dispatching another run. If the check fails, do not dispatch. Otherwise, dispatch `publish.yml` on the same release branch with both original run IDs. This fetches and verifies existing evidence rather than rebuilding; the new publication run still needs approval. Substitute the original numeric IDs:

```bash
gh workflow run publish.yml --repo luminusOS/images --ref release/45 \
  -f channel=stable -f candidate_run_id=123456789 -f validation_run_id=123456790
```

- The scheduled chain checks the exact Git tag for the version before validation and again before publication, and skips candidates superseded by a newer successful Auto Stable candidate on that line. Builds choose their sequence number from existing Git tags, so overlapping builds can pick the same version. The publisher separately refuses to overwrite an OCI version tag with a different digest. If another candidate owns the version, prepare and validate a fresh candidate; do not delete tags to make room.
- After a partial publication, inspect which destinations changed. Retry only the same candidate with its matching validation, and do not resume an older candidate after a newer release has advanced channel tags. Publication is not atomic across GHCR, SourceForge, R2 and GitHub.
- Before moving image tags, the publisher preflights existing GitHub assets and the public versioned `SHA256SUMS`; conflicts detected by those checks fail before public writes.
- [`gh release create` with assets](https://cli.github.com/manual/gh_release_create) creates a draft, uploads the assets, then publishes it. An interruption before the last step can leave a draft. On retry, the [publisher](../.github/scripts/workflow/release_publish.py#L1064-L1091) reuses matching assets and uploads only missing ones, but does **not** publish the draft. If a draft remains after an approved retry, the owner must reconcile its assets and other destinations before publishing it manually in GitHub.

### Revert

On an affected installed system with a previous deployment available, run `sudo bootc rollback` and reboot into that deployment. This is local recovery; it does not change the public stable channel or prevent it offering the bad version again.

There is no automated withdrawal or channel rollback. The maintainer should identify the bad version and digests, warn users in the GitHub release notes not to install or update to that version, and provide the local rollback instructions. A warning or a GitHub-only withdrawal does not remove GHCR tags or mirrored downloads. Prepare a fixed release on the same release line, validate it and publish it as a new version through the normal approval gate. Check that the Fedora-line tags and, where applicable, `latest` and `stable/latest.json` identify the replacement. Do not move or delete tags by hand.

### Risk exceptions

- **Testing:** renew still-needed exceptions before **2026-12-16 00:00 UTC**. See `shared/release/exceptions/*-testing-45.json`, `shared/release/base-trust-risk.json` and `shared/release/flatpak-scan-risk.json`.
- **Stable:** the current records expire **2026-12-18 00:00 UTC**. See `shared/release/exceptions/*-stable-45.json`, `shared/release/base-trust-risk-stable.json` and `shared/release/flatpak-scan-risk-stable.json`.

Review renewals on the appropriate branch; do not carry testing exceptions into stable or extend records automatically. Update workflow policy hash pins when policy bytes change. If refreshed records change the signed scan evidence or approval summary, do not reuse the old approval; prepare and validate against the new policy.

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
- The floating tags `latest` and `testing` and the download index `<channel>/latest.json` move only when publishing `LATEST_RELEASE`, so they never go backwards. Publishing an older supported line uploads its downloads and prunes only that line's previous versions.
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
