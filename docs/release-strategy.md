# Release Strategy: Fedora Versions and Updates

This document separates the current release contract from the longer-term branch lifecycle decision recorded on 2026-09-25. Proposed branch automation below is not a claim that it has been deployed.

## Current state

- One branch (`main`); `DEFAULT_FEDORA_VERSION` in `config/versions.env` selects the Fedora release.
- Channels: `testing` (`testing-45.X`, `testing-45`, `testing`) and `stable` (`45.X`, `45`, `latest`). Candidate creation and approval are separate operations: a scheduled build must not advance channel tags simply because it built successfully. Stable promotion preserves the approved core and workstation payload digests; the live installer is a separate artifact that may need rebuilding and revalidation.
- Installed systems follow `UPDATE_CHANNEL` (currently `testing`), through a Fedora-pinned tag (`testing-45`).
- The image enables `bootc-fetch-apply-updates.timer` with a drop-in that runs `bootc upgrade` without `--apply`. Updates are staged for the next reboot, not applied through a forced restart. Metered connections are excluded. Runtime behavior still needs confirmation on the installed system.

## Candidate approval contract

- Validation builds have read-only permissions, require no publishing secrets, and transfer images between jobs as artifacts rather than assuming runner-local storage is shared.
- Privileged publication is restricted to authorized repository runs. Candidate identities must distinguish retries; subsequent operations use the captured image digest, not a mutable tag lookup.
- Verify the candidate signature against `shared/trust/etc/pki/containers/luminusos.pub`. Cosign 2 is retained for compatibility with containers/image.
- Bind SBOM, vulnerability results, provenance, boot logs, and installer evidence to the source commit, image digests, and artifact hashes. Exceptions to the vulnerability policy require a specific package/finding, justification, and expiry.
- Generate and sign a checksum manifest for downloadable artifacts. Publish the detached signature alongside the manifest; an unsigned checksum table in release notes is insufficient.
- Require real Sirius installation and first-boot evidence. qcow2 boot screenshots alone do not satisfy this gate. Verify expected-key updates, unsigned and incorrect-key rejection, update and rollback, live/installed separation, and observed host security state.
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

`installation-validation.yml` runs only through manual dispatch on `main`. Provision a dedicated, trusted self-hosted Linux x86_64 runner with the `luminusos-validation` label. It needs Python 3.11+, GitHub CLI authentication through the job token, enough disk space for both downloaded artifacts and disposable VM disks, and the QEMU/firmware/KVM tooling required by the installation test driver. Do not attach this runner to fork or untrusted pull-request jobs.

Create the GitHub environment `release-validation`, restrict it to `main`, require human approval, and configure `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`. Use the key matching the repository's public key. GitHub environment protection and runner provisioning are operator tasks; committing the workflow does not configure them.

Install the real test driver at the fixed path `/usr/local/libexec/luminusos/validate-candidate`. The file and its ancestor directories must be root-owned and not writable by group or others. Its interface is:

```text
/usr/local/libexec/luminusos/validate-candidate \
  --candidate <verified-candidate.json> \
  --artifacts <verified-artifact-directory> \
  --receipts <private-output-directory>
```

The driver must perform the actual Sirius installation and subsequent tests against these exact artifacts. It must not replace installation with qcow2 boot, disable signature checking to get a successful result, or reuse unrelated VM state. The repository validates and signs the driver's receipts; it does not provide or certify an externally provisioned driver's VM automation. An absent driver is a provisioning blocker, not a successful gate.

The required receipt names are `sirius_install`, `first_boot`, `live_isolation`, `expected_key`, `unsigned_rejected`, `foreign_key_rejected`, `update`, `rollback`, `selinux_enforcing`, `firewall`, and `secure_boot`. Each JSON receipt records `name`, the observed `command` argument list, `exit_code`, timezone-aware `started_at`/`finished_at`, a relative nonempty `log`, its `sha256`, and `binding` matching `release_pipeline.binding(candidate)`. Do not execute command strings read from receipts. A successful rejection test records the test harness's success after observing rejection, not the unsigned update command's exit status as if the update should succeed.

Dispatch the installation workflow with the successful preparation run's `candidate_run_id`. It verifies the signed candidate, invokes the driver without signing secrets, checks all receipts and log hashes, and only then signs `validation.json`. The uploaded `installation-validation` artifact contains that document, its detached signature, and the receipts/logs. Promotion checks the GitHub run identity as well as the signature and exact candidate binding.

### Preparing and resuming a release

1. Dispatch `publish.yml` on `main` with `channel=testing` and leave `candidate_run_id` and `validation_run_id` empty. A successful preparation produces the signed `release-candidate` artifact; it does not move channel tags or publish downloads. Scheduled testing follows the same preparation path.
2. Run `installation-validation.yml` with that preparation's `candidate_run_id`, using the protected runner described above. Retain the successful validation run ID.
3. Resume `publish.yml` with the same channel and both `candidate_run_id` and `validation_run_id`. The workflow downloads and verifies the original candidate and matching validation instead of rebuilding them. It stages signed download evidence, preflights all three image references, promotes tags, and publishes downloads.
4. For stable preparation, select `channel=stable`, supply `promote_version`, `testing_run_id`, and `testing_validation_run_id`, and leave the resumption IDs empty. The testing candidate must already have matching approved installation evidence. Stable preserves its core/workstation digests and prepares a separate installer, which requires its own installation validation before resumption.

Stable eligibility checks the supported Fedora release and whether upstream `fedora-bootc:latest` has reached that Fedora major version. An upstream rebuild does not invalidate the tested candidate merely because the current base digest differs; the original base digest remains recorded as provenance.

### Diagnostic Auto Testing builds

The manual Auto Testing dispatch offers an opt-in vulnerability bypass, disabled by default. Use it only to investigate or boot-test a candidate while waiting for upstream package fixes. Scheduled runs and ordinary publication remain strict. This option is restricted to a fresh testing build from Auto Testing on `main`; it is not available for stable preparation or resumption.

The bypass permits validated blocking vulnerability findings, not missing or malformed scan results, failed scanners, invalid signatures, digest mismatches, or invalid provenance. Scanning still runs, findings remain in the evidence, and the execution records the bypass with an explicit warning. This is acceptance of risk for that diagnostic execution, not an approved false-positive exception or a successful vulnerability gate.

A bypassed execution may produce signed image candidates and diagnostic ISO/qcow2 artifacts, but never a signed `release-candidate`, even if its scan happens to be clean. It cannot be used for installation approval, channel promotion, stable preparation, or release publication through this workflow. To obtain a promotable candidate, run a new strict preparation and satisfy all ordinary gates; clearing a checkbox during resumption cannot rehabilitate a bypassed build.

Configure the publication signing key, SourceForge credentials, and R2 credentials before resumption. GitHub release assets contain `SHA256SUMS`, its signature, and `evidence.tar.gz`; ISO and qcow2 downloads are published through R2 and SourceForge. Promotion and download publication span external services and are not an atomic transaction: inspect completed steps before retrying an interrupted release.

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
