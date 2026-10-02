# Release checklist

Start here when publishing an AOS release. Work through the sections in order.
Use the same checklist for every registry; each destination's
[profile](qualification.md#profiles) determines its additional checks,
observation time, and approvals.

To publish only to the staging surface, without qualification, follow
[publishing to staging only](#publishing-to-staging-only) below: it is the
same procedure, stopped before production.

Keep a copy with this release's operator records, outside the source checkout.
Check an item only after its **Check when** condition is true. Beside the box,
record your name, UTC time, and the log, output directory, or approval showing
the result. Leave failed or unfinished items unchecked. Do not proceed past a
section with an unchecked required item.

Mark an item inapplicable only where this checklist explicitly permits it, and
record the reason. Enable `set -o noclobber` in the operator shell before running
the commands below so redirected evidence files cannot silently be replaced.

`aos maintain release advance` runs every automated step and stops at each human
decision with one `Waiting:` instruction. Whenever an item names a journal
state, run `aos maintain release status` and compare the line for the named destination
(or the global `State:` line) with the expected value. The driver keeps every
earlier journal under the work directory; later steps write successors.

**Qualification readiness:** packaged executors include native package and
Linux disk/container staging scenarios, with dedicated recovery and K3s
package scenarios. Install the exact platform closures and run them against
the published staging artifacts. Required report-backed scenarios still need
real campaign or operator evidence; do not substitute synthetic fleet reports.
Follow the [executor setup](qualification.md#native-executors) before treating
the test environments as ready. Main remains closed until its
[launch requirements](registry-main.md) are satisfied.

The destinations and what each one requires:

| Registry | Destination | Profile | Tests before publication | Reviews | Rollout | Fitness |
| --- | --- | --- | --- | --- | --- | --- |
| `andyl/main`, `andyl/experimental` | `staging/edge` | `build` | build only | none | all partitions on publish | none |
| `andyl/main`, `andyl/experimental` | `production/edge` | `smoke` | changed targets and cells | none | all partitions; completes automatically | none |
| `andyl/main` | `staging/candidate`, `staging/stable` | `build` | build only | none | all partitions on publish | none |
| `andyl/main` | `production/candidate` | `functional` | every target and cell | 1 per report | all partitions after fresh health; completes automatically | 14-day automated, 90-day operator |
| `andyl/main` | `production/stable` | `soak` | every target and cell, complete matrix | 1 per report, including each ring; completion approvals | 4, 32, 128, 256 partitions; 7-day soak; complete-phase report | as candidate plus key rotation |

These are the current contract values. A reviewed contract revision may change
them; record the frozen plan's values, which `aos maintain release explain` prints.

Only a destination whose profile selects `qualified` claims (today
`production/stable`, `soak`) needs a complete-phase report and the
release-evidence completion approvals. Every other destination records
`complete` automatically when its final ring's channel advance and public
read-back succeed.

### Publishing to staging only

There is no separate staging-only plan. To place a release on the staging
surface for operator testing without qualifying it, complete sections 1 to 3
and stop before [section 4](#4-publish-to-production). The staging
destinations' `build` profile needs no qualification, review, or fitness
attestation; the build's repeat check, an advisory disposition with no
unresolved advisories, the signed cache, manifest, and TUF metadata, and a full
public read-back are still required. The frozen plan already names the
production destinations, so the same release can continue to production later
with its actual qualification evidence. For an empty staging registry, perform
only the signed staging bootstrap.

## 1. Prepare the release

Complete this section before starting builds or requesting signatures.

- [ ] **Record the release.** Record the release version, registry, intended
  destinations, source commit, operator, and reviewer. Use a version whose
  class matches the intended channel: `-dev.YYYYMMDD.N` for `edge` on either
  registry, `-rc.N` for a main candidate, or a final `YYYY.M.P` for a main
  stable release. `andyl/experimental` accepts only edge versions.

  **Check when:** those fields are filled in and the registry/version
  combination is valid. A final version plans both candidate and stable
  destinations; an edge version plans both edge destinations.

- [ ] **Check the maintainer configuration.** Open the
  [maintainer configuration](canonical-releases.md#maintainer-configuration)
  for this registry and the
  [maintainer-machine configuration](canonical-releases.md#configure-the-designated-maintainer-machine).
  Locate the configured signer programs, independently obtained public keys,
  surfaces, receipt keys, executors, reviewer key, and alert destination.

  **Check when:** `registry` names this release's registry, `work_root` and
  `fitness_root` are private directories outside the source checkout, every
  signer role in the approved roster has a `[signer.roles.<role>]` table whose
  key IDs, verification identities, threshold, and provider revision match that
  roster, `[git]` names the organization's public release identity for
  registry commits, and the shell runs the installed
  [release tooling closure](canonical-releases.md#release-tooling-environment).
  One configuration serves one registry; load only its credentials.

- [ ] **Verify source and contributor authorization.** Use the protected source
  commit intended for release, not a working PR branch. Run
  `git status --porcelain` and `git rev-parse HEAD`. Complete the
  [contributor-authorization check](contributor-licensing.md) and confirm its
  public summary is the file named by `contributor_authorization`.

  **Check when:** Git reports no changes, the commit matches the release record,
  and authorization is verified. An emergency hotfix source follows the
  [hotfix rule](canonical-releases.md#generate-the-plan). Missing or unknown
  authorization stops the release.

- [ ] **Confirm the test environments are ready.** Confirm real test programs
  exist for both Linux disk/container targets and every platform receiving
  packages, including native macOS runners where needed, inside the installed
  release tooling closure's `libexec/aos-release/executors/<platform>/`.

  **Check when:** every required test has an implementation and each
  executor's `identity` file names the identity it reports. A generic runner,
  empty scenario mapping, or passing fixture test does not satisfy this item.
  Complete the executor setup described above.

- [ ] **Verify the registry and both surfaces.** Follow the preconditions
  and live-state commands in the [experimental](registry-experimental.md#preconditions)
  or [main](registry-main.md#inspect-live-state) runbook. For each surface,
  confirm its identity: the Hub deployment ID, or the `.aos-surface` identity of
  a [static surface](canonical-releases.md#static-surfaces). Record the
  registry base commit/generation and trust-root epoch.

  **Check when:** both surfaces identify the intended builds and registry, and
  the configuration's `[surfaces.staging]` and `[surfaces.production]`
  identities equal what the surfaces serve. Existing registries need a verified
  base; first-time bootstrap needs a recorded authoring base and verified empty
  destinations. Main requires its recorded go-live approval.

- [ ] **Check environment fitness.** Run:

  ```sh
  aos maintain release fitness status
  ```

  **Check when:** every fitness kind required by this release's production
  destinations is fresh and its bindings match the live values. For
  `andyl/experimental` releases, record that no fitness is required. A stale or
  mismatched attestation is not a per-release task to rush: perform the
  corresponding [fitness exercise](#fitness-exercises) on its own procedure
  before production publication, or schedule this release after it.

## 2. Freeze what will be released

- [ ] **Record the support matrix and acceptance criteria.** Use the
  [target support matrix](qualification.md#target-support-matrix).
  List the required QEMU and OCI configurations, every published package/platform
  cell, and additional physical, cloud or device claims. For each claim, record
  its compatibility scope, required assurance, release-blocking status, assigned
  configurations and evidence location. Record QEMU acceleration separately;
  identify CPU/device combinations and cloud provider/SKUs explicitly. Use the
  acceptance checks to define each test program's expected results.

  **Check when:** all four mandatory reference configurations have assigned
  tests at the assurance their destinations select (A2 for `smoke` and
  `functional`, A3 for `soak`), additional claims have explicit assurance
  obligations, and CPU, firmware, device and enabled-driver coverage has been
  reviewed. Broad compatibility assessments and directly tested configurations
  must be recorded separately. Additional A3 image/container claims need target
  cases before the plan is frozen.

- [ ] **Prepare the predecessor.** Confirm the configuration's
  `predecessor_bundle` is the verified signed bundle of the preceding release
  in this registry, with its public verification keys. The first public release
  needs a retained signed test snapshot as its predecessor; an empty registry
  base is not an installed OS to upgrade from. When no prior release exists,
  follow the
  [restricted qualification snapshot workflow](canonical-releases.md#create-a-first-qualification-predecessor)
  before freezing the public plan.

  **Check when:** the predecessor bundle verifies offline against independently
  obtained keys and names this registry.

- [ ] **Prepare an emergency override, if needed.** Mark this item inapplicable
  unless an incident requires `production/stable` to soak or roll out faster
  than its profile. Otherwise record the incident, prepare the
  [profile override](qualification.md#profile-overrides) for this release ID
  and `production/stable`, and obtain the release-evidence threshold of
  signatures over it.

  **Check when:** the override names the incident record, relaxes only soak
  (not below one day) and rings (ending at 256), and every signature verifies.
  An emergency does not waive any other check in this list.

- [ ] **Freeze the plan.** Write the reviewed Linux image decisions for this
  release to a JSON file, then from the clean source checkout run:

  ```sh
  aos maintain release new --registry andyl/experimental --version 2026.9.0-dev.20260929.1 --images images.json
  ```

  For a registry's first release, when no surface holds a publication yet,
  add `--first-release --source-registry <clean single-commit clone>` as
  described in
  [plan a registry's first release](canonical-releases.md#plan-a-registrys-first-release).
  For an emergency, add `--override DIR`, or immediately run
  `aos maintain release advance --to production/stable --override DIR` before any
  other `advance`, as described in
  [plan an emergency override](canonical-releases.md#plan-an-emergency-override).

  **Check when:** the command exits zero and the printed summary contains the
  intended source, registry, version, predecessor, both surfaces, every
  destination with its profile, the change scope, target decisions, and
  authorities. Save the reported plan digest and keep this checklist in the
  release's work directory from now on. If anything is wrong, fix the
  configuration or source and start a new release; do not edit the frozen plan.

- [ ] **Bootstrap a first registry base, if needed.** For an existing verified
  base, record its receipt and mark this item inapplicable. For a plan frozen
  with `--first-release`, obtain the separate staging and production bootstrap
  approvals for this plan. Run
  [release bootstrap](canonical-releases.md#bootstrap-the-first-registry-base)
  on the staging surface first with `--output <work>/bootstrap/staging`,
  verify its result, then repeat for production with that surface's approval
  and access profile and `--output <work>/bootstrap/production`.

  **Check when:** both bootstrap outputs are retained in the work directory,
  their public read-back succeeded, and their base commit and surface
  identities match the plan. Do not bootstrap over an existing publication.

## 3. Publish to staging

Run the driver for the first staging destination of this release:

```sh
aos maintain release advance --to staging/edge        # edge release on either registry
aos maintain release advance --to staging/candidate   # andyl/main candidate or final
```

It builds, signs, closes, verifies, and publishes the release, then moves the
staging channel. Rerun the same command after each `Waiting:` step. The driver
waits for these operator inputs, each at a fixed path in the release's work
directory:

| Input | Path | When |
| --- | --- | --- |
| Externally signed OCI release bundle: `container-release.json`, `signature-input.json`, `layout/` | `inputs/container/` | After image finalization, when the release carries an OCI artifact |
| Clean authoring registry clone at the planned base commit | `inputs/source-registry/` | Before `prepare-registry` |
| Acceptance of the reviewed registry transaction | `--accept-transaction`, recorded as `registry/transaction-accepted.json` | After `prepare-registry`, when a planned profile requires transaction review |
| Reviewed advisory disposition for `build/evidence/sbom.spdx.json` | `inputs/advisory-disposition.json` | After the cache is signed, before assembly |

For a final `andyl/main` version, repeat with `--to staging/stable` once
`staging/candidate` is published; the surface already holds the publication,
so only the channel moves.

- [ ] **Build and repeat-build the frozen outputs.** Let the driver run
  [release build](canonical-releases.md#build-the-frozen-package-matrix). Run
  the source regression suite as well:

  ```sh
  nix-build -A checks.qualification.all --no-out-link
  ```

  **Check when:** both exit zero, every planned output appears in the build
  report with `reproducibility: "reproduced"`, and `aos maintain release status` reports
  `State: built`. Save the Nix result path and logs.

- [ ] **Finalize both Linux images and the OCI artifacts.** The driver runs
  [finalize-image](canonical-releases.md#finalize-each-linux-image) for each
  planned Linux assembly into `images/<platform>/<variant>/`. When it waits
  for the OCI sidecar, follow the registry runbook's external container signing
  and immutable graph upload procedure and place the result in
  `inputs/container/`. When it waits for the authoring registry, place a clean
  clone at the planned base commit in `inputs/source-registry/`.

  **Check when:** both images have `finalized/` outputs and
  `finalized-image-set.json`, all requested disk formats passed byte-equivalence
  verification, and the signed OCI release/layout covers both Linux platforms.
  The authorities must belong to this release. Unsigned outputs and fixture
  keys do not satisfy this item.

- [ ] **Review the isolated registry transaction.** Mark inapplicable for
  `andyl/experimental`, whose `smoke` profile does not stop here. For `andyl/main`
  the driver waits after
  [prepare-registry](canonical-releases.md#prepare-and-finalize-the-isolated-registry).
  Review `registry/transaction.json` and the retained tree in
  `registry/prepared/` together, then run
  `aos maintain release advance --to staging/candidate --accept-transaction`.

  **Check when:** the transaction identifies exactly the planned
  package/platform outputs, the retained diff matches it, and the driver has
  finalized the registry and cache from those exact inputs with verifying
  narinfo signatures.

- [ ] **Review build evidence and close the bundle.** When the driver waits
  for the advisory disposition, prepare the canonical disposition described in
  [close and sign the bundle](canonical-releases.md#close-and-sign-the-bundle)
  at `inputs/advisory-disposition.json`. Review the assembled payload and unsigned manifest
  before the driver requests signatures.

  **Check when:** required build observations passed, every advisory has a
  disposition with no unresolved release blocker, and `aos maintain release status`
  reports `State: finalized`.

- [ ] **Verify the bundle independently.** Run
  [release verify](canonical-releases.md#verify-a-captured-bundle-offline) on
  `finalized/bundle/` with `finalized/release-journal.jsonl` and public keys
  obtained independently of the bundle and of the maintainer configuration.

  **Check when:** verification exits zero and names this release and the
  `finalized` journal state. Save the output. Missing files, wrong signatures,
  and mismatched digests stop the release.

- [ ] **Confirm the staging publication.** The driver
  [publishes](canonical-releases.md#publish-to-a-destination) with staging-only
  credentials, reads every object back anonymously, and advances the staging
  channel's single ring.

  **Check when:** `publish/staging-<channel>/published/receipt.json` exists and
  `aos maintain release status` reports the staging destination `complete`. This checks
  delivery; functional testing comes next. Repeat for `staging/stable` when
  planned.

## 4. Publish to production

Complete the subsection for each production destination the plan contains.
Switch to production-only access before the driver's production publication
step. Every production destination repeats the same pattern: collect
staging-phase evidence against the staging surface, review where required,
publish, and advance rings. `production/edge` and `production/candidate`
complete with their final ring; only `production/stable` adds a complete-phase
report and completion approvals.

### 4a. `production/edge` (`smoke`) on `andyl/main` or `andyl/experimental`

- [ ] **Confirm the change scope.** Run
  `aos maintain release explain --to production/edge`.

  **Check when:** the change scope names the expected predecessor and its
  image, container, and package decisions match the source changes. An
  unexpectedly narrow scope stops the release; a missing predecessor correctly
  selects every target.

- [ ] **Run the functional tests.** Run
  `aos maintain release advance --to production/edge`. The driver runs
  [qualify-run](canonical-releases.md#run-the-native-qualification-matrix)
  for the staging phase and signs the report with the qualification authority.

  **Check when:** every case listed by `explain` has a passing result in the
  signed report with retained logs, including installation, packages, update,
  and recovery cases selected by the scope. Missing or failed results stop the
  release.

- [ ] **Test physical-hardware claims.** If no A2 physical or device claim is
  made, record that scope and mark this item inapplicable. Otherwise execute
  the claimed functions on the exact published candidate and retain CPU SKU,
  chipset/SoC, firmware, device IDs, bound drivers, storage durability settings
  and TPM state.

  **Check when:** every directly tested configuration passes the checks for its
  claimed functions. Record untested combinations separately.

- [ ] **Publish and roll out.** The driver constructs the destination's TUF
  metadata and timestamp, publishes the exact bundle to the production surface,
  reads it back, and advances all 256 partitions. The final ring completes the
  destination; `smoke` needs no completion approval. For OCI, finish the
  registry runbook's release-tag publication against the published signed
  sidecar.

  **Check when:** `publish/production-edge/published/receipt.json` and
  `channels/production-edge/ring-1/channel-receipt.json` exist, and
  `aos maintain release status` reports `production/edge` `complete`. Then complete the
  clean-client, profile, and warning checks in
  [the experimental runbook](registry-experimental.md#publish-the-first-or-a-later-edge-release);
  they apply unchanged to a main edge release, whose artifacts also bake an
  edge warning.

### 4b. `andyl/main`: `production/candidate` (`functional`)

- [ ] **Assign every required test.** Run
  `aos maintain release explain --to production/candidate`.

  **Check when:** every listed case has an assigned program/environment or
  operator. `explain` shows cases as not yet evaluated: this box means the work
  is assigned, not that it passed. An unavailable environment does not make a
  case optional. Compare the cases with the support matrix: every mandatory
  configuration and additional claim must be covered, with the required cycle
  counts and package checks.

- [ ] **Test physical-hardware claims.** As in 4a. If no physical or device
  claim is made, mark this item inapplicable.

- [ ] **Collect the staging report.** Run
  `aos maintain release advance --to production/candidate`. The driver collects the
  staging-phase report against the staging surface and waits for review.

  **Check when:** every case has a passing result in the prepared report with
  retained logs. Inspect evidence for installation/provisioning, packages,
  configuration, HTTP/TLS, containers, reboot persistence, upgrade, interrupted
  update, fallback, rollback, offline recovery, and another successful update,
  as required by each case. Inspect committed-data checks and failed attempts
  too. Update achieved assurance in the matrix from those results. Any unmet
  release-blocking assurance obligation stops the release.

- [ ] **Review and sign the exact report.** The independent reviewer runs
  `aos maintain release review` against the prepared report, following
  [collect, review, and sign](qualification.md#collect-review-and-sign).

  **Check when:** the reviewer approved these exact report bytes and the
  driver's next run signs them with the qualification authority. Changing a
  report requires another review.

- [ ] **Confirm fitness and publish.** Run `aos maintain release explain --to
  production/candidate`, then rerun `advance`.

  **Check when:** every required fitness attestation is fresh and
  binding-matched, the driver published the exact bundle with the public
  release record, and `aos maintain release status` reports `production/candidate`
  `published`. For OCI, finish the registry runbook's release-tag publication.

- [ ] **Approve rollout health.** The driver collects a fresh rollout-phase
  report for the single ring and waits for review. Review it with
  `aos maintain release review` within ten minutes of collection.

  **Check when:** clean clients consume the intended artifacts, no integrity or
  recovery failure is unresolved, the ring's channel receipt exists, and
  `aos maintain release status` reports `production/candidate` `complete`. The
  `functional` profile completes with its single ring; it has no completion
  approval.

### 4c. `andyl/main`: `production/stable` (`soak`)

Publish a final version to `production/candidate` first, following the monthly
train in RFC-0017. The same bundle then enters `production/stable`.

- [ ] **Confirm the complete matrix and test assignment.** Run
  `aos maintain release explain --to production/stable`.

  **Check when:** the plan has no blocked package/platform cell, and every
  listed staging, rollout, and complete case is assigned, including the A3
  image and container observation claims.

- [ ] **Test physical-hardware claims.** If no A2/A3 physical or device claim
  is made, record that scope and mark this item inapplicable. For A3
  image-lifecycle claims, use disposable data to interrupt power during update
  and persistence, recover, verify acknowledged data, and update again.
  Redundant-storage claims also need disk replacement, boot from each ESP,
  rebuild, and unlock tests; other device claims need their own workload tests.

  **Check when:** A3 lifecycle claims have boot, recovery, data-preservation and
  workload results. Do not interrupt power or restore data on a live production
  system.

- [ ] **Collect, review, and publish.** Run
  `aos maintain release advance --to production/stable`, review the staging report with
  `aos maintain release review`, and rerun `advance`.

  **Check when:** the report passed review, fitness including `key-rotation` is
  fresh, and `aos maintain release status` reports `production/stable` `published`.

- [ ] **Start workload observation.** Start the configured workload monitor on
  the exact production artifacts. Record machines/runtime, artifact digests,
  UTC start, workload, and the plan's soak for `production/stable`. Measure
  successful/failed operations, reboots, updates, recovery attempts, resource
  growth, and data integrity.

  **Check when:** the monitor is running and recording actual operations. A
  timer without a workload is not evidence.

Repeat the next two items for **each** ring, keeping separate results:

- [ ] **Approve the next ring.** Run
  `aos maintain release advance --to production/stable --ring N` with the next ring
  number. The driver waits until the previous ring's observation time has
  elapsed, collects a fresh rollout report, and waits for review. Review it with
  `aos maintain release review` within ten minutes.

  **Check when:** the reviewer approved the health of the exact next partition
  range, the driver
  [advanced](canonical-releases.md#advance-a-planned-channel-ring) only that
  ring, and a new channel receipt exists under
  `channels/production-stable/ring-N/`.

- [ ] **Check the clients reached by this ring.** Inspect workload monitoring
  and clean-client package/image/container consumption.

  **Check when:** clients receive the intended release and no unexplained boot,
  trust, data-preservation, or recovery failure is present. Otherwise stop
  expansion and follow the failure procedure below.

- [ ] **Complete workload observation.** Run the workload for the full soak.
  Review operation counts, failures, resource trends, and recovery/data checks
  with the release owner, then let the driver collect the complete-phase report
  and review it with `aos maintain release review`.

  **Check when:** measured elapsed time meets the soak, real operation counts
  are present, no blocking failure remains, and the complete-phase report is
  signed. Do not backdate results or use synthetic fixture timing as an
  observation report.

- [ ] **Approve completion.** When the driver waits for completion approvals,
  each release-evidence approver signs the completion decision with
  `aos maintain release review` until the plan's threshold is reached. A completion
  decision cannot be rejected with `--reject`; withhold the approval and record
  the reason instead.

  **Check when:** every approval exists as
  `channels/production-stable/completion-<key_id>.json`, the driver ran
  [channel complete](canonical-releases.md#complete-a-rollout), and
  `aos maintain release status` reports `production/stable` `complete`.

## 5. Close the release

- [ ] **Verify retention and assign ongoing owners.** Check retained release
  bytes, matching source, plans, journals, receipts, metadata, reports, and
  private operator records. Record retention deadlines, the monitoring/renewal
  owner, recovery contact, and published known limitations. Confirm the
  timestamp renewal timer is active for each production surface and its next
  run precedes expiry.

  **Check when:** retained objects can be read back, required backups are
  verified, and named maintainers have accepted renewal, monitoring, and
  recovery responsibilities. Main also needs its compatibility/support
  obligations recorded.

- [ ] **Confirm every destination is complete.** Run:

  ```sh
  aos maintain release status
  ```

  **Check when:** every planned destination reports `complete`. Save the output
  and completed checklist. This is the release's final check.

## Fitness exercises

These exercises prove the release environment can recover. They are **not
per-release steps**. Each produces a signed
[fitness attestation](qualification.md#fitness-attestations) that serves every
release published while it is fresh and its bindings match. Record each in the
maintainer's operations log, not in a release checklist.

| Kind | Performed by | Cadence | Accepted for | Invalidated by a change to |
| --- | --- | --- | --- | --- |
| `storage-restore` | `aos-release-restore-check.timer` | weekly | 14 days | the installed release tooling closure |
| `alert-delivery` | `aos-release-alert-check.timer` | weekly | 14 days | the `[alert]` section |
| `authority-recovery` | operator | quarterly | 90 days | the plan's signer roster |
| `hub-restore` | operator | quarterly, and before a risky schema or storage migration | 90 days | the production surface identity or Hub schema |
| `key-rotation` | operator | quarterly | 90 days | the signer roster or production surface identity |

Only `andyl/main` production destinations require fitness today. Perform the
operator exercises while release mutations are paused, using an isolated
restore/test environment. Then record the result:

```sh
aos maintain release fitness run hub-restore --report /srv/aos-release/restricted/hub-restore-2026-09-14.json
aos maintain release fitness status
```

Without `--report`, `fitness run` reads the report from standard input. The
report is an `aos.release.fitness-report/v1` document stating the performed
time, each of the kind's checks with its result and detail, and the operator. Keep it in restricted storage; the attestation
carries only its digest. If the command rejects a report, fix the exercise, not
the report.

- [ ] **Storage restore (automated).** The weekly restore check restores the
  independent encrypted backup into a clean directory, verifies the retained
  bundles offline, and records the attestation. To run it on demand:

  ```sh
  systemctl start aos-release-backup.service
  systemctl start aos-release-restore-check.service
  systemctl show aos-release-backup.service aos-release-restore-check.service \
    -p Result -p ExecMainStatus
  aos maintain release fitness status
  ```

  **Check when:** the backup is held independently of the maintainer machine,
  both jobs report `Result=success` and `ExecMainStatus=0`, and `fitness status`
  shows a fresh `storage-restore` bound to the installed tooling closure. A
  successful backup upload alone is insufficient.

- [ ] **Alert delivery (automated).** The weekly alert check triggers the
  alert path with a synthetic unit name and records the attestation after the
  on-call maintainer acknowledges it.

  **Check when:** the acknowledgment is recorded, the message contains no secret
  material, and `fitness status` shows a fresh `alert-delivery`. A log entry
  without delivered notification is a failure.

- [ ] **Recover and verify the signing authorities (quarterly).** Restore the
  encrypted authority backup into the isolated environment using the secret
  store's recovery procedure. For every role in the signer roster, compare its
  recovered public identity with the roster, sign a non-public test payload,
  and verify with the independent key. Record `authority-recovery`.

  **Check when:** every role is recoverable, each test signature verifies, and
  the attestation's `signer-roster` binding matches the current roster. Never
  record private key bytes in the report or public evidence.

- [ ] **Recover each production surface into isolation (quarterly).** For a
  Hub surface, follow
  [capture a recovery point](aos-hub-backup-recovery.md#capture-a-planned-recovery-point)
  and the [isolated restore procedure](aos-hub-backup-recovery.md#routine-restore-exercise),
  including portable database export/import; an in-place PITR bookmark cannot
  satisfy that check. For a static surface, restore its object set and channel
  generation records into an isolated origin. Check registry generations,
  object inventories, and anonymous package/image/container reads in the
  restored copy. Record `hub-restore`.

  **Check when:** the recovered copy serves the expected bytes and state,
  object/row comparisons reconcile, and the attestation binds the production
  surface identity and schema.

- [ ] **Test key rotation and interrupted publication (quarterly).** In the
  isolated environment, follow the
  [experimental rotation procedure](registry-experimental.md#rotate-keys-without-resetting-trust)
  or [main key policy](registry-main.md#keys-rollback-recovery-and-removal).
  Verify that a clean client starting with the old anchor accepts the
  legitimate successor and rejects an unauthorized replacement. Interrupt
  publication before and after commit; verify retry or a new corrective
  release gives the intended public result. Record `key-rotation`.

  **Check when:** trust continuity and rejection both work, each interrupted
  publication has one known final state with matching bytes and generation,
  and the attestation binds the current roster and production surface.

## If a step fails or is interrupted

Stop the next publication or channel change. Preserve the command, logs, work
directory, and failed-attempt directories. Run `aos maintain release status` and record
the global and per-destination states. If a network operation may have
committed, inspect the live surface and receipts before retrying; a local
timeout does not establish that the public operation failed.

Resume only when recorded and live state agree and the same inputs still apply.
`advance` is idempotent: it skips steps whose outputs exist and whose journal
state matches, and refuses to continue past a disagreement. Never delete
evidence to force a retry or edit signed artifacts to make a check pass.
Changed source, artifacts, or policy need a new release. After public discovery
changes, publish a reviewed corrective release using the registry runbook. A
failure on one destination does not undo another destination's admission. A
experimental root reset is a separate operation, not an automatic response to a
failed release.
