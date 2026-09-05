# Release checklist

Start here when publishing an AOS release. Work through the sections in order.
Use the same checklist for testing and production; the release class determines
the additional checks and observation time.

Keep a copy with this release's operator records, outside the source checkout.
Check an item only after its **Check when** condition is true. Beside the box,
record your name, UTC time, and the log, output directory, or approval showing
the result. Leave failed or unfinished items unchecked. Do not proceed past a
section with an unchecked required item.

Mark an item inapplicable only where this checklist explicitly permits it, and
record the reason. Enable `set -o noclobber` in the operator shell before running
the commands below so redirected evidence files cannot silently be replaced.

Whenever an item names a journal state, inspect the journal it produced with
`aos release status --journal PATH_TO_JOURNAL` and compare the printed `State:`
line with the expected value. Keep the old journal; later commands write successors.

**Current blockers:** the test programs for published release artifacts still
need implementation and installation. Also, `release build` takes
`--completed-at` before executing the build; accurate completion-time capture
needs fixing before its report can be used for a real release. Do not substitute
synthetic fleet reports or guessed timestamps. Main also remains closed until
its [launch requirements](registry-main.md) are satisfied.

## 1. Prepare the release

Complete this section before starting builds or requesting signatures.

- [ ] **Create the release record and work directory.** Record the release ID,
  version, registry, class, source commit, operator, and reviewer. Create a new
  private directory in the designated maintainer machine's release storage and
  set `AOS_RELEASE_WORK` to its absolute path. Keep this checklist and command
  logs there. Use a new directory for each release.

  **Check when:** those fields are filled in, the directory exists outside the
  source checkout, and the registry/class/channel combination is valid:

  | Registry | Class | Channel | Workload observation | Independent report review |
  | --- | --- | --- | --- | --- |
  | `andyl/testing` | `edge` | `edge` | 24 hours | Optional |
  | `andyl/main` | `candidate` | `candidate` | 7 days | Required |
  | `andyl/main` | `stable` | `stable` | 14 days | Required |
  | `andyl/main` | `emergency` | `stable` | 14 days | Required |

  These are the current contract values. A reviewed contract revision may
  change them; record the frozen plan's values. Emergency does not waive checks.

- [ ] **Verify source and contributor authorization.** Use the protected source
  commit intended for release, not a working PR branch. Run
  `git status --porcelain` and `git rev-parse HEAD`. Complete the
  [contributor-authorization check](contributor-licensing.md) and save its public
  summary as `contributor-authorization.json` in the work directory.

  **Check when:** Git reports no changes, the commit matches the release record,
  and authorization is verified. Emergency source selection follows the
  [hotfix rule](canonical-releases.md#generate-the-plan). Missing or unknown
  authorization stops the release.

- [ ] **Confirm the release tools and test environments are ready.** Check the
  [maintainer-machine configuration](canonical-releases.md#configure-the-designated-maintainer-machine).
  Locate the configured signer programs, independently obtained public keys,
  backup/restore programs, and alert destination. Confirm real test programs
  exist for both Linux disk/container targets and every platform receiving
  packages, including native macOS runners where needed.

  **Check when:** the programs and operating instructions are available, signer
  identities match the approved role roster, and every required test has an
  implementation. A generic runner, empty scenario mapping, or passing fixture
  test does not satisfy this item. Resolve the current blockers above first.

- [ ] **Verify the registry and both Hub deployments.** Follow the preconditions
  and live-state commands in the [testing](registry-testing.md#preconditions)
  or [main](registry-main.md#inspect-live-state) runbook. Save the deployment IDs,
  registry base commit/generation, and trust-root epoch. For a first release,
  prepare the authoring base and topology from that runbook; bootstrap follows
  plan generation in section 2.

  **Check when:** both environments identify the intended builds and registry,
  and the release record contains those exact identities. Existing registries
  need a verified base; first-time bootstrap needs a recorded authoring base
  and verified empty destinations. Main requires its recorded go-live approval.
  Load only credentials for the current registry and operation.

## 2. Freeze what will be released

- [ ] **Record the support matrix and acceptance criteria.** Use the
  [target support matrix](qualification.md#target-support-matrix).
  List both architectures for QEMU images and OCI containers, every published
  package/platform cell, and any physical-hardware or cloud support being added.
  Record the assigned tier, promised artifacts, test environment and evidence
  location for each row. Use the concrete acceptance checks as the test
  program's acceptance criteria.

  **Check when:** all four Tier 1 runtime combinations have environments and assigned
  tests; package roles and representative hardware coverage have been reviewed;
  and every tier's artifact and testing obligations are accounted for. Tier 2
  physical targets require the promised generic images; Tier 3 cloud targets
  add no release gate. Any promotion to Tier 1 must have a reviewed policy change
  and required cases before the plan is frozen. A passing QEMU result alone
  cannot check off physical hardware or cloud qualification.

- [ ] **Export the requirements and prepare the request.** From the clean source
  checkout, run this with the selected class:

  ```sh
  aos --json release contract --class edge \
    --output "$AOS_RELEASE_WORK/qualification-contract.json" \
    > "$AOS_RELEASE_WORK/qualification-requirements.json"
  ```

  Prepare `release-request.json` using the
  [request fields](canonical-releases.md#prepare-a-plan-request). Copy `gates` and
  `public_evidence_policy_digest` from `qualification-requirements.json`.
  Include the verified predecessor,
  recorded registry/deployment identities, both Linux image decisions, signer
  roles, channel ranges, and retention policy. The first public release needs a
  retained signed test snapshot as its update predecessor; an empty registry
  base is not an installed OS to upgrade from.

  **Check when:** the request has been reviewed against the release record,
  every requested target has a test environment, and the predecessor bundle and
  public verification keys are available. Stable and emergency releases must
  have no blocked package/platform cells.

- [ ] **Generate and inspect the plan.** Run:

  ```sh
  aos release plan \
    --request "$AOS_RELEASE_WORK/release-request.json" \
    --contributor-authorization "$AOS_RELEASE_WORK/contributor-authorization.json" \
    --output "$AOS_RELEASE_WORK/release-plan.json"
  ```

  **Check when:** the command exits zero and the plan contains the intended
  source, registry, version, predecessor, target decisions, authorities, and
  channel ranges. Save its reported digest. If anything is wrong, prepare a
  new request and plan; do not edit the frozen plan.

- [ ] **Bootstrap a first registry base, if needed.** For an existing verified
  base, record its receipt and mark this item inapplicable. For a new registry,
  obtain the separate staging and production bootstrap approvals for this plan.
  Run [release bootstrap](canonical-releases.md#bootstrap-the-first-hub-registry-base)
  in staging first, verify its result, then repeat for production with that
  environment's approval and access profile.

  **Check when:** both bootstrap outputs are retained, their public read-back
  succeeded, and their base commit and deployment identities match the plan.
  Do not bootstrap over an existing publication.

## 3. Build and sign the artifacts

The links below go directly to the relevant commands. Replace their example
paths, key IDs, versions, and dates with this release's recorded values. Put
every output under `AOS_RELEASE_WORK`, using a new path for each command.

- [ ] **Build and repeat-build the frozen outputs.** Run
  [release build](canonical-releases.md#build-the-frozen-package-matrix), with
  output `release-build/`. Run the source regression suite as well:

  ```sh
  nix-build -A checks.qualification.all --no-out-link
  ```

  **Check when:** both commands exit zero, every planned output appears in the
  build report with `reproducibility: "reproduced"`, and the build journal reports
  `State: Built`. Save the Nix result path and logs. Published-artifact testing
  still follows in section 4.

- [ ] **Finalize both Linux images and the OCI artifacts.** Run
  [finalize-image](canonical-releases.md#finalize-each-linux-image) for each
  planned Linux assembly. Follow the registry runbook's external container
  signing and immutable graph upload procedure before registry finalization.

  **Check when:** both images have `finalized/` outputs and
  `finalized-image-set.json`, all requested disk formats passed byte-equivalence
  verification, and the signed OCI release/layout covers both Linux platforms.
  The authorities must belong to this release. Unsigned outputs and fixture
  keys do not satisfy this item.

- [ ] **Finalize the registry and cache.** Run
  [finalize-registry](canonical-releases.md#finalize-the-isolated-registry)
  with the exact build report and finalized container sidecar, followed by
  [finalize-cache](canonical-releases.md#generate-and-sign-the-static-cache)
  against that isolated registry.

  **Check when:** both commands exit zero, their result files identify the
  planned package/platform outputs, and cache narinfo signatures verify.
  Preserve the isolated registry, cache, and signer records.

- [ ] **Review build evidence and close the bundle.** Assemble the payload and
  unsigned manifest as specified in
  [close and sign the bundle](canonical-releases.md#close-and-sign-the-bundle).
  Include build observations, SBOM/advisory decisions, licenses, and matching
  corresponding source. Run `aos release finalize`, with output `finalized/`.

  **Check when:** required build observations passed, every advisory has a
  disposition with no unresolved release blocker, and finalization exits zero.
  Expect `finalized/bundle/` and `finalized/release-journal.jsonl`; its state must
  be `Finalized`.

- [ ] **Verify the bundle independently.** Run
  [release verify](canonical-releases.md#verify-a-captured-bundle-offline) on
  `finalized/bundle/` with `finalized/release-journal.jsonl` and public keys
  obtained independently of the bundle.

  **Check when:** verification exits zero and names this release and the
  `Finalized` journal state. Save the output. Missing files, wrong signatures,
  and mismatched digests stop the release.

## 4. Test the release in staging

- [ ] **Publish the finalized bundle to staging.** Run
  [release stage](canonical-releases.md#stage-a-finalized-m1-bundle) with
  `finalized/bundle/`, `finalized/release-journal.jsonl`, and staging-only
  credentials. Use `release-staging/` for its output.

  **Check when:** the command exits zero after anonymous read-back,
  `release-staging/staging-receipt.json` exists, and its journal reports
  `State: Staged`. This checks delivery; functional testing comes next.

- [ ] **Assign every required test.** List the tests for the exact bundle:

  ```sh
  aos release qualification cases \
    --plan "$AOS_RELEASE_WORK/release-plan.json" \
    --manifest "$AOS_RELEASE_WORK/finalized/bundle/release-manifest.json" \
    --phase staging > "$AOS_RELEASE_WORK/staging-cases.json"
  ```

  **Check when:** every listed case has an assigned program/environment or
  operator. The output says `not-evaluated`: this box means the work is assigned,
  not that it passed. An unavailable environment does not make a case optional.
  Compare the cases with the recorded support matrix: every Tier 1 combination
  must be covered, with the cycle counts and package checks from the acceptance
  criteria. Verify Tier 2 artifact obligations in the build report.

### Manual checks before collecting the staging report

Perform these while release mutations are paused, using an isolated restore/test
environment. Record each result in this release's operator report for the
collector to include in the corresponding case. If the collector cannot ingest
a required manual result, stop and fix that tooling.

- [ ] **Restore the backup without the original working files.** Run the
  configured jobs on the designated maintainer machine:

  ```sh
  systemctl start aos-release-backup.service
  systemctl start aos-release-restore-check.service
  systemctl show aos-release-backup.service aos-release-restore-check.service \
    -p Result -p ExecMainStatus
  journalctl -u aos-release-backup.service -u aos-release-restore-check.service
  ```

  In the clean restored directory, verify the retained bundle using
  `aos release verify` and independent public keys. Locate the request, plan,
  journal, receipts, and signer records.

  **Check when:** the backup is held independently of the maintainer machine,
  both jobs report `Result=success` and `ExecMainStatus=0`, offline verification
  succeeds, and no required record is missing. Record the backup identifier,
  restored manifest digest, and recovery duration. A successful backup upload
  alone is insufficient.

- [ ] **Recover and verify the signing authorities.** Restore their encrypted
  backup into the isolated environment using the secret store's recovery
  procedure. For every required role, compare its recovered public identity with
  the plan, sign a non-public test payload, and verify with the independent key.

  **Check when:** every role is recoverable and each test signature verifies.
  Record role/key IDs and the restricted recovery-log reference. Never record
  private key bytes in this checklist or public evidence.

- [ ] **Recover the Hub into an isolated deployment.** Follow
  [capture a recovery point](aos-hub-backup-recovery.md#capture-a-planned-recovery-point)
  and the [isolated restore procedure](aos-hub-backup-recovery.md#routine-restore-exercise).
  Check login/permissions, registry generations, object inventories, and anonymous
  package/image/container reads in the restored deployment. Candidate, stable,
  and emergency also require portable database export/import; an in-place PITR
  bookmark cannot satisfy that check.

  **Check when:** the recovered deployment serves the expected bytes and state,
  object/row comparisons reconcile, and the required recovery method worked.
  Record backup and test-deployment identities, comparisons, and duration.

- [ ] **Test key rotation and interrupted publication.** In the isolated
  environment, follow the [testing rotation procedure](registry-testing.md#rotate-keys-without-resetting-trust)
  or [main key policy](registry-main.md#keys-rollback-recovery-and-removal).
  Verify that a
  clean client starting with the old anchor accepts the legitimate successor
  and rejects an unauthorized replacement. Interrupt publication before and
  after commit; verify retry or a new corrective release gives the intended
  public result.

  **Check when:** trust continuity and rejection both work, and each interrupted
  publication has one known final state with matching bytes and generation.
  Retain client results, failed attempts, and publication receipts.

- [ ] **Verify alert delivery.** In the isolated test setup, deliberately fail
  each configured release, timestamp, backup, and restore job. Inspect its
  failure log and confirm delivery to the configured on-call maintainer.

  **Check when:** that maintainer acknowledges an actionable alert for each job,
  with no secret material in the messages. Record those acknowledgments. A log
  entry without delivered notification is a failure.

- [ ] **Test any physical-hardware qualification claims.** If physical targets
  remain Tier 2 and no additional tested feature is advertised, record that scope
  and mark this item inapplicable. For Tier 1 promotion or a tested feature claim,
  install the exact candidate on each representative configuration and record
  model, firmware, controller, storage durability
  settings, and TPM state. On disposable data, interrupt power during update
  and persistence, recover, verify acknowledged data, and update again.
  Redundant-storage claims also need disk replacement, boot from each ESP,
  rebuild, and unlock tests; other device claims need their own workload tests.

  **Check when:** every claimed configuration passes its boot, recovery,
  data-preservation, and workload checks with recorded equipment identities.
  Do not interrupt power or restore data on a live production system.

### Collect and approve the staging result

- [ ] **Run the functional tests and collect all results.** Use
  [qualify-run](canonical-releases.md#run-the-native-qualification-matrix) with
  `--phase staging --prepare-only --qualified-at now` and output
  `qualification-prepared/`. Programs must test the exact downloaded candidate
  and predecessor and include the recorded manual results.

  **Check when:** the command exits zero and every case in `staging-cases.json`
  has a passing result in `qualification-report.json` with retained logs in
  `reports/`. Inspect evidence for installation/provisioning, packages,
  configuration, HTTP/TLS, containers, reboot persistence, upgrade, interrupted
  update, fallback, rollback, offline recovery, and another successful update,
  as required by each case. Inspect committed-data checks and failed attempts
  too; missing or failed results leave this box unchecked.

- [ ] **Review and sign the exact report.** Obtain the class's required
  independent review using
  [collect, review, and sign](qualification.md#collect-review-and-sign).
  Repeat `qualify-run` with `--report-input`, required `--review-receipt` values,
  and output `qualification/`, omitting `--prepare-only`.

  **Check when:** the command exits zero, the required reviewer approved these
  exact report bytes, and `qualification/signed-qualification.json` exists.
  Retain the whole directory. Changing a report requires another review and
  signature. For edge, omit the independent review only if the plan permits it.

- [ ] **Admit the result to staging.** Run
  [release qualify](canonical-releases.md#admit-signed-qualification) with the
  staged journal/receipt and `qualification/`. Use `release-qualified/` as output.

  **Check when:** the command exits zero, the qualification receipt is retained,
  and its journal reports `State: Qualified`. Only then proceed to production.

## 5. Import the qualified release into production

- [ ] **Prepare and publish the required TUF metadata.** Construct the
  [immutable TUF set](canonical-releases.md#construct-immutable-tuf-metadata),
  then [refresh, compose, and publish the timestamp](canonical-releases.md#refresh-tuf-timestamp-metadata)
  using the finalized bundle and intended registry surface. Use the authenticated
  root and exact next metadata versions. This does not advance channel partitions.

  **Check when:** all commands exit zero, public metadata points to this exact
  manifest with an unexpired timestamp, and publication evidence is saved.
  Confirm the renewal timer is active and its next run precedes expiry.

- [ ] **Promote the exact qualified bundle.** Switch to production-only access
  and run [release promote](canonical-releases.md#promote-exact-bytes-to-production).
  Supply the qualified journal/receipts and original `qualification/` directory
  containing report bodies and reviews. Use `release-promoted/` as output.

  **Check when:** promotion and anonymous read-back succeed,
  `release-promoted/production-receipt.json` exists, and the journal reports
  `State: Promoted`. For OCI, finish the registry runbook's release-tag
  publication against the promoted signed sidecar and save the verified result.

- [ ] **Start workload observation.** Start the configured workload monitor on
  the exact production artifacts. Record machines/runtime, artifact digests,
  UTC start, workload, and required duration. Measure successful/failed operations,
  reboots, updates, recovery attempts, resource growth, and data integrity.

  **Check when:** the monitor is running and recording actual operations. This
  starts observation; section 7 determines when it has passed. A timer without
  a workload is not evidence.

## 6. Advance each planned channel range

Repeat these three items for **each** range, keeping separate results. Use the
latest journal: `release-promoted/` first, then the previous range's output.

- [ ] **Collect fresh health results for the next range.** Record the channel,
  observed prior generation, and inclusive first/last partitions in
  `NEXT_RANGE.json`. Run `qualify-run --phase rollout --prepare-only` with the
  production receipt, latest journal, and `--rollout-intent NEXT_RANGE.json`.
  Review and sign using the staging process and a new output directory.

  **Check when:** the request matches the plan and live generation, clean clients
  consume the intended artifacts, no integrity/recovery failure is unresolved,
  and the signed health approval is at most ten minutes old. Use the
  [rollout arguments](qualification.md#collect-review-and-sign), including the
  production receipt key rather than the staging key.

- [ ] **Advance only that range.** Run
  [channel advance](canonical-releases.md#advance-a-planned-channel-range) with
  the same journal, channel, generation, partitions, and signed qualification.
  Use a new output directory named for the range.

  **Check when:** the command exits zero after verifying selected public
  partitions, a new `channel-receipt.json` exists, and the journal reports
  `State: Rolling`. Record this as the latest journal.

- [ ] **Check the clients reached by this range.** Inspect workload monitoring
  and clean-client package/image/container consumption. Testing also requires
  the profile/warning checks in
  [its runbook](registry-testing.md#publish-the-first-or-a-later-edge-release).

  **Check when:** clients receive the intended release and no unexplained boot,
  trust, data-preservation, or recovery failure is present. Otherwise stop
  expansion and follow the failure procedure below.

## 7. Finish and hand over the release

- [ ] **Complete workload observation.** Run the section 5 workload for the
  full plan duration. Review operation counts, failures, resource trends, and
  recovery/data checks with the release owner.

  **Check when:** measured elapsed time meets the requirement, real operation
  counts are present, and no blocking failure remains. Investigate failures and
  retain logs before starting a new acceptance window. Do not backdate results
  or use synthetic fixture timing as an observation report.

- [ ] **Verify retention and assign ongoing owners.** Check retained release
  bytes, matching source, plans, journals, receipts, metadata, reports, and
  private operator records. Record retention deadlines, the monitoring/renewal
  owner, recovery contact, and published known limitations.

  **Check when:** retained objects can be read back, required backups are
  verified, and named maintainers have accepted renewal, monitoring, and recovery
  responsibilities. Main also needs its compatibility/support obligations recorded.

- [ ] **Approve completion and close the journal.** Run `qualify-run` for
  `--phase complete` against the production receipt and final rolling journal;
  review and sign the completed observation report. Obtain the separate
  release-evidence completion approvals, then run
  [channel complete](canonical-releases.md#complete-a-rollout) with every channel
  receipt and signed completion qualification. Use `release-complete/` as output.

  **Check when:** the command exits zero after checking all planned ranges and
  public partitions, and this command reports `State: Complete`:

  ```sh
  aos release status \
    --journal "$AOS_RELEASE_WORK/release-complete/release-journal.jsonl"
  ```

  Save the output and completed checklist. This is the release's final check.

## If a step fails or is interrupted

Stop the next publication or channel change. Preserve the command, logs, output
directory, and failed-attempt directories. Run `aos release status --journal`
with the last saved journal and record its state. If a network operation may
have committed, inspect the live registry and receipts before retrying; a local
timeout does not establish that the public operation failed.

Resume only when recorded and live state agree and the same inputs still apply.
Never delete evidence to force a retry or edit signed artifacts to make a check
pass. Changed source, artifacts, or policy need new release evidence. After
public discovery changes, publish a reviewed corrective release using the
registry runbook. A testing root reset is a separate operation, not an automatic
response to a failed release.
