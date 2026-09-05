# Release checklist

Use this same checklist for testing, candidates, stable, and emergency releases.
Read the frozen plan's class, contract, registry, and target matrix first.
Detailed commands are in [canonical releases](canonical-releases.md); the
[qualification policy](qualification.md) determines applicable obligations.

Each checked item records operator, UTC time, observed identity/result, and an
evidence reference. An inapplicable item records the policy rule that excludes
it. An unchecked required item stops the associated transition. Do not change
the contract while completing a checklist for an already frozen candidate.

## Prepare: before builds or signing

- [ ] SOURCE — clean protected commit and contributor authorization verified;
  record commit and authorization-summary digest. Stop on mismatch or unknown.
- [ ] CONTRACT — exported policy, class, gates, targets, package roles, and
  predecessor match the reviewed request. Record policy and plan digests.
- [ ] IDENTITIES — registry epoch, staging/production deployments, base
  generation, and role keys match the plan. Stop on any unexpected identity.
- [ ] CUSTODY — required keys recover from independent encrypted backup;
  record the restricted exercise reference, never private material.
- [ ] RECOVERY — current operator/Hub recovery exercise is valid for this
  environment and class. Follow [the exercise](qualification-exercises.md).

## Finalize: before admitting a closed bundle

- [ ] BUILD — exact derivations and repeat-build checks passed; closure,
  SBOM/advisory dispositions, license, and source inventories are complete.
- [ ] ARTIFACTS — final external signatures, logical disk/encoding equivalence,
  OCI graph, recovery material, and fixture exclusions passed.
- [ ] BUNDLE — offline verification succeeds with independent public anchors;
  record manifest and bundle digests. Preserve the original bytes.

## Qualify: before production-Hub import

- [ ] STAGING — deployment receipt and anonymous downloaded bytes match the
  bundle. Stop on digest, size, registry, or deployment drift.
- [ ] FUNCTION — every applicable package, disk, and OCI case passed; inspect
  the structured observations and retained logs, including failed attempts.
- [ ] TRANSITIONS — preceding snapshot → candidate → recovery/rollback →
  candidate passed with configuration and committed-data checks.
- [ ] EXERCISES — required operator/hardware exercises have valid evidence;
  production review and restore obligations are satisfied where selected.
- [ ] ADMISSION — aggregate qualification is complete, current, and signed by
  the planned authority. Record report and receipt digests.

## Roll out: before each planned channel range

- [ ] PRODUCTION — current deployment and public bytes match the imported
  release; record production receipt and fresh health evidence.
- [ ] RANGE — requested channel, previous generation, and partition range are
  exactly planned. Stop on stale generation or unexpected channel state.
- [ ] HEALTH — clean-client consumption works and previous rollout observations
  satisfy the stop conditions. Stop expansion on unexplained integrity,
  bootability, data-preservation, trust, or required-recovery failure.

## Complete: before closing the journal

- [ ] OBSERVE — required workload duration and operation denominators are
  recorded; all failures have dispositions and no blocking condition remains.
- [ ] RETAIN — release bytes, corresponding source, policy, journals, receipts,
  public evidence, and restricted operator evidence meet their retention rules.
- [ ] HANDOFF — monitoring, alert delivery, recovery ownership, known limits,
  and user documentation match the release. Required independent approval exists.
- [ ] CLOSE — every planned range and public partition is verified; record the
  completion receipt and terminal journal identity.

## Abnormal operation

On interruption, preserve the work directory and journal, identify the last
verified state, and resume only the matching documented operation. Never turn
an ambiguous operation into a passing checklist item. A failed release is
abandoned or corrected with new immutable release evidence. After public
discovery moves, use the reviewed fix-forward/channel procedure; do not replace
published bytes. Testing root resets follow the registry runbook and create a
new epoch. Production does not inherit disposable testing-data permissions.
