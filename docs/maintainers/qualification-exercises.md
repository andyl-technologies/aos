# Qualification exercises

These procedures apply to the shared release contract. The selected class and
target determine which exercises are required. Record actual observations and
failed attempts. A written procedure or backup manifest alone is not evidence
that an exercise passed.

## Record an exercise

Capture requirement/case identity, release/manifest and predecessor identities,
actual equipment and firmware inventory, executor identity, operator, reviewer
where required, UTC start/end, each acceptance result, operation counts, and
references to logs. Public evidence contains no credentials or secret bytes;
refer to restricted records by an opaque identifier and digest.

Use an isolated exercise environment and disposable workload data. Equipment
identities and destructive targets must be resolved before power interruption,
disk replacement, restore, or key-retirement steps. Publication authorization
does not authorize destructive work on unrelated operator infrastructure.

## Independent operator restore

1. Select an encrypted backup stored independently of the maintainer machine.
2. Restore into a clean environment without reading the original working state.
3. Derive public identities from restored role material and compare them with
   the frozen public roster. Exercise a non-public signing request and verify it.
4. Restore authoring state, policies, bundles, receipts, and journals; verify
   retained bundles offline using independently supplied public anchors.
5. Record recovery duration, missing dependencies, and every mismatch. Any
   missing authority or required release object fails the exercise.

## Hub recovery and publication interruption

Follow [Hub backup and recovery](aos-hub-backup-recovery.md) in an isolated
deployment. Validate topology/IAM, registry base and generations, retained
objects, anonymous package/image/OCI consumption, and deferred-work recovery.
Production requires portable database export/import and isolated restoration;
in-place PITR alone does not establish that capability.

Interrupt an upload before and after its public commit boundary. Resume from
retained evidence and verify exact bytes and one coherent publication. Abandon
a separate uncommitted release. Exercise a fix-forward successor after a
committed release. Record generation/receipt identities at every boundary.

## Key rotation and alerts

Exercise overlap and retirement with clean clients starting from the old public
anchor. Verify legitimate continuity and rejection of unauthorized roots. Keep
registry, boot, TUF, cache, qualification, and Hub roles separate. Use exercise
authorities when testing compromise/reset behavior.

Deliberately fail each monitored release, renewal, backup, and restore job in
the exercise deployment. Confirm the intended operator receives an actionable
alert without secret leakage. A log entry without delivery is not a pass.

## Physical storage and firmware qualification

Record model, controller, firmware, storage cache/durability settings, UEFI and
TPM configuration. Install the exact release image. Interrupt power at the
identified update/persistence boundaries, then verify boot selection, bounded
fallback, configuration consistency, and acknowledged workload data. Repeat
recovery and a subsequent update. A VM reset does not prove physical cache
durability.

For redundant-storage claims, independently exercise disk loss, boot from each
ESP, replacement, rebuild/import, TPM unlock, and offline recovery. For GPU,
watchdog, IPMI, cloud, or hypervisor claims, record the exact supported device
or provider configuration and exercise its documented workload and failures.
Do not generalize one equipment result to an untested architecture or model.

## Observation campaign

Run the declared workload and lifecycle operations for the class's required
window. Record machine count, execution mode, completed/failed requests,
updates, reboots, recovery attempts, resource growth, and data-integrity checks.
Investigate unexplained failures before restarting the acceptance window.
Preserve previous attempts. Report observed results with denominators; do not
translate a short zero-failure campaign into an uptime or failure-rate promise.
