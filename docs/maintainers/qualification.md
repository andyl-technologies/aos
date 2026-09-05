# Release qualification

AOS uses one versioned server contract for testing and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
The release class selects obligations in that contract; operators cannot
remove individual mandatory gates from a release request.

Use the [release checklist](release-checklist.md) to operate a release and the
[canonical runbook](canonical-releases.md) for command details. Physical and
operational work is specified in [qualification exercises](qualification-exercises.md).

## Inspect and freeze the contract

```sh
aos release contract --class edge --output qualification-contract.json
aos --json release contract --class edge
aos release contract --class stable --input qualification-contract.json
```

The output lists requirements, never claims that they passed. JSON output
contains the exact `gates` and `public_evidence_policy_digest` for the reviewed
plan request. `--output` writes a new canonical file and refuses replacement.
`--input` supports inspection without Nix or network. New plans use
`aos.release.plan/v2` and embed the complete contract; older v1 bundles remain
readable for archival verification.

Record a `qualification_predecessor` with the same registry, a distinct
`release_id`, and the verified preceding `manifest_digest`. First public
releases use a retained signed qualification snapshot as their predecessor.
A testing-to-main transition is a new main release and installation unless a
separate authenticated migration contract has been implemented and qualified.

## Shared obligations

| Obligation | Edge/testing | Candidate | Stable/emergency |
| --- | --- | --- | --- |
| Authentic artifacts, complete closures, source/license evidence | Required | Required | Required |
| Both reference Linux disk and OCI environments | Required | Required | Required |
| Declared install, configure, package, update, recovery workflows | Required | Required | Required |
| Blocked additional package/platform cells | Explicitly permitted | Explicitly permitted for incomplete candidates | Forbidden |
| Mixed-workload observation | 24 hours | 7 days | 14 days |
| Independent review and production recovery | Recorded testing arrangement | Required | Required |
| Operational exercise age | At most 30 days | At most 30 days | At most 30 days |

Durations are engineering policy, not statistical failure-rate claims. Record
machines, workload, attempts, successes, failures, and recovery operations.
Emergency is not a switch that removes integrity or recovery requirements.
Changing its observation rule requires a reviewed policy revision first.

## Requirements, subjects, and evidence

Each requirement specifies its hold point, subject population, observation
method, acceptance checks, regression coverage, and invalidation conditions.
The coordinator expands requirements into exact cases:

- release-wide gates cover the frozen release artifacts;
- package gates cover each published package/platform cell independently;
- image gates cover each variant and reference machine configuration;
- OCI gates cover the multi-platform index and exact platform artifacts; and
- update cases additionally bind the frozen preceding release.

The case digest binds these choices, the frozen plan, and the complete artifact
records (including byte digests and sizes). Reusing logical artifact names
cannot reuse an observation for changed bytes. An observation records each acceptance
condition, immutable executor identity, actual environment identity, execution
times, operation counts, and the predecessor exercised. Missing, failed,
unknown, duplicated, future-dated, expired, or incorrectly scoped evidence
cannot satisfy a required case. Preserve failed attempts; a later pass does not
erase them from the operational record.

Build observations belong in the immutable manifest. Staging observations
refer to that finished manifest and its staging receipt. Rollout and completion
observations are later records; never mutate the original manifest to add
evidence that did not exist when it was signed.

## Collect, review, and sign

Inspect the actual case population before allocating machines:

```sh
aos release qualification cases --plan release-bundle/release-plan.json \
  --manifest release-bundle/release-manifest.json --phase staging
```

This command displays requirements; it does not verify signatures or claim a
pass. Use `aos release verify` with independent public anchors for verification.

Run `aos release qualify-run --prepare-only` with the bundle, publication
receipt, applicable executor mappings, and `--qualified-at now` described in
[the runbook](canonical-releases.md#run-the-native-qualification-matrix).
Inspect the prepared report and its retained `reports/` directory. Sign an
independent review payload with a planned `release-evidence` key:

```json
{
  "schema_version": "aos.release.qualification-review/v1",
  "plan_digest": "sha256:<canonical-plan-hash>",
  "report_digest": "sha256:<exact-prepared-report-hash>",
  "authority_id": "<planned-reviewer-key-id>",
  "accepted": true
}
```

Use the existing signed-receipt envelope: Ed25519 signs the SHA-256 of
`aos.hub.release-evidence-signature/v1`, a NUL byte, then the canonical payload.
This is `RECEIPT_SIGNATURE_DOMAIN` in `crates/aos-release/src/receipt.rs`.
Keep review signing under the configured authority provider, outside the Nix
store. Review thresholds are required for candidate, stable, and emergency.
Testing may include reviews voluntarily. Human independence and custody are
confirmed in the maintainer checklist; separate key IDs alone do not prove it.

Repeat `qualify-run` with `--report-input PREPARED/qualification-report.json`
and each `--review-receipt PATH`, omitting `--prepare-only`. The authority checks
and signs the same report. Its output atomically retains report bodies,
reviews, and signatures. Keep that entire directory and the separately retained
`.aos-qualification-attempt-*` directories. `qualify` and `promote` recheck the
original report directory, including its bodies and reviews; a copied aggregate
JSON file alone is insufficient.

For rollout use `--phase rollout --publication-receipt PRODUCTION_RECEIPT`
(the latter aliases `--staging-receipt`), the production Hub receipt key,
`--journal CURRENT_JOURNAL`, and `--rollout-intent NEXT_RANGE.json`:

```json
{"channel":"edge","first_partition":0,"last_partition":31,"prior_generation":0}
```

For completion use `--phase complete` with the current production receipt and
rolling journal. No rollout intent is supplied. These authority signatures
bind the exact report, policy, manifest, publication receipt, entire journal,
and next range where applicable. Channel commands require `--qualification`
and `--qualification-key`; observations and approvals at rollout must be at
most ten minutes old. Recollect health for each new range. A completion
approval must also be fresh, while its workload report covers the full selected
observation window. Campaigns lasting days run outside a single bounded RPC;
import their retained observations for review and admission.

## Native executors

`lib.testing.mkQualificationExecutor` (from `lib/testing`) packages a runner
with explicit `platform`, `identity`, `scenarios`, absolute `workRoot`, and
`timeoutSeconds`. `scenarios` maps requirement IDs to absolute executables in
AOS-built Nix closures. Missing implementations fail; an empty adapter is never
a passing gate. Environment-specific adapters and remote macOS transport must
be provisioned before a campaign. All source regression groups are exposed at
`checks.qualification.<requirement-id>` and `checks.qualification.all`.

The runner reads a canonical v2 executor request on stdin. It verifies every
anonymous HTTPS download's size and SHA-256, retains it under a hashed name,
and writes `request.json`, `scenario-registry.json`, and `objects.json` in a
private attempt directory. The configured scenario receives the request on
stdin and runs in that directory with no inherited environment. `objects.json`
maps artifact IDs to the verified local paths. Scenarios use AOS-built tools
and the published image's normal provisioning and serial/SSH interfaces.

The scenario emits `QualificationExecutorResponseV1`. Its observation must
contain the exact case digest, acceptance checks, and predecessor. Set
`executor_digest` to the SHA-256 of the retained scenario registry bytes;
its store paths bind the executable closures. Include the actual non-sensitive
environment inventory in `report.environment`, and set `environment_digest`
to its canonical JSON SHA-256. Record real UTC times and measured workload
counts. The runner checks this binding and retains response bytes, stdout,
stderr, and failures. Coordinator attempts retain each request and returned
response, including rejected results. Never overwrite a failed attempt.

A fixture gate proves regression behavior only. The native Hub fleet uses
visibly synthetic observations and timing to test admission mechanics; those
records cannot establish release workload duration or physical reliability.
The same acceptance conditions govern real automated and operator adapters.

## Qualification roles and public status

Package roles describe consequences: `system-integrity`, `qualified-workload`,
or `general-catalog`. Dependencies inherit the obligations of the root that
uses them. The authenticated runtime closure is the source of dependency
membership. A library used by boot or recovery cannot avoid those tests by
being listed as a general catalog package.

Public status is separate: qualified for testing, preview, blocked, or not
applicable. A reference target in the contract is a requirement, not a passing
hardware claim. Publication integrity applies equally to preview packages.
Known failure of an advertised basic function blocks that artifact. Successful
builds and `--version` checks do not establish complete functionality.

## Test execution and reuse

Nix derivations own hermetic evaluation, build, and fixture/fleet regression
tests. Nix-packaged executors own fresh public-download and live-environment
qualification. Physical equipment and operator observations use the same
acceptance/evidence model. Do not put deployment credentials or private
attestations in Nix inputs, the store, or public reports.

The existing fleet tests may add agents or controlled fault hooks. Their
results describe those fixtures. Exact-artifact qualification boots the
published immutable image using its supported provisioning and serial/SSH
interfaces; it must not rebuild the image to insert a test agent.

Run the pure policy check with:

```sh
nix-build -A checks.qualification.policy --no-out-link
```

The Rust policy fixture is generated by evaluating `qualification/default.nix`
with package names `aos`, `nginx`, `containerd`, and `runc`. The Nix check compares
that fixture with the authoritative data so schema tests cannot drift silently.

Evidence is reusable only for unchanged subjects, policy, executor, and
environment under its age limit. New update pairs need new transition evidence.
Firmware, kernel, bootloader, initrd, storage, updater, and harness changes
invalidate dependent results. Live Hub health always needs a fresh observation.
Uncertain impact selects the broader campaign.

## Policy changes and standards

Review contract changes as release-authority changes. Preserve historical
policy bytes with each release. Requirements use stable IDs; a semantic change
changes the policy digest. Unknown schemas fail closed. Keep identifiers for
truly inapplicable package targets distinct from required but blocked work.

The design borrows assurance-case structure from ISO/IEC/IEEE 15026-2,
quality categories from ISO/IEC 25010, and traceability, failure analysis,
controlled change, and verification practices from security and dependability
engineering. These are engineering references, not claims of EAL, SIL,
DO-178C certification, or full standards conformance.
