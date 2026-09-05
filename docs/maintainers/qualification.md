# Release qualification

AOS uses one versioned server contract for testing and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
The release class selects obligations in that contract; operators cannot
remove individual mandatory gates from a release request.

Use the [release checklist](release-checklist.md) to operate a release and the
[canonical runbook](canonical-releases.md) for command details. Physical and
operational work is specified in [qualification exercises](qualification-exercises.md).
The [user contract](../users/aos/release-contract.md) explains the promises.

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

The case digest binds these choices. An observation records each acceptance
condition, immutable executor identity, actual environment identity, execution
times, operation counts, and the predecessor exercised. Missing, failed,
unknown, duplicated, future-dated, expired, or incorrectly scoped evidence
cannot satisfy a required case. Preserve failed attempts; a later pass does not
erase them from the operational record.

Build observations belong in the immutable manifest. Staging observations
refer to that finished manifest and its staging receipt. Rollout and completion
observations are later records; never mutate the original manifest to add
evidence that did not exist when it was signed.

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
