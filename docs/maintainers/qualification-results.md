# Qualification results and approvals

This page specifies how the [release qualification](qualification.md)
contract is evidenced: requirements and cases, scoped gate digests, the
release journal, how reports are collected, reviewed, and signed, when a
result may be reused, and the public release record.

## Requirements, subjects, and results

The release-test catalog uses the AOS `lib.evalModules` fixed point. Feature
modules under `qualification/modules/` own their options, configuration and
assertions. The module registry discovers feature files automatically and
excludes `_`-prefixed implementation files. `qualification/default.nix` accepts
additional `modules`; normal `mkDefault`, `mkForce`, `mkIf`, `mkMerge` and list
ordering rules apply. Required acceptance floors still constrain the result.
Package classifications and target claims derive from the final configuration.
`profiles.nix`, `destinations.nix`, and `fitness.nix` own the three tables
above.

Each requirement specifies its hold point, subject population, observation
method, acceptance checks, numeric bounds, regression coverage, and invalidation
conditions:

| Requirement | Phase | Scope | Selected by |
| --- | --- | --- | --- |
| `build-integrity` | build | release | every profile |
| `staging-delivery` | staging | release | `smoke`, `functional`, `soak` |
| `package-function` | staging | packages | `smoke`, `functional`, `soak` |
| `rollout-health` | rollout | release | `functional`, `soak` |
| `rollout-observation` | complete | release | `soak` |
| `ability-native-activation`, `ability-native-kubernetes`, `ability-native-recovery`, `ability-crucible-baseline`, `ability-native-adapter-matrix` | staging | release | `smoke`, `functional`, `soak` |
| `image-installation`, `image-lifecycle`, `image-update-recovery` | staging | image targets | functional claims |
| `container-lifecycle` | staging | container targets | functional claims |
| `image-observation`, `container-observation` | complete | image and container targets | qualified claims |

The coordinator expands the requirements a destination selects into exact
cases:

- release-wide gates cover the frozen release artifacts;
- package gates cover each published package/platform cell independently;
- image claims cover each variant and their declared target configuration;
- OCI claims cover the multi-platform index and exact platform artifacts; and
- update cases additionally bind the frozen preceding release.

The case digest binds these choices, the frozen plan, and the complete artifact
records (including byte digests and sizes). Reusing logical artifact names
cannot reuse an observation for changed bytes. An observation records each acceptance
condition, immutable executor identity, actual environment identity, execution
times, operation counts, and the predecessor exercised. Missing, failed,
unknown, duplicated, future-dated, expired, or incorrectly scoped results
cannot satisfy a required case. Preserve failed attempts; a later pass does not
erase them from the operational record.

Two ages are fixed in `aos_release_format::qualification::limits`: rollout
observations and approvals expire after 10 minutes, and any other observation a
report relies on expires after 30 days. A3 cases additionally require
observation at least as long as the destination's soak, or the soak of an
accepted override.

Cases use `aos.release.qualification-case/v2`. Every target observation
includes a reviewed assessment bound to the canonical environment-profile digest. A1 contains the
reviewer's rationale and exact retained references, without execution times or
operation counts. A2 and A3 additionally contain a typed
`aos.release.environment-inventory/v1` document. The coordinator verifies its
digest and matches the ordered host-to-subject topology, CPU predicates, backend
versions, boot implementation, security properties, resources and device bindings.
An environment digest alone cannot establish compatibility.

Finalized images publish `aos.image.metadata/v2` with an
`aos.image.capabilities/v1` inventory. The Nix assembly captures the built
kernel's resolved configuration; the finalizer inventories signed module bytes
and firmware from the runtime, normal initrd and both recovery filesystems.
Built-in drivers come from that kernel's `modules.builtin`. Image observations
retain the complete metadata value and its subject artifact ID. The coordinator
checks its size and hash against the manifest, verifies required configuration
values and driver/firmware availability at the required stages, and binds direct
execution to the same capability digest. Build availability and observed device
binding are separate requirements.

`aos.release.qualification-report/v1` records coordinator-derived claim outcomes
alongside the observations. Consumers recompute those outcomes; an executor
cannot assign its own assurance. Missing, failed and stale optional claims remain
visible and do not block approval. A malformed or incorrectly bound result is
rejected even for an optional claim. A complete functional run with insufficient
observation duration can establish A2 but cannot satisfy an A3 obligation. Reports
require the configured authority signatures and the destination's review
threshold before they authorize release operations.

Build checks run during assembly: the build report binding and the
repeat-build and advisory tier policies fail assembly directly, so a validated
manifest satisfies `build-integrity` and carries no separate build results.
Staging observations refer to that finished manifest and its signed staging
publication record. Rollout and completion observations are later records;
never mutate the original manifest to add results that did not exist when it
was signed.

### Scoped gate digests

Each gate identity is digested over only what it depends on, under the domain
`aos.release.gate-policy/v1`:

- a requirement gate digests the requirement; and
- a claim gate `claim-<id>` digests the claim, its target, and the requirements
  the claim references, in contract order.

Each planned destination additionally carries a `profile_digest` over its
profile under `aos.release.qualification-profile/v1`. Soak, review, fitness,
and ring changes therefore change the destination's binding without
invalidating case results for unrelated targets. Each gate records whether it
is `blocking`: requirement gates always block, and a claim gate blocks when its
claim does.

A plan's destinations each carry their own gate list, equal to
`contract.gates(destination, change_scope)`. There is no plan-wide gate union.

## Release journal and approvals

Each release keeps an append-only, hash-chained journal
(`aos.release.journal-entry/v1`). It records three global states and then one
state per planned destination:

```text
planned -> built -> finalized -+-> published(staging/c)    -> rolling -> complete
                               +-> published(production/c) -> rolling -> complete
any non-terminal state -> failed
```

- `planned`, `built`, and `finalized` are global and linear.
- A destination may become `published` once the release is `finalized` and
  every surface role in its `after` list already holds a published, rolling, or
  complete entry for the same release. Production destinations wait for
  staging; staging destinations wait for nothing.
- A published destination advances to `rolling` with its first ring, stays
  `rolling` across later rings, and becomes `complete` when its rollout is
  closed.
- Destinations interleave: publishing `production/candidate` does not wait for
  `staging/stable` to complete, and `production/stable` may be published while
  `production/candidate` is still rolling.
- `failed` is reachable from any non-terminal state and is terminal for the
  release bytes. The release succeeds when every planned destination is
  `complete`.

There is no separate tested state. The signed staging-phase test approval of a
production destination is attached, by digest, to that destination's
published entry. Rollout and completion approvals are attached to the rolling
and complete entries they authorize. The approvals of one release are
therefore independent per destination: a test failure for
`production/stable` does not undo `production/candidate`.

## Collect, review, and sign

`aos maintain release advance` performs this section's steps for each destination and
stops at every human decision. The underlying leaf commands are documented here
because their inputs and outputs are the test results and approvals.

Inspect the actual case population before allocating machines:

```sh
aos maintain release step qualification cases \
  --plan "$WORK/plan.json" \
  --manifest "$WORK/finalized/bundle/release-manifest.json" \
  --to production/candidate --phase staging
```

This command displays requirements, a `case_digests` map keyed by case ID, and
an `environment_profile_digests` map for target cases. It applies the
destination's profile and the plan's change scope. It does not verify
signatures or claim a pass. Use `aos maintain release step verify` with independent
public anchors for verification. `aos maintain release explain --to <destination>`
prints the same population with the current status of every case.

Run `aos maintain release step qualify-run --to <destination> --phase staging
--prepare-only` with the bundle, the signed staging publication record
(`--publication-receipt`), applicable executor mappings, and
`--qualified-at now` described in
[the runbook](release-step-commands.md#run-the-native-qualification-matrix).
For staging image update cases, also supply the retained snapshot through an
absolute `--predecessor-bundle` path.
Inspect the prepared report and its retained `reports/` directory. Each
reviewer signs an independent review payload with a planned `release-evidence`
key, either through `aos maintain release review` or directly:

```json
{
  "schema_version": "aos.release.qualification-review/v1",
  "plan_digest": "sha256:<canonical-plan-hash>",
  "report_digest": "sha256:<exact-prepared-report-hash>",
  "authority_id": "<planned-reviewer-key-id>",
  "accepted": true
}
```

Use the existing signed-record envelope: Ed25519 signs the SHA-256 of
`aos.hub.release-evidence-signature/v1`, a NUL byte, then the canonical payload.
This is `RECEIPT_SIGNATURE_DOMAIN` in `crates/release/aos-release-format/src/receipt.rs`.
Keep review signing under the configured authority provider, outside the Nix
store. The destination's profile sets the review threshold: `functional` and
`soak` require one reviewer, `smoke` and `build` none. A reviewer may be added
voluntarily where none is required. Human independence and custody are
confirmed in the maintainer checklist; separate key IDs alone do not establish it.
A rejected review (`"accepted": false`) stops the destination; the report must
be recollected.

Repeat `qualify-run` with `--report-input PREPARED/qualification-report.json`
and each `--review-receipt PATH`, omitting `--prepare-only`. The authority checks
and signs the same report. Its output atomically retains report bodies,
reviews, and signatures. Keep that entire directory and the separately retained
`.aos-qualification-attempt-*` directories. `step publish` and `step record`
recheck the original report directory, including its bodies and reviews; a
copied aggregate JSON file alone is insufficient.

For rollout, use `--phase rollout --ring N --prior-generation G` with the
destination's current signed publication record (`--publication-receipt`) and
the current journal. The command derives the ring's partition range from the
planned rings; `G` is the channel generation observed on the live surface.
Rings are numbered from 1 in profile order.

For completion, use `--phase complete` with the destination's signed
publication record and rolling journal. These authority signatures bind the
exact report, policy, manifest, publication record, entire journal, and next
ring where applicable. Channel commands require the signed rollout approval
when the profile has a rollout-phase gate; observations and approvals at rollout must be
at most ten minutes old. Recollect health for each new ring. A completion
approval must also be fresh, while its workload report covers the full soak
window. Campaigns lasting days run outside a single bounded executor process;
import their retained observations for review and approval.

## Test execution and reuse

Package testing expands every published package/platform cell into a
separate case. A package published for both `x86_64-linux` and `aarch64-linux`
requires successful observations for both; a local check on one architecture
does not satisfy the other. Package publication support policy determines
which cells apply. The package probe schema has no architecture selector that
can silently exempt an otherwise published cell. Only a change-scoped profile
narrows the population, and only to cells whose artifact set changed; see
[change scoping](qualification.md#change-scoping).

Recovery and K3s package cases also bind their published execution image. The
shared policy's `qualification.packageExecutionImageVariant` defaults to
`aos-experimental`, whose canonical image contains the public release profile and
trust inputs. Recovery and fleet executors derive their image variant from the
same package rule. Alternate reviewed contracts can select another canonical
published variant; a fixture image name is not an implicit substitute. Plan
validation rejects a missing execution image or platform before builds and
signing, rather than waiting for staging case expansion.

`qualify-run` routes each case to its platform's `--executor` mapping. The
package executor runs natively and validates the requested platform; it does
not create a VM itself. To test packages in Linux VMs, provision an executor
inside each architecture's VM and route the corresponding mapping to it.
Installing both executor closures on a coordinator does not establish that
either ran inside a VM. Retain the execution environment with the resulting
test results. Image tests separately boot the exact published image.

Nix derivations own hermetic evaluation, build, and fixture/fleet regression
tests. Nix-packaged executors own fresh public-download and live-environment
release tests. Physical equipment and operator observations use the same
acceptance checks and result model. Do not put deployment credentials or
private signed records in Nix inputs, the store, or public reports.

The existing fleet tests may add agents or controlled fault hooks. Their
results describe those fixtures. Exact-artifact release testing boots the
published immutable image using its supported provisioning and serial/SSH
interfaces; it must not rebuild the image to insert a test agent.

Run the pure policy check with:

```sh
nix-build -A checks.qualification.policy --no-out-link
```

The Rust policy fixture is generated by evaluating `qualification/default.nix`
with package names `aos`, `nginx`, `containerd`, and `runc`. The Nix check compares
that fixture with the authoritative data so schema tests cannot drift silently.

A test result is reusable only for unchanged subjects, policy, executor, and
environment under its age limit. New update pairs need new transition results.
Firmware, kernel, bootloader, initrd, storage, updater, and harness changes
invalidate dependent results. Live surface health always needs a fresh
observation. Uncertain impact selects the broader campaign. Scoped gate digests
keep this rule honest: a claim gate changes only when its claim, target, or
referenced requirements change, so results for an unrelated target survive a
policy edit elsewhere in the contract.

## Public release record

Registry finalization precedes release testing, so the test outcome cannot
live in the registry tree. After the staging-phase report for a production
destination is signed, `aos maintain release step record` composes
`aos.release-record/v1` from the frozen plan, the final manifest, the signed
test approval, and the public report, and the TUF and compose-surface steps
authorize and serve it beside the release manifest on that destination's
surface. The
record carries the result, policy, authority, and approval time
(`qualified_at`); each claim's required and achieved assurance and
disposition; the train's support statement; provenance digests; and the exact
signed envelope. Achieved assurance describes the results at approval; later
invalidation is recorded in a subsequent release, not by editing the record. See
[`canonical-releases.md`](release-step-commands.md#compose-the-public-release-record).
