# Release qualification

AOS uses one versioned qualification (release-test) contract for every
registry and destination.
The authoritative inputs are [`qualification/`](../../qualification/default.nix).
A release is published to one or more **destinations**. Each destination
selects a named **profile**, and the profile states every check the release
must pass before that destination may be published: gates, selected claims,
soak, review, matrix completeness, environment fitness, and rollout rings.
Operators cannot remove individual gates from a plan; the only permitted
relaxation is a signed [profile override](#profile-overrides) of the fields a
profile marks overridable.

Environment recovery is not tested per release. Backup restore, authority
recovery, Hub restore, key rotation, and alert delivery are **fitness
exercises** performed on their own cadence. Each produces a signed, dated
[fitness attestation](#fitness-attestations) bound to the identities it covered,
and a profile requires fitness attestations no older than its stated maximum age.

Start with the [release checklist](release-checklist.md), which gives the order
of operations and the fitness exercise cadence. This page specifies the
contract and the formats of test results and approvals; the
[command reference](canonical-releases.md)
documents command arguments.

## Pages

| Page | Contents |
| --- | --- |
| [Qualification support matrix and acceptance checks](qualification-acceptance.md) | Assurance levels, test axes, required coverage, the acceptance checks for each target kind, and package roles |
| [Qualification results and approvals](qualification-results.md) | Requirements and cases, gate digests, the release journal, collecting, reviewing, and signing reports, result reuse, and the public release record |
| [Qualification executors](qualification-executors.md) | Executor packaging, scenarios, request and report formats, and operator setup |

## Destinations and profiles

### Surfaces and destinations

An unpublished **release stage** is an exact candidate id, revision, and
artifact inventory; it is independent of the deployment named staging. See
[release stages](../engineering/registry/release-stages.md).

A **surface** is one publication endpoint with the role `staging` or
`production`. It is either an AOS Hub deployment or a
[static origin](#static-surfaces). A **destination** is one surface role and
one channel of the plan's registry, written `<role>/<channel>`. The registry
comes from the plan, so `production/edge` in an `andyl/main` plan and
`production/edge` in an `andyl/experimental` plan are distinct destinations on
different registries.

The contract exports exactly these destinations. Anything else is not a
destination, and plan validation rejects it.

| Destination | Registry tier | Profile | Published after |
| --- | --- | --- | --- |
| `staging/edge` | production (`andyl/main`) and testing (`andyl/experimental`, `andyl/experimental-vN`) | `build` | nothing |
| `production/edge` | production and testing | `smoke` | a staging publication |
| `staging/candidate` | production | `build` | nothing |
| `production/candidate` | production | `functional` | a staging publication |
| `staging/stable` | production | `build` | nothing |
| `production/stable` | production | `soak` | a staging publication |

`andyl/main` carries `edge`, `candidate`, and `stable`. Experimental registries
(the `testing` tier) carry the `edge` channel only. A channel kind selects the same profile on every
tier that carries it: the tier describes the key custody and pipeline behind a
registry, not what a release must pass. A per-train channel such as
`stable-2026.3` has the kind of the prefix before its first `-` and selects
that kind's destination.

The release class, derived from the version, restricts which destinations a
plan contains. An edge version (`-dev.YYYYMMDD.N`) plans only edge
destinations. A release candidate (`-rc.N`) plans only candidate destinations.
A final version (`YYYY.M.P`) plans both candidate and stable destinations,
because the same bundle is published to `candidate` and then to `stable`.
Qualification snapshots plan no destinations.

Staging surfaces are maintainer-facing. A staging destination's `build` profile
requires only the build gate, and its channel moves as soon as the publication
is read back. Production destinations are consumer-facing and require that a
staging destination of the same release is already published.

### Profiles

A profile is a closed set of release requirements. The shipped values are in
[`qualification/modules/profiles.nix`](../../qualification/modules/profiles.nix):

| Profile | Requirements | Claims | Change scoped | Soak | Reviews | Complete matrix | Transaction review | Fitness (max age) | Rings (cumulative partitions @ observation) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `build` | `build-integrity` | none | no | none | 0 | no | no | none | 256 @ 0 |
| `smoke` | `build-integrity`, `staging-delivery`, `package-function`, native ability requirements | functional (A2) | yes | none | 0 | no | no | none | 256 @ 0 |
| `functional` | `smoke` plus `rollout-health` | functional (A2) | no | none | 1 | no | yes | `storage-restore` 14 d, `alert-delivery` 14 d, `authority-recovery` 90 d, `hub-restore` 90 d | 256 @ 0 |
| `soak` | `functional` plus `rollout-observation` | qualified (A2 and A3) | no | 7 days | 1 | yes | yes | `functional` plus `key-rotation` 90 d | 4 @ 24 h, 32 @ 24 h, 128 @ 48 h, 256 @ 0 |

The fields mean:

- **Requirements** are release- and package-scoped requirement IDs, each
  required at its own phase. Image and container requirements enter through
  the selected claims. The native ability requirements are
  `ability-native-activation`, `ability-native-kubernetes`,
  `ability-native-recovery`, `ability-crucible-baseline`, and
  `ability-native-adapter-matrix`; `functional` and `soak` inherit them from
  `smoke`.
- **Claims** selects target claims. `functional` selects every `*-functional`
  claim (A2, staging phase). `qualified` adds every `*-qualified` claim (A3,
  complete phase).
- **Change scoped** narrows image, container, and package obligations to what
  changed relative to the predecessor. See [change scoping](#change-scoping).
- **Soak** is the minimum observed window for A3 claims and
  `rollout-observation`.
- **Reviews** is the number of distinct reviewer signatures, made with
  `release-evidence` keys, required over each test report the destination
  accepts.
- **Complete matrix** rejects a plan with any blocked package/platform cell.
- **Transaction review** stops the pipeline after `prepare-registry` until an
  operator accepts the isolated registry transaction.
- **Fitness** names the fitness attestation kinds that must be fresh and
  binding-matched when the destination is published or advanced.
- **Rings** are ordered cumulative partition counts. Each ring must be observed
  for its stated time before the next ring advances. The last ring is always
  256. A single `256 @ 0` ring advances every partition at once.

`soak` is the only profile whose soak and rings are overridable. The other
profiles mark nothing overridable.

Every profile is subject to floors enforced by both the Nix module and the Rust
contract type:

- every profile requires `build-integrity`;
- `qualified` claims require `rollout-observation` and a soak of at least one
  day;
- rings are strictly increasing and end at 256;
- fitness kinds must be declared in the contract; and
- a candidate or stable destination whose profile selects claims requires at
  least one reviewer, on every tier. Edge makes no support promise, so its
  automated A2 test results are published without a review.

A reviewed contract revision may change shipped values with `mkForce`, within
those floors. Record the frozen plan's values; the plan binds each
destination's profile by digest.

### Hold points by destination

Each requirement has one phase. The phases a destination actually exercises
follow from its profile:

| Destination | Build | Staging (before publication) | Rollout (before each ring) | Complete |
| --- | --- | --- | --- | --- |
| `staging/*` | `build-integrity` | none | none | none |
| `production/edge` | `build-integrity` | `staging-delivery`, changed `package-function` cells, functional claims of affected targets | none | none |
| `production/candidate` | `build-integrity` | `staging-delivery`, every `package-function` cell, every functional claim | `rollout-health` | none |
| `production/stable` | `build-integrity` | as `production/candidate` | `rollout-health`, fresh for every ring | `rollout-observation`, every qualified claim |

The staging phase always tests the public bytes on the staging surface. Rollout
and complete phases test the destination's own surface. Only a profile that
selects `qualified` claims (`soak`) has a complete phase: its destination
needs a complete-phase report and the completion approvals signed with
`release-evidence` keys. A
destination of any other profile records `complete` automatically when its
final ring's channel advance and public read-back succeed.

### Change scoping

A change-scoped profile (`smoke`) applies obligations only where the release
differs from its predecessor:

- image claims apply only when the release is image-affecting;
- container claims apply only when any OCI artifact digest differs; and
- `package-function` applies only to package/platform cells whose artifact set
  differs.

Planning records the decision in an `aos.release.change-scope/v1` document
inside the plan. It compares image artifact digests, OCI artifact digests, and
per-cell package artifact digests with the predecessor manifest.
`step qualify-run` and publication recompute the scope from the finalized
manifest and reject any disagreement. When the predecessor manifest is
unavailable or the predecessor is a qualification snapshot, everything is
affecting. Uncertainty never narrows the set of tests.

```json
{
  "schema_version": "aos.release.change-scope/v1",
  "predecessor_manifest_digest": "sha256:<predecessor-manifest-hash>",
  "image_affecting": false,
  "container_affecting": true,
  "changed_package_cells": [["nginx", "aarch64-linux"], ["nginx", "x86_64-linux"]],
  "reason": "image artifact digests unchanged; OCI index and nginx cells differ"
}
```

Non-scoped profiles ignore the change scope and exercise every target and
every published cell.

### Fitness attestations

A fitness attestation shows that the release environment can recover. Its schema
is `aos.release.fitness-attestation/v1`. Fitness exercises replace the
per-release operator recovery exercises of earlier contracts:
nothing about a single release is observed by restoring a backup, and a quarterly
exercise bound to the identities it covered says more than a rushed one before
every publication.

| Kind | Method | Cadence | Bindings | Checks |
| --- | --- | --- | --- | --- |
| `storage-restore` | automated | weekly timer | `tooling` | `independent-encrypted-backup`, `restore-to-clean-environment`, `offline-verification-of-restored-bundle` |
| `alert-delivery` | automated | weekly timer | `alert-config` | `failed-unit-alert-delivered`, `acknowledged-by-on-call`, `no-secret-material-in-alert` |
| `authority-recovery` | operator | quarterly | `signer-roster` | `key-custody`, `recover-encrypted-authority-backup`, `test-signature-per-role-verifies` |
| `hub-restore` | operator | quarterly | `surface`, `hub-schema` | `isolated-hub-restore`, `portable-database-export-import`, `anonymous-readback-of-restored-deployment` |
| `key-rotation` | operator | quarterly | `signer-roster`, `surface` | `registry-key-rotation-trust-continuity`, `unauthorized-replacement-rejected`, `interrupted-publication-single-final-state` |

The maintainer machine's `aos-release-restore-check` and
`aos-release-alert-check` services record the automated kinds. Operators record
the others with `aos maintain release fitness run <kind> --report PATH`, or with the
report on standard input, after performing the exercise in the
[release checklist](release-checklist.md#fitness-exercises). The input is an
`aos.release.fitness-report/v1` exercise report: `performed_at`, `operator`,
and a `checks` map giving each of the kind's checks as `{passed, detail}`. The
command copies those fields into the fitness attestation below, adds the live
bindings, and records the report's SHA-256 as `evidence_digest`.
Profiles accept automated fitness attestations for at most 14 days and operator
fitness attestations for at most 90 days.

A binding names an identity the fitness attestation carries and publication
compares with the live value:

| Binding | Live value |
| --- | --- |
| `surface` | The destination surface identity: the Hub deployment ID, or the static surface identity served at `.aos-surface` |
| `hub-schema` | The Hub schema version reported by the deployment. A static surface has none; the binding is recorded as `null` and is satisfied vacuously |
| `signer-roster` | Digest of the plan's `signers` list, canonical JSON under the domain `aos.release.signer-roster/v1` |
| `tooling` | Digest of the installed release tooling closure's store path |
| `alert-config` | Digest of the maintainer configuration's `[alert]` section |

A binding mismatch makes a fitness attestation unusable regardless of its age. A
new signer roster therefore requires fresh `authority-recovery` and
`key-rotation` records; a new production surface requires fresh `hub-restore`
and `key-rotation` records for that surface; a new `aos` tooling closure
requires the next restore check to run before a `functional` or `soak`
destination can be published.

A fitness attestation is canonical JSON signed with the standard signed-record
envelope by a `release-evidence` key, stored under the maintainer
configuration's `fitness_root` as `<kind>/<performed_at>.json`:

```json
{
  "schema_version": "aos.release.fitness-attestation/v1",
  "kind": "hub-restore",
  "registry": "andyl/main",
  "performed_at": "2026-09-14T15:00:00Z",
  "checks": {
    "isolated-hub-restore": {"passed": true, "detail": "Restored recovery point rp-0914 into hub-restore-test."},
    "portable-database-export-import": {"passed": true, "detail": "Exported and imported the portable database; row counts reconcile."},
    "anonymous-readback-of-restored-deployment": {"passed": true, "detail": "Read back every indexed object anonymously."}
  },
  "bindings": {"hub-schema": "2026-09", "surface": "production-2026-09"},
  "evidence_digest": "sha256:<restricted-report-hash>",
  "operator": "dplecki",
  "authority_id": "release-evidence-v1"
}
```

`checks` contains exactly the kind's checks, all passed. `evidence_digest`
binds the retained restricted report; the fitness attestation itself carries no
secret, provider account, or internal address. Fitness attestations are
maintainer-wide, not per release: one fresh record serves every release that
publishes while it remains valid.

### Profile overrides

A profile override is the only way to relax a destination's obligations. It is
how AOS handles an emergency; no release class relaxes obligations. An
override is an `aos.release.profile-override/v1` document, threshold-signed by
`release-evidence` keys (one envelope per signer, reaching the role threshold),
that names one release, one destination, and an incident record:

```json
{
  "schema_version": "aos.release.profile-override/v1",
  "registry": "andyl/main",
  "release_id": "release-2026.9.1",
  "destination": "production/stable",
  "incident_reference": "INC-2026-0914",
  "soak_seconds": 86400,
  "rings": [{"partitions": 32, "observe_seconds": 43200}, {"partitions": 256, "observe_seconds": 0}],
  "authority_id": "release-evidence-v1",
  "approved_at": "2026-09-14T16:00:00Z"
}
```

An override may set only fields the profile marks overridable. For the shipped
contract that is `soak_seconds` and `rings` of `soak`, so only
`production/stable` can be overridden. Two floors still apply: soak may not go
below one day, and rings must still end at 256.

An override never relaxes gates, selected claims, change scoping, reviews,
matrix completeness, transaction review, fitness, signature thresholds,
contributor authorization, closure and corresponding-source integrity, public
read-back, or the staging-before-production order.

The plan references each accepted override by digest, so an override changes
the plan digest: an emergency is planned as such, before any build. A plan that
references an override may also select a reviewed `dplecki/hotfix-*` source
branch; see [generate the plan](release-step-commands.md#generate-the-plan). An
override offered after the release is built is rejected; start a new release
instead.

## Inspect and freeze the contract

```sh
aos maintain release step contract --registry andyl/experimental
aos maintain release step contract --registry andyl/main --to production/stable
aos --json maintain release step contract --registry andyl/main --to production/candidate \
  --output qualification-contract.json
aos maintain release step contract --registry andyl/main --input qualification-contract.json
```

Without `--to`, the command prints the destination table for the registry tier
with each destination's profile. With `--to`, it prints that destination's
profile, profile digest, and gate identities. The gates shown assume every
target is affected; a change-scoped plan may require fewer. The output lists
requirements and never claims that they passed. `--output` writes a new
canonical contract file and refuses replacement. `--input` supports inspection
without Nix or network.

`aos maintain release new` exports the contract itself and freezes it into the plan.
Plans use `aos.release.plan/v1` and embed the complete
`aos.release.qualification-contract/v1` (`aos-system`). A plan or contract
with any other schema or identity is rejected.

Record a `qualification_predecessor` with the same registry, a distinct
`release_id`, and the verified preceding `manifest_digest`. The maintainer
configuration's `predecessor_bundle` supplies it to `aos maintain release new`. First
public releases use the restricted, non-public
[qualification snapshot workflow](release-step-commands.md#create-a-first-qualification-predecessor)
as their predecessor. A descriptor alone is insufficient: retain the signed
bundle and verification keys for the image update executor and for change
scoping. An experimental-to-main transition is a new main release and installation
unless a separate authenticated migration contract has been implemented and
tested.

Every destination requires authentic artifacts, complete closures, source and
license metadata, and a reproduced build through `build-integrity`. Durations
are engineering policy, not statistical failure-rate claims. Record machines,
workload, attempts, successes, failures, and recovery operations for every
observation window.

## Static surfaces

Release testing does not require an AOS Hub. A surface may be a static origin
(filesystem, S3, or SFTP, read back over HTTPS or `file://`), and every
requirement above applies unchanged. The differences are confined to identity
and signed publication records:

- executors download the staging-phase subjects from the staging surface's
  read-back origin, exactly as they would from a Hub route;
- the surface identity is the string served at `<readback>/.aos-surface`
  rather than a Hub deployment ID, and `staging-delivery` and `rollout-health`
  check it before and after publication;
- signed publication and channel records on a static surface are
  `aos.release.publication-receipt/v1` documents signed by the plan's
  `surface-receipt` role instead of a Hub receipt key; and
- the `hub-schema` fitness binding is recorded as `null`.

The `hub-restore` fitness kind still applies to a static production surface:
restore the origin's object set and channel generation records into an
isolated origin and read it back anonymously. The supported surface pairs and
upload mechanics are in
[static surfaces](release-static-surfaces.md#static-surfaces).

## Release-train support

Support is a forward-looking promise, separate from the results showing that a
release passed its gates, and it is reviewed with the rest of the contract.
[`qualification/modules/support.nix`](../../qualification/modules/support.nix)
declares it:

```nix
qualification.support = {
  default = { kind = "standard"; superseded_after_trains = 2; };
  trains."2026.9" = { kind = "lts"; supported_until = "2028-09-30"; };
};
```

A stable release `major.minor.patch` belongs to the train `major.minor`. A train
without an entry follows `default`: it stays supported until
`superseded_after_trains` newer stable trains exist. An explicit entry may give
a `supported_until` date, which then decides on its own; an `lts` train must
state one. The module rejects train keys with leading zeros, impossible dates,
LTS trains without an end date, and a rolling count of zero, and the exported
contract carries the policy under `support`. Current contracts must state it;
the Rust contract type validates the same rules.

Each source line states only what it owns. The `train/YYYY.M` branch that
maintains a train declares `trains."YYYY.M"` for that train alone; `master`
declares `default`. Registry finalization copies the release's own train entry
into the signed registry's `[support]` table and refuses a contract that names
another train, so a backport on an old train can extend that train's support
without touching newer ones, and no branch can rewrite the roadmap of another.
A Hub surface indexes the table with the registry metadata and renders it on
the Releases page; a static surface serves it only inside the signed registry.
Changing the promise is therefore a reviewed contract change on the owning
branch followed by that branch's next release, never a surface setting.

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
