# 10. Implementation and qualification

## 10.1. Crate boundaries

The implementation SHOULD use these focused boundaries. Names are proposed;
their ownership and dependency restrictions are normative.

| Crate/layer | Owns | Must not own |
| --- | --- | --- |
| `aos-assessment` | Canonical scan definitions/inventory/inputs, version policy, advisory identities/ranges, coverage, pure evaluator, findings, assessments, action intents | HTTP, filesystem, database, git/nix/process execution, ambient clock |
| `aos-assessment-providers` | Typed request construction, bounded response normalization, pagination/completion proofs, provider profile/version contracts | Runtime-specific HTTP clients, credentials, SQL, independent matching policy |
| `aos-assessment-runtime` | Shared scan/task state machine, transport/evidence/journal/clock ports, request-wide budgeting, resumable acquisition/evaluation orchestration | Native-only or Worker-only policy semantics, UI state, registry Git truth |
| Existing `aos-maintain` | Source-bound update planning/mutation contracts and explicit legacy report converters/reexports | A second copy of scan selection or CVE evaluation |
| Existing Hub core | Resource authorization, normalized inventory ingestion, logical schedules/transactions, assessment/alert services, event/outbox and release integration | Provider-specific forked algorithms or arbitrary source fetches in API handlers |
| Existing local/Native/Worker adapters | Port implementations, configuration and custody, HTTP/evidence I/O, runtime scheduling limits | Reimplementation of shared eligibility/matching/coverage rules |
| Existing CLI/console layers | Parsers, generated API clients, shared report renderer, typed action rendering | Advisory interpretation or authoritative result storage in a browser |

`aos-contract` remains the common canonical/digest implementation. Hub work
envelopes use existing versioned protocol conventions and may live in the
appropriate shared contract layer. Presentation remains reusable without
importing the entire CLI parser into Hub. Schema crates SHOULD avoid pulling
transport runtimes into consumers that only need immutable contracts.

Existing discovery policy moves once into the shared assessment layer, with
`aos-maintain` compatibility reexports/converters. The extraction MUST avoid
a dependency cycle in which assessment imports maintain and maintain imports
assessment. Native HTTP uses its normal client; Worker HTTP uses the platform
binding through the same transport port. The shared code must compile for
Worker's target without conditional policy forks or blocking filesystem calls.

Transport ports support bounded streaming, conditional requests, cancellation,
admitted origins/credentials, and exact-byte evidence receipts. Journal ports
provide compare-and-swap/transaction semantics; they do not reduce durable
state to a process-local map. Clock input is explicit. Capability discovery
is runtime-specific data, not a conditional compilation switch changing
the assessment algorithm.

## 10.2. Existing code extraction map

| Current location | Reuse/change |
| --- | --- |
| `aos-maintain` discovery/domain modules | Move shared selection, observations and policy without changing legacy behavior |
| CLI maintain discovery adapter | Split HTTP/time/cache effects from shared parsers and continuation rules |
| Maintain source envelope | Keep local update authorization; derive separate portable inventory |
| Maintain presentation | Version action intents/rendering; preserve old report schemas explicitly |
| `mkUpstream` and derivation metadata | Add validated optional security identities/coverage; export canonical declarations without building |
| Registry surface manifests | Add versioned authenticated inventory/scan-definition references, reader-first |
| Release SBOM generation | Enrich upstream identities, component instances and dependency relationships |
| HubDb / Native SQL and Hub core jobs | Add durable coordinator entities/transactions; preserve Hybrid logical-job refusal |
| Hybrid storage work | Reuse admitted object inspection/evidence custody; keep provider work separately scoped |
| Hub Connect API and console | Add services, generated clients and assessment views |
| Release advisory-disposition assembly | Version evidence binding and enforce pinned policy without weakening existing gates |

Direct code references and current/proposed distinctions appear in Chapter 11.
Extraction should be independently reviewable before provider expansion. A
large mechanical move and new vulnerability semantics SHOULD be separate
commits/PRs so preserved behavior can be assessed.

## 10.3. Delivery stages

### Stage A: contracts and behavior-preserving extraction

Define canonical schemas, comparator/identity profiles, explicit empty sets,
version converters, and frozen parity fixtures. Extract current GitHub/Go/
Repology parsing/selection into shared crates with local behavior unchanged.
Add portable inventory export and report action intents. This stage can land
without depending on Hybrid transport completion.

Exit criteria: legacy fixtures pass, unknown fields/versions fail as defined,
the shared engine/provider libraries compile for Native and Worker targets,
and local scan input/result digests reproduce without network or a checkout.

### Stage B: authenticated inventory and vulnerability evaluation

Extend `mkUpstream` metadata, evaluate/export declarations, enrich SBOM
identities/relationships, and ingest normalized inventory with provenance.
Implement OSV, explicit NVD/CPE mapping, KEV enrichment, retained advisory
snapshots, dispositions, and local vulnerability reports. Preserve unknown
coverage for packages that lack mappings; do not invent automatic name-based
identity coverage to make dashboards look complete.

Exit criteria: fixture corpus covers bundled/static dependencies, patched
versions, unknown comparators, alias/withdrawal behavior, provider paging,
conflicting severity and partial source outcomes. Self-contained bundle
reproduction works offline with required inputs present.

### Stage C: durable coordinator and all runtime modes

Add SQL/HubDb entities, coordinator/task ports, quotas, leases, generation
fences, schedule triggers, incremental indexes and full reconciliation.
Implement Native/Worker adapters and Hybrid provider plans/capabilities atop
RFC-0023. Admit bounded normalized evidence near Native SQL; prohibit
implicit Hybrid bulk fallback.

Exit criteria: the same corpus produces identical canonical assessments in
local, Native, Worker and Hybrid execution, and crash/race/outage qualification
passes. Provider response bodies in fixtures vary to demonstrate that bulk
size does not appear on the Worker-to-Native route.

### Stage D: API, CLI, web, alerts and delivery

Expose generated services and paired command grammar, immutable/history/live
views, event replay, alert episodes, schedules, subscriptions, signed webhooks,
and evidence exports/import receipts. Read handlers remain side-effect free.
All mutations and destinations have scoped permission/revision checks.

Exit criteria: cross-client JSON/report parity, scoped pagination/watch,
acknowledgement/resolution distinction, duplicate scan/outbox tests,
notification retry/dead-letter/revocation, and accessibility of uncertainty
states in the console are qualified.

### Stage E: enforced release evidence and production qualification

Introduce reader-first release-evidence versioning, disposition review/custody,
freshness/coverage enforcement, exact promotion binding and retained publication
evidence. Exercise runtime mode transitions, backup/restore, quotas, provider
outages, source/parser revocation, and operational metrics with runbooks.

Exit criteria: mandatory release gates cannot be bypassed by a matching digest,
an acknowledgement, an untrusted bundle, incomplete source coverage, or a
stale concurrent decision. Existing production unresolved-finding rejection
remains effective. All mode implementations expose the same supported feature
contract or explicit unavailable capabilities.

These stages are one design, not permanent reduced implementations. Temporary
feature flags identify incomplete capabilities explicitly. The final feature
set includes continuous reassessment, notifications, handoffs, and release
enforcement. Rollout must not silently present an updates-only implementation
as the vulnerability service specified here.

## 10.4. Migrations and compatibility

New readers land before producers of authenticated package metadata and
release evidence. Closed existing manifests MUST NOT receive unknown fields
without an explicit schema/version transition. Legacy observations map only
to coverage they actually establish; a Repology boolean cannot be converted
to a fabricated CVE record.

Database migrations add immutable entities/indexes before enabling producers,
and initialize desired generations without duplicating already tracked
alerts. Reindex/reassessment is bounded and checkpointed. Migration progress
is visible. Existing signed artifacts remain readable under their original
schemas and cannot be rewritten by a migration.

Rolling deployments negotiate provider capabilities before issuing work.
Already issued plans are supported through their maximum validity/lease
window or fail explicitly with a retriable capability error. An evaluator
upgrade changes semantic engine identity when behavior can change, retains
old assessment readers, and triggers explicit reassessment. It does not
silently reinterpret an old digest.

Backout disables new admission/schedules while preserving result reads and
durable evidence. It cannot weaken a release gate that already requires the
new evidence; such a gate remains unavailable/blocked until a compatible
implementation is restored or an existing authorized policy path applies.

## 10.5. Qualification matrix

The following are required qualification suites, not existing check names.
Implementation adds them to the repository's source-built check framework.

| Suite | Required evidence |
| --- | --- |
| Canonical contracts | Duplicate keys, unknown schemas/enums, noncanonical timestamps/numbers, ordering, digest domain separation, malformed reference rejection |
| Legacy preservation | Existing version vectors, prereleases, stream policies, minimum-age rules, report converters and source-bound update contracts |
| Cross-mode parity | Identical frozen input -> byte-identical assessment/action intents in local, Native, Worker, Hybrid; execution envelopes differ legitimately |
| Versions/ranges | Ecosystem-specific ordering, OSV event boundaries, multiple ranges, commit ancestry unavailable, NVD logical configurations, unsupported ranges remain unknown |
| Coverage | Empty complete vs partial response, paging/continuation, deleted/withdrawn records, 304 without cache, expired evidence, missing identities/dependency coverage |
| Provenance | Wrong artifact/platform/metadata binding, untrusted signer, revoked collector, private partition crossing, scoped disposition/backport conflicts |
| Coordinator | Concurrent claims, expired result, newer inventory generation, cancel/commit race, coalescing, restart and transaction/outbox atomicity |
| Budgets | Global provider throttling under many workers, consumed timeout allowance, request-wide exhaustion, provider circuit/fairness, bounded catch-up |
| Hybrid boundary | Wrong plan domain/audience/deployment, arbitrary URL rejection before credentials, oversized normalized result, no Native bulk fallback, absent logical Worker job authority |
| Alerts | Repeated equivalent scan, alias merge/split, uncertain rescan retains finding, authoritative resolution, acknowledgement episode scope, withdrawal/reopening |
| Delivery | Duplicate acceptance/retry, exact signed bytes, revision/secret rotation, revocation before send, dead-letter, finite digest membership |
| API/UI | Scope filtering, cursor binding/expiry, stream reconnect/revocation, side-effect-free reads, stable JSON envelopes, explicit unassessed/stale counts |
| Handoffs | Offline reproduction, closure/size/path rejection, missing evidence, unsupported engine, local dirty/clean binding, import cannot self-authorize |
| Release | Pinned freshness/policy/artifact, critical/KEV block, review scopes/expiry/revocation, stale approval conflict, historical publication immutable |
| Operations | SQL/evidence partial restore, key rotation, mode transition fences, retention pins, measured bytes/RPCs/latency and denial-of-service bounds |

Tests use recorded minimized provider fixtures and explicit time/history.
Property tests SHOULD cover ordering, range boundaries, idempotency, and
state-machine interleavings. Fixture revisions record provider schema/source
authority. Routine CI does not depend on a live provider being available.
Optional live canaries are separately budgeted integration qualification and
cannot grant release eligibility to fixture-based results.

## 10.6. Hermetic builds and documentation checks

New dependencies and optional scanner tools MUST be AOS packages built from
source. No host-tool or nixpkgs dependency is introduced. Runtime provider
requests are explicitly permitted service I/O; they are not hidden network
access inside a build derivation. Build/check fixtures are checked-in or
source-fetched with fixed hashes under the repository's hermetic rules.

Rust implementation changes require the repository's integration-target
compilation check in addition to focused semantic/runtime tests. Worker-target
compilation and generated API/client consistency are required when those
layers change. Nix metadata changes require pure evaluation/format checks
with valid/invalid declaration fixtures and without building scanned packages.

The specification text also requires documentation link/anchor checks,
fenced-example validation, numbering verification against open RFC PRs, and
whitespace/diff review. Documentation checks do not substitute for scanner,
runtime, database, or end-to-end qualification.
