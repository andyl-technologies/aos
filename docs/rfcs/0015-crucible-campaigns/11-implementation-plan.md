# 11 — Implementation plan and merge gates

This RFC is initially published for review without implementation. After design
approval, implementation is intended to continue in the same draft pull request
so requirements, gates, and code evolve together. No partial phase becomes the
default campaign path until its listed gates pass.

## 11.1 Sequencing principles

1. Preserve the existing `Configuration = (ScenarioDef, Schedule)` identity.
2. Land canonical codecs and offline model gates before daemon or QEMU behavior.
3. Add typed choices before adaptive candidate generation.
4. Add lazy local campaigns before hot QEMU forking.
5. Keep exact restore/thin replay as correctness fallbacks while hot fork is
   developed and gated.
6. Implement separate immutable-blob and mutable-ref traits, then directory
   leaves, composition layers, packing, and an S3-compatible leaf through one
   conformance suite.
7. Implement the language-neutral campaign/planner/local-executor contracts
   with direct and loopback-RPC adapters; do not implement multi-host fanout.
8. All QEMU-side code remains in the QEMU patch/plugin GPL scope with source and
   license-ledger updates.
9. Begin manual developer flights with the first vertical slice. No phase is
   described as usable and no campaign or hot-fork path becomes a default until
   its §14 operator evidence is accepted.

## 11.2 Phase 0 — RFC review and executable contracts

- [ ] **T-CAM-0.1** Review and accept the campaign vocabulary, three-plane
  boundary, scenario/campaign split, `ChoiceOpportunity`/`BranchPoint`/
  `ExpansionState` separation, branch/derive/hot-fork terminology, and strict
  versus streaming claims.
- [ ] **T-CAM-0.2** Resolve the measured QEMU fork spike questions in §12 without
  weakening the fail-closed capability contract.
- [ ] **T-CAM-0.3** Freeze requirement-to-gate mapping and assign every new wire
  format a schema/version owner.
- [ ] **T-CAM-0.4** Add a repository traceability check ensuring every
  `CAM`/`CMOD`/`SEL`/`GUIDE`/`LAZY`/`CCOMP`/`HFORK`/`CSTORE`/`CAPI`/`CMEAS`/`CSEC`/`CPERF`/`CMAN`
  requirement is covered by a task and gate.
- [ ] **T-CAM-0.5** Tabletop the realistic lifecycle, finding handoff,
  destructive recovery matrix, dogfood flight, evidence manifest, and owner
  sign-offs from §14.

**Exit:** the RFC and manual-flight design are accepted and the implementation
delta remains disabled.

## 11.3 Phase 1 — Canonical campaign model

Primary crates: `crucible`, `crucible-cas`, and codec-only API types.

- [ ] **T-CAM-1.1** Implement `CampaignLineage`, `CampaignPolicy`,
  `CampaignSnapshot`, `CampaignPlanningView`, planner engine/artifact/state and
  invocation identities, stable IDs, canonical binary encoding, and strict
  TOML authoring DTOs.
- [ ] **T-CAM-1.2** Implement immutable campaign facts, persistent Merkle
  sets/maps, snapshot ancestry, and content-reference walking.
- [ ] **T-CAM-1.3** Extend the existing campaign manifest roots with graph,
  exploration, observations, pins, and accounting while retaining corpus,
  coverage, findings, genesis, and provenance.
- [ ] **T-CAM-1.4** Implement CAS snapshot advancement, conflict diagnostics,
  policy activation, budget grants, pause/resume/seal commands, and idempotent
  command IDs.
- [ ] **T-CAM-1.5** Implement full projection rebuild and sampled cached-
  projection verification.
- [ ] **T-CAM-1.6** Add schema corruption, authoring-order canonicalization,
  stale-command, single-writer ownership, crash-window, and provenance-lineage
  tests.
- [ ] **T-CAM-1.7** Run the §14 Phase 1 offline model flight: create, inspect,
  derive, reject a stale command, pause, resume, and audit linear snapshot
  ancestry using only public object/API surfaces, and publish its evidence
  bundle.

**Gates:** `gate:campaign-model`, `gate:content-address`,
`gate:campaign-continuity-v2` model tier.

**Manual gate:** accepted §14 Phase 1 campaign-model flight.

## 11.4 Phase 2 — Typed choice model and guest protocol

Primary crates: `crucible`, `crucible-protocol`, `crucible-shmem`,
`crucible-guest`, `crucible-qemu-plugin`, and QEMU launch integration.

- [ ] **T-CAM-2.1** Implement Boolean, discrete, and integer domains; stable
  alternatives; units/scales; landmarks; choice groups; constraints; limits;
  domain hashing; and validation.
- [ ] **T-CAM-2.2** Implement `SelectableDeclaration`, `ChoiceOpportunity`,
  `ChoiceClassId`, `BranchPoint`, `ChoiceValue`, `Selection`, and canonical
  schedule encoding with branch-point identity separated from materialization.
- [ ] **T-CAM-2.3** Normalize genuine explorable decisions through the selection
  envelope and provide an explicit offline migration/rejection policy for older
  schedule artifacts.
- [ ] **T-CAM-2.4** Implement versioned register/request/reply guest messages and
  typed Rust guest helpers with complete negative decode and allocation tests.
- [ ] **T-CAM-2.5** Freeze guest selectable catalogs at setup, validate scenario
  expectations, support bounded narrowed runtime offers, and checkpoint pending
  requests exactly.
- [ ] **T-CAM-2.6** Adapt RFC-0014 Boolean outcome, transition, and parameter
  search surfaces to publish environment choice opportunities without weakening typed
  effect adapters.
- [ ] **T-CAM-2.7** Route application randomness through the integer selectable
  model and remove the parallel raw-width exploration path.
- [ ] **T-CAM-2.8** Integrate the actual network product guest with discrete and
  integral choices, exercise a pending selection across checkpoint/replay, and
  complete the §14 Phase 2 guest flight without internal protocol tooling.

**Gates:** `gate:typed-choice`, `gate:abi-conformance`,
`gate:e2e-determinism`, `gate:license-boundary`.

**Manual gate:** accepted §14 Phase 2 real-guest choice flight.

## 11.5 Phase 3 — Measurements and objectives

Primary crates: `crucible`, `crucible-guest`, `crucible-qemu-plugin`, and
`crucible-api`.

- [ ] **T-CAM-3.1** Add scenario measurement definitions, boundary selectors,
  cohort rules, metric types, exact aggregations, and canonical stop outcomes.
- [ ] **T-CAM-3.2** Add guest measurement begin/sample/end and semantic-marker
  protocol messages with scenario validation and limits.
- [ ] **T-CAM-3.3** Derive model-owned network, storage, scheduler, icount, and
  virtual-time metrics from canonical events.
- [ ] **T-CAM-3.4** Implement observation, objective-evaluation, Pareto,
  lexicographic, top-`K`, fairness-reserve, and explanation records.
- [ ] **T-CAM-3.5** Extend finding artifacts and retention policy with exact
  pre/post-failure pins and measurement/evidence closure.
- [ ] **T-CAM-3.6** Have an independent reviewer cross-check guest convergence
  markers, model-derived traffic evidence, measurement windows, objective
  ranking, and one known finding in the §14 Phase 3 flight.

**Gates:** `gate:campaign-model`, `gate:campaign-replay`, guest protocol
extensions under `gate:abi-conformance`.

**Manual gate:** accepted §14 Phase 3 measurement/finding flight.

## 11.6 Phase 4 — Lazy local campaign supervisor

Primary crates: `crucible`, `crucible-cas`, `crucible-api`, and
`crucible-daemon`.

- [ ] **T-CAM-4.1** Implement bounded finite and versioned generated
  `CandidateSource` forms plus generator specs for all/discrete, boundary,
  stratified, logarithmic, permuted, progressive integer, and corpus mutation.
- [ ] **T-CAM-4.2** Implement branch request/cause, branch-edge deduplication,
  immutable attempt execution basis, additional-cause association, proposal,
  attempt, observation, credit, input-only planner invocation, coordinator-
  accepted planner step/accounting, branch-point `ExpansionState`, and
  per-source portable continuation state.
- [ ] **T-CAM-4.3** Implement progressive-widening exact rational rules,
  interval refinement, deterministic PUCT, coverage/rarity/assertion/objective
  guidance, and path backpropagation.
- [ ] **T-CAM-4.4** Replace checkpoint-once frontier authority with branch-point
  source continuations, an attempt-level rebuildable queue, and volatile
  daemon-epoch reservations.
- [ ] **T-CAM-4.5** Implement `CampaignSupervisor`, `CampaignProjector`,
  `ProposalPlanner`, `AttemptQueue`, and a bounded local `WorkerPool`.
- [ ] **T-CAM-4.6** Implement strict and streaming commit modes, restart
  recovery, duplicate/conflict handling, backpressure, pagination, and
  projection rebuilding; reject stale, oversized, timed-out, cancelled, and
  nondeterministic planner invocations.
- [ ] **T-CAM-4.7** Implement hierarchical per-event promotion and existing
  minimization integration.
- [ ] **T-CAM-4.8** Complete the §14 Phase 4 local operator flight through lazy
  widening, additive finite branching, edge deduplication, live status,
  explanation, bounded pressure, pause/restart/resume, steering, and graceful
  stop.
- [ ] **T-CAM-4.9** Implement the authoritative language-neutral
  `CampaignService`, pure `PlannerEngine`, and local `ExecutorService` schemas;
  provide direct and loopback-RPC adapters, golden vectors, fake components,
  capability negotiation, idempotent assignment, and component conformance.

**Gates:** `gate:branch-point-model`, `gate:lazy-frontier`, `gate:attempt-idempotence`,
`gate:campaign-replay`, `gate:campaign-statistics`, `gate:harness-lint`.

**Manual gate:** accepted §14 Phase 4 local campaign flight.

## 11.7 Phase 5 — Composable content stores and durable closure efficiency

Primary crates: `crucible-cas` and `crucible-api` lifecycle/checkpoint code.

- [ ] **T-CAM-5.1** Introduce separate streaming `ImmutableBlobBackend` and
  conditional `MutableRefBackend` traits, capability and error models, and
  migrate current campaign/exact-closure persistence behind them.
- [ ] **T-CAM-5.2** Implement canonical object envelopes, domain-separated
  logical IDs, child-reference walking, persistent Merkle collections, partial
  closure traversal, and typed corruption diagnostics.
- [ ] **T-CAM-5.3** Remove full-file staging copies from the normal exact-closure
  publish/materialize path; stream with bounded buffers and preserve sparse
  extents where valid.
- [ ] **T-CAM-5.4** Implement immutable disk backing plus child overlay
  manifests and content-deduplicated changed-object storage.
- [ ] **T-CAM-5.5** Implement and validate an acyclic store-composition graph
  with verified, routed, tiered, read-through, write-through, write-back,
  compressed, encrypted, quota, metrics, and namespaced layers, including a
  durable GC-protected transfer journal for write-back operation.
- [ ] **T-CAM-5.6** Implement packed logical-object storage with crash-safe
  index generations, range authentication, concurrent-reader-safe repacking,
  logical/physical accounting, and page/extent IDs independent of pack layout.
- [ ] **T-CAM-5.7** Implement directory and S3-compatible leaf backends through
  the same conformance harness, including conditional refs, multipart
  interruption, corruption, credential expiry, and latency/failure injection.
- [ ] **T-CAM-5.8** Complete the §14 Phase 5 hibernate/restart/resume, backend
  outage, credential expiry, corruption, tier promotion/eviction, repacking,
  archival transfer/import, incompatible restore, retention, and plan/apply GC
  flights across multiple derived refs and active publication/transfer/write-
  back roots.
- [ ] **T-CAM-5.9** Implement metadata/findings/debug/executable/mirror closure
  policies, durability receipts, pins, sensitive-export reporting, resumable
  missing-object transfer, and offline maintenance transfer. Do not implement
  demand paging or worker fanout.

**Gates:** `gate:campaign-store-equivalence`, `gate:campaign-store-composition`,
`gate:exact-closure-streaming`, `gate:campaign-continuity-v2`.

**Manual gate:** accepted §14 Phase 5 storage and destructive-recovery evidence.

## 11.8 Phase 6 — QEMU hot-fork spike

Primary scope: QEMU patch series and the minimal GPL plugin support required for
the public protocol. The spike is not a production feature.

- [ ] **T-CAM-6.1** Inventory every thread, mutex, RCU/AIO context, bottom half,
  timer, block backend, descriptor, mapping, and plugin resource in the supported
  deterministic TCG launch profile.
- [ ] **T-CAM-6.2** Prototype `PrepareForkTemplate` and a QEMU-owned coordinator
  that proves all registered subsystems quiescent before process fork.
- [ ] **T-CAM-6.3** Prototype child reinitialization, new QMP/control channels,
  ring remapping, and a fresh branch-private disk overlay.
- [ ] **T-CAM-6.4** Inventory every memory mapping, reject writable shared guest
  RAM, prototype safe `MADV_DONTFORK` reconstruction for eligible scratch state,
  and measure transparent-huge-page, NUMA, allocator, and page-table effects.
- [ ] **T-CAM-6.5** Prove the parent remains unchanged and compare the child's
  first complete quantum with exact restore and thin replay across increasing
  guest RAM sizes.
- [ ] **T-CAM-6.6** Measure latency, page-table/private RSS, descriptor/thread
  leaks, and speedup against exact restore. Record the chosen supported profile
  and any rejected subsystem.
- [ ] **T-CAM-6.7** Stress at least 10,000 child lifecycles, deep template
  promotion, and resource-pressure fallback without unbounded growth.
- [ ] **T-CAM-6.8** Produce QEMU patch license/source-ledger updates and public
  protocol documentation.
- [ ] **T-CAM-6.9** Complete the §14 Phase 6 lab audit of quiescence, memory
  mappings, descriptors, private rings/disks, dirty-page growth, resource leaks,
  rejection paths, and exact/thin fallback using the representative product.

**Exit:** either the spike satisfies the structural and minimum-speedup targets,
its manual lab evidence is accepted, or hot fork remains rejected and the RFC is
revised around another measured local-COW mechanism. No optimistic partial
capability ships.

## 11.9 Phase 7 — Production hot fork and multi-node worlds

- [ ] **T-CAM-7.1** Complete the closed QEMU subsystem capability registry,
  quiescence acknowledgements, child resource disposition, sandboxing, and
  rollback paths.
- [ ] **T-CAM-7.2** Implement immutable template lifecycle, template identity,
  child readiness authentication, and invalidation rules.
- [ ] **T-CAM-7.3** Implement copy-on-write host continuation clones and exact
  pairing with each QEMU child.
- [ ] **T-CAM-7.4** Implement atomic multi-node world fork with failed-node and
  non-VM I/O-node semantics.
- [ ] **T-CAM-7.5** Integrate `HotCheckpointManager`, hotness scoring,
  resource/cgroup limits, demotion to exact/thin, and fallback diagnostics.
- [ ] **T-CAM-7.6** Add the complete equivalence, isolation, negative,
  resource-leak, and scaling matrix from §10.
- [ ] **T-CAM-7.7** Complete the §14 Phase 7 atomic multi-machine,
  massive-parallelism, deep-template, pressure, operator-handoff, and 24-hour
  dogfood flight with a final process/descriptor/memory/disk/store audit.

**Gates:** `gate:hot-fork-equivalence`, `gate:hot-fork-isolation`,
`gate:hot-fork-scaling`, `gate:world-fork-atomicity`,
`gate:license-boundary`, `gate:abi-conformance`.

**Manual gate:** accepted §14 Phase 7 dogfood evidence; hot fork remains
non-default before this gate.

## 11.10 Phase 8 — User-facing porcelain

Primary crates: `crucible-cli`, `crucible-api`, and `crucible-daemon`.

- [ ] **T-CAM-8.1** Implement campaign create/validate/start/pause/resume/stop,
  budget, steer, semantic `branch`, campaign `derive`, status, and watch, with
  `fork` only as a deprecated compatibility alias for `branch` if needed.
- [ ] **T-CAM-8.2** Implement graph/frontier/choices/findings/explain/compare
  queries with branch-point/source/provenance views, pagination, and versioned
  JSON.
- [ ] **T-CAM-8.3** Implement pin/unpin, replay/debug, export/import,
  push/pull/sync, and plan/apply GC.
- [ ] **T-CAM-8.4** Route existing run/search/fuzz/save/resume/fork/replay/triage
  through common branch-request and campaign primitives and remove parallel
  explicit-fork/search-expansion state models.
- [ ] **T-CAM-8.5** Publish user documentation and the worked network campaign
  as an executable fixture.
- [ ] **T-CAM-8.6** Have an operator who did not implement the feature complete
  the §14 standard lifecycle, finding-to-debug handoff, steering, retention, and
  cleanup flights using only public documentation and porcelain.

**Gates:** CLI/API contract tests, `gate:campaign-continuity-v2`,
`gate:campaign-replay`, and existing control-responsiveness gates.

**Manual gate:** `gate:campaign-operator-acceptance` with accepted §14 Phase 8
evidence.

## 11.11 Phase 9 — Final integration and release criteria

- [ ] **T-CAM-9.1** Run all existing Crucible determinism, replay, signal-fault,
  ABI, QEMU, package, and license gates with campaigns disabled and enabled.
- [ ] **T-CAM-9.2** Run performance baselines and prove the hot path meets the
  required scaling shape and minimum speedup.
- [ ] **T-CAM-9.3** Prove coordinator/executor restart, hibernation, backend-
  neutral archival and offline maintenance transfer, and fast midpoint
  debugging.
- [ ] **T-CAM-9.4** Prove all findings remain self-contained and reproduce on one
  host with no campaign daemon or shared store.
- [ ] **T-CAM-9.5** Verify no prohibited native pointers, QEMU structures,
  callbacks, Rust-native layouts, host paths, or distribution metadata cross the
  process/storage boundaries.
- [ ] **T-CAM-9.6** Update canonical user docs only after implementation behavior
  passes the full gate set.
- [ ] **T-CAM-9.7** Run the complete 72-hour §14 release-candidate dogfood,
  destructive recovery, hibernation/maintenance transfer, finding handoff, GC,
  cleanup, defect-disposition, and cross-owner sign-off flight.

**Manual gates:** `gate:campaign-operator-acceptance`,
`gate:campaign-destructive-recovery`, and `gate:campaign-dogfood`.

## 11.12 Implementation completion definition

This RFC is implemented only when:

- typed environment and guest choices use one selection model;
- explicit finite branches and generated exploration use one branch-point,
  request, edge, and lazy expansion model with provenance-preserving dedup;
- large integral domains are explored lazily with feedback and progressive
  widening;
- campaign pause/restart reconstructs the complete frontier and knowledge;
- local campaigns pull bounded attempts with deterministic replay evidence;
- direct and loopback-RPC coordinator/executor paths produce identical facts;
- exact closures stream through a validated composable store graph;
- hot fork is either production-gated for its declared TCG profile or explicitly
  rejected and removed from the completion claim;
- user-facing campaign commands operate on the one snapshot model;
- an independent operator completes the public lifecycle and another
  investigator reproduces a finding solely from its exported bundle;
- destructive process, host, store, credential, pressure, hot-fork, and GC drills
  preserve the last authenticated state and require no private repair;
- the realistic 72-hour dogfood flight sustains useful parallelism, steering,
  hibernation, handoff, and clean resource accounting;
- every required gate is green with no alternate compatibility runtime.

## 11.13 Initial requirement traceability

Phase 0 freezes this mapping at individual-requirement granularity. The initial
area mapping ensures that no part of the RFC is merely aspirational:

| Requirements | Primary phases | Primary gates |
| --- | --- | --- |
| `CAM-1..14` | 1–9 | campaign model, replay, continuity, ABI, license boundary, manual acceptance |
| `CMOD-1..28` | 1, 2, 4 | campaign model, content address, attempt idempotence, continuity |
| `SEL-1..21` | 2 | typed choice, ABI conformance, end-to-end determinism |
| `GUIDE-1..24` | 3, 4 | lazy frontier, campaign statistics, campaign replay |
| `LAZY-1..19` | 4 | lazy frontier, attempt idempotence, campaign replay |
| `CCOMP-1..22` | 0, 4, 8 | component contract, control responsiveness, attempt idempotence, ABI conformance |
| `HFORK-1..24` | 6, 7 | hot-fork equivalence/isolation/scaling, world-fork atomicity, ABI/license |
| `CSTORE-1..22` | 1, 5 | store equivalence, store composition, exact-closure streaming, continuity |
| `CAPI-1..13` | 8 | CLI/API contracts, continuity, campaign replay |
| `CMEAS-1..14` | 3, 8 | campaign model, replay, ABI conformance |
| `CSEC-1..12` | 1–9 | license boundary, ABI conformance, isolation, store equivalence |
| `CPERF-1..8` | 4–7, 9 | branch-point model, lazy frontier, hot-fork scaling/equivalence, exact-closure streaming |
| `CMAN-1..22` | 0–9 | operator acceptance, destructive recovery, dogfood, campaign replay |

The executable traceability check required by T-CAM-0.4 must expand every range,
name at least one implementing task and test for each requirement, reject stale
IDs in either direction, and remain part of the completion gate.
