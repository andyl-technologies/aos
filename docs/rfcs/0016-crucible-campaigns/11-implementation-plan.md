# 11 — Implementation plan and merge gates

This RFC was initially published for review without implementation. Its
implementation now continues in the same draft pull request so requirements,
gates, and code evolve together. Checked tasks have executable evidence in the
tree; manual and production gates remain unchecked until their recorded flights
are accepted. No partial phase becomes the default campaign path until its
listed gates pass.

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
- [x] **T-CAM-0.4** Add a repository traceability check ensuring every
  `CAM`/`CMOD`/`SEL`/`GUIDE`/`LAZY`/`CCOMP`/`HFORK`/`CSTORE`/`CAPI`/`CMEAS`/`CSEC`/`CPERF`/`CMAN`
  requirement is covered by a task and gate.
- [ ] **T-CAM-0.5** Tabletop the realistic lifecycle, finding handoff,
  destructive recovery matrix, dogfood flight, evidence manifest, and owner
  sign-offs from §14.

**Exit:** the RFC and manual-flight design are accepted and the implementation
delta remains disabled.

## 11.3 Phase 1 — Canonical campaign model

Primary crates: `crucible-campaign`, `crucible`, `crucible-cas`, and codec-only
API types.

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
- [x] **T-CAM-2.4** Implement versioned register/request/reply guest messages and
  typed Rust guest helpers with complete negative decode and allocation tests.
- [x] **T-CAM-2.5** Freeze guest selectable catalogs at setup, validate scenario
  expectations, support bounded narrowed runtime offers, and checkpoint pending
  requests exactly.
- [ ] **T-CAM-2.6** Adapt RFC-0014 Boolean outcome, transition, and parameter
  search surfaces to publish environment choice opportunities without weakening typed
  effect adapters.
- [x] **T-CAM-2.7** Route application randomness through the integer selectable
  model and remove the parallel raw-width exploration path.
- [ ] **T-CAM-2.8** Integrate the actual network product guest with discrete and
  integral choices, exercise a pending selection across checkpoint/replay, and
  complete the §14 Phase 2 guest flight without internal protocol tooling.

**Gates:** `gate:typed-choice`, `gate:abi-conformance`,
`gate:e2e-determinism`, `gate:license-boundary`.

**Manual gate:** accepted §14 Phase 2 real-guest choice flight.

The version-1 selectable ABI is now a pure, architecture-independent codec in
`crucible-protocol` with closed register/request/reply kinds, a 4,608-byte
aggregate bound, checked dense byte ranges, exact request/reply sequence
binding, a zero-filled mutable reply reservation, and a closed typed rejection
vocabulary. `crucible-guest` emits immutable setup registrations and validates
that a reply exactly occupies the lent request buffer without a stale sequence
or dirty tail. Golden vectors, every-truncation decoding, malformed range and
reserved-field cases, and allocation-before-bound regressions run under
`gate:abi-conformance`. This completes only T-CAM-2.4: catalog freezing,
scenario/declaration reconciliation, host doorbell dispatch, narrowed-domain
authority, and pending-request checkpoint ownership remain T-CAM-2.5.

The GPL-side plugin now also exposes a policy-free selectable callback core. It
decodes register/request messages at the exact trap coordinate, delegates them
to a typed catalog/decision authority, rejects guest-owned replies and stale
service replies, and writes one zero-padded reply through the existing
same-icount guest-input capability. This does not complete T-CAM-2.5: the live
runtime still needs to supply and persist the launch-authenticated inputs. The
plugin-side catalog state now enforces nonzero scenario ceilings under hard
4,096-declaration/1,000,000-request caps, exact required/optional declaration
matching, strictly advancing sequences, no late registration, and one
incarnation-bound pending request retained until an exact-sequence reply. The
live dispatcher now consumes that launch-authenticated plan, reconciles raw
guest registrations, freezes before publishing `setup_complete`, retains an
exact request without touching its zero-filled reply reservation, and requests
native VMStop. It preallocates cold-priming and restored catalog incarnations
over one shared declaration allocation, then swaps the exact continuation once
at the logical-restore boundary before acknowledgement. The live plugin now
publishes one bounded, versioned pending-request record through the existing
lossless marker ring after retention and VMStop request; the mapped host adapter
reconstructs the exact request, trap coordinate, and guest virtual reply target
without granting it semantic authority. Deferred requests use a 4,576-byte
nested-request profile so the 32-byte transport header cannot overflow the
4,608-byte marker entry. ABI v18 now appends a VM-local one-entry reply ring: the
host publishes only an exact-sequence reply that fits the retained reservation
at the current paused icount, and the plugin revalidates sequence/vCPU/icount,
zero-pads the guest reservation, writes it before resume, and charges completion
only afterward. The production node set now retains each drained request under
its exact `NodeId` until reply publication succeeds, preserving ownership across
multi-node drain failures, and exposes that node-qualified token through the
production lifecycle and daemon modeled-driver facade. Daemon-side scenario
schema V7 now owns canonical typed declarations and nonzero per-node/world
ceilings. Fresh production launch derives each white-box node's sealed catalog
plan from that exact scenario component; selectable-enabled exact restore fails
closed until its continuation exists. The daemon now resolves node-qualified
requests against the scenario, validates bounded narrowed domains, derives the
stable runtime opportunity, stops discovery without replying, applies exact
defaults for deterministic continuation, and consumes authenticated campaign
selections at the matching thin-replay boundary. Durable checkpoint composition
remains required to complete T-CAM-2.5.
The process-neutral `CRUCSCP2` catalog-plan codec now freezes the future sealed
descriptor body, including exact expectations, limits, registered identifiers,
sequence watermarks, completed counters, and a complete pending request/trap
coordinate plus its guest virtual reply target. Selection-free version-1 plans
remain readable; pending version-1 continuations fail closed because they lack
that target. The plugin catalog converts cold/restored plans bidirectionally and
creates a fresh token incarnation on restore, so prior-process tokens cannot
complete a restored pending request. The canonical `CRUCSUP2` composite now
length-frames the independently versioned app-random and selectable plans for
the negotiated setup profile. The existing control-protocol v2 third descriptor
remains the raw app-random plan, while v3 now hands off the complete composite;
the plugin decodes only the exact negotiated profile and transfers the
selectable continuation into the pinned live catalog owner. The host launch
profile retains and hashes the exact composite for any selectable-enabled node,
uses it in fresh and exact node setup, and rejects a v2 negotiation instead of
discarding selectable state. Empty-selectable launches preserve the existing
version-two launch identity and raw-v2 fallback.

The application-random path now implements the pure normalization and
application contract, executor-side verification of uniform model samples, live
producer routing, and lazy typed branch generation. The scheduler treats the
plugin's legacy `AppRandom` result as untrusted transport, reproduces the served
value from its named seeded stream, records canonical `RngDraw` plus
`Selection`, and hands the self-contained discovery records to the quantum
result. One exact-parent branch operation consumes those validated records
and emits only `CampaignBranch` selections; the parallel raw-width generator is
removed. Model samples and typed replacements consume the existing scenario
draw cap, and checkpoint relaunch recovers per-node positions from the
authoritative named-stream cursor. Retained legacy `AppRandom` schedule entries
remain readable and replayable but are not branchable; re-execution through the
live producer is the fail-closed conversion path. The broader legacy-decision
migration policy and Phase 2 real-guest flight remain under T-CAM-2.3 and
T-CAM-2.8 respectively.

The public static `crucible-guest` product client now constructs discrete and
unsigned-integral registrations and requests from the same canonical
`ChoiceDomain` and `ChoiceValue` types used by the coordinator. The actual
network-product initramfs registers a required recovery-policy choice and a
required stepped retry-quanta choice, blocks on both through the supported
guest CLI, and makes the returned values change a guest-originated Ethernet
frame. `checks.crucible.phase2.qemuLiveSelectableProduct` captures that guest
with the first request pending, writes the ordinary exact-snapshot envelope and
canonical catalog-plan sidecar, force-kills the source QEMU, restores a fresh
QEMU/plugin process, proves the pending token is exact, supplies the discrete
and integral replies, and observes `crucible-selected-fast-q7` from the guest.
Together with the production checkpoint-manifest version-5 codec tests, this is
the automated prerequisite for T-CAM-2.8. The task remains unchecked until the
§14 Phase 2 operator flight records its required human acceptance evidence.

## 11.5 Phase 3 — Measurements and objectives

Primary crates: `crucible`, `crucible-guest`, `crucible-qemu-plugin`, and
`crucible-api`.

- [ ] **T-CAM-3.1** Add scenario measurement definitions, boundary selectors,
  cohort rules, metric types, exact aggregations, and canonical stop outcomes.
  The pure scenario-owned v1 definition component now provides bounded static
  boundary selectors, validated node cohorts, typed metric sources and values,
  exact aggregation declarations, deterministic ordering, and scenario-v6
  identity/serialization with measurement-free v5 read compatibility. The pure
  bounded v1 replay evaluator now authenticates dense scheduler entries,
  resolves compound/cohort boundaries and modeled timeouts, retains canonical
  satisfying evidence, and recomputes exact integer, rational, histogram, and
  delta aggregates. Campaign measurement-set v2 retains the exact verified
  evaluation/definition identities and payload behind a model-specific verifier
  while preserving identity-exact v1 reads. Model-owned sample producers plus
  complete raw evidence attachment remain open, so this task is not yet
  complete.
- [x] **T-CAM-3.2** Add guest measurement begin/sample/end and semantic-marker
  protocol messages with scenario validation and limits.
  Doorbell protocol v3 now provides four byte-exact bounded kinds, seven closed
  typed value forms, canonical rational/vector/detail validation, guest CLI
  producers, and typed observational event-catalog projection. The fresh QEMU
  campaign driver enforces declared measurement/metric/source/type/cohort and
  exact marker-instance contracts, bounds simultaneous instances, requires a
  balanced begin/sample/end lifecycle, and feeds normalized guest samples into
  the verified measurement evaluator. ABI, malformed-message, typed event,
  exact-instance, and driver lifecycle regressions cover the boundary.
- [x] **T-CAM-3.3** Derive model-owned network, storage, scheduler, icount, and
  virtual-time metrics from canonical events.
  The pure bounded projector now authenticates the dense scheduler log, derives
  every closed v1 model source from exact typed event fields, fails closed on
  malformed source events, and merges replay-identical model samples with the
  independently validated guest stream before common windowing and exact
  aggregation. Source, replay, malformed-event, visit-bound, and end-to-end
  driver regressions pin the projection and retained evaluation.
- [x] **T-CAM-3.4** Implement observation, objective-evaluation, Pareto,
  lexicographic, top-`K`, fairness-reserve, and explanation records.
  The canonical bounded observation, verified-evaluation measurement-set v2,
  property-verdict-set, and coverage-projection record layer now feeds exact
  signed, unsigned, and reduced-rational objective values. Arbitrary-precision
  reduced reward arithmetic, Pareto/lexicographic/weighted top-`K` ranking,
  breadth-first and novelty reserves, and complete selected/filtered/dominated/
  pruned explanations are content-addressed and replay-validated. The Crucible
  adapter authenticates its exact model evaluation before projecting numeric
  aggregates. Candidate, aggregate-evidence-byte, Pareto-work, scalar-work,
  magnitude, and encoded-record bounds fail closed before unbounded work or
  publication, and repository publication preflights the complete dependency
  union before its first write.
  Exact-arithmetic, input-order, reserve, filtering, work-bound, model-adapter,
  failure-atomicity, load, and idempotent-replay regressions cover the contract.
  The integrated Phase 3 measurement/finding flight remains open under
  T-CAM-3.6.
- [x] **T-CAM-3.5** Extend finding artifacts and retention policy with exact
  pre/post-failure pins and measurement/evidence closure.
  Canonical bounded finding signatures, clusters, exact observation-owned
  measurement/evidence child closures, and self-contained reproduction records
  are implemented. Schema-v2 findings retain independently bounded
  pre-failure, last-successful-measurement, post-failure, and additional exact
  checkpoint roles. The daemon authenticates at most 4,096 exact candidates
  and deterministically selects nearest event boundaries with content-address
  tie-breaking. Crucible minimization is bounded by 4,096 candidates and
  128 MiB of conservative candidate-copy work; its seed/bounds, dense candidate
  history, observed fingerprints, accepted result, and final replay state are
  retained in verifier-backed reproduction schema v2. The repository preflights
  original/artifact bases before writes, atomically clusters occurrences and
  role sets, and revalidates the complete contract on import/restart. Paged
  proof-authenticated finding and finding-object queries are implemented. The
  integrated Phase 3 flight remains open under T-CAM-3.6.
- [ ] **T-CAM-3.6** Have an independent reviewer cross-check guest convergence
  markers, model-derived traffic evidence, measurement windows, objective
  ranking, and one known finding in the §14 Phase 3 flight.

**Gates:** `gate:campaign-model`, `gate:campaign-replay`, guest protocol
extensions under `gate:abi-conformance`.

**Manual gate:** accepted §14 Phase 3 measurement/finding flight.

## 11.6 Phase 4 — Lazy local campaign supervisor

Primary crates: `crucible`, `crucible-cas`, `crucible-api`, and
`crucible-daemon`.

- [x] **T-CAM-4.1** Implement bounded finite and versioned generated
  `CandidateSource` forms plus generator specs for all/discrete, boundary,
  stratified, logarithmic, permuted, progressive integer, corpus mutation, and
  model-bound uniform integer permutation through the full unsigned 64-bit
  app-random domain.
- [x] **T-CAM-4.2** Implement branch request/cause, branch-edge deduplication,
  discovery-versus-branch attempt starts, immutable attempt execution basis,
  global admission ordinal, authenticated branch path, additional-cause
  association, proposal, attempt, observation, credit, input-only planner
  invocation, coordinator-accepted planner step/accounting, branch-point
  `ExpansionState`, and per-source portable continuation state.
  Canonical records and repository owner transitions now cover every listed
  basis. Proposal admission assigns one global ordinal, deduplicates an exact
  execution basis while retaining later causes, and authenticates scoped path
  prefixes; strict observations commit in that global order. Planner Issue
  accepts only an exact served input page, atomically publishes its step,
  proposals, admissions, and accounting, and preserves replay identity.
  Branch-request, proposal, admission, observation, credit, expansion, and
  continuation transitions are recomputed during import and restart, with
  local/replay/convergence regressions covering each owner boundary.
- [x] **T-CAM-4.3** Implement progressive-widening exact rational rules,
  interval refinement, deterministic PUCT, coverage/rarity/assertion/objective
  guidance, and path backpropagation. New branch paths now retain exact
  branch-point/edge segments under schema version 2, while identity-preserving
  v1 reads remain available. Canonical schema-v1 observation/branch-point
  credits now survive replay and restart and drive exact completed-visit counts;
  schema-v4 observation transitions additionally retain every cumulative path
  under its exact child configuration, and direct non-genesis admission
  authenticates its prefix against that nested index after restart/import.
  Atomic planner `Issue` chooses the lowest authenticated parent path, requires
  it to be scoped version 2, derives the cumulative attempt, and recomputes the
  same owner rule after convergence and restart. The exact fixed-point PUCT
  term arithmetic, including staged rounding, integer square root, input
  invariants, and saturation, is implemented and conformance-tested. The
  progressive-widening `0`, `1/2`, and `1` exponent owner is also implemented
  with exact irrational comparison, initial allocation, visit-floor, ceiling,
  and overflow semantics. The repository now also rebuilds a bounded exact
  `BranchEdgeId` visit partition from idempotent observation credits and scoped
  path segments, with restart equality and duplicate-credit protection. A
  policy-bound projection normalizes one-million-micro proposal prior mass exactly,
  reserves fairness for the least-visited canonical edge, folds globally unique
  coverage identities from the exact canonical observation set under explicit
  root/observation/identity/byte bounds, folds owner-verified finding
  occurrences through three closed positive policy-guidance signals under
  finding-root/occurrence/body bounds, folds exact owner-published objective
  evaluations through a 65,536-record/128-MiB shared batch, and
  derives the active policy's exact edge scores with restart equality. Canonical
  frontier engine version 2 now consumes those completed/prospective explicit,
  modeled-finite, or uniform-prior, novelty, finding-reward, and fairness terms
  from exact owner-built guidance for every Ready offer. It carries the best score across pages,
  publishes guidance only after zero-write preflight, and reruns identically on
  restart/import. The request projector batches unique branch points, scans the
  canonical observation/finding roots once, charges 65,536 aggregate credits,
  128 MiB of credit/path bodies, 65,536 unique objective evaluations and 128
  MiB of their deduplicated evaluation/observation/property basis bodies, 128
  MiB of unique choice-domain bodies, and unique prior-provenance records within
  the existing visit-projection byte cap. Branch-request schema v2 adds bounded
  positive explicit finite weights, while v3 adds bounded finite masses bound
  to the exact model named by the opportunity; the owner selects the earliest
  credited execution basis per semantic edge and normalizes completed plus one
  prospective offer with exact edge-ordered remainder distribution. Uniform
  and generated sources remain weight one, and schema-v1/v2 request identities
  remain readable. Prospective bases are shared by branch point/raw weight and
  capped at 1,000,000 completed-edge visits per planner page.
  Progressive-integer implementation version 11 now retains version 9's exact
  prefix and visit gates while ranking remaining intervals by owner-derived
  endpoint PUCT-score difference, interval size, and lower offset. It uses the
  exact active policy and planning view, batches branch-point projections under
  the established guidance bounds, preserves the already-proposed value set,
  and revalidates identically after restart/import. Branch-request schema v4
  and generator implementation version 17 now resolve standardized uniform
  app-random models into a request-keyed, budget-bounded power-of-two integer
  permutation. Exact model/generator/domain validation, zero-write mismatch
  rejection, `2^64` closed-versus-exhausted semantics, and restart replay are
  covered. The standardized model surface is therefore complete: uniform
  application randomness is the only currently registered non-finite model
  family. A future opaque family requires its own concrete adapter and
  versioned portable generator contract, but does not leave this task open.
  Implementation version 12 adds the
  producer-landmark term: it prioritizes landmark count before version 11's
  endpoint PUCT difference, interval size, and lower offset, then emits the
  winning interval's landmark nearest its lower midpoint. Implementation
  version 13 now compares the exact rational difference between owner-verified
  endpoint mean objective rewards before those version-12 terms. Versions 11
  and 12 remain measurement-neutral, and local issue plus restart/import replay
  reject a substituted value before writes. Implementation version 14 now
  compares exact endpoint mean globally unique coverage-identity discontinuity
  before version 13's terms, while versions 11 through 13 retain their prior
  order; local issue and restart/import replay reject an objective-only
  substitution before writes. Implementation version 15 now compares exact
  endpoint mean active-policy-weighted verified finding-reward discontinuity
  before version 14's terms, while versions 11 through 14 retain their prior
  order; local issue and restart/import replay reject a coverage-only
  substitution before writes. Implementation version 16 now compares exact
  endpoint mean inverse-frequency coverage-rarity discontinuity before version
  15's terms, while versions 11 through 15 retain their prior order; local issue
  and restart/import replay reject a unique-coverage-only substitution before
  writes.
- [x] **T-CAM-4.4** Replace checkpoint-once frontier authority with branch-point
  source continuations, an attempt-level rebuildable queue, and volatile
  daemon-epoch reservations.
  The repository checkpoint now provides snapshot-bound, bounded accounting
  scans that authenticate canonical attempt membership, exclude completed
  observations, remain page-size independent to EOF, and rebuild identically
  through a fresh repository. Its bounded process-local reservation table is
  idempotent per worker slot, rejects stale epoch/generation releases, and
  restarts empty under a fresh daemon epoch. These owner primitives are
  integrated by the T-CAM-4.5 supervisor. The reward/novelty-sensitive
  generator versions described below completed under T-CAM-4.3. The repository
  also maintains a compact snapshot-authenticated continuation projection for
  each request and serves bounded proof-bearing frontier pages. Finite request,
  proposal, and admission transitions are owner-recomputed during import.
  Implementation-version 2 `all`
  generators over Boolean and discrete domains use the same exact ordinal and
  continuation fold as finite sources. Implementation-version 3
  `boundary_integer` adds a bounded exact static integer ordering, and
  implementation-version 4 `stratified_integer` adds a checked constant-space
  ordinal mapping capped at 4,096 strata. Implementation-version 5
  `log_integer` adds an at-most-65-value exact rounded-power ordering for
  strictly positive domains. Implementation-version 6 `permuted_integer` adds a
  four-round request-keyed bijection over up to `2^64 - 1` legal values without
  materialization. Implementation-version 7 `weighted_categorical` adds exact
  request-keyed integer-weight sampling without replacement over at most 256
  discrete alternatives, including bounded rejection sampling and restart
  replay. Implementation-version 8 `ordered_mixture` recursively schedules
  executable finite children by exact weighted virtual finish time, suppresses
  duplicate values while advancing their provenance, and enforces 512-value,
  8,192-work-unit, and 64-level bounds. Implementation-version 9
  `progressive_integer` adds the exact stratified prefix, largest-gap/lower-
  midpoint refinement order, checked visit thresholds, 4,096-strata/proposal
  bounds, and observation-driven frontier wakeups through a branch-point
  request index. Implementation-version 10 `mutate_near_corpus` derives exact
  retained completed integer selections at the request's branch point, emits
  canonical lower-then-upper legal-step neighbors, and uses the immutable
  request's exact previously proposed value set as its portable continuation so
  corpus growth cannot reinterpret prior proposals. It enforces 4,096-credit,
  4,096-distance, 4,096-proposal, 65,536-work-unit, 128-MiB canonical credit-
  body, and existing 4,096-ID/128-MiB selection-resolution bounds during local
  acceptance, import, and restart. It waits for another completed credit when
  the current retained corpus has no unproposed mutation and closes only at its
  proposal budget. Implementation-version 11 `progressive_integer` retains the
  version-9 prefix, threshold, and midpoint rules but selects the next interval
  by absolute exact endpoint PUCT-score difference, then interval size and lower
  offset. Planner input construction batches those snapshot-bound projections,
  and owner validation rejects a largest-gap substitution before writes and
  replays the selected value after restart. Implementation-version 12 retains
  that exact feedback basis while adding authenticated producer-landmark count
  as the primary interval term and nearest-lower-midpoint landmark selection;
  version 11 histories continue to ignore landmarks. Implementation-version 13
  adds exact owner-verified endpoint mean objective-reward discontinuity before
  version 12's terms, while versions 11 and 12 retain their prior order.
  Implementation-version 14 adds exact globally unique coverage-identity mean
  discontinuity before version 13's terms, while versions 11 through 13 retain
  their prior order. Implementation-version 15 adds exact
  active-policy-weighted finding-reward mean discontinuity before version 14's
  terms, while versions 11 through 14 retain their prior order.
  Implementation-version 16 adds exact inverse-frequency coverage-rarity mean
  discontinuity before version 15's terms, while versions 11 through 15 retain
  their prior order. Static continuation projection remains valid after modeled
  observations exist: it
  binds the exact observation root and projects exact completed visits from
  canonical branch-point credit sets. The independent exact PUCT arithmetic and
  guidance projection are consumed only by canonical frontier engine version 2;
  version 1 retains its original least-position ordering. Other generated
  requests remain conservatively `Open` and fail closed when proposal or
  expansion semantics are requested. Legacy snapshots remain unindexed and
  queries fail closed rather than constructing a partial index.
- [ ] **T-CAM-4.5** Implement `CampaignSupervisor`, `CampaignProjector`,
  `ProposalPlanner`, `AttemptQueue`, and a bounded local `WorkerPool`.
  A coordinator-owned `CampaignPlannerDriver` now reconstructs the exact
  portable state and same-view `ContinueScan` cursor from the authenticated
  planner head before each bounded component call, suppresses reinvocation of
  a terminal unchanged view, verifies exact repository/client planner
  authority and engine/artifact/state configuration before writes, and holds no
  repository mutation ownership across component execution. Restart and
  concurrent-head-change regressions cover cursor continuity and stale
  acceptance.
  The standalone bounded `AttemptQueue` reservation primitive and the daemon's
  single-host `LocalExecutorSupervisor` are implemented. The latter enforces
  exact assignment replay, aggregate slot/CPU/memory/disk capacity, a bounded
  pending queue, durable completion/cancellation races, and restart replacement
  of stale executions. The local worker now resolves repository-authenticated
  attempt inputs behind an execution-model trait, publishes a completely
  preflighted immutable observation-candidate bundle without advancing campaign
  state, and returns results to the supervisor actor for durable completion or
  bounded retry without holding supervisor state during guest execution.
  A coordinator-owned `CampaignExecutorDriver` now pages authenticated
  claimable attempts into exact bounded reservations, derives one deterministic
  assignment per lease, then polls its exact execution through the read-only
  status operation without growing assignment history. It retains the exact
  submit or status request across commit-indeterminate failure and invokes the
  checked direct/RPC executor boundary
  without repository mutation ownership, authenticates and incorporates
  completed observations, and rebuilds from semantic roots after restart.
  Retryable executor rejection rotates the assignment identity, authorization
  failure remains operational, and the sole eligible local executor's stable
  incompatibility closes the exact admission ordinal through the imported-
  validated `AttemptClosed` owner transition.
  A startup-fixed `LocalExecutorWorkerPool` now creates at most 256 workers and
  never more than the supervisor's advertised execution slots. Its cloneable
  checked service keeps repository-backed admission, guest execution,
  candidate preflight, and immutable publication outside the short supervisor
  actor. Linear phase tokens preserve execute-once semantics across retryable
  publication/ledger failure; sticky shutdown cancels in-flight work, drains
  queued work without launching it, and releases capacity only after worker
  exit. Blocked-guest, blocked-admission, queued-shutdown, retry, and caught-
  panic regressions exercise the responsive bounded owner.
  A fixed local executor listener now lends cloneable pool-service handles to
  at most 256 connection workers, retains at most 1,024 pending sockets, and
  caps one connection at 65,536 complete requests. It authenticates one exact
  effective UID/GID through Linux `SO_PEERCRED` before decoding component
  bytes, rejects excess or foreign sockets, distinguishes protocol from service
  failure telemetry, interrupts active connections on sticky shutdown, and
  joins every connection worker before returning. Its managed endpoint retains
  a separate lifetime namespace lock and exact socket inode until join while
  reusing the campaign endpoint's path, owner, mode, stale-recovery, and safe
  teardown contract. Campaign and executor sockets can coexist in one secure
  directory without sharing namespace authority. A coupled executor-service
  owner can obtain its component service only from the exact fixed semantic
  pool; service shutdown closes admission, cancels active attempts, interrupts
  connections, and joins both worker domains. Terminal semantic worker
  completion closes the listener, and worker poison takes precedence over an
  ordinary listener result. The unserved-owner drop backstop also joins the
  semantic pool before releasing the endpoint namespace. The daemon now also
  composes the concrete fresh/thin-replay QEMU worker, shared aggregate host
  allocator, disjoint stable per-worker recovery roots, durable assignment and
  checkpoint stores, managed endpoint, runtime, and campaign service from one
  strict owner-only deployment file. Worker count is fixed at startup and
  cannot exceed the admitted slot ceiling. Exact-resume worker selection and
  its concrete modeled driver remain open and are not advertised.
  A bounded `CampaignSupervisor` now composes one planner driver and one
  executor driver over the same repository, reloads exact lifecycle intent on
  every step, and performs at most one component operation. Running execution
  drains before one planner invocation is enabled; paused campaigns issue no
  new work. Drain polls only held reservations, cancel-and-retry cancels one
  exact execution or releases one unaccepted lease per step, and exact-
  checkpoint issues one exact-basis checkpoint request per step while retaining
  the reservation through publication and durable pause.
  A daemon-owned `CampaignRuntime` now gives that step machine one fixed
  long-lived thread, sticky shutdown, explicit progress wakeups, and a startup-
  bounded 1 ms through 60 s fallback poll for asynchronous executor progress.
  It continues immediately only after an outcome that can make another bounded
  transition, inserts an interruptible 1 ms fairness pause after at most 256
  immediate operations, reports terminal component failures to its join owner,
  and does not add a second modeled-work queue. The daemon bootstrap now
  attaches a startup-fixed set of 1 through 256 unique explicitly named
  existing campaigns to packaged canonical planner workers and matched
  authenticated local executors. It negotiates each executor
  description/lineage/resources basis before publishing that attachment's
  planner basis, prepares and sorts the complete set by canonical campaign
  name before any runtime starts, starts only after the CampaignService
  endpoint is acquired, and couples any runtime failure or process shutdown to
  listener shutdown and complete worker join. The packaged local QEMU executor
  remains a campaign-specific one-runtime composition.
  The authenticated service now enumerates campaign refs through an explicit
  all-campaign grant using bounded stable ref pages and validates every returned
  head closure. The nested CLI follows those checked pages under explicit page,
  entry, and response-byte budgets and emits resumable structured or human
  reports. Dynamic attachment, a shared packaged-executor allocator, and richer
  operational tuning remain open.
  The QEMU realization executor now exposes only a borrowed already-realized
  live-backend facade without generic VMState/process authority, and the daemon
  composes that capability with a pre-launch exact resource guard and mandatory
  teardown session. Guarded executor methods receive the guard during every
  blocking realization operation; failed reap transfers enforcement to
  quarantine instead of releasing it, including a failed launch before active
  backend installation. The Linux process layer now has a sealed pre-`exec`
  primitive that validates cgroup-v2 and sticky cancellation descriptors,
  places the child before QEMU executes, applies a per-file size backstop, and
  refuses implicit image-tool provisioning on the guarded spawn path.
  The Linux authority now creates one exact child below a pinned
  operator-delegated unified cgroup-v2 root, fails closed unless CPU, memory,
  and process controllers are delegated, installs exact
  CPU-rate/memory/no-swap/task ceilings, mints the
  sealed child contract, and retains cgroup kill/event authority for future
  cancellation and reap supervision. Root, configured-group, and failed-setup
  cleanup owners retain one exclusive delegated-namespace lock and pinned
  parent/child identities; setup and release errors return the remaining
  authority instead of dropping it. A concurrently forked child may retain the
  close-on-exec lock description until `exec`, so replacement acquisition
  remains fail closed and retries the transient handoff within its startup
  deadline. Process membership is fixed-memory and bounded to 65,536 tasks.
  The authority derives PID/start-time/executable
  identity from its owned direct child and checks that exact process generation
  on both sides of the scan. It then retains the nonduplicable direct-child wait
  handle in a must-reap authority that rechecks identity before force-kill and
  preserves the handle on every reap error. Failed realizations can consume the
  active node, discard modeled channels/backend authority, and surrender the
  child into that must-reap authority. The retained child carries the
  unforgeable watcher-lifecycle token, rejecting a removed/recreated cgroup at
  the same path. All other cgroup pseudo-file reads are byte-bounded.
  Production child contracts require a configured non-root user and group
  distinct from every real, effective, saved, or supplementary supervisor
  credential; the pre-exec path clears supplementary groups and installs all
  real, effective, and saved IDs after cgroup attachment, with `no_new_privs`
  set first. The delegated hierarchy must not grant those child credentials a
  separate write path to its controls. Exactly one persistent watcher must be
  live before child minting. Cancellation or ordinary finalization makes the
  sticky event readable before publishing terminal state, closes minting, and
  kills and checks the group at a fixed 10 ms cadence until empty. Ordinary
  control failures retry at that cadence with complete authority retained;
  caught invariant panics enter a non-reentrant parked quarantine. A bounded
  wait returns the live watcher on timeout, and dropping an unjoined watcher
  latches closure while its worker retains authority until empty.
  Public guarded preparation now rejects before run-directory access unless the
  command's fixed vCPU, guest-memory, and minimum writable-byte requirements fit
  the exact ceilings sealed into the child contract. The resulting pinned
  authority retains both that basis and the contract's private attempt-
  lifecycle token. Guarded spawn rejects a changed command, resource profile,
  ceiling, or equal-limit contract from another attempt before revalidation or
  descriptor allocation. Exact-checkpoint materialization now requires the
  same contract before path access.
  The writable ceiling also supplies a conservative per-file limit; aggregate
  enforcement now has a crate-internal ext4 project-quota transaction and
  daemon-incarnation storage owner. The owner locks a dedicated private empty
  ext4 root, allocates from a bounded operator-reserved project-ID range, creates
  fixed-width unique child names, installs synchronized/read-back hard block and
  inode limits, assigns the inheritable project ID, transfers exact mode-`0700`
  ownership to the non-root QEMU identity that is distinct from every
  supervisor credential, and synchronizes the parent before exposure.
  Non-aligned byte ceilings round down to the kernel's 1,024-byte
  quota unit. After process reap, descriptor-relative cleanup removes at most
  the configured ceiling of 65,536 named entries without following symlinks or
  crossing filesystems, uses a constant number of open directory descriptors,
  authenticates ascent and child identities, and synchronizes from leaves to
  root. Normal release then restores the empty directory, clears and
  reauthenticates a zero-use quota record, removes the exact named inode,
  synchronizes the root, and only then recycles the project ID. Partial create,
  cleanup, and release failures retain the directory, shared root lock, cleanup
  bound, quota, and ID lease for exact retry; a dirty restart root and an
  unfinished drop both fail closed. A public sealed Linux host facade now pairs
  the exact process and storage owners. It installs storage before exposing a
  process contract, proves reap before synchronous storage cleanup, and
  transfers both retained owners to a nondroppable detached worker with bounded
  retry and panic parking. The combined owner now admits the launch profile and
  creates, owns, and synchronizes fresh monotone generation directories plus
  their empty exact-VMState destinations through its retained attempt-root
  descriptor before lending descriptor-pinned prepared authorities. Every
  generation stays under the one aggregate project quota; issuance retains only
  the next ordinal, while the inode quota bounds allocation and cleanup. Raw
  storage descriptors remain sealed. Guarded-launch invocation,
  baked/thin image provisioning, and a real ext4 enforcement VM gate remain
  open before the production executor selects this owner.
  A prepared run-directory authority now pins the directory and exact regular
  VMState inode without following final symlinks. Guarded spawn reauthenticates
  the entry before allocation, changes directory by descriptor after cgroup and
  cancellation admission, and repeats the inode check immediately before
  credential drop and `exec`; replacement of the diagnostic path therefore
  cannot redirect launch. The production owner must still exclude concurrent
  namespace mutation until QEMU has opened every relative artifact.
  A crate-internal nondroppable process-quarantine worker now accepts only
  lifecycle-matched retained children, an optional not-yet-joined watcher, and
  a cgroup; it retries ordinary cleanup failures, parks with authority after an
  invariant panic, and remains live
  after its observation handle is dropped. A crate-internal attempt-process
  owner now starts the watcher before contract minting, joins and removes the
  group on normal finish, retains bounded raw child handles even when process-
  identity authentication failed, and transfers unfinished state to that
  worker from `Drop`. Concrete launchers retain an unreaped pre-install child
  and reject relaunch; the guarded replay session transfers that authority into
  its abstract attempt guard before returning the realization error. The exact
  process-local cancellation incarnation now supports a bounded blocking wait,
  wakes all guards on cancellation, and fails closed after synchronization
  poison. The process owner can lend a narrow sticky-event signal and refuses
  child-contract access after it fires. The daemon now registers exactly one
  synchronous idempotent resource callback on that incarnation and composes it
  with exact quantum accounting plus an indivisible process/filesystem host
  owner. Exact-limit mismatch and pre-cancellation roll back before admission;
  failed reap and live-owner drop transfer the complete host authority to
  quarantine. Linux composition of failed-child and active-node handoff into
  the cgroup owner now has a sealed process-only facade: it validates its
  daemon-incarnation namespace and operational bounds before root access,
  creates unique fixed-width child names, exposes no raw cgroup controls, and
  poisons itself while retaining authority after partial setup. Aggregate
  filesystem-quota reservation, exact run-directory binding, and nondroppable
  process/storage quarantine are now composed by the concrete Linux host owner.
  Descriptor-pinned multi-generation exact-VMState destination preparation and
  its daemon guard capability are now composed by that owner. The concrete
  exact-resume adapter obtains that authority from the guard, streams and
  authenticates the durable root into the pinned inode, installs a root-bound
  real-node launcher, and transfers failed-launch or active-node child authority
  back to the guard on failure. The canonical production lifecycle now retains
  one injected node-launch authority across initial fresh/exact launch,
  modeled crash/restart replacement, and whole-world debugger replay; a replay
  must obtain an independent authority or fail closed. This removes the
  lifecycle's direct-spawn bypass seam while keeping the packaged ordinary
  lifecycle behind an explicit default authority. The same exact
  node-generation request now also moves generation-directory creation,
  `qemu-img` overlay creation, authenticated restore-artifact materialization,
  and replacement cloning behind the launcher before process spawn; the
  lifecycle rejects fresh/exact preparation-kind mismatches before invoking
  it. Exact preparation now lends the complete per-node checkpoint-manifest
  identity and fixed-memory authenticated artifact streams, so the future Linux
  launcher can write the retained VMState through its pinned linear transaction
  instead of replacing the inode by path. Each launch now returns a linear lease
  bound to the exact scheduler node and positive process generation. Active and
  staged replacement leases remain disjoint; old leases
  release only after reap attestation, staged leases become active only with
  backend commit, and abort reaps before lease finish. A lease-release failure
  latches quarantine and prevents later aggregate release. Explicit shutdown reaps
  the nodes, finishes every exact generation lease, and then asks the authority
  to attest aggregate release, while failed finish or abandonment transfers
  remaining authority to quarantine. The daemon now provides the bounded join
owner for that contract: it retains one latest generation per scenario node,
rejects stale/reused generation identities, tracks at most the active linear
lease and one staged successor per node, rejects a third generation, and
quarantines the one attempt guard if any lease is dropped or aggregate finish
races a live generation. A daemon lifecycle adapter now implements fresh,
  retained exact, and local replacement generations. Fresh image tools run
  under the same cgroup, cancellation, quota, pinned directory, credential,
  parent-death, and deadline contract; retained exact artifacts stream into
  linear pinned destinations and bind to the complete checkpoint manifest;
  local replacement resolves the retained prior generation and reflinks both
  writable artifacts under the same quota. All three modes launch only through
  guarded entry points. No-process failures roll back the pending generation
  fence for exact retry; an unreaped QEMU or helper child is retained before the
  aggregate owner is quarantined. Every injected production lifecycle launcher
  must now explicitly admit and charge a scheduler quantum before modeled state
  can advance and recheck the retained authority before returning its outcome.
  The daemon launcher binds those calls to the attempt cancellation, host-limit,
  and exact quantum guard, while the packaged non-campaign launcher declares
  its no-op behavior explicitly. Concurrent modeled and post-boundary failures
  remain jointly observable, and an explicit retryable/canceled/terminal class
  survives both lifecycle and scheduler boundaries without diagnostic-text
  parsing. The daemon now composes fresh campaign lifecycle
  construction with that launcher: it rejects exact-resume roots, validates the
  scenario identity and VM-node bound before resource allocation, exact-checks
  the installed limits and cancellation incarnation, and quarantines the guard
  if lifecycle construction fails. An exact-origin worker router now keeps
  fresh execution and durable paused-root resume on disjoint runners without
  collapsing their failure classifications. The fresh runner now lends only
  bounded drive/evidence operations to its modeled driver, retains shutdown
  authority, always performs final drain and process/resource cleanup, and
  passes the drained event-log suffix to a distinct result-sealing phase.
  Cleanup failure takes terminal precedence while retaining an earlier driver
  diagnostic, and the runner itself rejects exact-resume roots before lifecycle
  construction. The fresh runner now reconstructs non-genesis discovery starts
  whose schedules contain only deterministic producer decisions and the
  standardized app-random model/branch selection. Before launch it derives a
  bounded per-node producer plan from the repository-resolved target and sends
  it through the version-negotiated sealed third `Setup` descriptor. Lifecycle
  construction first requires the plugin-plan and scheduler-selection identity
  sets to match exactly and rejects plans for missing or white-box-disabled
  nodes. The plugin
  exact-checks node-local draw ordinal, canonical stream, full seeded raw draw,
  and that the selected value fits the live width; the scheduler separately
  validates the exact `SelectionId`, opportunity, domain, provenance, live
  request width, and post-draw parent. It starts at scenario genesis, advances
  under the attempt's exact cancellation and execution-quanta guard, requires
  every newly appended decision to equal the requested prefix, and retains
  replayed event history under the same observation bounds before lending the
  exact target to the modeled driver. Divergence, early terminal state,
  cancellation, or quantum exhaustion still performs runner-owned teardown.
  Legacy app-random values, explorer overrides, and selections outside this
  exact app-random contract are rejected before installing resources. A
  concrete modeled driver now projects an already-materialized exact discovery
  or selected-branch child, preserves typed scheduler failures, stops at the
  requested choice/marker/time/event or terminal boundary, rejects uncommitted
  network output, and retains dense event state
  under exact 1,000,000-entry/64-MiB-material bounds plus choice state under the
  canonical 65,530-record/128-MiB bounds with shared immutable contracts. Its post-shutdown seal incorporates the final drained
  suffix, runs bounded offline property evaluation, derives
  duplicate-insensitive per-point coverage identities, reconstructs the exact
  scenario and child artifacts, and emits a complete `ObservationCandidate`.
  It deliberately emits no undeclared measurements; measurement definitions,
  raw event-log evidence, and objective aggregation remain T-CAM-3 work.
  The packaged daemon selects this fresh concrete driver and fixed-worker
  composition. It also routes a retained version-four root exclusively through
  the concrete exact-resume driver, which restores the complete scheduler and
  evidence continuation, rejects a retained-log suffix, performs final drain,
  and reports `ExactRestore` only after sealing. Fresh exact-cache remains a
  separate optimization. Packaged startup captures the baked source, installs
  one fixed replay-oracle promotion owner per semantic worker, and advertises
  exact restore only after that owner set exists.
  The driver now observes a sticky checkpoint request at
  each operational boundary, lets a terminal verdict win a coincident request,
  and transfers a nonterminal request only after the lifecycle reports an exact
  capture-ready boundary. Real-node exact-checkpoint capture is now an
  executor-owned, guard-retaining operation: it
  seals and exact-binds configuration, node icount, and event-log continuation
  before paused VMState/host-I/O capture. The real-node executor now completes
  final drain and reap before synchronizing, reauthenticating, and lending a
  bounded positional VMState reader with no directory or mutation authority.
  The daemon now adapts that reader into a reopenable CAS source with one
  independent positional cursor per open. The guarded session itself now turns
  that source into the linear captured-checkpoint token, records the successful
  capture as its backend reap attestation, and releases only the still-installed
  host guard during finalization. The compatibility session invokes the
  pool-owned root handoff before returning its opaque prepared result.
  The daemon now prepares and durably publishes a
  registered version-three exact-checkpoint root over canonical snapshot
  metadata, the complete scheduler continuation, and a bounded, streamed
  opaque VMState child, with no writes during preparation and
  children-before-root durable receipts. The executor now persists
  checkpoint-requested, checkpoint-publishing, paused, and raw-root
  checkpoint-promoting ledger states, stages
  the exact root before campaign-CAS writes, preserves it as a restart/GC root,
  recovers the expected root across daemon epochs, and releases capacity only
  after durable pause. The live driver now returns its same-boundary scheduler
  checkpoint,
  the session converts a winning sticky request into a guarded exact capture,
  and the fixed pool carries that linear capture through no-write preparation,
  root staging, immutable publication, and durable pause without rerunning the
  guest. Exact-pin resume now reauthenticates the selected current exact pin
  and complete checkpoint, while operational attempt resume authenticates the
  exact root retained by the durable execution origin and accepts only the
  attempt's pre-selection or post-selection configuration. Both stream opaque
  VMState through a length-bounded pinned-file transaction and record a root
  binding over metadata, scheduler continuation, and VMState only after
  authenticated EOF and file sync; interruption leaves guarded launch
  fail-closed. Legacy version-two roots remain readable but cannot resume a
  campaign attempt. The complete production lifecycle checkpoint store now
  also lends a read-only portable closure capability: it authenticates the
  version-five production manifest and exact sorted object inventory under the
  scenario's aggregate checkpoint bound, keeps overlay and VMState artifacts
  chunked, and reauthenticates each object while streaming without exposing its
  directory. A matching production-store installer accepts that narrow source
  interface, authenticates and semantically restores the complete closure in a
  private bounded store before publishing any destination object, then installs
  immutable objects idempotently and commits the manifest last. Campaign CAS
  now retains that complete closure under exact-root version four: a canonical
  production-manifest leaf and typed production-object leaves are covered by
  bounded 4,096-entry index envelopes, and the root binds the exact scenario,
  configuration, production identity, counts, and aggregate bytes. Preparation
  authenticates native and CAS identities without writes; publication places
  all leaves and indexes before the root; loading reconstructs a lazy portable
  source for the production semantic installer. Concrete packaged capture and
  ledger handoff are now wired into the fixed pool: the runner captures the
  complete source, validates its lineage scenario, prepares the version-four
  root, persists `checkpoint-publishing(root)` through a pool-owned callback
  while the lifecycle remains live, then shuts down and returns an opaque phase
  token for campaign-CAS publication and durable pause. The callback never
  releases the aggregate reservation before teardown, and its phase cannot be
  forged by an external model. Native overlay/VMState hashing and persistence,
  portable closure opening/validation, and campaign-CAS identity/publication
  streams now observe the exact execution cancellation between fixed one-MiB
  I/O chunks and between node/object operations. Cancellation remains typed,
  never retries as storage availability, and still runs mandatory QMP snapshot
  deletion/resume cleanup before the lifecycle can release its guard. The
  native lifecycle catalog remains a separate scenario-bounded capture layer.
  Version-four restore now loads the campaign root under the execution
  cancellation signal, installs it through one-MiB-bounded portable reads,
  reruns complete scenario-aware validation, and returns a typed modeled basis
  only when the restored schedule continues the exact effective attempt start
  without crossing another campaign branch edge; that attempt admission occurs
  before native destination publication. Version-four source-bound
  replay-oracle promotion now completely reauthenticates the raw portable
  closure, requires one exact source check per live node, lazily regenerates
  only `NotRun` to `Match` snapshot objects and their derived manifest/root
  identities, and reuses unchanged chunked artifacts. The daemon prepares this
  replacement without writes, routes it through the linear source/replacement
  staging and publication phases, and reauthenticates both complete roots after
  restart before the final paused-root CAS. The daemon can now authenticate the
  raw attempt root, stream one live-node snapshot at a time, and serialize the
  complete multi-node fat/thin comparison through node-specific guarded oracle
  owners that finish or quarantine before preparing that replacement.
  Restart discovery retains the exact resource/retention basis and resolves
  the same repository-authenticated lineage, scenario, attempt, path,
  configuration, and branch selection used by ordinary worker dispatch before
  constructing a guarded production-comparison target. That target now carries
  read-only bounded streaming capabilities for the exact overlay and VMState;
  each stream can check the caller-supplied attempt boundary around every
  bounded I/O quantum and rechecks the authenticated manifest length and
  content identity without exposing store mutation or path authority. One
  no-write restart
  dispatcher now maps a raw pause to that complete guarded comparison and maps
  a staged pair directly to full production-pair reauthentication, yielding
  linear stage or reconcile tokens without supervisor ownership.
  A fixed promotion-worker set now owns a deduplicated compact queue bounded at
  65,536 attempt keys, inventories raw and staged phases before service startup,
  enqueues newly committed pauses after releasing the actor, retries transient
  preparation/publication without rerunning semantic execution, cancels active
  comparisons on shutdown, and restores incomplete staged publication to the
  retained raw root. The production adapter binds one guarded replay factory to
  each fixed worker; repository, QEMU, and immutable-store work remains outside
  supervisor ownership.
  Packaged composition captures the baked source before endpoint binding,
  installs one promotion owner per semantic worker, derives `ExactRestore`
  advertisement from that nonempty owner set, and exposes the fixed
  promotion-worker count in its bounded report.
  The guarded fresh lifecycle now supplies the bootstrap half of the concrete
  thin source: it captures exact scenario genesis without a modeled quantum,
  performs mandatory teardown, and admits only a completely authenticated
  version-four native closure whose live-node set exactly equals the World.
  A concrete real-node replay factory now opens one node from a shared compact
  baked catalog, prepares independently bound exact and thin run directories,
  streams both authenticated artifact pairs under one resource guard, and
  returns the fixed-node paired launcher/store session. Assignment-root-aware
  cleanup of abandoned native entries remains open.
  Production-loop process reconstruction and
  exact-resume driver selection are implemented: `NotRun` is rejected during no-write admission,
  the exact closure is restored under the attempt guard, and the packaged
  worker uses a disjoint exact-origin runner. A guarded-only
  exact-root launcher now consumes that
  pinned authority, rechecks the selected snapshot and checkpoint identities,
  requires a common exact binding on VMState and every command-required root
  overlay, and uses the sealed child-process contract for pre-`exec`
  containment. The thin-path launcher applies the same pair check under a
  distinct thin-catalog hash domain; replacement, exact-target, and thin
  artifacts therefore cannot be substituted across roles. The
  daemon resume adapter derives production replay admission inside the QEMU
  boundary, rejects `NotRun` or mismatched oracle evidence before launch, and
  checks the guard immediately before and after realization. The single-host
  owner now validates the exact selected raw root through independent fat/thin
  realization, retains a source-bound comparison result, publishes a matching
  metadata/root promotion without rewriting VMState, and durably replaces the
  exact-pin selection. A guarded replay-validation session now owns the process
  contract and resource guard, routes target and thin-base VMState through
  disjoint launch capabilities, serializes their process generations, and
  reaps the final generation before promotion; failure quarantines the guard
  without writes. The packaged fixed worker set now owns and schedules those
  comparison flights. The nondroppable direct-child/cgroup/watcher worker exists
  crate-internally; complete production failure handoff into it remains open.
  The authority remains crate-internal until those security boundaries are
  composed. Validated launch commands now
  expose and exact-check their fixed vCPU, guest-memory, exact-VMState writable
  minimum, and root-overlay requirements against an admitted resource ceiling;
  the concrete session must invoke that check before spawn.
- [ ] **T-CAM-4.6** Implement strict and streaming commit modes, restart
  recovery, duplicate/conflict handling, backpressure, pagination, and
  projection rebuilding; implement snapshot-bound paged planner scans whose
  result is chunk-size independent; reject stale, oversized, timed-out,
  cancelled, and nondeterministic planner invocations.
  Exact observation publication now covers execution-basis authentication,
  strict global-admission order, stale-safe replay, deterministic conflict
  retention, exact root deltas, imported recomputation, and final-CAS safety;
  Executor restart recovery now uses direct-by-ID, bounded, checksummed,
  single-writer directory records and preserves exact responses, completed
  observations, and cancellation races without loading history. Bounded
  campaign-supervisor scheduling plus drain and cancel-and-retry pause policies
  are implemented. The guarded live session can now capture a basis-checked
  exact snapshot while retaining the paused process and resource guard;
  exact request/response, durable handoff, root-before-write phase tokens,
  restart root preservation, GC enumeration, captured-result propagation, and
  paused-capacity replacement are implemented. Exact-pin selection
  reauthentication and fail-closed VMState resume materialization are
  implemented. Strict v2 resume request/response messages now bind a fresh
  assignment to the exact prior execution, checkpoint, and unchanged execution
  basis. Durable supervisor, worker, loopback, and campaign-driver resume wiring
  is implemented, including restart recovery and GC retention of the resume
  input root. The QEMU attempt runner now bypasses ordinary exact-cache and
  thin-replay lookup for resumed work, delegates the retained root to the
  guarded live session, requires the returned immutable root ID to match, and
  rejects a non-resume, foreign-configuration, non-exact realization, missing
  scheduler continuation, or mismatched scheduler configuration, frontier,
  state, future decision-RNG cursor, event-log offset, or retained segment set
  before modeled guest execution. The complete
  scheduler continuation now survives capture, immutable publication, restart
  materialization, and the typed session-to-driver handoff. The complete-root
  attempt materializer and session trait handoff are implemented. Guarded
  raw-root replay-oracle validation,
  source-bound no-write preparation, linear source/replacement root staging
  and publication, version-6 ledger persistence of the exact
  resource/retention promotion basis, streaming restart discovery, restart
  reauthentication, explicit incomplete-promotion revert, and the final paused-root CAS are
  implemented without holding the supervisor actor across QEMU or store work.
  The fixed 65,536-entry promotion queue and fixed promotion worker set now
  schedule both newly paused and restart-discovered phases with exact-key
  deduplication, classified retry, cancellation, and bounded reporting.
  The crate-internal quota/run-directory owner and its public sealed composition
  with the process owner are implemented, including reap-before-storage release
  and nondroppable combined quarantine. The owner now lends fresh monotone,
  admitted descriptor-pinned generation directories and exact-VMState
  destinations through the daemon guard under one aggregate quota.
  The guarded exact-resume adapter now invokes the real-node launcher only after
  root materialization through the attempt-owned directory. The packaged worker
  selects that resume adapter without fresh fallback, restores the complete
  event prefix and quiescence boundary, and retains runner-owned shutdown and
  result sealing. Fresh exact-cache, native-catalog cleanup, and production
  tuning remain open; `NotRun` is still fail-closed. Packaged startup installs
  the fixed replay-oracle owners and advertises `ExactRestore` only after that
  owner set exists. The fixed worker
  pool and its
  linear observation/checkpoint
  publication/reconciliation paths are implemented.
  The repository owner now also implements the core schema-v5 pin transaction:
  graph-scoped target validation, exact command replay and reuse rejection,
  pins/accounting/coordination root projection, tombstoned unpin intent, and
  imported-history recomputation. The principal-aware user-facing service,
  versioned loopback, and exact-precondition `pin`/`unpin` CLI binding are now
  implemented. A bounded, snapshot-bound repository visitor now authenticates
  the current projection and its exact thin configuration/scenario artifacts;
  the daemon composes those records with a separately held, exclusive
  assignment-ledger fence that streams observation and checkpoint roots under
  one restart-stable generation. A bounded, checksummed, restart-safe
  single-writer exact-pin journal now authenticates one complete checkpoint
  against the current exact pin fact and modeled configuration. GC consumes it
  under the authoritative ref and selection fences, rejects missing or stale
  current selections, and revalidates the exact root manifest before apply.
- [ ] **T-CAM-4.7** Implement hierarchical per-event promotion and existing
  minimization integration.
  The execution-model bridge now normalizes one bounded, homogeneous
  signal-fault runtime frontier into exact campaign declaration, integer
  domain, and opportunity records. It reauthenticates those records and a
  campaign branch selection to reconstruct the exact selection plus optional
  override prefix, including the unmodified-result sentinel. Campaign attempt
  decoding recognizes this standardized adapter, reconstructs up to 4,096
  nested promoted events in exact schedule order, and retains one opaque
  validated replay plan. The fresh production lifecycle installs all finite
  signal overrides before launch, stops at each exact parent/time frontier,
  proves the exact producer choice through a consumed override or matching
  unmodified runtime frontier, injects only the typed selection-plus-optional-
  override prefix, prevents checkpoint capture while a prefix remains, and
  reconstructs the plan from immutable input after restart. Live publication
  now snapshots frontier history before each quantum, admits only newly recorded
  frontiers still at the exact current parent/time boundary, and returns a
  zero-node-progress result bounded to 4,096 frontiers and 128 MiB of unique
  canonical choice material. The modeled driver retains that discovery only
  when it causes the exact `NextChoice` stop; later-stop observations cannot
  retrospectively publish it, and a queued replay branch suppresses duplicate
  discovery. Promotion is now attempt-scoped: the fresh runner enables it only
  for `NextChoice` after exact start materialization, so historical prefix
  frontiers remain replay-only. Terminal, marker, time, and event-count
  executions pass through finite authored search frontiers without campaign
  pauses. Automatic planner selection of a bounded interesting suffix/window
  and automatic signature-preserving minimization remain open.
- [ ] **T-CAM-4.8** Complete the §14 Phase 4 local operator flight through lazy
  widening, additive finite branching, edge deduplication, live status,
  explanation, bounded pressure, pause/restart/resume, steering, and graceful
  stop.
- [ ] **T-CAM-4.9** Implement the authoritative language-neutral
  `CampaignService`, pure `PlannerEngine`, and local `ExecutorService` schemas;
  provide direct and loopback-RPC adapters, golden vectors, fake components,
  capability negotiation, idempotent assignment, and component conformance.
  The repository checkpoint now provides strict canonical planner/debugger
  submission messages with separate operational keys, public authority-specific
  direct adapters, zero-write authentication failure, and an exact replayable
  choice-discovery owner required before branching. The planner component now
  has strict 64-MiB request/response wire messages, by-value invocation inputs, a
  sorted content-addressed source-interpretation bundle, exact request-digest
  response binding, a mandatory adapter-owned execution-supervisor contract,
  supervised authority signing, checked direct clients,
  golden vectors, fake engines, and a versioned Unix-loopback adapter with
  finite absolute deadlines, close-on-error behavior, and direct/loopback
  equivalence. The coordinator now supplies capability-gated, snapshot-owner-
  recomputed continuation projections for every served source. Built-in
  `crucible-canonical-frontier` version 1 receives one exact next-candidate
  offer for the least Ready position on each page and consumes that
  bundle without repository authority, carries the least Ready offer across
  pages in bounded portable state, and deterministically returns Continue,
  Issue, or NoWork only at the valid scan boundary. Accepted offer envelopes
  become retained-request children after zero-write semantic preflight, and
  import/restart recompute the same source ordinal and value. Version 2 receives
  an offer and exact bounded PUCT guidance for every Ready source, ranks the
  owner-derived score across pages, and is now the packaged daemon default;
  version 1 remains replay-compatible. Both run behind a versioned one-request
  process protocol:
  a parent-owned supervisor measures deterministic page fuel, enforces a
  finite wall deadline and sticky cancellation, drains bounded pipes, and
  kills and reaps the authority-free worker before returning. The generic
  daemon-owned long-lived coordinator runtime is implemented. Process startup
  can now attach a bounded fixed set of up to 256 such runtimes to unique
  explicitly named existing campaigns, each with the packaged planner and a
  matched authenticated local executor. Automatic campaign discovery, dynamic
  attachment, shared packaged-executor allocation, and additional opaque
  non-finite model-prior adapters remain open. The first `CampaignService`
  checkpoint now provides
  strict principal/name types, 64-MiB canonical request/response messages for
  bounded by-value creation, authenticated current-head reads,
  lifecycle/budget/policy control, and additive operator branch submission,
  exact response-digest binding, a
  checked direct client, raw golden vectors, and a repository adapter that
  requires exact-request authentication/authorization before repository
  access. Creation loads and validates an exact imported transitive generator
  closure and replays
  the authenticated genesis for a semantically identical named retry in
  constant time from validation checkpoints after later mutations. The daemon
  now provides a narrow Crucible verifier-backed immutable artifact importer;
  large scenario/configuration bytes remain outside the campaign control
  message and are re-derived before publication. The daemon's local-service
  bootstrap now has an exclusive prepared-repository state that applies strict,
  bounded, exact-owner version-1 import manifests before socket bind; binding
  consumes that import authority, and read-only service mode rejects it. The
  same bootstrap can now authenticate an optional exact-owner mode-`0600`,
  fixed-size version-1 planner/debugger authority bundle before state open and
  construct the repository with distinct operational keys; omission explicitly
  leaves component acceptance unavailable until start/runtime attachment is
  composed. Stored
  generator closure validation streams within 4,096-record and 128-MiB
  aggregate-body bounds and does not rewrite imported records. Atomic
  name-based derivation now creates
  an audited successor of an exact authenticated source snapshot, optionally
  activates a compatible imported policy, leaves the source ref unchanged, and
  exactly replays the original derived snapshot after later target mutations,
  cache eviction, restart, or a same-basis CAS race. Canonical bounded finding
  and self-contained reproduction records now have a verifier-backed Crucible
  importer and an atomic occurrence-clustering owner with restart validation.
  Rich frontier explanation, start-attachment porcelain, and richer
  filtered/aggregated CLI views remain open. The CLI wiring uses the
  checked local Unix-stream client for authenticated `status`, one-shot
  resumable `watch`, exact immutable pages of graph keys, discovered choice
  opportunities, and continuation states, and exact-command,
  snapshot-preconditioned `resume`, `pause`, `stop`/`seal`, `unseal`, additive
  budget, and policy steering. Every mutation reports its prior/new snapshots,
  command ID, and replay status through the common table, Markdown, JSON, and
  JSONL renderers. A bounded
  coalesced `WatchCampaign`
  operation returns one exact current-head cursor and lifecycle projection,
  including stale/unknown-cursor recovery without ancestry work. A bounded
  `QueryGraph` page exact-binds the current snapshot and one authenticated
  graph-root key cursor, rejects a changed head, and returns at most 256 content
  IDs with the exact snapshot body and a minimal bounded Merkle proof. Checked
  clients replay the cursor, complete ancestor prefixes, range, and one-entry
  lookahead to authenticate exact continuation or EOF without fetching object
  bodies or scanning ancestry for cursor/page resolution beyond the
  repository's required authenticated-head checkpoint rebuild. The local
  graph-object read separately authorizes one exact graph key, authenticates
  its value with a fixed-depth minimal Merkle lookup proof, and exposes only
  strict configuration-artifact or choice-opportunity envelopes. A bounded
  `QueryFrontier` page authenticates a fixed exploration-root index anchor,
  exact request-ordered continuation projection bodies, continuation or EOF,
  and full snapshot metadata within the same proof/message bounds as the
  choice-index query. A separately authorized `GetFrontierObject` call proves
  one exact projection membership and returns only its strict branch-request
  body; it cannot read arbitrary exploration or content-store objects.
  A nested choice index is anchored in the graph root and updated atomically by
  explicit and observation-driven discovery. `QueryChoices` pages at most eight
  opportunity IDs with one exact anchor proof and one exact range/EOF proof;
  legacy heads without the optional index fail closed until a future explicit
  complete migration and ordinary mutations never create a partial index.
  A separate current-or-historical choice-object read authenticates the
  opportunity's authoritative graph membership at one exact named-history
  snapshot and returns only its exact declaration or effective domain;
  arbitrary non-graph reads remain unavailable.
  `QueryFindings` returns at most four complete canonical finding records from
  the authenticated findings root with an exact range/EOF proof and
  signature-key/body identity validation; the checked CLI renders their stable
  class, fingerprint, representative observation, occurrence count, and
  reproduction IDs without granting child-object reads. A separately
  authorized finding-object lookup proves one exact finding membership and
  returns only its representative/latest observation or original/minimized
  reproduction dependency. The checked `explain-finding` composition reads the
  representative observation and original reproduction, then verifies their
  exact finding, fingerprint, and configuration-artifact basis before rendering
  the handoff identities.
  A proof-bearing attempt explanation authenticates the semantic attempt and
  execution-basis admission in accounting, its optional branch proposal in
  exploration, its planner invocation result in coordination, and its canonical
  completion or absence in observations. The checked CLI renders the exact
  path, cause, admission ordinal, selection, proposal, completion, accepted
  planner step, fixed-point guidance terms, and coordinator accounting without
  granting arbitrary record reads.
  The local
  Unix-stream binding
  now dispatches all thirty-four current success messages plus one stable
  request-bound error envelope under a version-17, 64-MiB-body,
  absolute-deadline frame.
  `QueryCampaignGraph` authorization covers the complete anchoring snapshot
  metadata and all root IDs; bodies named by those IDs retain separate access
  control.
  `GetCampaignSnapshot` authenticates named-history membership and returns an
  exact identity-checked current or historical snapshot body under that same
  metadata capability.
  Protocol, canonical, I/O, and poisoned-lock failures shut down the connection;
  semantic failures keep it reusable, and concurrent exchanges receive a
  retryable busy error instead of queuing outside those deadlines. Direct and
  loopback clients now expose the same closed authorization/conflict/transition/
  resource/availability/integrity failure vocabulary. A connected-stream
  repository adapter now reads Linux `SO_PEERCRED`, resolves exact PID/UID/GID
  through a mandatory deployment policy, and binds the result to every claimed
  request principal before repository access. A bounded listener over either
  an embedded pre-bound socket or a managed filesystem endpoint now caps
  connection workers at 256 and its
  pending queue at 1,024, caps one connection at 65,536 requests, resolves peer
  identity once per connection, rejects excess sockets, interrupts active
  streams on sticky shutdown, and joins every worker before returning
  operational counters. An immutable local policy now maps at most 4,096 exact
  effective UID/GID pairs (never PID) to principals and retains at most 65,536
  exact operation plus campaign/all-campaign grants, rejecting ambiguity and
  unreachable grants. The registered strict version-1 TOML policy is bounded
  to 1 MiB before parsing and rejects unknown fields, versions, and operation
  labels. Managed listener bootstrap validates a canonical 107-byte Linux
  pathname, exact-owner non-group/other-writable parent, owner-only lifetime
  namespace lock, same-owner stale socket, configured socket mode, and
  exact-inode conditional teardown. The parent tree remains operator-owned
  deployment state. A durable bootstrap now opens the strict policy before
  mutation, holds one exact-owner state-root lock across private directory blob
  and ref backends, excludes a second socket incarnation, and reopens that state
  after restart. The existing `crucible serve` process exposes the socket,
  state, policy, and octal-mode profile as all-or-none flags. Optional paired
  runtime-name/executor-socket flags attach the packaged planner to one existing
  campaign only after exact-owner socket and `SO_PEERCRED` authentication plus
  executor-description negotiation. CampaignService/runtime failure and
  SIGINT/SIGTERM trigger shared shutdown and worker join. Process read-only mode
  also denies every campaign mutation after policy resolution. Structured
  diagnostic routing and richer creation/attach porcelain remain open; message
  framing or listener construction alone is not authentication.
  Checked
  request/response acceptance now retains the
  exact canonical request in a content-addressed envelope (32-MiB and 65,529
  bundle-object initial store profile) and commits both its ID and digest in
  planner-step schema v4. The executor
  checkpoint now provides strict 4-KiB canonical `SubmitAttempt`, execution
  status, exact-checkpoint, and cancellation request/response messages,
  nonzero operational assignment/execution/epoch IDs,
  explicit resource and retention fields, exact-request digest binding, stable
  retry/conflict outcomes, golden vectors, malformed-input rejection, an
  implementor-facing service trait, and one checked coordinator client for
  direct and RPC use. Repository validation authenticates the attempt and
  lineage for every response and the complete observation/attempt/lineage
  correspondence before accepting `already-completed`. The daemon now provides
  a trait-based memory/directory assignment ledger, fsynced immutable response
  publication, lineage-qualified conditional attempt state, exact
  resource/retention execution-basis deduplication, bounded aggregate and
  per-execution-quanta admission, reauthenticated completed-state reuse,
  idempotent running/checkpoint-requested/checkpoint-publishing/paused/
  completed/canceled transitions, commit-indeterminate publication recovery,
  restart and GC-root conformance tests, a production repository
  admission/completion adapter with an exact immutable executor profile, and a
  strict 4-KiB versioned Unix-loopback binding with finite deadlines,
  close-on-error behavior, direct/loopback equivalence, and hostile/partial
  frame tests. The repository candidate handoff and generic worker driver now
  use non-cloneable dispatch and phase tokens, keep semantic model input free
  of assignment and daemon identities, preflight the complete candidate before
  writes, and carry each newly discovered declaration, domain, and opportunity
  through a self-contained handoff bounded to 65,530 discoveries and 128 MiB
  of unique canonical choice records. The narrow executor store publishes that
  validated immutable bundle without gaining repository or mutable-ref
  authority. The supervisor persists a lineage-qualified `publishing` root
  before immutable publication, streams publishing/completed roots to GC,
  recovers exact expected results across restart, keeps cancellation resources
  charged until worker exit, and reconciles publication without holding the
  supervisor actor or rerunning the guest. Snapshot incorporation remains
  coordinator-only. A
  strict Crucible execution adapter now decodes versioned scenario/schedule
  payloads, re-derives semantic IDs before runner invocation, and exposes a
  typed runner boundary for operational hot/exact/thin selection. Branch input
  revalidates provenance against its exact parent, carries the selected
  canonical prefix, and keeps the runner's realized tier as operational
  telemetry outside immutable candidate bytes. The execution
  model now retains a validated campaign `Selection` as one canonical Schedule
  V2 decision with strict binary/serde decoding, content-address participation,
  event-log projection, and conservative reduction semantics. The daemon's
  exact/thin QEMU runner now invokes the existing authenticated realization
  coordinator through a mandatory attempt-scoped resource/cancellation session,
  classifies exact versus replay telemetry, delegates typed
  selection/stop/candidate work through the session's live-backend capability,
  and tears the session down on every exit. The live-node composition now
  installs and verifies the exact guard before launch authority is returned,
  exact-binds the cancellation incarnation, lends the driver only narrow live
  operations and a read-only unified event log through a session-owned facade
  that charges one guard quantum before every realization-replay or live
  advance. Backend-shaped charge errors retain their operational
  cancellation/resource classification.
  Replay exact-binds the caller's offset to that single log before backend
  work; candidate acceptance binds the driver's exact log offset and requires
  an unchanged paused-boundary seal plus an unchanged final shutdown drain. The
  session releases the guard only after reap attestation, and cleanup tracks
  backend and guard phases separately on explicit finish and drop. Normal
  shutdown receives that same guard, so a failed direct-child reap can retain
  or transfer its exact authority before quarantine. Only
  explicitly typed availability failures retry; deterministic realization
  failures terminate.
  Canonical `DescribeExecutor` and cursor-bound `WatchCapacity` messages now
  separate immutable compatibility/ceiling facts from daemon-epoch-scoped
  availability and exact/hot locality. Checked direct and Unix-loopback clients
  reject stale epochs, capability drift, non-advancing sequences, capacity
  above immutable ceilings, and unsupported locality. The local supervisor
  facade refuses startup unless advertised ceilings exactly equal enforced
  slots, CPU, memory, disk, and execution-quanta limits. The concrete host
  resource guard's Linux cgroup/quota owner, the versioned
  paused-restore reset of the plugin coverage novelty bitmap/ring plus host
  consumer state, coverage-aware live advancement and canonical coverage
  projection, hot-fork realization,
  full out-of-process campaign flight, and complete component conformance gate
  remain open. Until that reset exists, real-node coverage-enabled warm restore
  fails closed rather than retaining priming events or suppressing post-restore
  coverage.
- [x] **T-CAM-4.10** Replace repeated full-history validation on local owner
  mutations with bounded immutable validated-head/lifecycle checkpoints and
  authenticated membership and result-locator indexes; promote only after ref
  CAS, retain full fail-closed validation for imported or restarted heads, and
  exercise 10,000 mixed request/control mutations plus deep exact replay.

**Gates:** `gate:branch-point-model`, `gate:lazy-frontier`,
`gate:attempt-idempotence`, `gate:campaign-replay`,
`gate:campaign-statistics`, `gate:component-contract`,
`gate:control-responsiveness`, `gate:campaign-mutation-scaling`,
`gate:harness-lint`.

**Manual gate:** accepted §14 Phase 4 local campaign flight.

## 11.7 Phase 5 — Composable content stores and durable closure efficiency

Primary crates: `crucible-cas` and `crucible-api` lifecycle/checkpoint code.

- [ ] **T-CAM-5.1** Introduce separate streaming `ImmutableBlobBackend` and
  conditional `MutableRefBackend` traits, capability and error models, and
  migrate current campaign/exact-closure persistence behind them.
- [ ] **T-CAM-5.2** Implement canonical object envelopes, domain-separated
  logical IDs, child-reference walking, persistent Merkle collections, partial
  closure traversal, and typed corruption diagnostics.
- [x] **T-CAM-5.3** Remove full-file staging copies from the normal exact-closure
  publish/materialize path; stream with bounded buffers and preserve sparse
  extents where valid.
- [ ] **T-CAM-5.4** Implement immutable disk backing plus child overlay
  manifests and content-deduplicated changed-object storage.
- [ ] **T-CAM-5.5** Implement and validate an acyclic store-composition graph
  with verified, routed, tiered, read-through, write-through, write-back,
  compressed, encrypted, quota, metrics, and namespaced layers, including a
  durable GC-protected transfer journal for write-back operation.
- [x] **T-CAM-5.6** Implement packed logical-object storage with crash-safe
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

The admitted graph checkpoint currently provides bounded acyclic validation,
exact kind routing, logical verification, ordered tiers and promotion,
source-authoritative read-through caching, write-through mirroring, and
path-free saturating synchronous operation/byte/error/elapsed-nanosecond counters
plus deferred stream opens, authenticated completions, partial abandonments,
failures, delivered bytes, and open/read elapsed nanoseconds over memory,
durable directory, and packed leaves. Read-through falls through only on exact
absence,
treats promotion as non-semantic, and never reports cache durability as
authoritative source durability. Durable write-back now requires durable
streaming staging/destination children, acknowledges only after staging plus a
checksummed bounded journal append, survives restart, flushes idempotently in
canonical order, and exposes the exact pending set behind a shared/exclusive
lifecycle fence. GC planning includes those IDs in the canonical root manifest;
apply reacquires and holds the fence, rejects a changed set before deletion, and
therefore cannot collect a children-before-journal publication. Tests cover
restart, torn-tail recovery, corrupt-journal rejection, count/byte limits,
durable-child and non-overlapping-path admission, lifecycle exclusion,
single-pass staging authentication, transfer completion, and stale GC plans.
Destination-specific durability policy plumbing,
compression/encryption below plaintext identity, restart-safe aggregate quota,
namespaced authorization, S3, and composed administrative inventory/GC remain
open; therefore T-CAM-5.5 is not checked by this checkpoint.

The packed leaf now provides immutable bounded multi-object pack files, a
checksummed persistent logical index with monotonic generations, full logical
authentication after range extraction, exact logical/physical accounting, and
a separately held logical-inventory/deletion fence. Repack is an explicit
canonical plan/apply operation bound to the backend configuration, persistent
instance, exact index generation and digest, and pre-apply accounting. Apply
publishes and verifies all replacement packs before the atomic index switch,
records the applied plan for restart-safe indeterminate-commit replay, and only
then removes superseded names. Open readers pin old inodes. Startup reclaims
unindexed complete packs while missing or malformed referenced packs fail
closed. Tests cover one-object-to-multi-object pack identity stability,
authenticated range reads, concurrent old-generation readers, restart replay,
stale and corrupt plans, sparse logical deletion, pack-before-index recovery,
index corruption, referenced-pack loss, empty objects, accounting, graph
admission, and physical configuration mismatch. Phase 5's composed-tier, S3,
global-GC, archival, and realistic operator flights remain under T-CAM-5.7
through T-CAM-5.9 rather than weakening this completed leaf contract.

The memory, directory, and packed blob leaves now expose separately held,
exclusive administrative fences for physical logical-object inventory. The
memory and directory ref leaves separately fence the complete authoritative ref
namespace. Object inventory streams exact placements under a
backend-instance generation and supports idempotent deletion of an already
planned candidate. Ref inventory streams exact name bindings under its own
monotonic generation; every accepted replacement advances it, so same-value ABA
is distinct across restart. Directory generations use registered checksummed v1
state records and advance durably before cooperating mutation. Tests cover
restart, object and ref ABA, early visitor failure, malformed/oversized input,
valid staging-prefix names, and mutation exclusion while fenced. Store-graph
administrative composition, the now-implemented fenced operational-ledger root
snapshot, and a strict registered v1 plan header now compose store-graph,
root-manifest, candidate-manifest, blob, ref, and ledger hashes/generations into
one immutable identity. Complete manifest/reachability planning,
interruption-safe global-GC apply/recovery, composed store-graph administration,
and production maintenance ownership remain open. Those gaps do not weaken the
separately completed packed-leaf T-CAM-5.6 contract.

The production exact-closure checkpoint now holds every running QEMU node
paused while it authenticates and streams the live generation's overlay and
VMState directly into bounded content chunks. It publishes the closure before
deleting transient QMP snapshots and resuming the originally running nodes, and
it no longer copies both artifacts through an additional full-file staging
tree. Direct-file and chunk-sequence restore now use one fixed 1 MiB buffer,
authenticate length and whole-object identity during the copy, recreate zero
runs as sparse extents, publish the destination atomically, and leave no partial
destination after corrupt or missing input. Immutable backing plus
changed-overlay manifests and `O(changed state)` capture remain open, so
T-CAM-5.4 remains unchecked.

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

The first Phase 6 protocol checkpoint is implemented without claiming the
spike complete. Patched QEMU owns a fixed, versioned readiness bitmap exposed
through typed QMP, and the Apache client rejects unknown schemas, changed proof
sets, unknown acknowledgements, and contradictory readiness. QEMU currently
acknowledges only precise icount, single-threaded sim RR, and an authenticated
exact paused/device-flush boundary. It deliberately leaves the AIO/BH/timer,
RCU, block-snapshot, plugin-ring, mapping/descriptor, and child-reinitialization
proofs clear, so no hot-fork capability can be advertised yet. The remaining
T-CAM-6.1 inventory and T-CAM-6.2 coordinator work must move those bits through
subsystem-owned barriers rather than weakening this fail-closed query.

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
  `fork` only as a deprecated compatibility alias for `branch` if needed. The
  checked local client now exposes canonical create/derive inputs and exact
  finite or already-imported generated operator branch requests in addition to
  lifecycle control. Exhaustive `--all` authenticates the exact current or
  historical opportunity domain, derives the canonical version-2 generator and
  cardinality budget, and is owner-checked against the active exhaustive policy
  before publication. The initial repeatable daemon-startup import manifest now
  admits dependency-ordered compact scenario/schedule pairs and canonical
  generator bodies through the narrow verifier-backed importer before endpoint
  bind. Offline `campaign validate-import` now applies the same strict file and
  configuration checks, requires a self-contained dependency-ordered generator
  set, streams one body at a time, and reports exact derived identities without
  opening repository state. `campaign create --start-command COMMAND` now
  submits a separate idempotent `Resume` against the exact returned genesis
  snapshot and reports both checked results; creation and start are deliberately
  retry-safe rather than atomic. The standalone `campaign start` command now
  applies the same exact-preconditioned, idempotent `Resume` transition while
  retaining `start` as the reported operator intent. Operator branch porcelain
  now resolves an exact declaration name, selectable ID, or semantic tag
  through the proof-bearing choice index and separately authorized
  opportunity/declaration/domain reads.
  Up to sixteen repeated predicates form a conjunction; resolution scans to
  authenticated EOF under a 4,096-opportunity ceiling and rejects absent or
  ambiguous matches before publication. Rich manifest authoring and policy-file
  selector expressions remain open.
- [ ] **T-CAM-8.2** Implement graph/frontier/choices/findings/explain/compare
  queries with branch-point/source/provenance views, pagination, and versioned
  JSON. Snapshot-bound graph/frontier/choices/findings traversal is exposed
  through the checked local client in table, Markdown, JSON, and JSONL. One
  page remains the default; an explicit page budget follows at most 256 pages
  while admitting at most 65,536 aggregate entries and 128 MiB of aggregate
  canonical response bytes. Each page is independently proof- and
  request-validated before accumulation, repeated cursors fail closed, and the
  version-2 report preserves the start/resume cursor, authenticated EOF, and
  exact page/byte accounting. Exact graph configuration/opportunity bodies, choice
  declaration/domain dependencies, and frontier branch requests are also
  exposed through their separately authorized proof-bearing operations with
  semantic source, budget, continuation, and provenance fields. Exact historical
  snapshot inspection and two-snapshot comparison use independently checked
  named-history reads and report policy, transition, direct-parent, and all-root
  changes. The first explanation operation joins an authenticated choice
  declaration to an authenticated frontier request and fails closed unless
  their opportunity and domain agree before reporting legality, producer,
  cause, budget, stop, and continuation state. A proof-bearing findings page
  returns complete canonical clusters in signature-key order and renders their
  stable failure and reproduction projection. A second explanation operation
  composes separately authorized observation and reproduction reads for one
  exact indexed finding, rejects cross-finding/configuration/fingerprint drift,
  and renders its causal, evidence, occurrence, stop, and replay basis.
  Exact attempt/execution-basis/proposal/completion explanation now also proves
  the coordinator-accepted planner step for planner-issued proposals and
  renders its fixed-point guidance decomposition and accounting. Aggregate
  ranking now has a public owner-independent per-request projection: it
  revalidates each retained offer/guidance pair against the by-value policy,
  recomputes the decomposed fixed-point score, and returns best-first order with
  the exact packaged-planner edge/position tie-break. The proof-bearing
  `GetCampaignPlannerRankings` query authenticates one accepted step under the
  current snapshot's coordination root, returns its complete retained request,
  and exposes the parent step as the next page. CLI `campaign rankings` follows
  at most 64 such pages under a 128 MiB aggregate response-byte budget and
  applies the same deterministic comparator across all candidates, stopping at
  a policy/engine/artifact/view boundary. Exact branch-point and source filters
  run after proof validation, and an at-most-65,536 top-result cap runs after
  global best-first ordering; the versioned machine report retains the filter
  basis and pre-truncation match count. `--policy-groups` now continues across
  policy changes under the same page/byte/cycle bounds, emits consecutive
  policy epochs, and nests separately ordered exact
  policy/engine/policy-artifact/planning-view bases. It preserves each epoch's
  step range and pre-truncation count, applies filters only after proof
  validation, and applies the top-result limit per comparable basis rather than
  comparing incompatible scores.
- [ ] **T-CAM-8.3** Complete pin/unpin by consuming its authenticated semantic
  projection in generation-bound GC retention plans. Snapshot-bound semantic
  and operational root inventory plus the exclusive generation-bound memory,
  directory, and packed physical-leaf inventory/delete, authoritative-ref
  inventory, and operational-ledger inventory primitives plus the canonical
  bounded plan identity are implemented. The daemon now constructs the
  canonical root and physical-candidate manifests, authenticates their complete
  logical closure,
  produces a non-destructive plan across an ordered set of physical leaves,
  persists the exact plan/manifests and phase in a durable external journal, and
  excludes campaign children-before-ref publication with a shared/exclusive ref
  lifecycle fence. `StoreGraph::build_with_admin` now returns a separate,
  non-cloneable maintenance capability containing every current physical leaf
  in canonical node-ID order; the ordinary graph retained by the repository has
  no administrative escape. The graph and administrative value share one
  registered canonical configuration identity, and public GC plan/apply derive
  both that identity and the exact physical capability set from the
  administrative value rather than accepting independently supplied inputs.
  Exact-generation single-host physical-leaf apply now revalidates every root
  and physical basis, deletes under the leaf fence, and leaves interrupted
  journals recovery-required. A restart regression applies
  that path to a sparse packed leaf and proves logical deletion retains the live
  object and shared pack. Exact-pin materialization selection is now
  restart-safe, exact-configuration/fact-bound, and consumed by both planning
  and apply; stale records cease to root checkpoint closures after unpin.
  Transform/S3 administration, policy-aware reachable-cache eviction, and full
  operator-flight tests remain open. Implement
  replay/debug, export/import, push/pull/sync, and plan/apply GC.
- [ ] **T-CAM-8.4** Route existing run/search/fuzz/save/resume/fork/replay/triage
  through common branch-request and campaign primitives and remove parallel
  explicit-fork/search-expansion state models.
- [x] **T-CAM-8.5** Publish user documentation and the worked network campaign
  as an executable fixture. The public Crucible guide now documents the
  shipped single-host campaign surface: strict offline import, managed daemon
  ownership, authenticated creation and inspection, lifecycle mutations,
  proof-bearing explanations, restart rules, and packaged local execution. The
  `campaign fixture worked-network` command now emits an owner-only canonical
  scenario/configuration, lineage, policy, and dependency-ordered generator
  import set. It revalidates the manifest before success, and an automated
  blank-repository flight imports the complete set and creates the campaign
  through the checked service API. The generated control-plane fixture omits
  product kernel/root-image references; the actual supported product build and
  full QEMU flight remain mandatory under T-CAM-8.6 and §14.
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
| `CMOD-1..30` | 1, 2, 4 | campaign model, content address, attempt idempotence, continuity |
| `SEL-1..21` | 2 | typed choice, ABI conformance, end-to-end determinism |
| `GUIDE-1..29` | 3, 4 | lazy frontier, campaign statistics, campaign replay |
| `LAZY-1..51` | 4 | lazy frontier, attempt idempotence, campaign replay |
| `CCOMP-1..24` | 0, 4, 8 | component contract, control responsiveness, attempt idempotence, ABI conformance |
| `HFORK-1..24` | 6, 7 | hot-fork equivalence/isolation/scaling, world-fork atomicity, ABI/license |
| `CSTORE-1..22` | 1, 5 | store equivalence, store composition, exact-closure streaming, continuity |
| `CAPI-1..14` | 8 | CLI/API contracts, continuity, campaign replay |
| `CMEAS-1..14` | 3, 8 | campaign model, replay, ABI conformance |
| `CSEC-1..12` | 1–9 | license boundary, ABI conformance, isolation, store equivalence |
| `CPERF-1..9` | 4–7, 9 | branch-point model, lazy frontier, hot-fork scaling/equivalence, exact-closure streaming |
| `CMAN-1..22` | 0–9 | operator acceptance, destructive recovery, dogfood, campaign replay |

The executable traceability check required by T-CAM-0.4 must expand every range,
name at least one implementing task and test for each requirement, reject stale
IDs in either direction, and remain part of the completion gate.
