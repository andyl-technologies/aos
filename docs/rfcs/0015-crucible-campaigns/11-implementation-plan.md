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
  The canonical bounded observation, measurement-set, property-verdict-set,
  and coverage-projection record layer is implemented; aggregate verification,
  objectives, ranking, explanations, and the Phase 3 flight remain open.
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
  discovery-versus-branch attempt starts, immutable attempt execution basis,
  global admission ordinal, authenticated branch path, additional-cause
  association, proposal, attempt, observation, credit, input-only planner
  invocation, coordinator-accepted planner step/accounting, branch-point
  `ExpansionState`, and per-source portable continuation state.
- [ ] **T-CAM-4.3** Implement progressive-widening exact rational rules,
  interval refinement, deterministic PUCT, coverage/rarity/assertion/objective
  guidance, and path backpropagation. New branch paths now retain exact
  branch-point/edge segments under schema version 2, while identity-preserving
  v1 reads remain available. Canonical schema-v1 observation/branch-point
  credits now survive replay and restart and drive exact completed-visit counts;
  schema-v4 observation transitions additionally retain every cumulative path
  under its exact child configuration, and direct non-genesis admission
  authenticates its prefix against that nested index after restart/import.
  Planner-issued non-genesis path selection and reward, novelty, finding,
  interval, and PUCT folds remain open.
- [ ] **T-CAM-4.4** Replace checkpoint-once frontier authority with branch-point
  source continuations, an attempt-level rebuildable queue, and volatile
  daemon-epoch reservations.
  The repository checkpoint now provides snapshot-bound, bounded accounting
  scans that authenticate canonical attempt membership, exclude completed
  observations, remain page-size independent to EOF, and rebuild identically
  through a fresh repository. Its bounded process-local reservation table is
  idempotent per worker slot, rejects stale epoch/generation releases, and
  restarts empty under a fresh daemon epoch. Adaptive generated-source
  continuations and supervisor integration remain open. The repository now also
  maintains a compact snapshot-authenticated continuation projection for each
  request and serves bounded proof-bearing frontier pages. Finite request,
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
  materialization. Static continuation projection remains valid after modeled
  observations exist: it binds the exact observation root and projects exact
  completed visits from canonical branch-point credit sets while leaving richer
  reward, novelty, and finding statistics zero. Other
  generated requests remain conservatively `Open` and
  fail closed when proposal or expansion semantics are requested. Legacy
  snapshots remain unindexed and queries fail closed rather than constructing a
  partial index.
- [ ] **T-CAM-4.5** Implement `CampaignSupervisor`, `CampaignProjector`,
  `ProposalPlanner`, `AttemptQueue`, and a bounded local `WorkerPool`.
  The standalone bounded `AttemptQueue` reservation primitive and the daemon's
  single-host `LocalExecutorSupervisor` are implemented. The latter enforces
  exact assignment replay, aggregate slot/CPU/memory/disk capacity, a bounded
  pending queue, durable completion/cancellation races, and restart replacement
  of stale executions. The local worker now resolves repository-authenticated
  attempt inputs behind an execution-model trait, publishes a completely
  preflighted immutable observation-candidate bundle without advancing campaign
  state, and returns results to the supervisor actor for durable completion or
  bounded retry without holding supervisor state during guest execution.
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
  authority instead of dropping it. Process membership is fixed-memory and
  bounded to 65,536 tasks. The authority derives PID/start-time/executable
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
  authority retains that basis, and guarded spawn rejects a changed command
  resource profile or ceiling before revalidation or descriptor allocation.
  The writable ceiling also supplies a conservative per-file limit; aggregate
  enforcement remains the responsibility of the open filesystem quota
  composition.
  A prepared run-directory authority now pins the directory and exact regular
  VMState inode without following final symlinks. Guarded spawn reauthenticates
  the entry before allocation, changes directory by descriptor after cgroup and
  cancellation admission, and repeats the inode check immediately before
  credential drop and `exec`; replacement of the diagnostic path therefore
  cannot redirect launch. The production owner must still exclude concurrent
  namespace mutation until QEMU has opened every relative artifact.
  A nondroppable daemon owner preserving the lifecycle-bound combined
  child/cgroup/watcher process quarantine, aggregate
  filesystem quota, execution-quantum counter composition, exclusive run-
  directory namespace ownership through artifact open, the modeled attempt
  driver, concrete session wiring, and responsive multi-slot scheduling remain
  open.
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
  observations, and cancellation races without loading history. Campaign
  supervisor scheduling, non-modeled ordinal closure, and claim-reservation
  integration remain open.
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
  equivalence. A killable production supervisor that enforces fuel, wall-clock,
  and cancellation bounds, the coordinator-owned Merkle-proof guidance bundle,
  and concrete closed planner remain open. The first `CampaignService`
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
  message and are re-derived before publication. Stored generator closure
  validation streams within 4,096-record and 128-MiB aggregate-body bounds and
  does not rewrite imported records. Atomic name-based derivation now creates
  an audited successor of an exact authenticated source snapshot, optionally
  activates a compatible imported policy, leaves the source ref unchanged, and
  exactly replays the original derived snapshot after later target mutations,
  cache eviction, restart, or a same-basis CAS race. Paged finding queries,
  rich frontier explanation, and CLI wiring remain open. A bounded
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
  A separate choice-object read authenticates the opportunity's authoritative
  graph membership and returns only its exact declaration or effective domain;
  arbitrary non-graph reads remain unavailable.
  The local
  Unix-stream binding
  now dispatches all twenty-two initial success messages plus one stable
  request-bound error envelope under a version-10, 64-MiB-body,
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
  request principal before repository access. Production accept-loop and policy
  configuration plus CLI wiring remain open; message framing alone is not
  authentication. Checked
  request/response acceptance now retains the
  exact canonical request in a content-addressed envelope (32-MiB and 65,529
  bundle-object initial store profile) and commits both its ID and digest in
  planner-step schema v4. The executor
  checkpoint now provides strict 4-KiB canonical `SubmitAttempt` request and
  response messages, nonzero operational assignment/execution/epoch IDs,
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
  idempotent running/completed/canceled transitions, commit-indeterminate
  publication recovery, restart conformance tests, a production repository
  admission/completion adapter with an exact immutable executor profile, and a
  strict 4-KiB versioned Unix-loopback binding with finite deadlines,
  close-on-error behavior, direct/loopback equivalence, and hostile/partial
  frame tests. The repository candidate handoff and generic worker driver now
  use non-cloneable dispatch and phase tokens, keep semantic model input free
  of assignment and daemon identities, preflight the complete candidate before
  writes, persist a lineage-qualified `publishing` root before immutable
  publication, stream publishing/completed roots to GC, recover exact expected
  results across restart, keep cancellation resources charged until worker
  exit, and reconcile publication without holding the supervisor actor or
  rerunning the guest. Snapshot incorporation remains coordinator-only. A
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
  resource guard's quantum-counter composition, modeled driver, the versioned
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
| `CMOD-1..30` | 1, 2, 4 | campaign model, content address, attempt idempotence, continuity |
| `SEL-1..21` | 2 | typed choice, ABI conformance, end-to-end determinism |
| `GUIDE-1..24` | 3, 4 | lazy frontier, campaign statistics, campaign replay |
| `LAZY-1..43` | 4 | lazy frontier, attempt idempotence, campaign replay |
| `CCOMP-1..24` | 0, 4, 8 | component contract, control responsiveness, attempt idempotence, ABI conformance |
| `HFORK-1..24` | 6, 7 | hot-fork equivalence/isolation/scaling, world-fork atomicity, ABI/license |
| `CSTORE-1..22` | 1, 5 | store equivalence, store composition, exact-closure streaming, continuity |
| `CAPI-1..13` | 8 | CLI/API contracts, continuity, campaign replay |
| `CMEAS-1..14` | 3, 8 | campaign model, replay, ABI conformance |
| `CSEC-1..12` | 1–9 | license boundary, ABI conformance, isolation, store equivalence |
| `CPERF-1..9` | 4–7, 9 | branch-point model, lazy frontier, hot-fork scaling/equivalence, exact-closure streaming |
| `CMAN-1..22` | 0–9 | operator acceptance, destructive recovery, dogfood, campaign replay |

The executable traceability check required by T-CAM-0.4 must expand every range,
name at least one implementing task and test for each requirement, reject stale
IDs in either direction, and remain part of the completion gate.
