# 04 — Lazy frontier, persistent continuations, and daemon ownership

A campaign may imply more branches than can be enumerated, stored, or run. The
daemon therefore treats the frontier as a pull-based collection of suspended
candidate sources attached to branch points and materializes only a bounded
active window.

## 04.1 Persistent iterators, not stored closures

The useful intuition is a suspended iterator:

```rust,illustrative
pub enum ContinuationPoll {
    Yield {
        proposal: Proposal,
        next: ContinuationSnapshot,
    },
    WaitForFeedback {
        dependencies: Vec<ObservationDependency>,
    },
    Exhausted,
}
```

The durable store never serializes a Rust closure, trait object, code pointer,
or VM stack. It stores:

- a closed versioned generator kind and parameters in `CampaignPolicy`;
- a bounded immutable `BranchRequest` and its finite or generated source;
- the stable `BranchPointId`, `BranchRequestId`, and `ChoiceDomainId`;
- immutable proposals and observations;
- optional authenticated projection snapshots;
- policy and implementation versions.

The continuation is recomputed as a pure fold. A static sampler's cursor is the
first unissued ordinal. An adaptive sampler's interval partition and statistics
come from the observation set.

- **[LAZY-1]** Durable continuation state MUST be portable data interpreted by a
  versioned campaign planner. Native executable closures are prohibited.
- **[LAZY-2]** Deleting every continuation projection cache and restarting the
  daemon MUST reconstruct an equivalent frontier from the campaign snapshot.

## 04.2 Frontier composition

The frontier projection contains:

```rust,illustrative
pub struct CandidateContinuationKey {
    pub branch_point: BranchPointId,
    pub request: BranchRequestId,
}

pub struct CampaignFrontier {
    pub ready_sources: MerkleSet<CandidateContinuationKey>,
    pub waiting_sources: MerkleSet<CandidateContinuationKey>,
    pub open_branch_points: MerkleSet<BranchPointId>,
    pub admitted_attempts: MerkleSet<AttemptId>,
    pub completed_attempts: MerkleSet<AttemptId>,
}
```

A source continuation may move from ready to waiting after yielding one
candidate and become ready again when descendant feedback raises its widening
allowance. Its branch point may be open but low priority for a long period. A
finite request exhausts when every requested value has been admitted or already
deduplicated. A complete finite domain is exhausted only when every legal value
is admitted or the generator supplies an authenticated exhaustion proof.
`WaitingForFeedback(completed_visits, required_visits)` carries the exact
current distinct observation-credit count and the next inclusive visit
threshold; it is not a timer, executor-progress estimate, or mutable wakeup
counter.

The claimable work set is:

```text
admitted attempts
  - completed observations
  - explicit non-modeled terminal dispositions
  - currently live local reservations
```

- **[LAZY-3]** Frontier readiness MUST be derived from semantic facts and policy.
  Reservation state affects local claimability only and MUST NOT change whether
  an attempt exists or a branch point/source continuation is open.
- **[LAZY-4]** The frontier API MUST paginate or stream. It MUST NOT require all
  continuations or attempts to be loaded into memory. Page size and scan
  suspension boundaries MUST NOT alter a deterministic planner result.

## 04.3 Pull-based planning and backpressure

The local daemon issues work only when capacity exists:

```text
resource slot opens
       |
CampaignSupervisor selects one ready source at a branch point
       |
ProposalPlanner polls its finite iterator or generator once
       |
publish Proposal + admit/reuse semantic Attempt
       |
ExecutorService reserves Attempt locally
       |
HotCheckpointManager chooses realization
       |
run -> publish Observation
       |
CampaignProjector updates guidance/frontier projections
```

The planner may keep a small configurable ready-attempt buffer to hide QEMU
startup latency, but it never fills the latent domain merely because storage is
available.

Selecting globally across a large frontier is itself a suspended deterministic
computation. The coordinator exposes a snapshot-bound canonical scan ordered by
stable continuation key. Planner state records the scan cursor, accumulated
best candidate and score evidence, source snapshot/view, and remaining fuel.
The planner may return `continue-scan` without issuing a proposal. Page size,
RPC chunking, and restart boundaries are operational delivery choices and MUST
NOT change the selected source or its tie break. A changed snapshot invalidates
the scan rather than combining pages from different semantic views.

- **[LAZY-5]** Maximum admitted-but-unreserved attempts, in-flight attempts, live
  QEMU worlds, paused hot children, and dirty-memory bytes MUST have independent
  backpressure limits.
- **[LAZY-6]** Reaching an operational limit MUST pause proposal issuance or
  demote materializations. It MUST NOT silently prune semantic branches or
  report domain exhaustion.

## 04.4 Daemon components

The long-lived daemon gains six responsibilities:

```text
CampaignSupervisor
  owns campaign refs, lifecycle, policy activation, and budget grants

CampaignProjector
  folds facts into graph/frontier/guidance/status projections

ProposalPlanner
  selects branch points/sources and deterministically generates proposals

AttemptQueue
  exposes idempotent local reservations and completion publication

WorkerPool
  owns local execution slots and process supervision

HotCheckpointManager
  tracks hot templates, exact closures, replay costs, pins, and eviction
```

The Crucible execution scheduler remains inside a world/session and owns
virtual time, deterministic event ordering, and schedule recording. The
campaign planner is outside it. The resource scheduler may prefer a cache-local
attempt but cannot choose its value.

- **[LAZY-7]** Campaign planning, modeled execution scheduling, and operational
  resource placement MUST be separate interfaces and modules. Executor and
  store-placement metadata is forbidden from the first two except that a
  recorded campaign proposal supplies a typed selection to execution.
- **[LAZY-8]** The daemon MUST expose a bounded responsive control path for
  pause, status, pin, and shutdown even while every worker slot is busy.

## 04.5 Local attempt reservations

```rust,illustrative
pub struct AttemptReservation {
    pub attempt: AttemptId,
    pub daemon_epoch: DaemonEpoch,
    pub worker_slot: WorkerSlotId,
    pub generation: u64,
}
```

Reservations are volatile operational hints owned by one local daemon. The
authoritative `Attempt` is immutable. Restart discards reservations under the
old daemon epoch and makes every admitted attempt without a canonical
observation claimable again. Observation publication uses conditional create by
`AttemptId`; identical results dedup and different results trigger determinism
investigation.

The authoritative observation index is a conditional mapping from `AttemptId`
to `ObservationId`. Repeating the same pair is idempotent. A different
observation for an already completed attempt is retained as determinism-defect
evidence but is never selected by arrival time or last-writer-wins.

The existing RFC-0010 `SharedFrontier` keyed by checkpoint content hash becomes
a rebuildable attempt index keyed by `AttemptId`. It no longer asserts that a
checkpoint is expanded once.

The first repository checkpoint projects that index directly from one
authenticated `CampaignSnapshot`. `ProjectClaimableAttempts` scans a bounded
page of the accounting root, accepts only canonical `accounting.attempt` keys,
and removes attempts present under either the canonical `observations.attempt`
owner or the exact `accounting.attempt-disposition` owner.
Its opaque continuation carries the snapshot identity and exclusive accounting
key. A head advance rejects the old continuation rather than mixing semantic
roots, and concatenating all pages to EOF produces the same canonical sequence
for every valid scan bound. Because the accounting root is heterogeneous, an
empty result page may still carry a continuation.

`AttemptQueue` then applies a separately bounded in-process reservation table
to those pages. One worker slot obtains at most one exact reservation;
repeating that claim is idempotent, and release requires the complete current
attempt/epoch/slot/generation tuple. The daemon supplies a fresh nonzero epoch
when constructing a new queue after restart. The queue and cursor are
operational Rust interfaces at this checkpoint, not canonical campaign objects
or component messages; a later service schema must preserve these semantics
without adding reservation fields to semantic identity.

The coordinator-owned `CampaignExecutorDriver` composes those two primitives
without making its cursor or reservation authoritative. One call consumes at
most one accounting page and one checked executor exchange. Assignment identity
is derived from the exact daemon epoch, lease generation, attempt, lineage,
resource ceiling, and retention basis, but none of those operational fields
enter modeled identity. A checked running response installs one bounded
read-only `GetAttemptExecution` poll keyed by the exact epoch, lineage, attempt,
execution, and execution-basis digest. Status polls create no assignment-ledger
records; a transport or response-validation failure retains the exact query for
commit-indeterminate replay. `Backpressure` and `UnavailableInput` release
the lease so the next bounded scan uses the fresh `AssignmentId` required by
the executor retry contract. `Unauthorized` retains only the volatile lease and
requires local reconfiguration; it never fabricates a campaign policy fact.
Because the supported deployment has exactly one eligible local executor, a
stable `Incompatible` response closes the execution-basis ordinal with an
`AttemptClosed(PermanentlyIncompatible)` owner transition. Completion IDs are
reloaded, closure-authenticated, and incorporated only through the observation
owner transaction. Restart discards driver state and reconstructs both pending
work and already resolved attempts from the authenticated roots.

The daemon's `LocalExecutorWorkerPool` provides the matching fixed execution
owner. Startup creates `1..=256` worker threads and never grows that set; the
count cannot exceed the supervisor's admitted execution slots. Its cloneable
service implements the same checked submit and capability interfaces used by
direct and loopback clients. Exact assignment replay/epoch checks run under the
short supervisor actor, repository-backed admission validation runs after that
actor is released, and final admission rechecks assignment identity under the
actor. Each accepted `QueuedAttempt` then moves linearly to one worker. Guest
execution, candidate preflight, and immutable publication occur outside actor
ownership; only publication-root staging and durable completion/cancellation
reconciliation reacquire it.

Retryable worker failure requeues the same accepted execution without growing
capacity. Retryable candidate-publication or ledger failure retains the exact
phase token and retries that phase without re-running the guest. Sticky pool
shutdown prevents new admission, signals every active cancellation token,
drains accepted-but-not-started tokens as cancellations, and releases resource
reservations only after physical worker exit acknowledgement. A caught worker
or admission-validator panic poisons the executor incarnation and cancels all
active work; a worker panic additionally reconciles that exact execution before
its thread exits. These fixed threads keep capacity reporting, submission, and
cancellation responsive while another worker is blocked in a bounded guest or
storage operation.

The coordinator's bounded `CampaignSupervisor` composes the planner and
executor drivers over the same repository capability. Each step reloads one
exact lifecycle projection and performs at most one component operation.
Running campaigns give already-admitted executor work priority; one empty
executor scan enables at most one planner invocation on the following step, so
the ready buffer remains bounded. Paused campaigns never page new work or invoke
the planner. `drain` polls only already-held reservations,
`cancel-and-retry` cancels or releases one exact reservation per step, and
`exact-checkpoint` requests one exact execution checkpoint per step and retains
that reservation through durable publication and pause. Resume reconstructs
the frontier from semantic roots, so canceled attempts become claimable
without a modeled state change.

The daemon owns that step machine through one fixed long-lived runtime thread
per attached campaign. The runtime performs one initial step, continues
immediately only when the prior outcome permits another bounded operation, and
otherwise sleeps until an explicit repository/executor progress wake or a
finite fallback poll. The fallback interval is fixed at startup in
`1 ms..=60 s`; the default is 100 ms. This preserves progress when an external
component cannot deliver a wake without introducing another modeled-work
queue. Even a continuous progress chain pauses interruptibly for at least 1 ms
after 256 component operations, preventing a faulty component or maximum-sized
scan from creating an unbounded hot loop. Shutdown is sticky, interrupts a
quiescent wait, and prevents the
runtime from beginning another component operation. A repository, planner, or
executor failure terminates the runtime and remains observable to its daemon
owner; it is not converted into an unbounded retry loop. Process startup still
needs to enumerate/configure the campaigns to attach and couple runtime failure
to the user-facing service lifecycle.

The real-node realization boundary now has an executor-owned exact-capture
primitive for that checkpoint path. It seals the unified event
log, exact-checks the installed configuration and current node instruction
count against a materialized scheduler checkpoint, captures VMState plus the
host-I/O continuation while leaving QEMU paused, and keeps the attempt resource
guard charged until the lifecycle owner explicitly finishes the session.
Modeled attempt drivers do not receive capture or guard-release authority. The
executor persists checkpoint-requested, checkpoint-publishing, paused, and
raw-root checkpoint-promoting states; stages every expected root before
immutable writes; retains source and replacement roots for GC and restart; and
releases capacity only after durable pause. The campaign supervisor drives this
exact request/status protocol. Capture-result wiring, complete-root attempt
resume materialization, guarded replay validation, and crash-safe promotion are
implemented. Concrete run-directory/process-guard composition and the full
real-node executor flight remain open.

- **[LAZY-9]** Daemon epoch, worker slot, reservation generation, retry count,
  and execution handle MUST NOT enter attempt, configuration, observation, or
  finding identity. Reservations MUST NOT be required to recover the frontier.
- **[LAZY-10]** A daemon crash after publishing an observation but before
  releasing a reservation MUST at worst cause duplicate execution. It MUST NOT
  lose the observation or block the attempt permanently. Conflicting canonical
  observations for one attempt MUST be reported as a determinism defect.

## 04.6 Feedback and backpropagation

Every attempt carries the ordered branch-edge path by which it was admitted. On
canonical completion, the projector credits its observation to the expansion
state at each branch point on that path. No in-memory MCTS stack is required.
New schema-v2 paths carry exact `(BranchPointId, BranchEdgeId)` segments because
an edge digest is deliberately non-invertible. Legacy schema-v1 edge-only paths
remain identity-preserving historical inputs and are admissible only for a
single-edge genesis request, whose authenticated request recovers the point.
Nested admission and feedback require a fully scoped cumulative v2 path.

```text
root branch point B0
  -> selection A
     -> branch point B1
        -> selection B
           -> observation O

credit O to B1 and B0, exactly once
```

Canonical credit identity is `H(observation, branch point)`. Schema version 1
stores the exact observation and branch point and therefore owns one completed-
visit increment. Its observation child retains the reward vector, coverage,
properties, and measurements from which later richer folds are derived. A
branch-point-keyed nested Merkle set prevents duplicate credit. Rich reward,
novelty, and finding accumulation remains an implementation-plan gate; it MUST
not be inferred from unauthenticated telemetry in the meantime.

- **[LAZY-11]** Backpropagation MUST use recorded branch-edge paths and idempotent
  credit IDs. It MUST survive restart and arbitrary result duplication.
- **[LAZY-12]** Operational failure produces retry telemetry, not backpropagated
  reward. A modeled guest crash is canonical only after the execution scheduler
  records the corresponding modeled outcome.

## 04.7 Strict and streaming commit

In strict mode, `CampaignSupervisor` assigns monotonically recorded attempt
sequences and the projector commits observations in that order. Results may
execute concurrently and wait in a content-addressed completed set. Missing
earlier attempts are retried; operator cancellation is an explicit accounting
fact with a non-modeled disposition that closes the ordinal without inventing
an observation. This prevents a cancelled or permanently rejected attempt from
leaving an unfillable strict-order gap.

In streaming mode, the projector may commit any completed observation. Each
`PlannerStep` records the exact observation root it saw. The planner remains a
single logical sequencer on one host, so duplicate callbacks cannot issue
untracked proposals.

- **[LAZY-13]** A strict campaign MUST reproduce planner steps from its initial
  snapshot, policy, seed, attempt-order results, and budget grants.
  Every admission ordinal MUST eventually receive one canonical observation or
  an explicit non-modeled terminal disposition.
- **[LAZY-14]** A streaming campaign MUST reproduce every recorded planner step
  from its named observation basis even when a fresh campaign run would receive
  observations in another order.

## 04.8 Hotness and materialization policy

The daemon estimates a configuration's reuse value from campaign facts:

```text
hotness =
    pending attempts
  + expected future widening
  + number of descendant continuations sharing the prefix
  + interactive/finding pin value
  - dirty-memory and file-descriptor pressure
  - restore/replay cost already paid elsewhere
```

This is operational scoring and may use host measurements. It selects among
equivalent realization tiers but cannot alter proposal priority or branch
meaning. A parent may move from live template to durable closure to thin-only
state and later be restored. A checkpoint without a pending choice opportunity
may be valuable for debugging or replay without being a branch point. A branch
point without a checkpoint remains valid and is realized through an available
ancestor; hot-fork eligibility is only a cache capability.

- **[LAZY-15]** Materialization policy MUST expose why a checkpoint is hot,
  pinned, demoted, or evicted. Those reasons are telemetry, not canonical
  campaign evidence.

## 04.9 Local executor boundary

The campaign supervisor invokes the local executor through the normative
contract in [`04a-coordinator-executor-contract.md`](04a-coordinator-executor-contract.md).
The semantic operations remain location-independent even though this RFC
implements exactly one executor on the same host:

```text
describe executor and capacity
submit immutable attempt by ID
watch execution state
publish immutable result objects
report result IDs or operational failure
retain or evict local materializations
```

The executor resolves the parent configuration through its configured content
store, chooses hot fork, exact restore, or thin replay, and may retain the parent
as a hot sibling hub. Materialization affinity affects realization cost only.

- **[LAZY-16]** Attempt and observation schemas MUST work through both direct
  and loopback-RPC executor adapters without a shared path or serialized
  daemon-native session handle.
- **[LAZY-17]** The local executor MAY publish immutable result objects but MUST
  NOT advance the campaign ref, admit proposals, or interpret campaign policy.

## 04.10 Recovery procedure

After daemon restart:

1. resolve each configured campaign ref;
2. authenticate its snapshot and lineage;
3. rebuild or validate campaign projections;
4. discard old-epoch reservations and treat uncompleted attempts as claimable;
5. inventory valid exact closures and discard stale hot-process handles;
6. recompute hotness, expansion state, and ready source continuations;
7. resume pulling only when user intent is `running`.

- **[LAZY-18]** Recovery MUST be safe after interruption between every pair of
  object publication and ref-update steps. Corrupt or incomplete objects remain
  unreachable and eligible for later garbage collection.
- **[LAZY-19]** Publishing a branch request MAY make a finite or generated
  continuation ready, but MUST NOT eagerly enqueue all of its values. The daemon
  polls it only under proposal-buffer, attempt-budget, and resource backpressure,
  including when the request was explicitly issued by an operator.

## 04.11 Atomic branch-request acceptance

The first local coordinator transaction is intentionally smaller than planner
polling. `SubmitBranchRequest(name, expected_snapshot, request)` performs this
exact sequence under the campaign's sole-writer boundary:

1. authenticate the current snapshot and complete reachable closure;
2. return the original transition if the exact `BranchRequestId` already occurs
   in ancestry, before evaluating the caller's now-stale precondition;
3. validate the exact parent configuration, opportunity, effective domain,
   finite values or generator, and cause closure;
4. prove the parent is the exact artifact indexed by its semantic identity in
   the campaign graph and that planner/policy causes use the active policy;
5. publish the immutable request and `BranchRequestIssued` fact;
6. add `BranchRequestId -> BranchRequest`, update its exact continuation
   projection, and, for a feedback-gated source, add the request to the
   branch-point request index used for feedback wakeups;
7. publish the successor snapshot and compare-and-swap the campaign ref last.

The acceptance transition creates no proposal, branch edge, attempt, executor
reservation, or VM. A projector/planner later pulls one source continuation
under current budget and backpressure. An imported successor is accepted only
if replaying the transition over its parent produces the exact exploration-root
delta and no unrelated root or policy change.

- **[LAZY-20]** Exact branch-request replay MUST precede stale-snapshot rejection
  and return the originally committed prior/new snapshot pair.
- **[LAZY-21]** Branch-request acceptance MUST add exactly one request
  membership plus its owner-derived continuation and branch-point request-index
  projections. Candidate enumeration and attempt admission are separate later
  transitions, and import MUST reproduce the same exact exploration-root delta.

## 04.12 Atomic proposal issuance

`IssueProposal(name, expected_snapshot, proposal)` is the sole-writer transition
that advances one request continuation without admitting execution. It first
authenticates the complete head, returns an exact prior transition before stale
precondition rejection, and proves that the proposal names an authoritative
request, the active policy, and the current complete planning view. Static
proposal ordinal `n` names exactly value `n` in canonical source order and
requires ordinal `n - 1` to exist when `n > 1`. This includes finite sources
and implementation-version 2 `all` generators over Boolean or discrete
domains. The latter yield `false`, then `true`, or alternatives in stable
`AlternativeId` order. Implementation-version 3 `boundary_integer` is also
static and uses the exact boundary/default/landmark/neighbor/power order in
§03.2. Implementation-version 4 `stratified_integer` is static and uses the
exact bounded ordinal-to-stepped-value formula in §03.2.
Implementation-version 5 `log_integer` is static for strictly positive integer
domains and uses the exact rounded-power order in §03.2.
Implementation-version 6 `permuted_integer` is request-keyed and static for
integer domains with at most `2^64 - 1` legal values, using the four-round
bijection in §03.2. Implementation-version 7 `weighted_categorical` is static
for discrete weight maps containing at most 256 alternatives and uses the exact
request-keyed rejection-sampled integer order in §03.2. Implementation-version
8 `ordered_mixture` recursively composes those finite owners under the exact
weighted virtual-finish schedule, duplicate suppression, and work/depth/output
bounds in §03.2. Implementation-version 9 `progressive_integer` uses the exact
stratified-prefix and largest-gap order in §03.2, but an ordinal after the
initial prefix is valid only when the source snapshot contains its exact
authenticated completed-visit threshold. Proposals from every other generated
source require the selected deterministic generator owner to reproduce the same
value and remain fail-closed until that owner is implemented.

The transition publishes the immutable `Proposal` and `ProposalIssued` fact,
then makes an exact three-key delta to the exploration root:

```text
exploration.proposal[ProposalId] = Proposal
exploration.proposal-request-ordinal[(BranchRequestId, ordinal)] = Proposal
exploration.proposal-request-value[(BranchRequestId, ChoiceValue)] = Proposal
```

All three keys use distinct versioned domain separation. The ordinal index
proves gapless request-local progress; the value index rejects repeated output
from one source; and the identity index provides canonical typed membership. A
proposal may remain pending between this transition and a later admission
transition. Its existence consumes proposal budget but does not consume attempt
budget, create a graph child, or count as an admitted continuation value.

- **[LAZY-22]** Proposal replay MUST precede stale-snapshot rejection and return
  the originally committed prior/new snapshot pair.
- **[LAZY-23]** Proposal issuance MUST be an exact three-key exploration delta
  and MUST preserve every other root, lineage, and active policy. Imported
  successors MUST reproduce the same delta from their parent.
- **[LAZY-24]** Static proposal ordinals MUST be gapless and bind to canonical
  source-value order. Implementation-version 2 `all` over Boolean or discrete
  domains, implementation-version 3 `boundary_integer`, and
  implementation-version 4 `stratified_integer`, and implementation-version 5
  `log_integer` over a strictly positive integer domain are static generated
  sources, as is implementation-version 6 `permuted_integer` over an integer
  domain with at most `2^64 - 1` legal values and implementation-version 7
  `weighted_categorical` over at most 256 exact discrete alternatives and
  implementation-version 8 `ordered_mixture` within its exact recursive work
  profile. Implementation-version 9 `progressive_integer` also has a
  deterministic ordinal order, but its refinement ordinals MUST additionally
  satisfy the exact source-snapshot feedback threshold in §03.2. Other
  generated proposal issuance MUST fail closed unless the named
  deterministic generator owner reproduces the value from authenticated
  campaign facts.
- **[LAZY-45]** Weighted-categorical implementation-version 7 MUST derive every
  ordinal by the exact request-keyed rejection-sampled `u128` algorithm in
  §03.2, remove each selected alternative before the next draw, reject domain
  keys or counts outside its exact 256-alternative profile, and reconstruct the
  same order during import and restart. Earlier and unknown weighted versions
  MUST remain suspended.
- **[LAZY-46]** Ordered-mixture implementation-version 8 MUST schedule only
  executable finite child owners by the exact virtual-finish fractions in
  §03.2, use component ordinal as the final tie-break, advance duplicate-
  producing children without emitting the value twice, and enforce the exact
  512-value, 8,192-work-unit, and 64-level bounds during local and imported
  owner replay. A suspended child MUST suspend the complete mixture.
- **[LAZY-47]** Progressive-integer implementation-version 9 MUST index every
  accepted request under its exact branch point, derive completed visits only
  from distinct authenticated expansion credits, reject a refinement before
  its exact threshold without writes, and atomically update every affected
  continuation projection when a canonical observation adds credit. Imported
  observation and proposal successors and restart reconstruction MUST reproduce
  the same frontier state. The complete feedback-request index, including its
  branch-point slots, MUST remain bounded to 65,536 entries so every admitted
  history remains projectable by one bounded observation transition. A legacy
  campaign without the canonical frontier anchor MUST reject version-9 request
  admission rather than create a partial index over only its newer history.

## 04.13 Atomic attempt admission

`AdmitProposal(name, expected_snapshot, proposal, selection, path, attempt)` is
the sole-writer transition that gives one authoritative proposal exactly one
admission disposition. Exact replay by `ProposalId` precedes stale-precondition
rejection. The coordinator authenticates the proposal's exploration membership,
selection, branch path, semantic attempt, request, and stop condition, then
recomputes the role rather than accepting a caller-supplied role or ordinal.

New paths encode each selected edge together with its exact branch point. Owner
validation requires the terminal segment to match the request's branch point
and selected edge. A genesis-parent path has an empty prefix. A non-genesis
path prefix must be a member of the exact parent configuration's authenticated
nested path set under
`observations.configuration-path-index[ConfigurationArtifactId]` in the source
snapshot. Canonical observation incorporation adds the complete path under the
exact child configuration; convergence retains all distinct path identities.
Legacy edge-only paths remain admissible only for one-edge genesis requests.
For atomic planner `Issue`, the pure planner ranks only the semantic
branch-point/source continuation. The coordinator chooses the member with the
lowest `BranchPathId` ordering key from the exact parent set. The
chosen member must be a scoped version-2 path; a lowest legacy member fails
closed without scanning an unbounded historical prefix. The coordinator
appends the selected terminal segment and records that cumulative path in the
derived attempt. This owner rule is independent of page boundaries and is
recomputed identically for imported successors.

If no execution basis exists for `AttemptId`, the transition spends one unit of
the proposal request's `maximum_attempts`, assigns the next one-based global
`AdmissionOrdinal`, and publishes `ExecutionBasis`. The request-local count is
computed with a bounded page scan that counts only entries whose Merkle key is
the canonical `accounting.attempt-admission[AttemptAdmissionId]` key. Repeated
values stored under other accounting indexes therefore cannot inflate the
count. If an execution basis already exists, the transition publishes
`AdditionalCause` and spends no attempt budget or ordinal.

Every admission adds these two canonical accounting entries:

```text
accounting.attempt-admission[AttemptAdmissionId] = AttemptAdmission
accounting.proposal-admission[ProposalId] = AttemptAdmission
```

A new execution basis additionally adds:

```text
accounting.attempt[AttemptId] = Attempt
accounting.attempt-execution-basis[AttemptId] = AttemptAdmission
accounting.admission-ordinal[AdmissionOrdinal] = AttemptAdmission
accounting.admission-sequence[] = AttemptAdmission
```

The sequence entry is the only replacement: it points to the latest execution
basis. Every other admission key is insertion-only. An imported successor is
valid only when owner recomputation derives the identical admission bytes and
its accounting root equals exactly these upserts over the parent. Exploration,
graph, observations, and every other root remain unchanged. Admission does not
create a graph child; that still requires an authenticated execution result and
observation.

- **[LAZY-25]** One proposal MUST have exactly one immutable admission
  disposition. Replay with another `AttemptId` is an integrity error.
- **[LAZY-26]** One semantic attempt MUST have exactly one `ExecutionBasis` and
  one global ordinal. Later convergent proposals MUST be `AdditionalCause` and
  MUST NOT spend attempt budget or advance the admission sequence.
- **[LAZY-27]** Attempt-budget projection MUST stream bounded Merkle pages and
  authenticate canonical admission keys; it MUST NOT infer counts from repeated
  values under heterogeneous accounting indexes.
- **[LAZY-28]** Admission successors MUST be exact accounting-root deltas and
  MUST preserve the campaign basis and every unrelated root. The first global
  execution basis has ordinal one; every later basis uses the checked successor
  of the prior sequence entry.

## 04.14 Snapshot-bound finite expansion projection

`ProjectFiniteExpansion(source_snapshot, branch_point, page_after, page_size)`
publishes one rebuildable `ExpansionState` version 2 cache page. The projector
first authenticates the complete source snapshot and derives its exact
`CampaignPlanningView`; it never accepts roots supplied independently by the
caller. It scans the authoritative exploration and accounting roots in bounded
10,000-entry chunks and produces three homogeneous branch-point indexes:

```text
request_root[BranchRequestId digest] = BranchRequest
proposal_root[ProposalId digest] = Proposal
admission_root[AttemptAdmissionId digest] = AttemptAdmission
```

An input record participates only when its authoritative heterogeneous-root key
equals the exact domain-separated identity key for its record type. The
homogeneous root then uses the typed content digest directly, making Merkle
order identical to canonical typed-ID order. The page contains at most
`page_size` continuation states and `page_size` is limited to 10,000.
`page_after` must name a request present in the recomputed request root for the
same snapshot and branch point. `next_after` is present only when another
request exists and names the last returned request.

Executable continuation state is derived without retaining all request values
or continuations. A static source is an explicit finite source,
implementation-version 2 `all` over a Boolean or discrete domain, or
implementation-version 3 `boundary_integer`, or implementation-version 4
`stratified_integer`, or implementation-version 5 `log_integer` over a strictly
positive integer domain, or implementation-version 6 `permuted_integer` over an
integer domain with at most `2^64 - 1` legal values, or implementation-version
7 `weighted_categorical` over at most 256 discrete alternatives, or
implementation-version 8 `ordered_mixture` over executable finite children:

- no proposal at the next canonical ordinal and remaining proposal budget is
  `Ready`;
- any issued proposal without its unique admission disposition is `Open`;
- all static values proposed and disposed is `Exhausted`;
- proposal budget reached before all values are disposed is `Closed`.

Implementation-version 9 `progressive_integer` uses the same pending-proposal
and budget rules, but readiness is feedback-dependent. Its initial stratified
prefix is `Ready` immediately. After that prefix, the source is `Ready` only
when its completed-visit count reaches the next checked threshold, otherwise it
is `WaitingForFeedback` with the exact current and required counts. Completing
the bounded stream is `Exhausted` only when the request budget covers the exact
domain; a truncated stream is `Closed`.

`admitted_children` counts only distinct `ExecutionBasis` admissions rooted
at the branch point. A pending proposal contributes zero, and an
`AdditionalCause` contributes an admission record but no new child. This
statistic therefore means admitted semantic attempts, not realized temporal
graph configurations; graph-child accounting begins only after authenticated
execution results exist.

The current owner deliberately rejects unimplemented history-dependent
generators and unknown generator implementation versions. Static readiness and
exhaustion are observation-independent, while progressive version 9 consumes
only the exact authenticated completed-visit count. The owner projects that
count from the nested credit-set entry count. The same schema-v4 observation
transition maintains a second nested set
from each exact child configuration artifact to every authenticated cumulative
path that reached it; direct non-genesis admission checks membership in that
set. Reward, novelty, and finding statistics remain zero until their richer
canonical folds land. The exact fixed-point PUCT arithmetic is already a pure
conformance-tested primitive, but no planner version may consume it while
these owner projections remain zero. Loading an
`ExpansionState` repeats the complete source-snapshot validation and owner
recomputation; a structurally valid cache with an omitted request, proposal, or
admission is rejected.

- **[LAZY-29]** Every admissible expansion page MUST bind one exact source
  snapshot and its derived complete planning view. Caller-assembled filtered
  roots MUST NOT be accepted as authoritative inputs.
- **[LAZY-30]** Request, proposal, and admission projection roots MUST be
  rebuilt by bounded scans that authenticate each heterogeneous-root key before
  inserting it into a homogeneous typed-ID-ordered root.
- **[LAZY-31]** Expansion cursors MUST be snapshot-bound request identities.
  The owner MUST reject a cursor absent from the exact branch-point request
  root, and concatenated pages MUST follow canonical `BranchRequestId` order
  independently of page size.
- **[LAZY-32]** Static-source readiness and exhaustion MUST derive from
  canonical source order and proposal admission dispositions. Proposal
  existence alone MUST NOT count as an admitted child or prove exhaustion.
- **[LAZY-33]** Expansion admitted-child statistics MUST count distinct
  `ExecutionBasis` attempts. `AdditionalCause` deduplication MUST NOT create
  another child or consume another attempt.
- **[LAZY-34]** The expansion projector MUST fail closed for generated requests
  other than implementation-version 2 `all` over Boolean or discrete domains
  and implementation-version 3 `boundary_integer` or implementation-version 4
  `stratified_integer` or implementation-version 5 `log_integer` over a
  strictly positive integer domain or implementation-version 6
  `permuted_integer` over an integer domain with at most `2^64 - 1` legal
  values or implementation-version 7 `weighted_categorical` over at most 256
  exact discrete alternatives or implementation-version 8 `ordered_mixture`
  within its exact recursive work profile, or implementation-version 9
  `progressive_integer` within its exact bounds and feedback thresholds. Static
  continuation state MAY bind a nonempty observation root because its state is
  independent of feedback. Every completed-visit statistic and progressive
  wakeup MUST equal the exact nested credit-set count, and the projector MUST
  NOT synthesize reward, novelty, or finding statistics before their canonical
  owners are implemented.

## 04.15 Atomic observation publication

`PublishObservation(name, expected_snapshot, observation)` is the sole-writer
transition that records one modeled completion. Before any campaign mutation it
authenticates the attempt's unique `ExecutionBasis`, exact branch path, semantic
and exact child configuration, stop condition, measurement set, property-
verdict set, coverage projection, and discovered choices. A `NextChoice` stop
requires at least one discovered choice, and every discovered choice must belong
to the campaign scenario at the observed child.

This authentication is a read-only preflight over the union of newly supplied
child closures and completes before the observation body or any owner-index
node is written. Nested campaign records receive their complete semantic
validation, not only envelope validation. Choice opportunity validation keeps
full declaration/domain objects transient and shares only a compact digest of
the copied reference contract. That cache is explicitly bounded and spans
ancestry-owner replay plus closure traversal, preventing both repeated parsing
of one large shared domain and retention of schema-sized domain bodies.

The canonical observation owner conditionally maps `AttemptId` to
`ObservationId`. Repeating the same observation returns the original prior/new
snapshot pair before checking a stale precondition. A different observation
for that attempt is retained under a domain-separated conflict key, but it does
not replace or modify the canonical graph child, corpus entry, coverage,
accounting, strict sequence, or expansion credits. This makes a determinism
defect durable without allowing arrival order or last-writer-wins mutation to
rewrite campaign truth.

A canonical completion atomically updates six semantic roots. The graph binds
the semantic configuration and any branch edge to the exact child artifact and
adds discovered choice/branch-point memberships. The corpus retains the child.
The observation root indexes the attempt result, observation, path, and exact
measurement/property/coverage objects. For every distinct scoped branch point
in the path it also updates one nested credit set with the immutable
`ExpansionCredit(observation, branch_point)`. The coverage root adds the immutable
`CoverageProjectionId`; the grow-only identity union is the deterministic union
of those records. Accounting binds the attempt and global admission ordinal to
the observation. The exploration root updates every indexed version-9
progressive request at a credited branch point to its owner-recomputed next
continuation state; static and suspended requests are unchanged. In strict mode
the accounting sequence advances only to the next global admission ordinal;
streaming and statistical modes accept any completed admitted attempt while
preserving the exact snapshot basis seen by planning.

Imported successors are accepted only when read-only owner recomputation
derives those exact upserts, every unrelated root and campaign basis is
unchanged, and the coordination root has the exact parent-result locator. Local
publication advances the campaign ref last and promotes an incremental
validation checkpoint only after successful CAS. A rejected final CAS leaves
immutable unreachable objects but no trusted child or authoritative state
change.

- **[LAZY-35]** An observation MUST bind one admitted semantic attempt to its
  exact path, semantic and exact child configuration, modeled stop outcome,
  bounded evidence records, and discovered choices. Operational placement and
  retry data MUST NOT enter these identities.
- **[LAZY-36]** Canonical observation publication MUST require an authenticated
  `ExecutionBasis` and apply the exact graph, exploration, observation, corpus,
  coverage, and accounting owner deltas while preserving every unrelated root.
- **[LAZY-37]** Exact observation replay MUST precede stale-snapshot rejection.
  A different result for an already observed attempt MUST be retained as
  determinism-conflict evidence without replacing any canonical semantic fold.
- **[LAZY-38]** Strict observation publication MUST follow global admission
  ordinal order. Streaming and statistical publication MAY accept completed
  attempts out of order but MUST retain each planner's exact observation basis.
- **[LAZY-39]** Imported observation successors MUST be validated by read-only
  owner recomputation. Local publication MUST advance the ref last and MUST NOT
  promote a rejected CAS child as validated acceleration state.
- **[LAZY-40]** Claimable-attempt projection MUST scan a bounded number of
  authenticated accounting entries, accept only canonical attempt membership,
  exclude canonical observation membership, bind continuations to one exact
  snapshot, and produce a page-boundary-independent sequence to EOF.
- **[LAZY-41]** Local reservations MUST be bounded and epoch-local. A worker
  slot's repeated claim MUST return its exact reservation, release MUST reject
  a stale or different-epoch tuple, and constructing a fresh daemon epoch MUST
  recover every admitted unobserved attempt without durable lease state.
- **[LAZY-42]** Canonical completion MUST add exactly one idempotent expansion
  credit for each distinct scoped branch point in its path. Exact replay and a
  conflicting completion MUST add no credit, and restart/import validation MUST
  recompute the exact nested credit-root delta.
- **[LAZY-43]** Canonical completion MUST add the complete scoped path to the
  exact child configuration's authenticated nested path set. Non-genesis
  admission MUST require its complete prefix in the exact parent configuration
  set, MUST retain every convergent path, and MUST reject a missing, foreign,
  legacy, or terminal-scope-mismatched prefix before advancing the campaign.
- **[LAZY-44]** Atomic planner `Issue` MUST derive its parent prefix as the
  lowest ordering-key member of the exact authenticated path set and MUST fail
  closed unless that member is scoped version 2. The pure planner MUST NOT
  invent or influence that prefix, and local publication, exact replay, and
  imported owner recomputation MUST derive the same cumulative attempt path.
