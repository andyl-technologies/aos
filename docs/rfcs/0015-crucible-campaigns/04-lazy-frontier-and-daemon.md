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

The claimable work set is:

```text
admitted attempts
  - completed observations
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

```text
root branch point B0
  -> selection A
     -> branch point B1
        -> selection B
           -> observation O

credit O to B1 and B0, exactly once
```

Credits include count, reward vector, coverage novelty, property result,
measurement deltas, and finding signature. Canonical credit identity is
`H(observation, branch point)`. A persistent set prevents duplicate credit.

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
6. add exactly `BranchRequestId -> BranchRequest` to the exploration Merkle
   root while preserving lineage, policy, and every other root;
7. publish the successor snapshot and compare-and-swap the campaign ref last.

The acceptance transition creates no proposal, branch edge, attempt, executor
reservation, or VM. A projector/planner later pulls one source continuation
under current budget and backpressure. An imported successor is accepted only
if replaying the transition over its parent produces the exact exploration-root
delta and no unrelated root or policy change.

- **[LAZY-20]** Exact branch-request replay MUST precede stale-snapshot rejection
  and return the originally committed prior/new snapshot pair.
- **[LAZY-21]** Branch-request acceptance MUST be an exact one-key exploration
  delta. Candidate enumeration and attempt admission are separate later
  transitions.

## 04.12 Atomic proposal issuance

`IssueProposal(name, expected_snapshot, proposal)` is the sole-writer transition
that advances one request continuation without admitting execution. It first
authenticates the complete head, returns an exact prior transition before stale
precondition rejection, and proves that the proposal names an authoritative
request, the active policy, and the current complete planning view. Finite
proposal ordinal `n` names exactly value `n` in canonical source order and
requires ordinal `n - 1` to exist when `n > 1`. Generated proposals require the
selected deterministic generator owner to reproduce the same value and remain
fail-closed until that owner is implemented.

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
- **[LAZY-24]** Finite proposal ordinals MUST be gapless and bind to canonical
  source-value order. Generated proposal issuance MUST fail closed unless the
  named deterministic generator owner reproduces the value from authenticated
  campaign facts.
