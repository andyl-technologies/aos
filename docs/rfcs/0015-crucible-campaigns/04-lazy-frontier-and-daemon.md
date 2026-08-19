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
  - currently live, unexpired lease hints
```

- **[LAZY-3]** Frontier readiness MUST be derived from semantic facts and policy.
  Lease state affects claimability only and MUST NOT change whether an attempt
  exists or a branch point/source continuation is open.
- **[LAZY-4]** The frontier API MUST paginate or stream. It MUST NOT require all
  continuations or attempts to be loaded into memory.

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
WorkerPool leases Attempt
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

- **[LAZY-5]** Maximum admitted-but-unleased attempts, in-flight attempts, live
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
  exposes idempotent attempt leases and completion publication

WorkerPool
  owns local execution slots and process supervision

HotCheckpointManager
  tracks hot templates, exact closures, replay costs, pins, and eviction
```

The Crucible execution scheduler remains inside a world/session and owns
virtual time, deterministic event ordering, and schedule recording. The
campaign planner is outside it. The resource scheduler may prefer a cache-local
attempt but cannot choose its value.

- **[LAZY-7]** Campaign planning, execution scheduling, and resource placement
  MUST be separate interfaces and modules. Distribution metadata is forbidden
  from the first two except that a recorded campaign proposal supplies a typed
  selection to execution.
- **[LAZY-8]** The daemon MUST expose a bounded responsive control path for
  pause, status, pin, and shutdown even while every worker slot is busy.

## 04.5 Attempt leasing

```rust,illustrative
pub struct AttemptLease {
    pub attempt: AttemptId,
    pub owner: WorkerId,
    pub generation: u64,
    pub expires_at: OperationalTime,
}
```

Leases are mutable operational hints. The authoritative `Attempt` is immutable.
An expired lease permits another worker to repeat the attempt. Observation
publication uses conditional create by `AttemptId`; identical results dedup and
different results trigger determinism investigation.

The existing RFC-0010 `SharedFrontier` keyed by checkpoint content hash becomes
a rebuildable attempt index keyed by `AttemptId`. It no longer asserts that a
checkpoint is expanded once.

- **[LAZY-9]** Lease owner, expiry, renewal cadence, and generation MUST NOT
  enter attempt, configuration, observation, or finding identity.
- **[LAZY-10]** A daemon crash after publishing an observation but before
  releasing a lease MUST at worst cause duplicate execution. It MUST NOT lose
  the observation or block the attempt permanently.

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
fact.

In streaming mode, the projector may commit any completed observation. Each
`PlannerStep` records the exact observation root it saw. The planner remains a
single logical sequencer on one host, so duplicate callbacks cannot issue
untracked proposals.

- **[LAZY-13]** A strict campaign MUST reproduce planner steps from its initial
  snapshot, policy, seed, attempt-order results, and budget grants.
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

## 04.9 Future worker-host boundary

The initial implementation keeps all workers local, but defines location-free
operations:

```text
claim_attempt(worker capabilities, cached configuration IDs)
renew_attempt(attempt ID, lease generation)
fetch_attempt(attempt ID)
publish_observation(attempt ID, observation ID)
publish_operational_failure(attempt ID, diagnostic)
release_attempt(attempt ID, lease generation)
```

A future worker fetches the parent configuration and selected exact closure,
restores once, and may become the preferred host for later sibling attempts.
Soft hash affinity affects placement only.

- **[LAZY-16]** Attempt and observation schemas MUST be usable without a shared
  filesystem and without serializing a daemon-native session handle.
- **[LAZY-17]** Future multi-host planning MAY use one logical campaign leader
  or CAS-elected planner. Worker execution and object publication remain
  at-least-once and idempotent; no distributed consensus is required to execute
  or store one attempt.

## 04.10 Recovery procedure

After daemon restart:

1. resolve each configured campaign ref;
2. authenticate its snapshot and lineage;
3. rebuild or validate campaign projections;
4. treat uncompleted attempts with absent/expired local leases as claimable;
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
