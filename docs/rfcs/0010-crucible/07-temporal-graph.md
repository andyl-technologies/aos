# 07 — Temporal graph: the checkpoint DAG

This file specifies the **temporal graph**: the recorded, checkpointed execution
of a scenario as a content-addressed directed acyclic graph of **Checkpoints**
whose edges are **Decisions**. Where [`05-execution-model.md`](05-execution-model.md)
gives the *algebra* (the `Configuration` / `step` / `reduce` / `instantiate` /
`bake` model) and [`06-spatial-graph.md`](06-spatial-graph.md) gives the
immutable *definition* of a run (the `ScenarioDef`, "configuration #0"), this
file gives the *data structure that records the unfolding* of that definition
under scheduling decisions, and the on-disk store, sharing, and garbage
collection that make that structure economical enough to search.

It satisfies — and is governed by — the headline goal [G-4] (one unified
execution model), goal [G-6] (reproduce-then-explore), and the invariants
[INV-2] (replay-oracle equality), [INV-6] (content addressing), and, in its
search-tractability section, [INV-1] (purity of reduction). It is the consumer
of the execution model (05) and the producer that the session control plane
(20), the advanced features (22), and the determinism harness (24) build on.

The chapter does **not** re-derive the execution model. `Configuration`,
`step`, `reduce`, `instantiate`, and `bake` are defined in 05 and used here as
given; this file specifies the *graph of recorded configurations* and how it is
stored, shared, validated, and pruned.

## 1. The temporal graph is the closure of the spatial graph under `step`

The temporal graph is, precisely, **the closure of the genesis configuration
under the `step` reducer**. The genesis configuration is `(def, [])` — the
spatial graph (06) of file `ScenarioDef` paired with the empty `Schedule` (05
§2). Every other node is reached from genesis by a finite sequence of `step`
applications, each appending one `Decision` (05 §3). Because `step` is the pure
temporal-graph edge constructor (05 [EXEC-10]) and a `Configuration`'s identity
is `hash(def.id, schedule)` (05 [EXEC-4]), the resulting structure is a
content-addressed DAG, not a tree: two distinct decision paths that arrive at
the same `(def, schedule)` are **one** node (05 [EXEC-26]).

```text
  spatial graph (06)         = ScenarioDef = configuration #0 = (def, [])
  temporal graph (this file) = closure of (def, []) under step
                             = { (def, schedule) reachable by appending Decisions }

  nodes  = Checkpoints      (recorded Configurations, §2)
  edges  = Decisions        (one resolved scheduling choice, 05 §3)
  root   = genesis checkpoint   (the baked snapshot of the World, 05 §6)
```

The two graphs are joined by exactly one function, `reduce` (05 §4): the
temporal graph is the operational record of `State(t) = reduce(def,
Schedule[0..t])` as `t` ranges over every recorded prefix of every recorded
schedule. A Checkpoint is the *recorded* form of a `Configuration`; it adds to
the bare `(def, schedule)` identity the cached, content-addressed artifacts —
materialized state, virtual-time coordinates, coverage fingerprint, metadata —
that make realization (05 §5 `instantiate`) cheap. None of those additions are
part of identity (05 [EXEC-1], [EXEC-2]); they are a cache keyed by it.

- **[TEMP-1]** The temporal graph MUST be the closure of the genesis
  configuration `(def, [])` (06; 05 §2) under the `step` reducer (05 §3): its
  nodes are recorded `Configuration`s and its edges are `Decision`s. A node's
  identity MUST be `Configuration::id() = hash(def.id, schedule)` (05
  [EXEC-4]); the graph MUST be a content-addressed DAG in which two decision
  paths reaching the same `(def, schedule)` are a single node (05 [EXEC-26]).
  *Gate:* `gate:content-address`. *Spec:* §1; cross-ref 05 §2–§4, 06.

- **[TEMP-2]** A Checkpoint MUST be the recorded form of exactly one
  `Configuration`: it carries that configuration's identity plus
  content-addressed cache artifacts (materialized state, virtual-time
  coordinates, coverage fingerprint, metadata). None of the cache artifacts MAY
  contribute to the Checkpoint's identity, which MUST equal its
  `Configuration::id()` (05 [EXEC-1], [EXEC-2]). *Gate:* `gate:content-address`.
  *Spec:* §1, §2.

- **[TEMP-3]** The genesis node of the temporal graph MUST be the baked genesis
  checkpoint (05 §6 `bake`): a `loadvm`-able snapshot of each VM at its ready
  point, content-addressed and shared across every `ScenarioDef` and every fork
  with the same `World` (05 [EXEC-18]). The temporal graph MUST NOT contain a
  cold-boot node other than the one produced inside `bake` (05 [EXEC-16]).
  *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §1; cross-ref
  05 §6.

## 2. Checkpoint structure

A **Checkpoint** is a node of the temporal graph. Its identity is derived purely
from its parent and the decision that produced it; everything else it carries is
either a content-addressed coordinate (virtual time, per-node icount) or a
reference into the content-addressed store (§7) that may be present (a *fat*
checkpoint) or absent (a *thin* checkpoint, §4). The illustrative sketch below
shows the intended shape; the authority is the prose requirements (00, "Code
sketches in this RFC").

```rust,illustrative
/// A node of the temporal graph: a recorded `Configuration` (05 §2) plus the
/// content-addressed cache that makes realizing it cheap.
///
/// Identity is `id = hash(parent_id, schedule_delta)` — a function of the
/// parent's identity and the single `Decision` on the incoming edge, and of
/// nothing else. The `state` cache, the coverage fingerprint, and metadata
/// are *not* part of identity (05 [EXEC-1], [EXEC-2]); they are keyed by it.
#[derive(Clone)]
pub struct Checkpoint {
    /// Content address of this checkpoint: `hash(parent_id, schedule_delta)`.
    /// Equal for any two checkpoints denoting the same `(def, schedule)`
    /// (05 [EXEC-4], [EXEC-26]); this is the temporal-graph node id and the
    /// store key (§7).
    pub id: ContentHash,

    /// The `ScenarioDef` this checkpoint belongs to (its `id`, 06). Genesis
    /// and every descendant of one scenario share this reference.
    pub scenario_ref: ContentHash,

    /// The parent checkpoint, or `None` at genesis (the baked snapshot, §1).
    /// Edges run parent → child; following `parent` to the root yields the
    /// schedule prefix that defines this node (05 §4, prefix-closure).
    pub parent: Option<ContentHash>,

    /// The decision(s) on the incoming edge: the `schedule_delta` between the
    /// parent's schedule and this node's. Normally a single `Decision` (one
    /// `step`, 05 §3); a coalesced edge MAY carry a short run (§4).
    pub schedule_delta: SmallVec<[Decision; 1]>,

    /// The shared virtual-time coordinate of this checkpoint and the per-node
    /// executed-instruction counts that derive it (09). A pure function of the
    /// schedule prefix; recorded as a coordinate, never a source of identity.
    pub virtual_time: VirtualTime,
    pub icount: BTreeMap<NodeId, u64>,   // deterministic (sorted) per-node icount

    /// The materialized state, if this is a FAT checkpoint (§4). `None` for a
    /// THIN checkpoint, whose state is reconstructed by replay from the
    /// nearest fat ancestor (05 §5 `instantiate`). Either way the *denoted*
    /// state is identical (INV-2).
    pub state: Option<MaterializedState>,

    /// A cheap, deterministic digest of the execution reached here: coverage
    /// edges hit plus the execution fingerprint (24). Drives symmetry and
    /// partial-order reduction (§9) and coverage-guided search (22). Not part
    /// of identity.
    pub coverage_fingerprint: CoverageFingerprint,

    /// Bookkeeping that is never part of identity: store refcount (§8),
    /// fat/thin status, last-materialized timestamp, oracle-validated flag.
    pub metadata: CheckpointMeta,
}
```

The two load-bearing facts about this structure:

1. **`id = hash(parent_id, schedule_delta)`.** A checkpoint's identity is a
   function of its parent's identity and the decision delta on its incoming
   edge — and of nothing in `state`, `coverage_fingerprint`, or `metadata`.
   This is the recursive, Merkle-style form of `Configuration::id() =
   hash(def.id, schedule)` (05 [EXEC-4]): unrolling `parent` to the root spells
   out `(def.id, [d0, d1, ..., dk])`. Two checkpoints with equal parent and
   equal delta are the same node; this is what makes the graph a DAG with
   content-addressed dedup (§9).

2. **`state` is optional.** Identity does not depend on whether the checkpoint
   is materialized. A thin checkpoint (`state = None`) and a fat checkpoint
   (`state = Some(_)`) for the same configuration have the *same `id`*; the
   replay oracle (§6) requires that the materialized state hash-equals the
   thin derivation, so the two are interchangeable as far as the model is
   concerned (05 [EXEC-17], [EXEC-22]).

- **[TEMP-4]** A Checkpoint's `id` MUST be `hash(parent_id, schedule_delta)`,
  recursively rooted at the genesis checkpoint's id, and MUST equal the
  `Configuration::id()` of the configuration it records (05 [EXEC-4]). The id
  MUST NOT depend on `state`, `coverage_fingerprint`, or `metadata`. Two
  checkpoints with equal parent id and equal `schedule_delta` MUST have equal
  id and MUST be the same graph node. *Gate:* `gate:content-address`.
  *Spec:* §2.

- **[TEMP-5]** A Checkpoint MUST carry: `scenario_ref` (the `ScenarioDef` id,
  06); `parent` (`None` only at genesis); `schedule_delta` (the `Decision`s on
  the incoming edge); `virtual_time` and per-node `icount` (09, deterministic
  sorted order); an optional `state` (`Some` iff fat, §4); a
  `coverage_fingerprint` (24); and identity-irrelevant `metadata`. The
  per-node `icount` and `virtual_time` MUST be pure functions of the schedule
  prefix (INV-4), recorded as coordinates and never as sources of identity.
  *Gate:* `gate:content-address`, `gate:single-vm-fingerprint`. *Spec:* §2.

- **[TEMP-6]** Following a checkpoint's `parent` chain to the root MUST yield
  exactly the schedule prefix that, with `scenario_ref`, defines the recorded
  `Configuration` (05 §4, prefix-closure [EXEC-12]). The concatenation of
  `schedule_delta`s along the path from genesis to a node MUST equal that
  node's `Schedule`. *Gate:* `gate:replay-oracle`. *Spec:* §2; cross-ref 05 §4.

## 3. `MaterializedState`: what a fat checkpoint stores

A fat checkpoint's `state` is the cached realization of `reduce(def, schedule)`
(05 §4) at this node: everything `instantiate` would need to bring a live
runtime up at exactly this configuration without replaying from an ancestor. It
is composed of independently content-addressed pieces so that unchanged pieces
are shared with the parent by reference (§5). The contents below are the
**authoritative list of what a materialized checkpoint must capture**; the
detailed byte layout of a VM snapshot is specified in 13/15 (this file
references it, it does not redefine it), and the event log is specified in 19.

```rust,illustrative
/// The cached realization of `reduce(def, schedule)` at a fat checkpoint (§2).
///
/// Every field is a content-addressed reference or a CoW delta over the
/// parent's `MaterializedState`, so a fat checkpoint stores only what changed
/// since its nearest fat ancestor (§5). Restoring it (05 §5 `instantiate`,
/// the `loadvm` branch) stacks the parent's pieces under these deltas.
#[derive(Clone)]
pub struct MaterializedState {
    /// Per-VM architectural snapshot: a reference to the VM-state blob plus
    /// the icount at which it was taken. The blob's *contents* (CPU regs,
    /// device model state, RAM image) are defined by 13/15 — this file
    /// references them and never redefines them. Stored as a CoW delta of
    /// dirty RAM pages over the parent VM blob where possible (§5).
    pub vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>, // NodeBlobRef (05 §7) + icount

    /// Per-device copy-on-write overlay delta: the block/9p overlay pages
    /// made dirty since the parent (15), plus each device's deterministic RNG
    /// state. The base image is the read-only `World` artifact (06); only the
    /// CoW delta lives here.
    pub device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>, // dirty pages + device RNG

    /// The authoritative scheduler state (08), without which a resume could
    /// not reproduce cross-node ordering: per-node horizons, the pending
    /// shared-memory frame queues with their delivery icounts, the timer
    /// registry, the set of active faults, and the active tag-to-fault binding
    /// used by tag-based heal. This is the state that 05 [EXEC-13] insists
    /// lives *inside* the configuration, not in ephemeral process memory.
    pub scheduler: SchedulerState {
        horizons: BTreeMap<NodeId, VirtualTime>,
        pending_frames: BTreeMap<NodeId, Vec<PendingFrame>>, // delivery icount + payload ref (13)
        timers: TimerRegistry,                               // armed timers, fire icounts (08, 09)
        active_faults: BTreeMap<FaultTag, FaultState>,       // in-effect faults + heal points (17)
        active_fault_tags: BTreeMap<FaultTag, MembershipFault>, // heal tags + current binding (17)
        active_fault_table: ActiveFaultTable,                // directed edge/node/device lookup table (17)
    },

    /// The harness decision-RNG state: the position of every seeded per-entity
    /// RNG stream (04, 08), so the next `Decision::RngDraw` (05 §3) resolves
    /// identically on resume as it would have without the pause (05 [EXEC-13]).
    pub decision_rng: DecisionRngState, // per-stream positions, forked by name-hash (04)

    /// The byte offset into the totally-ordered event log (19) at which this
    /// checkpoint sits. A resume continues appending at this offset; the log
    /// prefix up to it is shared CoW with ancestors (§5). The event log is
    /// defined by 19; this file stores only the offset, the shared-prefix ref,
    /// and the appended segment ref.
    pub event_log_offset: EventLogOffset, // offset + shared prefix ref + appended segment ref
}
```

The decomposition is deliberate: each field is the *boundary* with another
layer, and each is captured here only as a content-addressed reference or a
delta:

- **Per-VM snapshot** (icount + blob ref) — *what is in the blob* (CPU
  registers, full device-model state, RAM) is owned by 13 (shmem ABI / VM
  snapshot) and 15 (I/O sub-nodes). This file records the *reference* and the
  *icount* at which the snapshot was taken (09), and stores RAM as a CoW delta
  of pages dirtied since the parent (§5).
- **Per-device CoW overlay delta + device RNG** — owned by 15. The base disk/9p
  image is a read-only `World` artifact (06, INV-5: guests never mutate their
  base image); the checkpoint stores only the overlay pages dirtied since the
  parent plus the device's deterministic RNG state.
- **Scheduler state** — owned by 08: per-node horizons, the pending shared-memory
  frame queues (each frame carrying its delivery icount, source, sequence, and
  payload reference, 13), the timer registry (armed timers and their fire
  icounts, 08/09), and the active fault set (in-effect faults and their heal
  points, 17). This is the state 05 [EXEC-13] requires to live inside the
  configuration.
- **Harness decision-RNG state** — owned by 04/08: the position of each seeded
  per-entity stream, forked by name-hash so unrelated `World` edits don't
  perturb other streams (05 [EXEC-9]).
- **Event-log offset** — owned by 19: the offset into the single totally-ordered
  log at which this node sits, plus a content reference to the shared log prefix.

- **[TEMP-7]** A `MaterializedState` MUST be sufficient for `instantiate`'s
  `loadvm` branch (05 §5) to bring up a runtime at exactly this configuration
  without replaying from an ancestor. It MUST capture, at minimum: per-VM
  snapshot reference + icount (13, 15); per-device CoW overlay delta + device
  RNG (15); scheduler state — per-node horizons, pending shared-memory frame
  queues with delivery icounts, timer registry, active faults (08, 17); the
  harness decision-RNG stream positions (04, 08); and the event-log offset
  (19). *Gate:* `gate:replay-oracle`. *Spec:* §3; forward-ref 13, 15, 19.

- **[TEMP-8]** Each component of a `MaterializedState` MUST be a
  content-addressed reference or a delta over the parent's corresponding
  component (§5), never an inline full copy where a delta is possible. The
  *contents* of a VM snapshot blob and of the event log are owned by 13/15 and
  19 respectively; this file MUST reference them and MUST NOT redefine their
  byte layout. *Gate:* `gate:content-address`. *Spec:* §3; forward-ref 13, 15,
  19.

- **[TEMP-9]** A device's read-only base image MUST NOT appear in a
  `MaterializedState`; only the copy-on-write overlay delta and the device RNG
  state are stored (INV-5: guests never mutate their base image; 15). The base
  is a `World` artifact (06) referenced by content hash. *Gate:*
  `gate:any-guest`, `gate:content-address`. *Spec:* §3; cross-ref 06, 15.

- **[TEMP-10]** The scheduler state captured in a `MaterializedState` MUST be
  exactly the state required by 05 [EXEC-13] to make resume bit-identical to an
  uninterrupted run: horizons, pending frame queues (with delivery icounts),
  timers, active faults, and decision-RNG positions. A `MaterializedState` that
  omits any of these is incomplete and MUST fail the replay oracle (§6). *Gate:*
  `gate:replay-oracle`. *Spec:* §3; cross-ref 05 §4, 08.

## 4. Thin vs fat checkpoints

A checkpoint exists in one of two forms, distinguished only by whether `state`
is present, never by identity:

- A **thin checkpoint** is `(parent, schedule_delta)` with `state = None`. It is
  **always correct and always cheap to store** — it is just the incoming edge —
  but **slow to realize**, because `instantiate` must walk to the nearest fat
  ancestor and replay the intervening schedule suffix forward (05 §5,
  ancestor-replay branch). A thin checkpoint is the canonical, source-of-truth
  form: the schedule delta is the thing that cannot be recomputed and therefore
  must be stored (05 [EXEC-8]).
- A **fat checkpoint** additionally carries a `MaterializedState` (§3). It is
  **fast to realize** — `instantiate` `loadvm`s it directly (05 §5, exact-snapshot
  branch) — but **must be validated**, because a materialized snapshot is a
  *cache* of `reduce`, and a cache can be wrong (an incomplete snapshot, a
  missing field). Its validation is the replay oracle (§6): a fat checkpoint
  MUST hash-equal its thin derivation, or it is rejected.

The thin form is always correct; the fat form is an optimization that must earn
its trust. This asymmetry is what lets Crucible **hedge the snapshot-completeness
risk** (the spike in [`30-risks-spikes.md`](30-risks-spikes.md): QEMU's `savevm`
may not capture every bit of device state). If snapshotting turns out to be
incomplete for some device, the affected checkpoints simply stay thin: they are
slower but still bit-correct, because replay-from-ancestor never depends on
`savevm` completeness — it depends only on Contract A/B determinism (04) and the
schedule delta. The system degrades to "slower," never to "wrong."

The search policy follows directly: keep **most checkpoints thin** (cheap; the
frontier of an exploration is enormous and almost all of it is never resumed),
and **materialize the hot nodes** — the ones that are forked from repeatedly, sit
on a replay path used by many descendants, or are the targets of an interactive
session. Materialization is a caching decision driven by access patterns, not a
correctness decision; eviction (turning a fat checkpoint thin) is always safe
(05 [EXEC-30]).

```text
  thin   = (parent, schedule_delta), state = None
           always correct · cheap to store · slow to realize (replay)
  fat    = thin + MaterializedState (§3)
           fast to realize (loadvm) · must pass the replay oracle (§6)

  policy: most nodes thin; materialize hot nodes (fork hubs, shared replay
          paths, interactive targets). materialize = cache decision (perf),
          NOT a correctness decision. evict (fat→thin) is always safe.

  hedge:  if savevm is incomplete for a device, leave affected nodes thin.
          replay-from-ancestor never depends on savevm completeness — only on
          Contract A/B (04) + the schedule delta. degrade to slow, never wrong.
```

- **[TEMP-11]** Every checkpoint MUST be storable in **thin** form — `(parent,
  schedule_delta)` with `state = None` — and the thin form MUST be the
  canonical source of truth: the schedule delta is the non-recomputable datum
  that MUST be stored (05 [EXEC-8]). A thin checkpoint MUST be realizable by
  `instantiate`'s ancestor-replay branch (05 §5) with no dependence on any
  `savevm`/`loadvm` snapshot. *Gate:* `gate:replay-oracle`. *Spec:* §4;
  cross-ref 05 §5.

- **[TEMP-12]** A **fat** checkpoint MUST carry a `MaterializedState` (§3) and
  MUST be validatable against its thin derivation by the replay oracle (§6): a
  fat checkpoint that does not hash-equal its replay-from-ancestor
  reconstruction MUST be rejected as a cache miss and the thin derivation used
  instead. Materialization MUST be a performance decision, never a correctness
  decision (05 [EXEC-17]). *Gate:* `gate:replay-oracle`. *Spec:* §4, §6.

- **[TEMP-13]** Crucible MUST be able to keep a checkpoint thin when its
  materialized snapshot would be unreliable (e.g. a device whose `savevm` is
  incomplete; see [`30-risks-spikes.md`](30-risks-spikes.md)). Leaving a node
  thin MUST degrade performance only, never correctness: replay-from-ancestor
  depends only on Contract A/B determinism (04) and the schedule delta, never
  on snapshot completeness. *Gate:* `gate:replay-oracle`. *Spec:* §4;
  forward-ref 30.

- **[TEMP-14]** The materialization policy MUST keep most checkpoints thin and
  materialize hot nodes (repeated fork sources, shared replay paths,
  interactive-session targets) under a budget. Turning a fat checkpoint thin
  (eviction) MUST be safe at any time and MUST NOT change any node's denoted
  state (05 [EXEC-30]). The policy is advisory (SHOULD-level) on *which* nodes
  to materialize; correctness MUST NOT depend on the choice. *Gate:*
  `gate:replay-oracle`. *Spec:* §4; cross-ref 05 §10.

## 5. Copy-on-write sharing across the DAG

State-space search builds an enormous graph: branching at every scheduling point
multiplies nodes exponentially. If each node stored a full materialized state,
the graph would not fit on disk for any non-trivial scenario. The temporal graph
is economical because **a checkpoint stores only its delta from its parent**, and
deltas are content-addressed so that identical deltas reached by different paths
are stored once.

Concretely, a fork from a parent checkpoint references the parent's pieces and
layers deltas over them:

- **Block/9p overlay pages** — a child stores only the overlay pages it dirtied;
  unchanged pages resolve up the parent chain to the read-only base image (15).
- **Dirty VM memory pages** — a child's VM snapshot stores only RAM pages
  dirtied since the parent's snapshot; clean pages are shared by reference. (The
  dirty-page set is what the QEMU integration exposes, 10–13.)
- **Schedule delta** — the child stores only the `Decision`s on its incoming
  edge, never the full schedule (the prefix is its parent chain, §2).
- **Log prefix** — the child shares the parent's event-log prefix by reference
  and appends only its own segment (19); `event_log_offset` (§3) records where
  it begins.

All four deltas are keyed by the BLAKE3 hash of their content (§7), so the store
deduplicates automatically: two siblings that dirty the same page, two forks
that take the same first decision, two branches whose logs share a prefix — each
shared piece is stored once and referenced many times. This content-addressed
page/blob dedup is what keeps the graph from exploding (INV-6), and it is the
sole reason state-space search (22) is tractable on real hardware.

```text
  parent checkpoint                 child checkpoint (fork)
  ┌──────────────────┐              ┌──────────────────────────────┐
  │ vm RAM blob   ◄──┼──────────────┼─ shares clean pages (by ref)  │
  │ block overlay ◄──┼──────────────┼─ shares clean pages (by ref)  │
  │ event-log prefix◄┼──────────────┼─ shares prefix (by ref)       │
  └──────────────────┘              │ + dirty RAM pages   (delta)    │
                                    │ + dirty overlay pgs (delta)    │
                                    │ + schedule_delta    (1 Decision)│
                                    │ + log segment       (append)   │
                                    └──────────────────────────────┘
  every delta keyed by BLAKE3(content) → identical deltas stored once (§7)
```

- **[TEMP-15]** A checkpoint MUST store its `MaterializedState` (when fat, §3) as
  copy-on-write deltas over its parent: dirty VM memory pages, dirty
  block/9p overlay pages, the schedule delta, and the appended event-log
  segment — never a full copy of unchanged state. Unchanged pieces MUST resolve
  by reference up the parent chain to the base (read-only `World` images for
  block/9p, the parent's snapshot for RAM, the parent's log prefix). *Gate:*
  `gate:content-address`. *Spec:* §5; cross-ref 10–13, 15, 19.

- **[TEMP-16]** Every CoW delta (page, blob, log segment, schedule delta) MUST be
  keyed by the BLAKE3 hash of its content (§7), so identical deltas reached by
  different decision paths are stored exactly once (INV-6). Two siblings that
  dirty the same page, two forks that take the same decision, and two branches
  that share a log prefix MUST each share the underlying stored object. *Gate:*
  `gate:content-address`. *Spec:* §5, §7.

- **[TEMP-17]** CoW sharing MUST be the mechanism that makes the temporal graph
  fit in storage during state-space search (22): the marginal storage cost of a
  forked checkpoint MUST be proportional to its delta from its parent, not to
  the full size of its state. A design in which forking copies full VM memory or
  full disk images is non-conformant. *Gate:* `gate:content-address`. *Spec:*
  §5; forward-ref 22.

## 6. The replay oracle as a structural invariant

The correctness of the fat-checkpoint *cache* is not a matter of careful coding;
it is a **structural invariant of the data model, enforced as a CI gate**. This
is the temporal-graph face of [INV-2] and of 05 §8: for any checkpoint, the
state obtained by materializing its stored fat snapshot MUST equal the state
obtained by re-deriving it thin — replaying from any fat ancestor along the same
schedule — compared by content hash.

```text
  hash( loadvm(fat_checkpoint.state) )                            (the cache)
    ==
  hash( instantiate(nearest_fat_ancestor) then replay(suffix) )  (the truth)

  for every fat checkpoint, on every host, in any process            (INV-2)
```

In data-model terms: the fat form and the thin form of one checkpoint denote the
same configuration (they have the same `id`, §2), so they MUST realize to
content-equal `RuntimeState` (05 [EXEC-17], [EXEC-22]). The oracle is the
running assertion of that equality. It is checked by re-instantiating the same
checkpoint via different `instantiate` branches and comparing execution
fingerprints (24), and it is gated as `gate:replay-oracle` — not an aspiration,
a build-breaking check. A detected violation MUST localize to the first
differing decision or instruction (divergence bisection, 24,
`gate:divergence-bisect`), never be smoothed over (INV-10; 05 [EXEC-24]).

Because save, resume, and fork are all `instantiate` (05 §5, §9), this single
equality simultaneously validates all three plus snapshot completeness: a fat
checkpoint that omitted a piece of `MaterializedState` (§3) fails the oracle,
which is exactly how snapshot incompleteness is *detected* rather than silently
producing a wrong resume.

- **[TEMP-18]** For every fat checkpoint, `hash(loadvm(state))` MUST equal
  `hash(replay-from-nearest-fat-ancestor)` (INV-2; 05 [EXEC-23]). This equality
  MUST be enforced as the CI gate `gate:replay-oracle`, not left to convention.
  A fat checkpoint that fails it MUST be treated as a corrupt cache entry:
  rejected, its `state` dropped to thin, and the thin derivation used. *Gate:*
  `gate:replay-oracle`. *Spec:* §6; cross-ref 05 §8, 24.

- **[TEMP-19]** A replay-oracle failure MUST localize to the first differing
  decision or instruction via divergence bisection (24) and MUST NOT be repaired
  silently (INV-10; 05 [EXEC-24]). The temporal graph MUST NOT contain any path
  that reconciles a fat/thin disagreement by overwriting one with the other
  without surfacing the divergence. *Gate:* `gate:divergence-bisect`. *Spec:*
  §6; forward-ref 24.

- **[TEMP-20]** The replay oracle MUST serve as the snapshot-completeness check:
  a `MaterializedState` that omits required state (§3) MUST cause the oracle to
  fail (the fat realization diverges from the thin one), so snapshot
  incompleteness is detected at the gate rather than producing a silently wrong
  resume. *Gate:* `gate:replay-oracle`. *Spec:* §6; cross-ref §3, 30.

## 7. The content-addressed checkpoint store (DAG store)

The temporal graph is persisted in a **content-addressed store**: a key/value
store whose keys are the BLAKE3 hashes of the values, holding three kinds of
object — checkpoint nodes (the DAG structure: id, parent, delta, coordinates,
fingerprint), the CoW deltas they reference (RAM pages, overlay pages, log
segments, VM-snapshot blobs), and the genesis (baked) snapshots. The store
interface is small and total:

```rust,illustrative
/// The content-addressed store backing the temporal graph (§1) and its CoW
/// deltas (§5). Keys are BLAKE3 hashes of values; equal content has equal key
/// (INV-6), so `put` of identical content is idempotent and deduplicating.
#[async_trait::async_trait]
pub trait DagStore: Send + Sync {
    /// Store an object, returning its content-addressed key (BLAKE3 of bytes).
    /// Idempotent: storing identical content twice yields the same key and
    /// does not duplicate storage.
    ///
    /// # Errors
    /// Returns an error if the backend cannot persist the object.
    async fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError>;

    /// Retrieve an object by key.
    ///
    /// # Errors
    /// Returns `NotFound` if no object has that key; an I/O error otherwise.
    async fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError>;

    /// Whether an object with this key is present (cheap; no full read).
    ///
    /// # Errors
    /// Returns an error if the backend cannot be queried.
    async fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError>;
}
```

The default backend is the local filesystem in a **two-level layout** —
`{root}/{first 2 hex chars}/{full hex hash}` — so a single directory never holds
millions of entries and lookups stay fast. The store is the same shape as the
session snapshot store sketched in [`29-patterns-and-sketches.md`](29-patterns-and-sketches.md):
`put`/`get`/`exists`, BLAKE3 keys, two-level fan-out. Remote backends (object
storage, a shared team cache so a reproduction artifact's checkpoints can be
fetched rather than recomputed) are a future addition behind the same trait; the
content-addressed key is portable across backends because it is a pure function
of content. This is also the seam at which a future shared substrate with
RFC-0007 (`ratchet`) could be merged (README "Relationship to RFC-0007"; 26
"ratchet gate"), kept behind that gate so Crucible ships standalone (NG-7).

- **[TEMP-21]** The temporal graph and its CoW deltas MUST be persisted in a
  content-addressed store exposing `put`/`get`/`exists` with BLAKE3 content
  keys. `put` MUST be idempotent and deduplicating: storing identical content
  twice MUST yield the same key and MUST NOT duplicate storage (INV-6). *Gate:*
  `gate:content-address`. *Spec:* §7.

- **[TEMP-22]** The default store backend MUST use a two-level on-disk layout
  (`{root}/{first 2 hex}/{full hex}`) so no directory holds an unbounded number
  of entries. The store interface MUST be backend-agnostic so future remote
  backends (object storage, a shared team cache) can be added behind the same
  trait without changing keys, which are pure functions of content. *Spec:* §7;
  forward-ref 26.

- **[TEMP-23]** A reproduction artifact (06, 23) MUST be expressible purely in
  terms of content-addressed store keys (the genesis snapshot, the schedule
  deltas, and the `ScenarioDef`), so a run can be reproduced by fetching its
  closure from a store rather than re-baking and re-deriving from scratch where
  a store is shared. The store MUST NOT be required for correctness — a thin
  artifact (def + seed + schedule) reproduces by replay alone (§4) — only for
  speed. *Gate:* `gate:content-address`. *Spec:* §7; cross-ref 05 §9, 23.

## 8. Garbage collection of the DAG

Search and interactive forking create checkpoints faster than they are kept:
abandoned branches, evicted fat snapshots, and dead-end explorations accumulate.
The store therefore needs garbage collection, and because everything is
content-addressed and reference-counted, GC is standard and safe.

Two complementary mechanisms:

- **Reference counting** for the common case. Each stored object (checkpoint
  node, CoW delta, log segment, VM blob) carries a refcount of the live objects
  that name it: a child checkpoint references its parent and its deltas; a fat
  `MaterializedState` references the page/blob objects it is composed of. When a
  branch is abandoned (a session closes, a search prunes a subtree), the
  refcounts of its objects drop; an object reaching zero references is freed.
  Because CoW deltas are shared (§5), freeing an abandoned branch frees **only**
  the pages unique to it — pages still referenced by a live sibling stay (this
  is the whole point of content-addressed dedup: deletion is also deduplicated).
- **Mark-and-sweep** for the periodic case and to reclaim cycles-of-bookkeeping
  or leaked refcounts. The roots are the live sessions' tip configurations, the
  saved/pinned checkpoints, and the genesis snapshots; everything reachable from
  a root by `parent`/delta references is marked; the unmarked rest is swept. The
  temporal graph is a DAG, so mark-and-sweep terminates and there are no
  reference cycles to special-case.

GC MUST preserve the invariant that any *pinned* checkpoint remains fully
realizable: pinning a checkpoint roots it and its ancestor chain and all deltas
they depend on. GC operates on the cache, never on identity — collecting a fat
snapshot turns its checkpoint thin (still correct, §4), and collecting a thin
checkpoint is only allowed when it is unreachable from every root, i.e. truly
abandoned.

- **[TEMP-24]** The checkpoint store MUST support garbage collection by
  reference counting: each stored object (checkpoint node, CoW delta, log
  segment, VM blob) tracks the live objects that reference it, and an object
  reaching zero references is freed. Freeing an abandoned branch MUST free only
  the objects unique to it; objects still referenced by a live sibling MUST be
  retained (content-addressed dedup applies to deletion as well as storage,
  INV-6). *Gate:* `gate:content-address`. *Spec:* §8.

- **[TEMP-25]** The store MUST additionally support periodic mark-and-sweep GC
  rooted at live sessions' tips, pinned/saved checkpoints, and genesis snapshots,
  reclaiming everything unreachable from a root. Because the temporal graph is a
  DAG, the sweep MUST terminate and MUST NOT need cycle detection. *Spec:* §8.

- **[TEMP-26]** GC MUST operate on the cache, never on identity: collecting a fat
  snapshot MUST turn its checkpoint thin (still correct, §4), and a thin
  checkpoint MUST be collectable only when unreachable from every root.
  A pinned checkpoint MUST remain fully realizable after any GC: pinning MUST
  root the checkpoint, its ancestor chain, and every delta they depend on.
  *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §8.

## 9. Search-tractability: symmetry and partial-order reduction

The temporal graph is the work-list and dedup index for state-space search (22).
Two graph-level optimizations keep the search from exploring redundant nodes.
These are **graph-level optimizations on the content-addressed DAG, not a
formal-methods engine**: Crucible deliberately includes no model checker and no
specification-language evaluator (NG-3). They are heuristics for *not building
nodes we can prove equivalent to nodes we already have*, expressed entirely in
terms of the content addresses and coverage fingerprints this file already
defines.

- **Symmetry reduction.** When several frontier checkpoints are *interchangeable*
  — they differ only by a relabeling of equivalent nodes (e.g. three identical
  replica VMs whose roles are symmetric, so "replica A crashes" and "replica B
  crashes" reach structurally equivalent states) — the search explores one
  representative and treats the others as already-covered. The equivalence is
  detected by a canonicalizing fingerprint: hash the state under a canonical
  relabeling of symmetric entities; equal canonical fingerprints ⇒ one
  representative. This rides on the `coverage_fingerprint` (§2) and the
  content-addressed `id` (a symmetry that produces an identical `(def,
  schedule)` is *already* deduped by §1, [EXEC-26]; symmetry reduction extends
  this to states that are equivalent-up-to-relabeling but not byte-identical).
- **Partial-order reduction.** When two decisions are *independent* — their
  effects commute, so applying them in either order reaches the same state (e.g.
  delivering an in-flight message to node X and, separately, to unrelated node Y
  — the order does not matter) — the search explores **one** representative
  interleaving instead of all permutations. Independence is detected
  conservatively from the scheduling structure (08): two decisions are
  independent when they touch disjoint sets of nodes and neither enables or
  disables the other. Because the graph is content-addressed, if two orderings
  genuinely reach the same `(def, schedule)`-equivalent state they collapse to
  one node anyway (§1); partial-order reduction *avoids generating* the
  redundant orderings in the first place.

Both reductions are **soundness-preserving heuristics**: they MUST only skip a
node when it is provably equivalent (by canonical fingerprint, or by
independence) to a node already explored, and when in doubt they MUST explore
(a missed reduction costs time, an unsound one costs coverage). They are
detailed, with the search algorithm they serve, in
[`22-advanced-features.md`](22-advanced-features.md); this file specifies only
that they are graph-level node-deduplication optimizations over the
content-addressed DAG.

- **[TEMP-27]** State-space search over the temporal graph MAY apply **symmetry
  reduction**: when frontier checkpoints are equivalent up to a relabeling of
  interchangeable entities (detected by a canonical-relabeling fingerprint
  derived from the `coverage_fingerprint`, §2), the search MUST explore one
  representative and treat the symmetric others as covered. Symmetry reduction
  MUST be sound: it MUST only skip a node provably equivalent to one already
  explored. *Spec:* §9; forward-ref 22.

- **[TEMP-28]** State-space search MAY apply **partial-order reduction**: when
  two `Decision`s are independent (commuting effects, disjoint node sets,
  neither enabling/disabling the other — detected conservatively from the
  scheduling structure, 08), the search MUST explore one representative
  interleaving rather than all permutations. Partial-order reduction MUST be
  sound (conservative independence; explore when in doubt). *Spec:* §9;
  forward-ref 08, 22.

- **[TEMP-29]** Symmetry and partial-order reduction MUST be implemented as
  graph-level node-deduplication optimizations over the content-addressed DAG
  (using `id` and `coverage_fingerprint`, §2), NOT as a model checker or
  specification-language evaluator (NG-3). They MUST NOT change the denoted
  state of any explored node; they only avoid *generating* provably redundant
  nodes. *Gate:* `gate:content-address`. *Spec:* §9; cross-ref NG-3,
  forward-ref 22.

## 10. Save / resume / fork / replay / search as operations on this graph

This section closes the loop with 05 §9: the five user-facing operations are
operations on the temporal graph, expressed in the structure this file defines.
They are restated here in temporal-graph terms (not re-derived — 05 owns the
algebra; 22 owns the search algorithm).

```text
  operation   temporal-graph form
  ─────────   ────────────────────────────────────────────────────────────────
  save        materialize instantiate(config) → a FAT checkpoint (§3, §4),
              keyed by config.id() (§2), CoW-shared with its parent (§5),
              put into the DagStore (§7). Thin form (parent, delta) is the
              source of truth (§4); fat form is validated by the oracle (§6).
  resume      instantiate the TIP checkpoint: loadvm its fat snapshot, or
              replay from the nearest fat ancestor if it is thin (05 §5, §4).
  fork        instantiate a NON-TIP checkpoint (a prefix node, §6), then step
              (05 §3) with DIFFERENT decisions to grow a new branch (§5 CoW).
  replay      reconstruct a checkpoint thin (replay from a fat ancestor) and
              assert its fingerprint equals the stored fat form — the replay
              oracle (§6) run on demand.
  search      the temporal graph IS the work-list and dedup index (§1, §9):
              enumerate Decisions at a frontier checkpoint, step each to a child
              (deduped by content address, §1), materialize the hot ones (§4),
              prune with symmetry/partial-order reduction (§9). Detailed in 22.
```

The unification is the same one 05 makes: there is no separate save/resume/fork
data path, because all three are `instantiate` against a checkpoint whose `state`
may or may not be present, over the one content-addressed DAG this file defines.
Search is the same machinery driven by a frontier work-list instead of a user
command.

- **[TEMP-30]** Save, resume, fork, replay, and state-space search MUST all be
  operations on the single content-addressed temporal graph defined in this
  file, expressed via `instantiate` (05 §5) against checkpoints whose `state`
  may be fat or thin (§4): save materializes a fat checkpoint into the
  `DagStore` (§7) keyed by `config.id()` (§2) with CoW sharing (§5) and oracle
  validation (§6); resume/fork are `instantiate` of the tip / a prefix node;
  replay is the on-demand replay oracle (§6); search is frontier `Decision`
  enumeration with content-addressed dedup (§1) and the reductions of §9. No
  operation MAY introduce a checkpoint store or state representation outside
  this graph (05 [EXEC-25]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §10; cross-ref 05 §9, forward-ref 22.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-TEMP-1** Define the `Checkpoint` type with `id =
  hash(parent_id, schedule_delta)`, `scenario_ref`, `parent`, `schedule_delta`,
  `virtual_time` + per-node `icount`, optional `state`, `coverage_fingerprint`,
  and identity-irrelevant `metadata`; property-test that id equals the
  recorded `Configuration::id()` and is independent of `state`/fingerprint/
  metadata. — satisfies [TEMP-1], [TEMP-2], [TEMP-4], [TEMP-5]; spec §1, §2.
  - Completed by `crucible::Checkpoint` and
    `checks.crucible.phase1.gates.contentAddress`: the model now records
    `scenario_ref`, `parent`, `schedule_delta`, `virtual_time`, per-node
    `node_icounts`, optional `MaterializedState`, `coverage_fingerprint`, and
    `CheckpointMeta` while preserving `Checkpoint::id == Configuration::id()`.
    The content-address gate's checkpoint corpus mutates materialized state,
    coverage fingerprint, and metadata independently and asserts the checkpoint
    identity remains byte-identical; it also rejects malformed parent edges
    (missing descendant parent, genesis-with-parent, wrong-scenario parent, and
    non-prefix parent) before such checkpoints can enter the temporal graph.
- [x] **T-TEMP-2** Implement the temporal graph as the content-addressed closure
  of genesis under `step`, with the baked genesis snapshot as root and DAG
  dedup of configurations reached by different paths; test the `parent`-chain ⇒
  schedule-prefix identity. — satisfies [TEMP-1], [TEMP-3], [TEMP-6]; spec §1,
  §2.
  - Completed by `crucible::TemporalGraph` and
    `checks.crucible.phase1.gates.contentAddress`: the graph stores
    content-addressed checkpoint nodes rooted at the baked genesis snapshot,
    records `step` children as thin checkpoint nodes via `record_step`, dedups
    duplicate child configurations by `Configuration::id()`, routes frontier
    enumeration through the same checkpoint DAG, and exposes
    `checkpoint_parent_chain` for root-to-target chain validation. The gate
    reconstructs a two-step schedule from parent-chain `schedule_delta` values,
    asserts the root is the exact baked fat checkpoint, and asserts each
    checkpoint id is the corresponding schedule-prefix configuration id.
- [x] **T-TEMP-3** Define `MaterializedState` capturing per-VM snapshot ref +
  icount (13, 15), per-device CoW overlay delta + device RNG (15), scheduler
  state (horizons, pending frame queues + delivery icounts, timer registry,
  active faults — 08, 17), decision-RNG positions (04), and event-log offset
  (19); test it is sufficient for the `loadvm` branch. — satisfies [TEMP-7],
  [TEMP-8], [TEMP-9], [TEMP-10]; spec §3.
  - Completed by `crucible::MaterializedState`,
    `checks.crucible.phase1.gates.contentAddress`, and
    `checks.crucible.phase1.gates.replayOracle`: fat checkpoints now carry
    structured VM snapshot refs with icounts, device overlay deltas with device
    RNG state, scheduler state, decision-RNG cursors, and event-log offsets.
    The content-address gate checks the component hash shape and icount
    sensitivity; the replay-oracle gate loads baked genesis through the `loadvm`
    branch and rejects incomplete fat checkpoint state.
- [x] **T-TEMP-4** Implement thin checkpoints (`state = None`, realized by
  ancestor-replay) and fat checkpoints (`MaterializedState`, realized by
  `loadvm`), the thin-is-source-of-truth rule, and the materialize-hot-nodes /
  evict-fat→thin policy. — satisfies [TEMP-11], [TEMP-12], [TEMP-14]; spec §4.
  - Completed by `crucible::TemporalGraph`, `crucible::MaterializationPolicy`,
    and `checks.crucible.phase1.gates.replayOracle`: descendant checkpoint DAG
    nodes remain thin (`state = None`) while exact fat snapshots live in the
    separate cache, `materialize_checkpoint` validates a fat cache against the
    thin ancestor path before insertion, `materialize_hot_checkpoint` applies
    the repeated-fork/shared-replay/interactive-target budget, and
    `evict_fat_checkpoint_to_thin` drops the fat cache without changing the
    checkpoint id or replayed runtime state.
- [x] **T-TEMP-5** Implement the savevm-completeness hedge: keep affected
  checkpoints thin when a device's snapshot is unreliable, proving
  replay-from-ancestor stays bit-correct independent of snapshot completeness.
  — satisfies [TEMP-13], [TEMP-20]; spec §4, §6; cross-ref 30.
  - Completed by `crucible::SavevmCompletenessHedge` and
    `checks.crucible.phase1.gates.replayOracle`: `cache_snapshot_with_savevm_hedge`
    refuses fat cache insertion for materialized states touching unreliable
    device overlays, `materialize_checkpoint_with_savevm_hedge` and
    `materialize_hot_checkpoint_with_savevm_hedge` keep such nodes thin, and
    `thin_replay_until_full_s3` evicts an already-hot fat checkpoint back to
    the thin ancestor-replay path while preserving the realized runtime hash.
- [x] **T-TEMP-6** Implement CoW sharing across the DAG: a fork stores only
  dirty VM pages, dirty overlay pages, its schedule delta, and its appended log
  segment; unchanged pieces resolve by reference; all deltas BLAKE3-keyed and
  deduped; assert marginal fork cost ∝ delta size. — satisfies [TEMP-15],
  [TEMP-16], [TEMP-17]; spec §5.
  - Completed by `crucible::CowDeltaRef`, `crucible::CowSharingStats`, and
    `checks.crucible.phase1.gates.contentAddress`: checkpoints now enumerate
    typed CoW delta refs for dirty VM memory, dirty device overlays,
    `schedule_delta`, and explicit appended event-log segments while preserving
    the inherited log prefix as a shared reference; `TemporalGraph`
    computes logical vs unique CoW object counts across recorded DAG nodes and
    fat cache entries; and `marginal_fork_cow_delta_objects` proves a sibling
    fork with identical VM, overlay, and log deltas only adds its new schedule
    delta instead of copying full state.
- [ ] **T-TEMP-7** Implement the replay oracle as a structural invariant and
  CI gate: `hash(loadvm(fat)) == hash(replay-from-fat-ancestor)`, reject
  failing fat checkpoints to thin, localize failures via divergence bisection,
  and use it as the snapshot-completeness check. — satisfies [TEMP-18],
  [TEMP-19], [TEMP-20]; spec §6; cross-ref 24.
  - Completed by `TemporalGraph::replay_oracle_admit_cached_snapshot`,
    `TemporalGraph::validate_cached_snapshots_with_replay_oracle`, and
    `checks.crucible.phase1.gates.replayOracle`: cached fat snapshots are
    admitted through thin replay before materialization paths or direct
    exact-cache realization trust them, and cached ancestors are admitted before
    descendant targets so a corrupt replay source cannot validate a matching
    corrupt descendant; a corrupt cached `MaterializedState` is evicted back to
    the thin checkpoint and surfaces `ReplayOracleMismatch` while the
    ancestor-replay derivation remains realizable; the gate also keeps the
    harness first-mismatch /
    divergence-bisection path and QEMU snapshot-completeness probes wired into
    the replay-oracle result artifact.
- [x] **T-TEMP-8** Implement the content-addressed `DagStore`
  (`put`/`get`/`exists`, BLAKE3 keys, idempotent dedup, two-level on-disk
  layout) with a backend-agnostic trait for future remote backends and
  store-key reproduction artifacts. — satisfies [TEMP-21], [TEMP-22],
  [TEMP-23]; spec §7.
  - Completed by `crucible::DagStore`, `crucible::MemoryDagStore`,
    `crucible::LocalDagStore`, `crucible::TemporalGraphStoreKeys`,
    `TemporalGraph::persist_checkpoint_closure`,
    `crucible::DagStoreReproductionArtifact`, and
    `checks.crucible.phase1.gates.contentAddress`: raw object bytes now produce
    portable BLAKE3-backed `ContentHash` keys via `ContentHash::from_bytes`;
    `put`/`get`/`exists` are backend-agnostic and idempotently dedup equal
    bytes; the default local backend stores objects at
    `{root}/{first 2 hex chars}/{full hex hash}` and repairs corrupt local paths
    on `put`; temporal-graph checkpoint closures persist checkpoint nodes, cached
    fat snapshots, and typed CoW delta descriptors through the store; and
    reproduction artifacts can name the scenario, genesis snapshot, and schedule
    deltas purely as deduplicated store-key closures.
- [x] **T-TEMP-9** Implement DAG garbage collection: reference counting that
  frees only objects unique to an abandoned branch, periodic mark-and-sweep
  rooted at live tips / pinned checkpoints / genesis, and the cache-not-identity
  / pinned-stays-realizable rules. — satisfies [TEMP-24], [TEMP-25], [TEMP-26];
  spec §8.
  - Completed by `crucible::TemporalGraphGcRoots`,
    `crucible::TemporalGraphReferenceCounts`,
    `crucible::TemporalGraphGcReport`,
    `TemporalGraph::reference_counts`, `TemporalGraph::garbage_collect`,
    `TemporalGraph::garbage_collect_store`,
    `TemporalGraph::collect_cached_snapshot`,
    `TemporalGraph::collect_cached_snapshot_store`,
    `crucible::DagStore::delete`, `checks.crucible.phase1.gates.contentAddress`, and
    `checks.crucible.phase1.gates.replayOracle`: live session tips, pinned
    checkpoints, and baked genesis snapshots form the mark roots; root
    multiplicity is reflected in checkpoint reference counts; sweep removes only
    unreachable checkpoint/cache/configuration entries, identifies CoW refs that
    fell to zero, and deletes their deterministic store-key closure through the
    backend; sibling-shared deltas are retained; explicit cache collection turns
    a fat snapshot back into a thin checkpoint without changing identity; missing
    roots fail without deleting store objects; and pinned/cache-collected
    checkpoints keep their ancestor/delta closure replay-oracle-realizable after
    GC.
- [x] **T-TEMP-10** Implement symmetry reduction and partial-order reduction as
  sound, graph-level node-deduplication optimizations over the content-addressed
  DAG (canonical-relabeling fingerprint; conservative decision independence),
  explicitly not a formal-methods engine. — satisfies [TEMP-27], [TEMP-28],
  [TEMP-29]; spec §9; cross-ref 22.
  - Completed by `crucible::FrontierReductionPolicy`,
    `crucible::FrontierReductionReport`,
    `crucible::SymmetryReductionClasses`,
    `crucible::SymmetryReductionKey`,
    `crucible::PartialOrderReductionPolicy`,
    `crucible::PartialOrderReductionKey`,
    `Decision::touched_nodes`, `Decision::is_independent_from`,
    `Decision::reduction_order_key`,
    `Checkpoint::symmetry_reduction_key`,
    `TemporalGraph::symmetry_reduction_key`,
    `TemporalGraph::enumerate_frontier_reduced`, and
    `checks.crucible.phase1.gates.contentAddress`: reduced frontier expansion
    keeps existing content-addressed configuration identities, treats symmetric
    cached checkpoints as covered only when explicit interchangeable-node
    classes, non-default `coverage_fingerprint`, and the full loadable
    materialized state yield the same unambiguous canonical-relabeling
    fingerprint, skips only the non-canonical ordering of disjoint-node
    decisions with an explicit independence proof after recording that
    canonical representative on demand, and explores when coverage,
    materialized state, symmetry classes, touched nodes, representative state,
    or ordering resources are unknown.
- [x] **T-TEMP-11** Wire save/resume/fork/replay/search as operations on the
  temporal graph via `instantiate`, with no checkpoint store or state
  representation outside the DAG. — satisfies [TEMP-30]; spec §10; cross-ref
  05 §9, 22.
  - Completed by `TemporalGraph::save`, `TemporalGraph::resume`,
    `TemporalGraph::fork`, `TemporalGraph::replay`, `TemporalGraph::search`,
    `crucible::TemporalGraphSave`, `crucible::TemporalGraphRuntime`,
    `crucible::TemporalGraphFork`, `crucible::TemporalGraphSearch`,
    `checks.crucible.phase1.gates.contentAddress`, and
    `checks.crucible.phase1.gates.replayOracle`: save materializes a
    replay-oracle-checked fat checkpoint and persists the same graph closure to
    the DAG store; resume records the thin closure before realizing through
    `instantiate`; fork realizes the base and records the branch as a thin graph
    checkpoint; replay validates the stored fat checkpoint against thin replay;
    and search expands a reduced frontier, materializing only explored children
    through the configured checkpoint policy. No separate checkpoint-store state
    representation is introduced.
