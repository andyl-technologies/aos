# Execution graph

The execution graph (the temporal graph) records how a scenario unfolds under
scheduling decisions. It is a content-addressed directed acyclic graph whose
nodes are checkpoints and whose edges are decisions. It is the cache that makes
`instantiate` cheap, the work list and deduplication index for search, and the
unit that is persisted, shared, and garbage-collected.

The algebra it records (`Configuration`, `try_step`, `instantiate`, the replay
oracle) is described in [execution-model.md](execution-model.md). This page
covers the data structure, its storage, and its lifecycle. The code lives in
`crates/crucible/crucible-engine/src/model/temporal_graph/`,
`model/materialized.rs`, and `model/dag_store.rs`.

## Closure of genesis under `try_step`

```text
  spatial graph   = ScenarioDef            (scenario-model.md)
  genesis         = Configuration::genesis(def) = (def, [])
  temporal graph  = { (def, schedule) reachable from genesis by try_step }

  nodes  = Checkpoints   one per recorded Configuration
  edges  = Decisions     each edge appends exactly one Decision
  root   = the baked genesis checkpoint for the scenario
```

A node's identity is its configuration's identity, `Configuration::id()`, so
the structure is a DAG rather than a tree: two decision paths that reach the
same `(def, schedule)` are one node. Recording a configuration records its
whole closure. `record_checkpoint_closure` walks to the immediate parent (the
schedule minus its last decision), records it recursively, and then records
the child as a thin checkpoint, so every edge carries a single decision and
every prefix of a recorded schedule is itself a node. The root is the baked
genesis checkpoint; there is no cold-boot node.

`TemporalGraph` (in `model/temporal_graph/core.rs`) holds five maps keyed by
content address:

| Map | Contents |
| --- | --- |
| `recorded_configurations` | Every configuration the graph has seen |
| `checkpoint_nodes` | The DAG: thin nodes plus the baked genesis roots |
| `cached_snapshots` | Fat checkpoints for non-genesis configurations, the exact-snapshot cache |
| `baked_genesis` | One `GenesisCheckpoint` per scenario id |
| `non_canonical_debug_branches` | Debugger branches kept outside the canonical DAG ([time-travel-debugging.md](time-travel-debugging.md)) |

Thin DAG nodes are the source of truth. Fat snapshots live in a separate cache
map so that adding, validating, or evicting them never changes the DAG.

## Checkpoint

```rust
pub struct Checkpoint {
    pub id: ContentHash,
    pub configuration: ContentHash,
    pub scenario_ref: ContentHash,
    pub parent: Option<ContentHash>,
    pub schedule_delta: Schedule,
    pub virtual_time: VirtualTime,
    pub node_icounts: BTreeMap<NodeId, Icount>,
    pub state: Option<MaterializedState>,
    pub coverage_fingerprint: ContentHash,
    pub assertion_proximity_fingerprint: ContentHash,
    pub metadata: CheckpointMeta,
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    pub execution_closure: Option<ContentHash>,
    pub kind: CheckpointKind,
}
```

| Field | Role | Part of identity |
| --- | --- | --- |
| `id`, `configuration` | Both equal `Configuration::id()` of the recorded configuration | Yes (they are the identity) |
| `scenario_ref` | The scenario id | Through the configuration |
| `parent` | The parent checkpoint id; `None` only at genesis | Through the configuration |
| `schedule_delta` | The decision on the incoming edge | Through the configuration |
| `virtual_time`, `node_icounts` | Coordinates derived from the schedule prefix | No |
| `state` | `Some(MaterializedState)` for a fat checkpoint | No |
| `coverage_fingerprint`, `assertion_proximity_fingerprint` | Observation-only digests for guided search | No |
| `metadata` | `CheckpointMeta` labels for humans and cache policy | No |
| `node_blobs` | Per-node `NodeBlobRef` VM-state references | No |
| `execution_closure` | Content address of the production continuation closure (VMState, host I/O, scheduler, trigger, fault runtime, lifecycle state); absent for pure model checkpoints | No |
| `kind` | `CheckpointKind::Fat` or `CheckpointKind::Thin` | No |

Because identity is the configuration id, mutating state, fingerprints, or
metadata never changes a checkpoint's id. Following `parent` from any node to
the root and concatenating the `schedule_delta`s reproduces that node's
schedule exactly; `TemporalGraph::checkpoint_parent_chain` returns the
root-to-target chain and rejects a cycle or a missing parent.

`Checkpoint::from_recorded_configuration` validates the edge before a node can
enter the graph (`checkpoint_edge` in `model/engine/reduction_helpers.rs`). Each
violation is `EngineError::CheckpointTopologyMismatch` with a reason:

| Reason | Condition |
| --- | --- |
| `genesis-has-parent` | A genesis checkpoint names a parent |
| `descendant-missing-parent` | A non-genesis checkpoint has no parent |
| `parent-scenario-mismatch` | The parent belongs to another scenario |
| `parent-not-schedule-prefix` | The parent's schedule is not a prefix of the child's |
| `empty-descendant-delta` | The child adds no decision |

## Materialized state

A fat checkpoint's `state` is the cached realization of the configuration:
everything needed to bring up a runtime at exactly this point without replaying
from an ancestor.

```rust
pub struct MaterializedState {
    pub id: ContentHash,
    pub vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
    pub device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
    pub scheduler: SchedulerState,
    pub decision_rng: DecisionRngState,
    pub event_log: EventLogOffset,
    pub event_log_segments: Vec<ContentHash>,
}
```

| Component | Contents | Owner of the bytes |
| --- | --- | --- |
| `vm_snapshots` | Per VM: a `NodeBlobRef` (baked blob or CoW delta) and the icount at capture | QEMU integration ([qemu-integration.md](qemu-integration.md)) |
| `device_overlays` | Per device: `DeviceOverlayDelta { parent, delta, resolved, rng }`, the dirty overlay delta over a parent overlay or the read-only base, plus device RNG positions | I/O sub-nodes ([io-subnodes.md](io-subnodes.md)) |
| `scheduler` | `SchedulerState` (below) | Scheduler ([scheduling.md](scheduling.md)) |
| `decision_rng` | `DecisionRngState`: per-stream positions of the seeded decision streams | Determinism core ([determinism.md](determinism.md)) |
| `event_log` | `EventLogOffset { prefix, appended_segment, bytes, events }` | Event log ([event-log.md](event-log.md)) |
| `event_log_segments` | Retained segment keys for shared-store fetches | Event log |

`SchedulerState` captures the state required for a resume to reproduce
cross-node ordering: per-node `horizons`, `pending_frames` (each
`PendingFrame` has a source, sequence, `delivery_icount`, and payload hash),
`network_link_cursors`, `event_sequences`, the effective topology epoch, edges,
and pending topology changes, the `timers` registry, pending device decisions,
and the captured search frontier. These are exactly the pieces that must live
inside the configuration for resume plus continue to equal an uninterrupted
run. A checkpoint that omits one fails the replay oracle.

`MaterializedState::id` hashes the domain `crucible.materialized-state.v2` over
the VM snapshots, device overlays, scheduler state, decision-RNG state, and
event-log offset. The retained segment list is not part of the id. A device's
read-only base image never appears in materialized state; only its overlay
delta and RNG state do.

This page names the components and their references. The byte layouts of a VM
snapshot, an overlay, and an event-log segment belong to the owning layers.

## Thin and fat checkpoints

A checkpoint exists in one of two forms. Identity does not depend on which.

```text
  thin = (parent, schedule_delta), state = None
         always correct, cheap to store, realized by replay
  fat  = thin + MaterializedState
         fast to realize, must pass the replay oracle before it is trusted
```

The thin form is canonical. The schedule delta is the one datum that cannot be
recomputed, so it is what must be stored. Replay from an ancestor depends only
on intra-VM determinism and the delta, never on snapshot completeness. A fat
checkpoint is a cache of `reduce`, and a cache can be wrong, so it must earn
trust through the replay oracle. If a device's checkpoint capture were
incomplete, keeping the affected checkpoints thin degrades performance and
never correctness.

The cache API on `TemporalGraph` (in
`model/temporal_graph/core/checkpoint_cache.rs`):

| Method | Behavior |
| --- | --- |
| `cache_baked_genesis`, `with_baked_genesis` | Register the fat genesis root for a scenario; the checkpoint must name `Configuration::genesis(def)` |
| `cache_snapshot`, `with_cached_snapshot` | Register a fat snapshot for a non-genesis configuration; genesis is rejected (`GenesisSnapshotMustBeBaked`) and thin checkpoints are rejected (`CheckpointNotLoadable`) |
| `record_thin_checkpoint` | Record the thin closure of a configuration |
| `materialize_checkpoint` | Realize through `instantiate`, check the result against thin replay, then cache it |
| `materialize_hot_checkpoint` | Apply `MaterializationPolicy` to decide fat or thin |
| `evict_fat_checkpoint_to_thin` | Drop the fat cache entry; the thin node and its id are unchanged |
| `save_checkpoint` | Materialize; idempotent for a configuration already saved |

`MaterializationPolicy { max_fat_checkpoints }` is an advisory budget. A node
is materialized only when its `MaterializationTrigger` is hot
(`RepeatedForkSource`, `SharedReplayPath`, or `InteractiveTarget`) and the
cache holds fewer than the budget; `Cold` nodes stay thin.
`MaterializationPolicy::thin_only()` keeps every ordinary checkpoint thin. The
search frontier is large and mostly never resumed, so most checkpoints stay
thin and the nodes that are forked from repeatedly, sit on shared replay paths,
or are interactive targets are materialized. Which nodes are materialized is a
performance choice; correctness never depends on it, and eviction is always
safe.

## Copy-on-write sharing

State-space search branches at every scheduling point. Storing full state per
node would not fit on disk for any nontrivial scenario, so a checkpoint stores
only its delta from its parent, and identical deltas reached by different
paths are stored once.

```text
  parent checkpoint                  child checkpoint (fork)
  +--------------------+             +-------------------------------+
  | VM state blob   <--+-------------+-- clean state by reference    |
  | device overlay  <--+-------------+-- clean pages by reference    |
  | event-log prefix<--+-------------+-- shared prefix by reference  |
  +--------------------+             | + VmMemory delta              |
                                     | + DeviceOverlay delta         |
                                     | + ScheduleDelta (1 decision)  |
                                     | + EventLogSegment (appended)  |
                                     +-------------------------------+
  every delta is keyed by the hash of its content
```

`CowDeltaKind` names the four delta namespaces: `VmMemory`, `DeviceOverlay`,
`ScheduleDelta`, and `EventLogSegment`. A `CowDeltaRef { kind, content }` is a
typed content-addressed delta object. `Checkpoint::cow_delta_refs` enumerates
the schedule delta plus the deltas in its materialized state: the CoW
`NodeBlobRef`s, every device overlay delta, and the appended event-log
segments. The inherited log prefix is kept as a shared reference
(`EventLogOffset::prefix`) and only the appended segment is a new object.

Accounting is explicit. `CowSharingStats` counts logical references against
unique typed objects, and `TemporalGraph::cow_sharing_stats` reports it for the
whole graph. `TemporalGraph::marginal_fork_cow_delta_objects(checkpoint)` counts
how many new CoW objects a checkpoint would add: a sibling fork with identical
VM, overlay, and log deltas adds only its schedule delta. The marginal cost of
a fork is proportional to its delta, not to the size of its state.

## Replay oracle

For every fat checkpoint, materializing the stored snapshot must equal
re-deriving it thin from the nearest cached ancestor or from genesis. This is
the check that admits fat checkpoints into the cache and keeps them there. The
semantics, comparison fields, and admission order are in
[execution-model.md](execution-model.md#the-replay-oracle). Graph-side
consequences:

- A fat checkpoint that fails the oracle is evicted back to its thin node and
  the mismatch is returned; it is never overwritten with the thin result.
- Cached ancestors are admitted from genesis outward before a target, so a
  corrupt ancestor cannot validate a matching corrupt descendant.
- Because a fat checkpoint that omits state fails the oracle, the oracle is
  also the snapshot-completeness check.

## The DAG store

The temporal graph and its deltas persist in a content-addressed store.

```rust
pub trait DagStore: Send + Sync {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError>;
    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError>;
    fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError>;
    fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError>;
}
```

`crucible_engine::DagStore` (in `model/dag_store.rs`) keys objects with
`ContentHash::from_bytes`, the BLAKE3 hash of the raw bytes. Equal bytes get
equal keys on every backend, so `put` is idempotent and deduplicating and keys
are portable across backends. Implementations:

| Backend | Behavior |
| --- | --- |
| `MemoryDagStore` | In-process map for model tests and adapters |
| `LocalDagStore` | Filesystem store at `{root}/{first 2 hex chars}/{full hex hash}`, so no directory holds an unbounded number of entries |

`LocalDagStore::put` returns early when a valid object already exists,
otherwise writes a temporary file and renames it into place, replacing a
corrupt object at the same path. `get` rehashes the bytes and returns
`DagStoreError::ContentMismatch` when they do not match the key; `exists`
validates the same way. `delete` reports whether an object was present.
`DagStoreError` also covers `NotFound`, `StorePoisoned`, `CorruptIndex`, and
`Io` with the operation and path.

### Persisting a closure

`TemporalGraph::persist_checkpoint_closure(store, frontier)` records the
frontier's closure and writes, in order:

1. The scenario record (`crucible.dag-store.scenario-def.v2`: scenario id,
   seed, app-random cap).
2. The baked genesis checkpoint.
3. Every checkpoint node on the root-to-frontier chain, plus each node's cached
   fat snapshot when one exists.
4. Each node's CoW deltas: schedule deltas as
   `crucible.dag-store.schedule-delta.v3` records, VM-memory and
   device-overlay deltas as `crucible.dag-store.cow-delta-ref.v2` descriptors,
   and event-log segments by reference. An event-log segment must already be in
   the store (the scheduler writes segment bytes when it emits them); a missing
   segment is a store error, not a silent gap.

Checkpoint nodes are stored as line-oriented records:

```text
crucible.dag-store.checkpoint-node.v2
id=<hex>
configuration=<hex>
scenario_ref=<hex>
parent=<hex or none>
schedule_delta=<hex>
kind=fat|thin
virtual_time_ticks=<u64>
coverage_fingerprint=<hex>
assertion_proximity_fingerprint=<hex>
node_icounts=<n>
node_icount.node=<name>
node_icount.retired=<u64>
state=<hex or none>
...
```

The call returns `TemporalGraphStoreKeys`: maps from checkpoint ids to stored
node and snapshot keys, from `CowDeltaRef`s to stored delta keys, and a
`DagStoreReproductionArtifact` that names the scenario record, the genesis
snapshot, the schedule deltas, and retained event-log segments purely as store
keys. `store_keys()` returns the deduplicated closure.

The store is never required for correctness. A thin reproduction (scenario,
seed, schedule) replays without it; a shared store only lets a run fetch
checkpoints instead of recomputing them. `TemporalGraph::save(store, config)`
is the user-facing save: materialize a replay-oracle-checked fat checkpoint,
then persist the closure.

### Fleet storage

`crates/crucible/crucible-store` provides the same seam for fleet and campaign
use: `crucible_store::DagStore` with `put`, `get`, and `has` over BLAKE3 keys,
and `MemoryDagStore`, `LocalDagStore`, and `SharedDagStore` implementations.
`SharedDagStore` uses the same two-level layout but publishes through a
per-writer temporary path and an atomic hard link, so concurrent writers of
identical bytes converge on one object and a writer that finds different bytes
under a key fails with `CasError::ContentMismatch`. A remote backend is
another implementation of the same narrow trait; authorization belongs to the
transport around it, not to the trait. See
[distributed-exploration.md](distributed-exploration.md).

## Garbage collection

Search and forking create checkpoints faster than they are kept. Everything is
content-addressed and the graph is acyclic, so collection is a mark and sweep
over reachability.

`TemporalGraphGcRoots` holds explicit roots with multiplicity:
`live_tips` (checkpoints held by live sessions, counted per holder) and
`pinned_checkpoints` (saved checkpoints, counted per pin). Every baked genesis
checkpoint is an implicit root.

| Method | Effect |
| --- | --- |
| `reference_counts(roots)` | Count live references to checkpoint nodes, cached snapshots, and CoW deltas in the rooted closure |
| `garbage_collect(roots)` | Mark each root's parent chain to genesis; drop unreachable checkpoint nodes, cached snapshots, and recorded configurations; report collectible CoW deltas and store keys |
| `garbage_collect_store(store, roots)` | Run `garbage_collect`, then delete every store key unique to the swept closure |
| `collect_cached_snapshot(config)` | Turn a reachable fat checkpoint thin without deleting its identity |
| `collect_cached_snapshot_store(store, config)` | The same, deleting store keys only the fat cache referenced |

Rules the implementation keeps:

- **Roots must exist.** A live or pinned root that is not in the DAG fails with
  `EngineError::CheckpointNotRecorded` before anything is swept or deleted.
- **Shared objects survive.** Keys are computed for the retained closure and
  only the difference is deleted, so a delta still referenced by a live sibling
  is retained. Deduplication applies to deletion as well as storage.
- **Cache, not identity.** A reachable fat snapshot is never removed by the
  sweep; `collect_cached_snapshot` turns it thin, which is still correct. A
  thin checkpoint is collected only when no root reaches it.
- **Pinned means realizable.** Pinning roots the checkpoint, its ancestor
  chain, and every delta they depend on, so a pinned checkpoint stays
  replay-oracle realizable after any collection.

`TemporalGraphGcReport` lists the live checkpoints and reference counts, the
collected checkpoints, snapshots, and configurations, the collectible CoW
deltas, the live and collectible store keys, and, for store-backed passes, the
keys deleted and the keys that were already absent. A store error during
deletion can occur after the graph maps have been swept.

## Frontier expansion and reduction

The graph is the work list and deduplication index for search.

- `TemporalGraph::enumerate_frontier(frontier, decisions)` applies each
  candidate with `try_step`, deduplicates children by configuration id,
  returns them in content-address order, and marks children that were already
  recorded so a driver can skip re-materializing them.
- `TemporalGraph::enumerate_frontier_reduced(frontier, decisions, policy)`
  additionally applies a `FrontierReductionPolicy` with two parts:
  - **Partial-order reduction.** A candidate is skipped only when an explicit
    independence proof (`PartialOrderReductionPolicy`) covers adjacent decisions
    with disjoint node sets and no shared ordered resource, and the candidate
    is the non-canonical ordering. The candidate is marked covered only
    after recording that canonical representative on demand.
  - **Symmetry reduction.** Cached checkpoints are treated as covered only when
    explicit interchangeable-node classes (`SymmetryReductionClasses`), a
    non-default coverage fingerprint, and the full loadable materialized state
    yield the same unambiguous canonical-relabeling key
    (`Checkpoint::symmetry_reduction_key`).

Both reductions are sound heuristics: when coverage, materialized state,
symmetry classes, touched nodes, or ordering resources are unknown, they
explore. They never rewrite a child configuration, and covered children report
the representative that justified skipping them. They are graph-level
deduplication over content addresses, not a model checker or specification
evaluator. `TemporalGraph::search` resumes the frontier, enumerates its
runtime-derived decisions through the reduced path, and passes each explored
child to `materialize_hot_checkpoint`. Strategies and guidance are described
in [exploration.md](exploration.md).

## Operations on the graph

| Operation | Graph form |
| --- | --- |
| save | `TemporalGraph::save`: materialize a replay-checked fat checkpoint keyed by `Configuration::id()` and persist its closure |
| resume | `TemporalGraph::resume`: record the thin closure of the tip, then `instantiate` |
| fork | `TemporalGraph::fork`: resume a base, apply new decisions, record the branch as a thin checkpoint |
| replay | `TemporalGraph::replay`: check the stored fat checkpoint against thin derivation |
| search | `TemporalGraph::search`: expand a reduced frontier, materialize only hot explored children |

No operation introduces a checkpoint store or state representation outside
this graph. Production exact checkpoints (the authenticated closures referenced
by `Checkpoint::execution_closure`) are realization artifacts for the same
configuration ids; see
[execution-model.md](execution-model.md#production-realization-routes).

## Verification

| Check | Covers |
| --- | --- |
| `checks.crucible.phase1.gates.contentAddress` | Runs the `crucible-engine` `gate_content_address` test: checkpoint identity independent of state, fingerprints, and metadata; malformed parent edges; parent-chain schedule reconstruction; `crucible_engine::CowDeltaRef` sharing and `marginal_fork_cow_delta_objects`; `crucible_engine::DagStore`, `crucible_engine::LocalDagStore`, and `crucible_engine::DagStoreReproductionArtifact`; `crucible_engine::TemporalGraphGcRoots` and `crucible_engine::TemporalGraphGcReport`; `crucible_engine::FrontierReductionPolicy` and `TemporalGraph::enumerate_frontier_reduced`; `TemporalGraph::save` and `TemporalGraph::fork` |
| `checks.crucible.phase1.gates.replayOracle` | Fat/thin equality, materialization admission, eviction on mismatch, GC realizability |
| `checks.crucible.phase1.executionGraphOperations` | Save, on-demand replay, and frontier enumeration |
| `checks.crucible.phase1.executionCacheEviction` | Eviction leaves identity and replayed state unchanged |
