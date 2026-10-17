# 16 — Run Arena and Run Journal

A campaign attempt is one deterministic run of a QEMU world under the host
scheduler. Everything the host knows about that run, apart from guest memory
and device state, lives in host processes. This chapter defines one owner for
that state, the **Run Arena**, and one owner for the run's event history, the
**Run Journal**. It also defines the **Campaign Arena**, a campaign-level view
over the executor's operational records.

The chapter builds on [§05](05-hot-fork-and-checkpoints.md) (realization tiers,
host continuation cloning, and the exact closure) and on
[§15](15-segmented-event-log.md) (segmented attempt logs and bounded
evaluation). It does not change configuration identity, campaign truth, the
realization-tier model, or the process boundary. It changes how the host owns,
shares, persists, and restores run state so that hot fork, exact checkpoint,
pause, graceful restart, debugging, and introspection are operations over one
structure rather than separate gatherers over many.

## 16.1 Problem

No root object owns a run's state. Each consequence below follows from that.

**The lifecycle loop mixes four kinds of state.** `ProductionVmLifecycleLoop`
(`crates/crucible-api/src/vm_lifecycle.rs`) is the closest thing to a run root.
It has more than fifty fields. They mix modeled continuation (scheduler,
trigger, assertion, fault, and lifecycle state), live operating-system authority
(node leases, launchers, run directories, lock and journal owners, hot-fork
backing files), derived caches (the lowered trigger graph, the assertion oracle,
node indexes), and transients that must be empty before any capture (pending
network prefixes, held host outcomes, unapplied branch continuations). Nothing
in the type distinguishes them.

**One field set exists as four types, filled by hand at three sites.** The
in-memory exact checkpoint set (`ProductionVmExactCheckpointSet`), the hot-fork
world continuation (`ProductionVmHotForkWorldContinuation`), the native
version-nine closure wire (`ClosureManifest`, `ClosureObjects`, and
`LifecycleWire`), and the canonical closure record for the campaign root
(`ExactCheckpointClosureRecord`) all describe the same host continuation. Two
capture functions (`capture_reserved_exact_checkpoint_set` and
`capture_hot_fork_world_continuation`) gather it line for line, and
`into_restore_parts` maps one representation into another field by field.
Adding one host-model field means editing all of them. Missing one breaks
[HFORK-11] pairing or fat/thin equivalence. Restore is already unified:
`build_production_vm_lifecycle_loop_with_restore`
(`crates/crucible-api/src/vm_lifecycle/construction.rs`) serves fresh start,
exact restore, hot adoption, and debug replay.

**Per-attempt daemon state has no owner.** For one attempt, the daemon keeps
state in about ten places: the supervisor's queued and active entries, the
modeled driver's stack frame (retained log, choices, frontier), a per-worker
evidence recorder behind a mutex, the lifecycle loop, the assignment-ledger
record, the prepared-result journal directory, two attempt-log directories, the
native checkpoint catalog, the campaign-store checkpoint objects, and the
pool-owned hot-fork source world that outlives the attempt.

**Each event-log entry is stored eight to ten times.** The scheduler keeps the
complete log as its condition prefix in memory and writes its own per-quantum
segments in a different encoding to the scenario-scoped DAG store. The modeled
driver and the evidence recorder each keep an attempt log in a third encoding.
The prepared-result journal and the repository trace leaves hold further
placements. Every scheduler checkpoint embeds every retained entry
(`condition_entries: log.retained_entries().to_vec()` in
`crates/crucible/src/scheduler/checkpoint.rs`). The hot-fork continuation holds
every scheduler segment's bytes in memory. The session actor and session event
stream keep two more complete copies on the API path. Exact-checkpoint capture
reads every segment back and re-persists it, so capture costs O(total log)
rather than O(changed state) ([HFORK-15]).

**Atomicity is implemented by whole-value clones.** The scheduler is
`#[derive(Clone)]` and is staged by whole clones at run admission, cap
readmission, dispatch and input boundaries, fixed-input settlement, every
network-output batch (`crates/crucible-api/src/vm_lifecycle/network_faults/route.rs`),
and every signal-fault boundary. The fault runtime is deep-cloned on every
coordinated 9p I/O transaction. Each clone copies every ledger that grows with
the run, so per-quantum work grows with elapsed virtual time ([CPERF-10]).

**Caps exist because run-length data is resident.** Many resource caps in the
host exist only because a structure whose size is proportional to the run is
held whole in memory or encoded as one object. [§15](15-segmented-event-log.md)
removed the whole-log bound for the attempt log; the same shape remains in
scheduler ledgers, fault ledgers, recorded controls, debug evidence, and the
checkpoint wires that nest them as opaque byte vectors.

## 16.2 Vocabulary

| Term | Meaning |
| --- | --- |
| **Run Arena** | The single owner of one run's modeled host-side state: a set of typed tables plus a reference into the Run Journal. One arena exists per attempt execution. |
| **Campaign Arena** | A campaign-scoped view joining the campaign ref, the executor's operational records, and the runs' journals. It starts read-only. |
| **Run Journal** | The single append-only, segmented event journal of one run. Every other holder of event-log content is a projection of it or a reference into it. |
| **Table** | One typed, versioned collection inside a Run Arena, keyed by stable semantic keys and owned by one subsystem. |
| **Hot table** | A table held as a persistent collection with structural sharing, cloned in constant time. |
| **Chunked table** | A table of append-growing records stored as immutable content-addressed chunks plus one open chunk; sealed chunks may spill. |
| **Layer** | One representation of a frozen arena: L0 live, L1 frozen in memory, L2 native catalog and spill cache, L3 campaign store root. |
| **Frozen arena** | An immutable L1 value produced by `freeze`. Hot-fork continuations, exact capture, and introspection consume it. |
| **StateRoot** | The Merkle root over the canonical logical encoding of an arena's tables and its journal position. It identifies host model state for verification; it is not a configuration identity. |
| **Journal position** | The coordinates of a point in a Run Journal: entry count and entry-prefix digest, plus the sealed segment count and chain hash when the point is a seal boundary. |
| **Run Authority** | The non-serializable owner of a run's live operating-system resources. |
| **Resource slot** | The serializable description of one authority resource: a stable slot ID, a recipe for recreating it, and the proof it must report after rebinding. |
| **Unsettled state** | Transient run state that cannot be frozen. A run with unsettled state cannot be checkpointed, forked, persisted, or retained. |
| **Tier attachment** | The tier-specific half of a frozen run: QEMU artifact references for an exact target, or adopted children and host-I/O projections for a hot fork. |

## 16.3 Run Arena model

### Tables and collections

A Run Arena is a manifest plus a fixed catalog of tables. Each table belongs to
one subsystem and has a stable table ID, a schema version, and a key type made
of semantic identities such as `NodeId`, `LinkId`, an event sequence number,
or a declared property leaf. Keys never encode allocation history, process identities, or
memory addresses. When a subsystem allocates counters or generational indexes
that affect results, the allocator state is itself a table entry.

Two storage shapes cover the catalog:

- **Hot tables** hold state touched every quantum and bounded by the scenario:
  scheduler queues and cursors, network link state, fault evaluator state,
  trigger and assertion folds, and per-node continuations. They use persistent
  ordered collections, so a clone shares every node and an update copies only
  the path to the changed entry.
- **Chunked tables** hold records that grow with the run: the schedule's
  decisions, scheduler application ledgers, fault emission and commit ledgers,
  recorded controls, storage observations, and campaign effect records. Records
  append to one open chunk. A full chunk is sealed, encoded canonically,
  addressed by content, and may be evicted from memory and reloaded by its
  content ID. This generalizes the chunked shared history already used for the
  configuration's decisions.

Every table has a write barrier. Mutation through the table API records the
dirty key or chunk index; there is no other mutation path. Persisting a frozen
arena encodes only dirty chunks and recomputes only the affected Merkle paths.
An untouched table reuses its previous root.

The initial catalog is illustrative; T-CAM-10.4 fixes it with the field
classification of T-CAM-10.2.

```text
Table               Today's owner                                   Shape
schedule            Configuration / Schedule                        chunked
scheduler-core      SingleScheduler frontier, queues, cursors        hot
scheduler-ledgers   subdivision, preemption, control, topology,      chunked
                    rendezvous, and ceiling records
network             world links, link RNG positions, effect state    hot
fault               fault evaluator, adapters, host action state     hot
fault-ledgers       emitted events, issued and committed actions     chunked
trigger             event-graph state                                hot
assertion           obligations, marker state, named-leaf folds      hot
lifecycle           terminal verdict, branch, service states         hot
recorded-controls   applied lifecycle controls                       chunked
host-io             per-node block, 9p, accelerator continuations    hot
node-continuation   per-node time, console, ring snapshots           hot
failed-nodes        process-free host-I/O state of failed nodes      hot
signal-artifacts    references to content-addressed artifacts        hot
```

- **[ARENA-1]** Every piece of host-side state reachable from a run MUST be
  classified as exactly one of: Run Arena table content, Run Authority, a cache
  rebuilt from the arena and the scenario, or unsettled state. Modeled state
  MUST live only in Run Arena tables. No component outside the arena may retain
  an independent mutable copy of modeled state; staging and rollback copies
  MUST be arena clones.
- **[ARENA-2]** A table MUST have a stable table ID, a registered schema
  version, and keys made of semantic identities. Iteration order, encoded
  bytes, and results MUST NOT depend on hash order, allocation history, pointer
  identity, or reference counts; pointer equality MAY serve only as a shortcut
  that returns the same answer as a full comparison.
- **[ARENA-3]** Cloning a Run Arena or any table MUST cost O(number of tables)
  independent of table contents. A per-quantum or per-boundary update MUST cost
  time proportional to the entries it touches. Atomic multi-table updates MUST
  stage on a clone and commit by replacing the arena value, never by deep
  copying and swapping subsystem state.
- **[ARENA-4]** State that grows with run length MUST be a chunked table.
  Sealed chunks MUST be immutable and content-addressed. Resident memory for a
  chunked table MUST be bounded by its open chunk plus the executor's configured
  residency budget. An evicted chunk MUST be reloaded and authenticated by its
  content ID before use, and eviction MUST NOT change any result.
- **[ARENA-5]** Every table MUST record mutations through a write barrier.
  Persisting a frozen arena MUST encode only dirty chunks and recompute only the
  Merkle paths above them, so persist cost is proportional to changed state. A
  full re-encode, such as the first persist of a run or a persist after a schema
  change, is correct but MUST be reported, as [HFORK-15] requires for full
  capture.

### Layers

A run's arena has four representations. L1 and L2 are faster caches of L3, and
thin replay remains the source of truth ([HFORK-2]).

| Layer | Name | Contents | Present today as | Lifetime |
| --- | --- | --- | --- | --- |
| **L0** | Live | The mutable arena owned by the run's single writer | The lifecycle loop's fields | The execution |
| **L1** | Frozen in memory | Immutable, structurally shared frozen arenas | Hot-fork world continuation and retained source pool | Daemon process |
| **L2** | Native catalog and spill | Encoded chunks, table roots, and arena manifests in executor-owned local storage | Native exact catalog | Until retired by the executor |
| **L3** | Campaign store root | The arena manifest and chunks reachable from an exact-checkpoint root in the campaign store | Version-five exact-checkpoint root | While a retention root reaches it |

L0 to L1 is `freeze`. L1 to L2 is `persist`. L2 to L3 is the existing
root-last publication of [§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure).
Restore runs the other way: L3 or L2 objects decode into an L1 frozen arena,
and thawing it under a fresh Run Authority produces L0.

- **[ARENA-6]** L1 and L2 are caches. Deleting every L1 value and every L2
  object MUST NOT lose state that cannot be recovered from an L3 root or by
  thin replay, and MUST leave the campaign recoverable ([CCOMP-22]). The layer
  from which a run was materialized MUST NOT enter any identity, observation,
  or result.

### Canonical codec and StateRoot

Every table has exactly one canonical encoding per schema version. That
encoding serves persistence, comparison, identity, and transfer; there is no
second debug or transport encoding of the same state. Table chunks are encoded
in key order, use explicit integer widths, contain no native floating point
(invariant 7), and are rejected on decode unless re-encoding reproduces the
same bytes ([CSTORE-13]).

Chunk boundaries are a pure function of the table's logical content. For an
append-only table, chunk `i` holds records `[i * n, (i + 1) * n)` for the
table's fixed record count `n`. For a keyed table, boundaries are chosen by a
content-defined rule over the canonical key order. Two arenas with equal logical
content therefore have equal chunks, whatever sequence of inserts, removals,
evictions, and reloads produced them.

```text
chunk ID        ContentId("crucible.run-arena.chunk", table schema version,
                          canonical chunk bytes)
table root      H("crucible.run-arena.table.v1", table ID, schema version,
                  ordered [(first key, record count, chunk ID)])
StateRoot       H("crucible.run-arena.state-root.v1", arena schema version,
                  configuration ID, entry count, entry-prefix digest,
                  ordered [(table ID, table root)])
```

The StateRoot commits to host model state and to the journal position through
the segmentation-independent entry-prefix digest of
[§16.5](#165-run-journal). It does not commit to segment boundaries, QEMU
artifact identities, Run Authority, realization generations, caches, or the
layer from which tables were loaded. Guest-state equality across tiers remains
the job of execution fingerprints ([§10.8](10-performance-and-validation.md#108-equivalence-matrix)).

- **[ARENA-7]** Each table schema version MUST define exactly one canonical
  encoding. Decoders MUST reject noncanonical bytes. Identity-bearing encodings
  MUST NOT use JSON, native floating point, or maps ordered by hash. Chunk
  boundaries MUST be a pure function of the table's logical content.
- **[ARENA-8]** The StateRoot MUST be computed over canonical logical encodings
  only. Two arenas with equal logical tables and equal journal entry prefixes
  MUST have equal StateRoots, independent of mutation history, chunk residency,
  spill placement, layer, and realization tier. The StateRoot MUST NOT include
  Run Authority, caches, realization generations, segment boundaries, or QEMU
  artifact identities. It is a verification identity: it MUST NOT enter a
  `ConfigurationId`, a campaign fact, or a planner input.

### Splitting the lifecycle loop

Today's lifecycle loop becomes four parts with distinct types. The field names
below are examples at the time of writing; T-CAM-10.2 classifies every field.

| Part | Today's fields (examples) | Treatment |
| --- | --- | --- |
| `RunArena` | Scheduler state inside `inner`, `trigger_state`, `assertion_evaluator`, `terminal_verdict`, `checkpoint_terminal_cause`, `initial_lifecycle_observations_pending`, `branch`, `recorded_controls`, `fault_runtime`, `storage_fault_observations`, `failed_host_io`, `block_bindings`, `ninep_bindings`, `immutable_root_images`, `node_service_states`, `signal_artifact_objects` | Frozen, persisted, and covered by the StateRoot |
| `RunAuthority` | `node_leases`, `node_launcher`, `_run_directory`, `node_run_directories`, `lifecycle_persistence`, `lifecycle_journal`, `run_manifest`, `retained_hot_fork_disk_owners`, `retained_resource_owners`, `hot_fork_backing_files`, `debug_gateway`, the live handles inside `checkpoint_targets` and `exact_ram_parents`, `node_generations` | Never serialized; described by resource slots |
| Rebuilt caches | `trigger_graph`, `trigger_world`, `assertion_oracle`, `node_indexes`, `launch_configs`, `debug_backend_paths`, `runtime_progress` | Derived from the arena and scenario on thaw |
| Unsettled state | `continuation_branches`, `signal_fault_branches`, `pending_live_network_prefix`, `pending_held_host_outcomes`, `indeterminate_debug_candidate`, `debug_attach`, unpublished checkpoint targets | Must be empty at freeze |

Process generations are realization state. They change between a hot child and
an exact restore of the same boundary, so they belong to the Run Authority as
the expected successor in a resource slot's proof, not to the StateRoot. The
same test classifies every borderline field: a value that may legitimately
differ between two equivalent realizations of one configuration is not modeled
state.

The scattered capture-refusal checks (`exact_checkpoint_ready`,
`require_published_host_continuation`, `final_boundary_retainable`, and the
inline refusals in the capture functions) become one predicate:

```rust,illustrative
impl RunArena {
    /// Returns every reason this run cannot be frozen now; empty means settled.
    fn unsettled(&self, transients: &RunTransients) -> UnsettledReasons;
}
```

- **[ARENA-9]** A run MUST expose one `unsettled()` predicate that reports every
  reason it cannot be frozen. Freeze for checkpoint, hot fork, persist, or
  source retention MUST refuse with those typed reasons while the predicate is
  non-empty, and no other capture-refusal predicate may exist.

## 16.4 Run Authority and resource slots

Live operating-system resources are not state. A process handle, pidfd, cgroup,
memfd, shared-memory mapping, socket, lock, lease, temporary directory, or QMP
snapshot handle is authority held by one daemon process. It cannot be
serialized meaningfully, and copying it would alias it. The Run Authority owns
every such resource for one run. Its type implements neither `Clone` nor
`Serialize`, so a cloned or persisted arena cannot carry authority and every
consumer of a frozen arena must bind its own.

What persists instead is a **resource slot** per resource:

| Field | Meaning |
| --- | --- |
| `slot` | Stable semantic ID such as `(node, role)` or `(run, role)`; never a descriptor number, PID, or host path. |
| `kind` | Closed vocabulary: QEMU process, cgroup, attempt storage root, run directory, shared-memory region, protocol ring, control or QMP endpoint, console endpoint, lock, lease, debug gateway, hot-fork template, QMP snapshot. |
| `recipe` | Deterministic construction inputs: an exact closure target, frozen canonical ring bytes and their protocol role, the launch profile, an immutable backing identity. |
| `expected` | The proof the rebound resource must report: process incarnation and checked generation successor, instruction counter and execution fingerprint, private-ring identity, backing identity. |

Rebinding runs in slot order and is one transaction. It creates each resource
from its recipe, obtains the resource's own report, and compares that report
with the expected proof before any node executes a guest instruction or the run
emits a canonical event. This is the existing restore discipline of
[§05.6](05-hot-fork-and-checkpoints.md#056-child-resource-isolation) through
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) (launch through
exact preparation, counter and fingerprint verification, private-ring
authentication, and generation successor checks) stated once for every
resource class. Slots also give graceful shutdown one place to prove that every
resource was reaped.

A resource slot is a description, not a capability. Persisted bytes alone never
authorize a restore: a restore still requires a promoted root and its replay
claim ([§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure),
[HFORK-16]) and authority issued by the current daemon epoch.

- **[ARENA-10]** Run Authority MUST NOT be cloned, serialized, or included in
  the StateRoot. No persisted arena byte may contain a descriptor number,
  process ID, host path, socket name, daemon epoch, or lease handle.
- **[ARENA-11]** Every authority resource MUST be described by a resource slot
  with a recipe and an expected proof. Rebinding MUST proceed in slot order as
  one all-or-nothing transaction and MUST verify every proof before guest
  execution or canonical event emission. A mismatch MUST fail closed and
  quarantine every resource created by the transaction. A resource slot MUST
  NOT authorize a restore by itself.
- **[ARENA-12]** The Run Authority MUST be the single owner of its resources'
  teardown. Ending a run, including a graceful daemon stop, MUST either reap
  every slot's resource or transfer it to quarantine, and MUST report which.

## 16.5 Run Journal

### One journal, many projections

Each run has one Run Journal. It is the attempt log of
[§15](15-segmented-event-log.md) extended to every consumer: an ordered sequence
of sealed segments followed by one open tail, chained as in
[§15.2](15-segmented-event-log.md#152-attempt-segments), bounded by
[CCOMP-25] through [CCOMP-29]. The scheduler appends to it once per quantum. The
scheduler's own per-quantum segment stream and the daemon's attempt logs merge
into it, so one encoding of each entry exists.

Every current holder of event-log content becomes one of three things: a
**projection** (bounded fold state computed from entries as they are appended),
a **position reference** into the journal, or a **durable placement** of a
sealed segment under its own content ID.

| Today's copy | Under the Run Journal |
| --- | --- |
| Scheduler condition prefix holding every entry | Bounded fold state and open tail ([§15.4](15-segmented-event-log.md#154-bounded-evaluation-state)) |
| Scheduler per-quantum segments in the scenario DAG store | Appends to the journal tail |
| Scheduler checkpoint `condition_entries` | Journal position |
| Modeled driver's retained attempt log | The journal, through the executor's handle |
| Evidence recorder's attempt log | Reference to the journal's sealed segments and fold state |
| Prepared-result journal segments | Durable placement of the same segment IDs ([§15.3](15-segmented-event-log.md#153-retention-bound-and-storage)) |
| Repository trace leaves | Durable placement of the same segment IDs ([CCOMP-29]) |
| Checkpoint closure event-log objects | References to sealed segments plus a journal position |
| Hot-fork continuation's in-memory segment bytes | Journal position plus shared sealed-segment references |
| Session event stream and session actor copies | Bounded tail window; older entries read from sealed segments |
| Per-quantum outcome entry, segment, and text copies | Borrowed views of the batch appended in that quantum |

- **[RJRNL-1]** Each run MUST have exactly one Run Journal with one writer. It
  MUST be the only source of the run's event entries; every other durable copy
  of journal bytes MUST be a placement of one of its sealed segments.
- **[RJRNL-2]** The Run Journal MUST use the segment, chain, sealing, storage,
  and publication rules of [CCOMP-25] through [CCOMP-29]. The scheduler's event
  log and the executor's attempt logs MUST be the same journal with one segment
  encoding.
- **[RJRNL-3]** Every other consumer of event-log content MUST hold a bounded
  projection, a journal position, or a byte-identical durable placement of a
  sealed segment. No consumer may hold a second encoding of entries or a
  complete in-memory copy of the log.

### Positions instead of copies

A checkpoint or hot-fork continuation names where the journal stood, not what
it contained:

```text
JournalPosition
  entry count
  entry-prefix digest
  sealed segment count       # seal boundaries only
  chain hash                 # seal boundaries only
```

An exact closure references the sealed segments covering its position by
content ID, and publication places them before the root as it places every
other closure object. A hot-fork child shares its parent's sealed prefix by
reference and continues its own tail from the fork position. Resume continues
from the position and the bounded fold state ([CCOMP-30], [CMEAS-16]). Capture
cost no longer depends on journal length: sealing the tail at the capture
offset is the only log work a checkpoint performs.

- **[RJRNL-4]** Checkpoints, exact closures, and hot-fork continuations MUST
  reference a journal position and the sealed segments that cover it. They
  MUST NOT copy entries. The log work of a capture MUST be independent of the
  number of sealed segments.

### Sealing at checkpoint and fork offsets

[CCOMP-26] already requires the tail to be sealed at every checkpoint or fork
offset. The current executor does not implement that rule
([§16.14](#1614-known-defects-found-during-the-survey)); the Run Journal depends
on it. A capture position is always a seal boundary, so a checkpoint never
references an open tail, and a forked child's shared prefix is immutable before
the fork transaction begins.

- **[RJRNL-5]** The journal MUST seal its tail at every checkpoint offset and
  every hot-fork offset before freeze completes. A checkpoint or fork position
  MUST be a seal boundary. Seal points MUST remain a pure function of the entry
  sequence and those offsets ([CCOMP-26]).

### Identity-bearing encoding

Three journal values carry identity, each for one purpose.

1. **Canonical entry bytes.** Each entry has one canonical encoding. Segments
   frame those bytes without re-encoding them. Determinism, replay, and
   measurement comparisons compare these bytes ([CCOMP-27]).
2. **Entry-prefix digest.** A running digest over canonical entry bytes:

   ```text
   digest_0 = H("crucible.run-journal.entry-prefix.v1", "empty")
   digest_n = H("crucible.run-journal.entry-prefix.v1", digest_(n-1),
                canonical bytes of entry n)
   ```

   It depends only on entries, never on where segments were sealed, so two
   equivalent realizations that sealed at different offsets agree. It is the
   journal component of the StateRoot and of every position used for
   equivalence, replay targets, and fork pairing. Computing it costs work
   proportional to each appended batch.
3. **Segment chain.** The chain hash of
   [§15.2](15-segmented-event-log.md#152-attempt-segments) identifies a sealed
   log as evidence and authenticates segments in order. It depends on seal
   points, so it never enters the StateRoot.

- **[RJRNL-6]** Journal entries MUST have exactly one canonical encoding, and
  every durable placement of a segment MUST be byte-identical and addressed by
  the same content ID; copying MUST NOT re-encode. Entries MUST NOT contain host
  paths, wall time, daemon epochs, or placement data ([CMOD-2]). Equivalence and
  state identities MUST use the entry-prefix digest; only evidence identities
  MAY use the segment chain. An identity that hashes a vector of retained
  entries MUST be replaced by one that hashes a journal position.

### Readers and retention

Readers follow [CMEAS-22]: they stream sealed segments in order and never
materialize a complete log. The session and debug planes keep a bounded tail
window for live subscribers; a subscriber that falls behind reads sealed
segments by reference. A sealed segment is retained while any retention root
reaches it (a paused or pinned exact root, a prepared result, or a published
trace leaf) and is removed with the run's storage otherwise.

- **[RJRNL-7]** Live tail windows for session, debug, and API subscribers MUST
  be bounded by configuration, independent of run length. A subscriber behind
  the window MUST read sealed segments by reference and MUST NOT cause the
  journal or its projections to retain additional entries.
- **[RJRNL-8]** A sealed segment MUST remain readable while a paused root, a
  pinned or selected exact root, a prepared result, or a published trace leaf
  references it, and MUST otherwise be removed with the run's storage
  ([CCOMP-29]). Liveness MUST derive from those references, never from access
  time ([CSTORE-19]).

## 16.6 Operations over the arena

### Freeze and snapshot

`freeze` checks `unsettled()`, seals the journal at the current offset, and
returns an immutable frozen arena that shares every table with L0. It is the
only capture operation. The exact checkpoint set and the hot-fork continuation
become one frozen arena plus a tier attachment:

```text
FrozenRun
  frozen arena                (L1, shared)
  tier attachment
    Exact(targets)            QEMU RAM layers, device state, overlay artifacts
    Hot(adoptions)            adopted children, disk bases, host-I/O projections
```

### Persist

`persist` encodes the frozen arena's dirty chunks, writes chunks and table
roots to L2, and writes the arena manifest. An exact closure then references
the arena manifest, the journal's sealed segments, and the tier attachment's
QEMU artifacts; L3 publication proceeds root-last as in
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure). The arena
manifest replaces today's nested opaque byte vectors in checkpoint wires
(scheduler state, network state, device state, and the whole-value fault,
trigger, assertion, and lifecycle encodings) with table roots. That replacement
is a closure schema version bump.

### Introspect and diff

A frozen arena is a value. A debugger, status RPC, or offline tool reads it
from another thread without locking the quantum loop. A uniform table catalog
gives one generic browser: list tables, read a key range, decode a chunk. Two
arenas diff by comparing table roots and descending only into differing chunks,
so the cost of a diff is proportional to the difference.

### Restore and adopt

Restore decodes an L3 or L2 manifest into a frozen arena; adopt receives a
frozen arena directly from a hot-fork continuation. Both pass the frozen arena,
its tier attachment, and a fresh Run Authority to one thaw constructor, which
rebinds resource slots ([ARENA-11]) and rebuilds caches.

- **[ARENA-13]** Exactly one freeze operation MUST produce the host continuation
  for both exact capture and hot fork, and exactly one thaw constructor MUST
  consume it for fresh start, exact restore, hot adoption, and debug
  reposition. No field-by-field adapter between continuation representations
  may exist.
- **[ARENA-14]** Introspection and diff MUST read frozen arenas only. They MUST
  NOT block, mutate, or extend the lifetime of resources owned by L0, and their
  cost MUST be proportional to the data read or the difference found.

### Graceful daemon restart

The local executor already supports exact pause: a checkpoint request parks a
running attempt as `paused(root)`, the record survives restart, promotion work
is re-enumerated at startup, and `resume_paused` restores without guest replay.
Shutdown does not use it. Today a stop signal prevents new work and cancels
active attempts, and retained hot sources demote to thin fallbacks.

Graceful restart composes the existing pieces into a checkpoint-drain stop:

```text
stop signal under the checkpoint-drain policy, deadline D
  stop admission
  for each active attempt: request checkpoint      -> checkpoint-requested
    attempt reaches an exact-ready boundary (unsettled() empty)
    freeze, persist to L2, derive the L3 root      -> checkpoint-publishing(root)
    publish the root's closure, root last; durable -> paused(raw)
  attempts not paused by D: cancel                  (operational; resubmitted)
  published-root hot sources: freeze, persist, record exact fallback
  genesis hot sources: discard                      (recaptured at startup)
  reap or quarantine every Run Authority
  exit

startup under a fresh daemon epoch
  open and reconcile the assignment ledger; enumerate promotion work
  promote paused(raw) -> paused(promoted)
  coordinator resubmits; executor reports already-paused; resume_paused
  restore: authenticate root, rebind resource slots, verify proofs, continue
```

The drain is operational. It never writes a campaign pause fact: after restart
the campaign is still running, and the coordinator's ordinary resubmission
finds the paused attempts ([CMOD-2], [LAZY-9], [CCOMP-22]). An attempt that
cannot reach a settled boundary before the deadline, for example one with an
attached debugger, a pending branch choice, or a held host outcome, is canceled
and later re-executed from its origin, which is already the restart behavior.

A retained source from a published root may demote to an exact fallback (an
`ExactCheckpointId` in the hot-checkpoint fallback catalog of
[§06.10](06-storage-replication-and-gc.md#0610-pinning-eviction-and-garbage-collection))
instead of a thin one. After restart it can be restored and, once it passes the
replay oracle ([HFORK-16]), promoted again into a template without replaying
from genesis.

- **[ARENA-15]** The executor SHOULD offer a checkpoint-drain stop mode with an
  operator deadline. It MUST request checkpoints through the ordinary
  checkpoint request path and the ordering of
  [§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service),
  MUST NOT publish a campaign-truth transition, and MUST cancel every attempt
  not durably paused by the deadline. A drained restart MUST NOT change any
  observation, finding, or campaign fact relative to cancel-and-retry.
- **[ARENA-16]** On a checkpoint-drain stop, the executor SHOULD demote retained
  published-root hot sources to exact fallbacks when their roots can be durably
  published before the deadline. A restored source MUST pass [HFORK-16] before
  it becomes a template.
- **[ARENA-17]** A run paused at a quantum boundary, persisted, and resumed in a
  fresh daemon process MUST produce, at every later quantum boundary, the same
  StateRoot as the uninterrupted run, and MUST produce the same observation.

### Restart cost floor

Resume requires a promoted root.
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) makes a raw
root ineligible for resume,
[§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service)
admits resume only from `paused(promoted)`, and [HFORK-16] applies the same
replay oracle before a restored runtime becomes a template. Promotion compares
the raw root's exact snapshot with an independently realized thin path, and for
an executed attempt that thin path replays the attempt's causal prefix. A
graceful restart therefore costs one capture, one full prefix replay, and one
restore per paused attempt. It saves the post-checkpoint guest work that
cancel-and-retry would repeat and keeps result identity stable, but it is not
cheaper than retry in guest time for the prefix.

The Run Arena makes the bookkeeping uniform; it does not remove this floor.
Three options are recorded as
[OQ-9](12-decisions-and-open-questions.md#oq-9-how-should-graceful-restart-pay-the-promotion-replay-floor):
keep the floor; promote incrementally from stride checkpoints taken while the
attempt runs, so a drained root needs only a suffix comparison against a
promoted ancestor (recommended); or accept closures produced by the same daemon
identity without a new comparison. The second and third options change
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) and require an
RFC decision before implementation.

### Migration within the single-host scope

Moving a run between daemon processes on one host is the restart path above.
Moving it between hosts is the offline maintenance transfer of
[§05.10](05-hot-fork-and-checkpoints.md#0510-exact-pause-debugging-and-offline-maintenance-transfer):
the L3 closure, including the arena manifest, chunks, and journal segments,
moves as authenticated logical objects reachable from its root
([CSTORE-17]). The assignment ledger is local and is not transferred, so a
paused attempt is re-executed at the destination unless a later decision makes
paused roots transferable.

- **[ARENA-18]** Run state MUST cross a process or host boundary only as an
  authenticated L3 closure or as an L2 manifest read by the same executor, under
  [HFORK-17] and [HFORK-18]. Live migration, remote paging, and transferring Run
  Authority are not supported.

## 16.7 Campaign Arena

Campaign truth already has one root: the campaign ref names an immutable
snapshot whose Merkle collections share structure across snapshots. What has no
root is the executor's operational state about that campaign. The Campaign
Arena starts as a read-only view that joins it:

| Source | Joined as | Survives restart |
| --- | --- | --- |
| Campaign ref and snapshot | Head, lineage, semantic pins | Yes |
| Assignment ledger | Attempt states, including paused and promoting roots | Yes |
| Exact-pin materialization journal and hot-checkpoint fallback catalog | Retained exact and thin fallbacks | Yes |
| Hot-fork source pool | Live templates and their fallbacks | No |
| Prepared-result journals | Results awaiting publication | Yes |
| Run Journals | Per-attempt positions and sealed segment sets | As [§15.3](15-segmented-event-log.md#153-retention-bound-and-storage) and [RJRNL-8] state |

The view answers operational questions in one place: what is resumable, what is
pinned and why, which roots the next GC plan will retain, and what a restart
would lose. It writes nothing.

Later, the assignment ledger and the run journals' operational indexes may move
into Campaign Arena tables, so that the executor's operational state is one
versioned structure rather than several directory formats. When that happens
is recorded as
[OQ-10](12-decisions-and-open-questions.md#oq-10-when-should-the-ledger-and-journals-move-into-campaign-arena-tables).
Garbage collection does not change: liveness remains reachability from
authenticated retained roots ([CSTORE-19]).

- **[ARENA-19]** The Campaign Arena view MUST be derived only from the sources it
  joins and MUST NOT be a source of truth. Deleting it MUST change no campaign,
  executor, or GC decision ([LAZY-2], [CCOMP-22]).
- **[ARENA-20]** Moving operational records into Campaign Arena tables MUST
  preserve the durable ordering of
  [§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service)
  (request before signal, `checkpoint-publishing(root)` before the first
  campaign-store write, `paused` only after durable placement, capacity release
  last) and the crash recovery of
  [§04a.8](04a-coordinator-executor-contract.md#04a8-recovery-and-conformance).
  Spill-cache entries MUST NOT be GC roots.

## 16.8 Process and license boundary

The arena is Apache host code. QEMU guest RAM, device VMState, root overlays,
persistent fault rules, and execution fingerprints stay inside the GPL-side
process and reach the host only through the versioned snapshot and control
protocols. The arena refers to them by content ID inside a tier attachment and
never parses them, exactly as
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) already
requires of storage code. Ring and region-header snapshots are public protocol
data and may appear in host tables as such. The arena itself is never placed in
shared memory.

- **[ARENA-21]** Run Arena and Campaign Arena code MUST NOT link QEMU, include
  QEMU headers, or store QEMU-private structures, native pointers, callback
  tables, or Rust-native layouts in any table, chunk, or manifest. QEMU state
  MUST appear only as opaque artifacts referenced by content ID, and nothing may
  cross the process boundary except the versioned socket and shared-memory
  protocols.

## 16.9 Determinism and identity

The arena is a realization mechanism. It inherits every identity rule in
[§05.1](05-hot-fork-and-checkpoints.md#051-three-realization-tiers): tiers and
layers are caches ([HFORK-1], [HFORK-2], [HFORK-19]), materialization choice is
executor-owned ([CCOMP-3]), and the campaign product does not depend on where
or how an attempt ran ([CCOMP-21]).

The StateRoot gives those rules an executable check. A thin replay, an exact
restore, and a hot child of the same boundary must reach equal StateRoots, and
a resumed run must reproduce the uninterrupted run's StateRoot sequence. Once
the StateRoot exists, it is the natural host continuation digest for template
identity ([HFORK-7]) and child pairing ([HFORK-11]); adopting it there is a
template schema version bump.

Formats follow [CSEC-9] and [CSEC-10]. Each arena manifest, table schema,
chunk encoding, and journal encoding has one current version and a
current-only decoder, so every format change is a version bump and old objects
are not rewritten. Each format receives its schema-registry row when its
implementation lands.

- **[ARENA-22]** For every supported checkpoint fixture, thin replay, exact
  restore, and a hot child of the same boundary MUST produce equal StateRoots.
  A mismatch is a correctness failure ([CPERF-7]).
- **[ARENA-23]** Observations, findings, and campaign facts MUST be identical
  whether a run used a retained hot world, an exact closure, thin replay, any
  layer, or any spill placement.
- **[ARENA-24]** Every arena manifest, table schema, chunk encoding, and journal
  encoding MUST carry an explicit version with a current-only decoder. A change
  to any of them MUST be a version bump.

## 16.10 Storage technology

The arena is built in this repository on safe Rust. The design rules below
follow from the workspace's `unsafe` policy, the hermetic build, and the
identity rules above. Named libraries are examples of a category, not
endorsements.

- **Persistent ordered collections for hot tables.** A persistent B-tree map
  (for example `imbl::OrdMap`) gives constant-time clone and path-copy updates
  with values shared across threads. Hash-ordered variants are excluded because
  their order depends on the hasher. Node shapes of a balanced persistent tree
  depend on operation history, so identity never comes from tree nodes: it
  comes from the canonical chunks of [§16.3](#163-run-arena-model).
- **Chunked tables over the existing content store.** Sealed chunks are
  ordinary content-addressed objects, reusing envelope, verification, tiering,
  transfer, and GC.
- **An optional evicting spill backend behind a trait.** Today's store tiers do
  not evict. A local cache that evicts clean, already persisted chunks may use a
  pure-Rust embedded store (for example redb or fjall) behind a narrow trait.
  Replacing or deleting the backend changes no logical byte.
- **No mmap stores.** Memory-mapped database environments (LMDB-style stores)
  require `unsafe` at the call site and a C dependency, and make physical layout
  part of the state. They are excluded.
- **Not an ECS.** Entity-component stores mutate in place, so a snapshot is a
  full copy, and their entity IDs are world-local and remapped on load. Their
  uniform tables, registries, and change ticks inform the design; the crates do
  not fit it.
- **Not a key-value store as the arena.** Embedded key-value stores provide
  durability and rollback savepoints but not cheap writable forks, and their
  checksums are layout-bound, so identity would be computed twice. They fit only
  as the spill backend above.

- **[ARENA-25]** Arena storage MUST be implemented without `unsafe` code in
  arena crates and without memory-mapped or C/C++ storage engines. A spill
  backend MUST sit behind a trait and MUST NOT affect logical bytes, identities,
  or results; deleting its contents MUST be equivalent to a cache miss.

## 16.11 Relationship to resource-cap conversion

The resource-cap conversion work removes caps that end long attempts because
run-length data is held in memory. The arena is the general form of that
conversion. A growing buffered list becomes a chunked table whose sealed chunks
spill; a buffered copy of event-log content becomes a journal projection or
position. The limits that remain are storage limits, which are operational in
the sense of [CCOMP-28]: exhausting them ends the attempt as an operational
failure, never as a policy result or finding ([CSEC-12]).

- **[ARENA-26]** No host component may bound a run by the in-memory size of
  state that grows with run length. Such state MUST be a chunked table or a
  journal projection, and any remaining bound MUST be an operational storage
  limit that does not enter identity or policy.

## 16.12 Staged implementation

Each step is independently useful and leaves the tree consistent. Tasks are in
[§11.12](11-implementation-plan.md#1112-phase-10--run-arena-and-run-journal).

| Step | Task | Change | Value on its own | Gates |
| --- | --- | --- | --- | --- |
| 1 | T-CAM-10.1 | Replace whole-value clones of the scheduler, fault runtime, network effect state, and device trees with structurally shared values | Per-quantum work stops growing with the run | `gate:campaign-performance`, `gate:host-clone-cost` |
| 2 | T-CAM-10.2 | Split the lifecycle loop into arena, authority, caches, and transients; add `freeze_run_arena()` and `unsettled()`; delete the duplicated capture paths and the field-by-field adapter, keeping version-nine bytes unchanged | One place to add a host field; one refusal predicate | `gate:hot-fork-equivalence`, `gate:exact-closure-streaming` |
| 3 | T-CAM-10.3 | Unify scheduler and attempt logs into the Run Journal; seal at checkpoint and fork offsets; checkpoints reference positions | Capture independent of log length; [CCOMP-26] met | `gate:campaign-replay`, `gate:content-address`, `gate:campaign-cold-continuity` |
| 4 | T-CAM-10.4 | Typed tables, write barriers, chunked tables, canonical chunks, StateRoot | Incremental persist; executable equivalence checks | `gate:content-address`, `gate:hot-fork-equivalence` |
| 5 | T-CAM-10.5 | Arena manifest replaces nested opaque blobs in checkpoint wires (closure version bump) | Persist cost proportional to dirty chunks | `gate:exact-closure-streaming`, `gate:campaign-store-composition` |
| 6 | T-CAM-10.6 | Run Authority with resource slots; one rebind transaction | Uniform restore checks; provable reaping | `gate:hot-fork-isolation`, `gate:campaign-operational-continuity` |
| 7 | T-CAM-10.7 | Evicting spill cache; read-only Campaign Arena view | Bounded resident memory; one operational status view | `gate:campaign-store-composition`, `gate:campaign-cold-continuity` |
| 8 | T-CAM-10.8 | Checkpoint-drain stop, exact hot-source demotion, promotion-only resume admission | Graceful restart without losing running work | `gate:campaign-operational-continuity`, `gate:campaign-component-contract` |

Two test contracts are added to existing gates:

- **Restart equivalence**, in `gate:campaign-operational-continuity`: run a
  fixture to quantum `k`, pause, persist, stop the daemon, resume in a fresh
  process, and compare the StateRoot at every later quantum boundary and the
  final observation with an uninterrupted run of the same attempt
  ([ARENA-17]). The test repeats for several `k`, including a boundary inside a
  long phase after a deep branch point.
- **Tier root equality**, in `gate:hot-fork-equivalence`: extend the
  [§10.8](10-performance-and-validation.md#108-equivalence-matrix) matrix so
  every path also compares StateRoots ([ARENA-22]), including a hot child of an
  exact-restore-created template.

The performance gates check flat resident memory and per-quantum time over a
long-horizon attempt ([CPERF-10]) and persist bytes proportional to dirty
chunks. The license and ABI gates cover [ARENA-21] unchanged.

## 16.13 Non-goals

- Multi-host scheduling, placement, live migration, and remote paging remain
  outside this RFC ([CCOMP-5]).
- Restart never changes campaign truth. A drained restart writes no campaign
  fact and changes no observation.
- The arena does not replace campaign snapshots, the campaign store, or exact
  closures as the portable interchange
  ([D-16](12-decisions-and-open-questions.md#d-16-exact-checkpoint-closures-remain-the-portable-interchange)).
  It changes their host-side producer and the encoding inside a closure.
- The arena does not change configuration identity, the replay oracle, or the
  requirement that persisted bytes alone cannot authorize a restore.
- Session and debugger state that today lives only in memory gains no restart
  semantics here. A graceful restart ends attached sessions unless they are
  detached and captured first.

## 16.14 Known defects found during the survey

The survey behind this chapter found the following defects. Each is tracked by
a task; none is fixed by this chapter.

| Defect | Where | Tracking |
| --- | --- | --- |
| Resume admission accepts an unpromoted paused root. `resume_after_validation` accepts any `Paused` record with a matching basis and does not check promotion, contrary to the `paused(promoted)` rule of [§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service); the raw root is rejected only later by the worker. | `crates/crucible-daemon/src/executor_supervisor/admission.rs`, `crates/crucible-daemon/src/qemu_campaign_resume.rs` | T-CAM-10.8 |
| [CCOMP-26] sealing at checkpoint and fork offsets is not implemented. The attempt log seals only at its size target and at the attempt stop, and the checkpoint path drops the driver's retained log. | `crates/crucible-daemon/src/attempt_event_log.rs`, `crates/crucible-daemon/src/qemu_campaign_driver.rs` | T-CAM-10.3 |
| The demanded exact hot-fork source path appears unreachable. The hot-first router tries hot fork only when the attempt has no resume checkpoint, while the world factory derives the exact-checkpoint source key only when it has one. | `crates/crucible-daemon/src/qemu_hot_first_router.rs`, `crates/crucible-daemon/src/qemu_hot_fork_world_factory.rs` | T-CAM-10.9 |
| The packaged executor deletes `run-state.json` unread. Startup retires the `campaign-workers` namespace and seven others, so orphan quarantine from the prior run's process journal never runs for packaged lifecycles; containment relies on fail-closed cgroup and attempt-storage root checks. | `crates/crucible-daemon/src/packaged_qemu_executor.rs` | T-CAM-10.6 |
| Production debug goto replays from genesis twice, contrary to restore-nearest-then-replay ([DBG-14]), and debug runtime evidence grows without a cap. | `crates/crucible-api/src/vm_lifecycle/runtime.rs` | T-CAM-10.9 |
| Stale RFC numbers. [§05.5](05-hot-fork-and-checkpoints.md#055-control-protocol) names hot-fork template schema 29, and §04a names template schema 29, resource-stage schema 13, and fork schema 3, where the code uses 30, 14, and 4. §04a describes attempt-state record v11 as the format that persists the execution scope, where the code and schema registry use v15. [§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) names two retired namespaces and says baked genesis is not retired, while the packaged executor retires eight namespaces including baked genesis. | This RFC | T-CAM-10.9 |

[DBG-14]: ../0010-crucible/36-time-travel-debugging.md
