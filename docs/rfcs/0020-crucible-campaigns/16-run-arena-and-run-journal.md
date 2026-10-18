# 16 — Run Arena and Run Journal

A campaign attempt is one deterministic run of a QEMU world under the host
scheduler. Everything the host knows about that run, apart from guest memory
and device state, lives in host processes. This chapter defines one owner for
that state, the **Run Arena**, and one owner for the run's event history, the
**Run Journal**. [§16a](16a-run-authority-and-restart.md) defines the Run
Authority that owns the run's live operating-system resources, graceful
restart, migration, the spill cache, and the **Campaign Arena**, a
campaign-level view over the executor's operational records.

The chapter builds on [§05](05-hot-fork-and-checkpoints.md) (realization tiers,
host continuation cloning, and the exact closure) and on
[§15](15-segmented-event-log.md) (segmented attempt logs, bounded evaluation,
and the segmented trace, schedule, scheduler-log, and block-overlay forms of
§15.10 through §15.14). It does not change configuration identity, campaign
truth, the realization-tier model, or the process boundary. It changes how the
host owns, shares, persists, and restores run state so that hot fork, exact
checkpoint, pause, graceful restart, debugging, and introspection are
operations over one structure rather than separate gatherers over many.

Code references name repository-relative paths and symbols as surveyed at the
time of writing; they locate today's behavior and are not normative.

## 16.1 Problem

No root object owns a run's state. Each consequence below follows from that.

**The lifecycle loop mixes five kinds of state.** `ProductionVmLifecycleLoop`
(`crates/crucible-api/src/vm_lifecycle.rs`) is the closest thing to a run root.
It has fifty-five direct fields. They mix modeled continuation (trigger,
assertion, fault, and lifecycle state), immutable run inputs (the scenario, its
source form, and the lifecycle configuration), live operating-system authority
(node leases, launchers, run directories, lock and journal owners, hot-fork
backing files, live block devices), derived caches (the lowered trigger graph,
node indexes, launch configurations), and transients that must be empty before
any capture (pending network prefixes, held host outcomes, unapplied branch
continuations). Its `inner` field, a `BackendQuantumLoop` over the scheduler,
the live `QemuNodeSet`, and the fault and network interceptor, nests every one
of those kinds again: modeled host-I/O state and sequence counters live inside
each `QemuNode`, an authority object. The fault runtime, the storage
observations, the interceptor cursor, and the live block devices are shared
between owners through `Arc<Mutex<_>>` handles. Nothing in the types
distinguishes the kinds.

**One field set exists as five types, filled by hand at seven sites.** The
in-memory exact checkpoint set (`ProductionVmExactCheckpointSet`), the hot-fork
world continuation (`ProductionVmHotForkWorldContinuation`), the hot-fork
restore parts (`ProductionVmHotForkRestoreParts`), the native version-eleven
closure wire (`ClosureManifest`, `ClosureObjects`, and `LifecycleWire` in
`crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs`), and
`ExactCheckpointClosureRecord` (`crates/crucible/src/exact_checkpoint.rs`),
which re-declares the same manifest schema in a second crate, all describe
the same host continuation. Seven production sites fill them field by field:
the two captures (`capture_reserved_exact_checkpoint_set` and
`capture_hot_fork_world_continuation`), the branch clone
(`try_clone_for_branch`), the `into_restore_parts` adapter, the native and
campaign-root closure decoders, and the closure encoder (`encode_lifecycle`
with its manifest construction). The restore constructor
`build_production_vm_lifecycle_loop_with_restore`
(`crates/crucible-api/src/vm_lifecycle/construction.rs`) is already the single
consumer for fresh start, exact restore, hot adoption, and debug replay, but it
consumes the set field by field across about 1,400 lines. Adding one
host-model field means editing all of them; missing one breaks [HFORK-11]
pairing or fat/thin equivalence.

**Per-attempt daemon state has no owner.** For one attempt the daemon keeps
state in the supervisor's queued and active entries, the modeled driver's stack
frame (retained log, choices, frontier), a per-worker evidence recorder behind a
mutex, the lifecycle loop, and these directories:

| Holder | Location | Survives restart |
| --- | --- | --- |
| Assignment ledger | `<state>/executor-ledger/` | Yes |
| Prepared-result journals | `<run-state>/campaign-prepared-results/` | Yes, reconciled at startup |
| Driver and observer attempt logs | `<run-state>/campaign-attempt-event-logs/` | No, retired at startup |
| Native exact catalog and scheduler segment store | `<run-state>/campaign-workers/worker-NNN/<scenario>/` | No, retired at startup |
| Exact-checkpoint roots and closure objects | Campaign store | Yes |
| Exact-pin materialization journal | `<state>/exact-pin-materializations` | Yes |
| Hot-checkpoint fallback catalog | `<state>/hot-checkpoint-fallbacks` | Yes |
| Hot-fork source pool | Memory, plus `campaign-hot-fork-sources` and `-demanded` | No |

**Event-log content has two encodings and three identities.** [§15.12](15-segmented-event-log.md#1512-scheduler-continuation-log)
already moved the scheduler continuation to sealed-segment references plus an
open tail and sealed the session views into the scheduler's segment store. What
remains:

- The scheduler writes a non-decodable per-append segment ([OBS-20]) for every
  append and chains it into `EventLogOffset` ([OBS-17]); the per-quantum
  outcome also carries the appended bytes and a text view.
- The scheduler, the driver, the observer, and the session views each seal
  byte-identical attempt segments, by size, into different stores under
  different identities: a bare BLAKE3 `ContentHash` in the scheduler store and
  the native catalog, `ContentId(Trace, 1)` in attempt storage, prepared-result
  journals, and trace leaves, and `ContentId(DeviceState, _)` at the campaign
  root.
- The condition prefix still holds every entry, and restore refolds it from
  every segment.
- Exact resume and hot-fork start copy the whole retained log into memory
  (`resume_state`) and re-seal it into a new attempt directory; automatic
  finding capture collects complete logs (`complete_log`).
- Durable closure publication re-hashes every segment already present at L2
  and re-derives each segment's identity at L3 by reading it.
- Savepoint and observation proofs hash the entry count before the entries, so
  every proof rescans the whole log.
- Both captures read every referenced resolved-effect trace segment into a
  resident map (`capture_fault_trace_objects`).

Capture therefore remains O(total log) in I/O and O(trace) in memory, contrary
to [HFORK-15] and [CMEAS-28].

**Atomicity is implemented by whole-value clones.** The scheduler is
`#[derive(Clone)]` and is staged by whole clones on every host-concurrent
quantum, every RUN admission (retained as the admission `source`), I/O
inventory import, fixed-input preparation and validation, every input,
dispatch, and cap boundary, device-group and external selection, every
network-output batch (`crates/crucible-api/src/vm_lifecycle/network_faults/route.rs`),
and every signal-fault boundary. Fixed-input and device-group validation also
compare full canonical checkpoint encodings. `History` clones cost O(1), but
its sealed-chunk index is one flat vector, so every seal while another clone
shares it copies the whole index. Still copied in full on each clone: trigger
action vectors, the fault runtime's issued and committed QEMU action ledgers
and trace tail (on every coordinated 9p step), and the 9p `FsTree` with its file
contents (on every 9p request). Every scheduler checkpoint encodes the whole
schedule and six history ledgers, including `ceiling_publications`, which grows
on every RUN publication. Per-quantum work therefore grows with elapsed
virtual time ([CPERF-10]).

**Caps exist because run-length data is resident.** Many resource caps in the
host exist only because a structure whose size is proportional to the run is
held whole in memory or encoded as one object. [§15](15-segmented-event-log.md)
removed the whole-log bound for the attempt log and the whole-trace and
whole-schedule bounds; the same shape remains in scheduler ledgers, fault
action ledgers, recorded controls, debug evidence, and the checkpoint wires
that nest them as opaque byte vectors.

## 16.2 Vocabulary

| Term | Meaning |
| --- | --- |
| **Run** | One execution incarnation of an attempt. A fresh execution, an exact resume, and a hot-fork child each start a new run with its own Run Arena, Run Authority, and Run Journal handle; a resumed or forked run's journal continues from the inherited position. |
| **Run Arena** | The single owner of one run's modeled host-side state: a set of typed tables plus a position in the Run Journal. |
| **Run Inputs** | Immutable values a run is constructed from (scenario, source form, configuration, authored artifacts). They are covered by scenario and configuration identity, referenced by a frozen run, and excluded from the StateRoot. |
| **Campaign Arena** | A campaign-scoped, read-only view joining the campaign ref, the executor's operational records, and the runs' journals ([§16a.8](16a-run-authority-and-restart.md#16a8-campaign-arena)). |
| **Run Journal** | The single append-only, segmented event journal of one run. Every other holder of event-log content is a projection of it, a position in it, or a placement of one of its sealed segments. Other "journals" (prepared-result, lifecycle, materialization, authority) are always named in full. |
| **Projection** | Bounded fold state computed from journal entries as they are appended. |
| **Table** | One typed, versioned collection inside a Run Arena, keyed by stable semantic keys and owned by one subsystem. |
| **Hot table** | A table held as a persistent collection with structural sharing, cloned in constant time. |
| **Chunked table** | A table of append-growing records stored as immutable content-addressed chunks plus one open chunk; sealed chunks may spill. |
| **Layer** | One representation of a frozen arena: L0 live, L1 frozen in memory, L2 native catalog and spill cache, L3 campaign store root. |
| **Frozen arena** | An immutable L1 value produced by `freeze`. Hot-fork continuations, exact capture, and introspection consume it. |
| **Settled boundary** | A quantum boundary at which `unsettled(persist)` reports no reason. |
| **StateRoot** | The Merkle root over the canonical logical encoding of an arena's tables and its journal entry prefix, defined only at settled boundaries. It identifies host model state for verification; it is not a configuration identity. |
| **Journal position** | The coordinates of a point in a Run Journal: entry count and entry-prefix digest, plus the sealed-prefix coordinates and the open tail when the position is a capture. |
| **Seal receipt** | The durable record, written by the executor segment store after a segment is synchronized, that binds a segment's content ID to its length. |
| **Run Authority** | The non-serializable owner of a run's live operating-system resources ([§16a.1](16a-run-authority-and-restart.md#16a1-run-authority-and-resource-slots)). |
| **Resource slot** | The serializable description of one authority resource: a stable slot ID, a kind, a mode, dependencies, a recipe, and the proof it must report after rebinding. |
| **Unsettled state** | Transient run state that blocks freezing for a given purpose. |
| **Tier attachment** | The tier-specific half of a frozen run: QEMU artifact references and expected proofs for an exact target, or adopted children and host-I/O projections for a hot fork. |

## 16.3 Run Arena model

### Tables and collections

A Run Arena is a manifest plus a fixed catalog of tables. Each table belongs to
one subsystem and has a stable table ID, a schema version, and a key type made
of semantic identities such as `NodeId`, `LinkId`, an event sequence number,
or a declared property leaf. Keys never encode allocation history, process
identities, or memory addresses. When a subsystem allocates counters or
generational indexes that affect results, the allocator state is itself a
table entry.

Two storage shapes cover the catalog:

- **Hot tables** hold state touched every quantum and bounded by the scenario:
  scheduler queues and cursors, network link state, fault evaluator state,
  trigger and assertion folds, and per-node continuations. They use the
  persistent collections of [§16.9](#169-storage-technology), so a clone shares
  every node and an update copies only the path to the changed entry.
- **Chunked tables** hold records that grow with the run: scheduler
  application ledgers, issued and committed fault actions, recorded controls,
  storage observations, and campaign effect records. Records append to one
  open chunk. A full chunk is sealed, encoded canonically, addressed by
  content, and may be evicted from memory and reloaded by its content ID.

Tables whose records already have a segmented form reuse it rather than chunk
the same records a second time: the schedule table is the [CCOMP-32] schedule
segments, the fault-trace table is the [CCOMP-31] trace segments, and the block
overlay inside the host-I/O table is the [CCOMP-39] chunks. The chunking rule
below applies only to tables without an existing segment schema.

Every table has a write barrier. Mutation through the table API records the
dirty key or chunk index; there is no other mutation path. Persisting a frozen
arena encodes only dirty chunks and recomputes only the affected Merkle paths.
An untouched table reuses its previous root.

The initial catalog follows. T-CAM-10.4 fixes it from the field
classification of [§16.4](#164-splitting-the-lifecycle-loop).

```text
Table                 Today's owner                                  Shape
schedule              Configuration schedule                          CCOMP-32 segments
scheduler-core        SingleScheduler frontier, queues, cursors,      hot
                      committed frontier, selectable catalog plans
scheduler-ledgers     subdivision, preemption, control, topology,     chunked
                      rendezvous, and ceiling records
trigger-actions       applications, savepoints, forks, diagnostics    chunked
network               links, link RNG positions, effect state,        hot
                      campaign log, interceptor cursor
fault                 fault evaluator, adapters, host action state,   hot
                      referenced-event window (CMEAS-26)
fault-actions         issued and committed QEMU actions               chunked
fault-trace           resolved-effect trace                           CCOMP-31 segments
storage-observations  storage fault observation journal               chunked
trigger               event-graph state                               hot
assertion             obligations, marker state, named-leaf folds     hot
lifecycle             terminal verdict, branch, service states        hot
recorded-controls     applied lifecycle controls                      chunked
host-io               per-node block, 9p, accelerator continuations;  hot (block overlay:
                      block overlay chunks                            CCOMP-39 chunks)
node-continuation     per-node time, console, ring snapshots,         hot
                      fault and network-output sequence counters
failed-nodes          process-free host-I/O state of failed nodes     hot
```

- **[ARENA-1]** Every piece of host-side state reachable from a run MUST be
  classified as exactly one of: Run Arena table content, Run Inputs, Run
  Authority, a cache rebuilt from the arena, the inputs, or the tier
  attachment, or unsettled state. Modeled state MUST live only in Run Arena
  tables. No component outside the arena may retain an independent mutable copy
  of modeled state; staging and rollback copies MUST be arena clones. Modeled
  state MUST NOT be reachable through shared interior-mutable handles, and a
  frozen arena MUST NOT observe any later L0 mutation. The classification MUST
  be enforced by a test that fails when a field is added without one.
- **[ARENA-2]** A table MUST have a stable table ID, a registered schema
  version, and keys made of semantic identities. Iteration order, encoded
  bytes, and results MUST NOT depend on hash order, allocation history, pointer
  identity, or reference counts; pointer equality and generation tokens MAY
  serve only as shortcuts that return the same answer as a full comparison.
- **[ARENA-3]** Cloning a Run Arena or any table MUST cost O(number of tables)
  independent of table contents. A per-quantum or per-boundary update MUST cost
  time proportional to the entries it touches. Atomic multi-table updates MUST
  stage on a clone and commit by replacing the arena value, never by deep
  copying and swapping subsystem state. This refines [CPERF-10] for staging and
  rollback copies.
- **[ARENA-4]** State that grows with run length MUST be a chunked table or a
  reused segmented form. Sealed chunks MUST be immutable and content-addressed.
  Resident memory for a chunked table MUST be bounded by its open chunk plus the
  executor's configured residency budget. An evicted chunk MUST be reloaded and
  authenticated by its content ID before use, and eviction MUST NOT change any
  result.
- **[ARENA-5]** Every table MUST record mutations through a write barrier,
  relative to a per-table base root ([dirty tracking](#dirty-tracking-baseline)).
  Persisting a frozen arena MUST encode only chunks dirty against that base and
  recompute only the Merkle paths above them, so persist cost is proportional
  to changed state. A full re-encode, such as the first persist of a run, a
  persist whose base chunks are unavailable, or a persist after a schema change,
  is correct but MUST be reported, as [HFORK-15] requires for full capture.

### Layers

A run's arena has four representations. L1 and L2 are faster caches of L3, and
thin replay remains the source of truth ([HFORK-2]).

| Layer | Name | Contents | Present today as | Lifetime |
| --- | --- | --- | --- | --- |
| **L0** | Live | The mutable arena owned by the run's single writer | The lifecycle loop's fields | The execution |
| **L1** | Frozen in memory | Immutable, structurally shared frozen arenas | Hot-fork world continuation and retained source pool | Daemon process |
| **L2** | Native catalog and spill | Encoded chunks, table nodes, and arena manifests in executor-owned local storage | Native exact catalog | Until retired by the executor; the packaged executor retires it at startup |
| **L3** | Campaign store root | The arena manifest and chunks reachable from an exact-checkpoint root in the campaign store | Version-five exact-checkpoint root | While a retention root reaches it |

L0 to L1 is `freeze`. L1 to L2 is `persist`. L2 to L3 is the existing
root-last publication of [§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure).
Restore runs the other way: L3 or L2 objects decode into an L1 frozen arena,
and thawing it under a fresh Run Authority produces L0. Because the packaged
executor retires its native namespaces at startup, only L3 carries a run across
a daemon restart.

- **[ARENA-6]** L1 and L2 are caches. Deleting every L1 value and every L2
  object MUST NOT lose state that cannot be recovered from an L3 root or by
  thin replay, and MUST leave the campaign recoverable ([CCOMP-22]). The layer
  from which a run was materialized MUST NOT enter any identity, observation,
  or result.

### Canonical codec, chunking, and StateRoot

Every table has exactly one canonical encoding per schema version. That
encoding serves persistence, comparison, identity, and transfer; there is no
second debug or transport encoding of the same state. Table chunks are encoded
in key order, use explicit integer widths, contain no native floating point
(invariant 7), and are rejected on decode unless re-encoding reproduces the
same bytes ([CSTORE-13]).

**Hash.** `H(tag, f1, ..., fn)` is BLAKE3 over `u64be(len(tag)) || tag`
followed by `u64be(len(fi)) || fi` for each field in order. Tags are ASCII
domain strings with a version suffix; integers are encoded as fixed-width
big-endian fields before length prefixing. No arena hash concatenates fields
without lengths.

**Chunk IDs.** A sealed chunk is an object in the content store's
`merkle-node` kind under the registered schema `crucible.run-arena.chunk`, so
its identity is `ContentId(MerkleNode, chunk schema version, canonical chunk
bytes)` and it reuses the store's envelope, verification, tiering, transfer,
and GC. Interior table-tree nodes use the same kind under
`crucible.run-arena.table-node`. Manifests and closures name chunks and nodes
by `ContentId`, never by a bare `ContentHash`.

**Chunk boundaries** are a pure function of the table's logical content:

- An **append-only** table seals its open chunk before an append would make it
  exceed the table schema's record count `n` or encoded byte target `B`
  (defaults 1,024 records and 1 MiB). A record whose encoding exceeds `B` fails
  the run closed. Boundaries therefore depend only on the record sequence, as
  segment seals do ([CCOMP-26]).
- A **keyed** table places a boundary after record `r` when the low `k` bits of
  `H("crucible.run-arena.cdc.v1", canonical key bytes of r)` are zero, with
  `k = 6`, at least 16 and at most 1,024 records per chunk, and a forced
  boundary before a chunk would exceed `B`. Boundaries depend on keys, not
  values, so updating a value moves no boundary unless it crosses `B`.

Two arenas with equal logical content therefore have equal chunks, whatever
sequence of inserts, removals, evictions, and reloads produced them.

**Table roots** are Merkle trees over chunk descriptors, so an update
recomputes one path rather than hashing every descriptor:

```text
descriptor      (first key, record count, encoded bytes, chunk ID)
leaf level      descriptors in key order
append-only     fixed fanout 64: node = H("crucible.run-arena.table-node.v1",
                level, ordered [(first key, record count, child hash)])
keyed           content-defined: a node closes after a child whose hash has
                its low 4 bits zero, with 4 to 64 children per node
table root      H("crucible.run-arena.table.v1", table ID, schema version,
                record count, top node hash or H(tag, "empty"))
reused stream   H("crucible.run-arena.table.v1", table ID, schema version,
                existing identity)   # schedule content hash; trace chain and
                                     # counters; block chunk identities and bitmaps
StateRoot       H("crucible.run-arena.state-root.v1", arena schema version,
                configuration ID, journal entry count, entry-prefix digest,
                ordered [(table ID, table root)])
```

Appending to an append-only table changes only the right spine of its tree;
updating a keyed table changes the path from the chunk to the root and, at
most, the neighbors a moved boundary touches.

The StateRoot commits to host model state and to the journal position through
the segmentation-independent entry-prefix digest of
[§16.5](#165-run-journal). It is defined only at settled boundaries: at an
unsettled boundary some state is transient, and computing a root there would
either include transients or describe state the run cannot freeze. Guest-state
equality across tiers remains the job of execution fingerprints
([§10.8](10-performance-and-validation.md#108-equivalence-matrix)).

The following values vary between equivalent realizations of one boundary and
are stripped from every StateRoot input:

1. process generations (`node_generations` and adopted generation successors);
2. host-I/O and node-continuation execution bindings (`execution_binding` in
   `QemuHostIoCheckpoint` and `QemuNodeContinuationCheckpoint`);
3. segment chain fields: the per-append offset chain (`prefix`,
   `appended_segment`), sealed segment references, chain hashes, and
   `base_events`, all replaced by the entry count and entry-prefix digest;
4. process-local owner identities such as the fault runtime's
   `lifecycle_owner_instance`;
5. QEMU artifact identities, Run Authority, caches, the layer, and debug state;
6. pending verification by the StateRoot v0 probe: the fault runtime's QEMU
   fault command and event sequences and execution fingerprints, and
   `logical_time_calibration`. Each is kept in the root only if the probe shows
   it equal across tiers, and otherwise moves to the tier attachment's expected
   proof.

The **StateRoot v0 probe** precedes any StateRoot gate. It digests the existing
canonical subsystem encodings, with the strip list applied, together with the
entry-prefix digest, and the [§10.8](10-performance-and-validation.md#108-equivalence-matrix)
matrix records it as an observation on every path. A difference between tiers
names a tier-variant field to strip or move. StateRoot comparison becomes a
failing check only once the probe reports no variance on every fixture.

- **[ARENA-7]** Each table schema version MUST define exactly one canonical
  encoding. Decoders MUST reject noncanonical bytes. Identity-bearing encodings
  MUST NOT use JSON, native floating point, or maps ordered by hash. Chunk
  boundaries MUST be a pure function of the table's logical content under the
  rules above, and a table whose records already have a segmented form MUST
  reuse that form and its identities.
- **[ARENA-8]** The StateRoot MUST be computed with the hash, tree, and strip
  list above over canonical logical encodings only, and only at settled
  boundaries. Two arenas with equal logical tables and equal journal entry
  prefixes MUST have equal StateRoots, independent of mutation history, chunk
  residency, spill placement, layer, and realization tier. The StateRoot MUST
  NOT include Run Authority, caches, realization generations, execution
  bindings, segment boundaries, or QEMU artifact identities. It is a
  verification identity: it MUST NOT enter a `ConfigurationId`, a campaign
  fact, or a planner input. No StateRoot comparison may fail a gate before the
  v0 probe reports no tier variance.

### Dirty tracking baseline

Dirtiness is measured against a per-table **base root**: the root of the
table's last persisted state that the run can still reference. A fresh run
starts with empty bases. Persist advances each base to the root it wrote. A
hot-fork child inherits its parent's bases, whose chunks live in the executor
chunk store shared by both runs, so the child's first persist writes only what
the child changed. An exact restore takes its bases from the loaded manifest.
When a base's chunks are no longer readable, for example because the native
catalog was retired, the next persist re-encodes that table in full and
reports it ([ARENA-5]). An exact closure names its parent arena manifest so its
object inventory is a delta, as `ExactRamManifest.parent_closure` already does
for RAM.

### Transitional opaque-record tables

Subsystems in `crucible`, `crucible-device`, and `crucible-qemu` mutate their
own state internally. So that T-CAM-10.4 can land incrementally, a subsystem
MAY first appear as an **opaque-record table**: one record holding the
subsystem's existing canonical encoding with the strip list applied, and one
coarse dirty bit set by any mutation through the subsystem's API. The StateRoot
formula is final from the first landing. Converting an opaque-record table to a
structured table is a table schema version bump; equivalence checks compare
roots computed under the same catalog version.

## 16.4 Splitting the lifecycle loop

### Five classes

| Class | Meaning | Treatment |
| --- | --- | --- |
| **Run Arena** (M) | Modeled state that evolves with the run | Frozen, persisted, covered by the StateRoot |
| **Run Inputs** (I) | Immutable construction inputs | Referenced by identity; excluded from the StateRoot |
| **Run Authority** (A) | Live operating-system resources and handles to stores | Never serialized; described by resource slots ([§16a.1](16a-run-authority-and-restart.md#16a1-run-authority-and-resource-slots)) |
| **Rebuilt cache** (C) | Derived from the arena, the inputs, or the tier attachment | Rebuilt or discarded on thaw |
| **Unsettled** (U) | Transients that block freezing | Reported by `unsettled(purpose)` |

A value that may legitimately differ between two equivalent realizations of
one configuration is not modeled state. Process generations are therefore
authority, carried as the expected successor in a resource slot's proof.

### Field classification

Every direct field of `ProductionVmLifecycleLoop`, as surveyed:

| Field | Class | Note |
| --- | --- | --- |
| `runtime_progress` | C | Process-local telemetry; discarded on thaw |
| `inner` | mixed | Decomposed below |
| `trigger_graph` | C | Lowered from the scenario |
| `trigger_state` | M | |
| `trigger_world` | C | Clone of the source's world |
| `assertion_evaluator` | M | |
| `assertion_oracle` | C | Stateless |
| `terminal_verdict` | M | |
| `checkpoint_terminal_cause` | M | Set by `prepare_terminal_checkpoint` before capture |
| `initial_lifecycle_observations_pending` | M | |
| `branch` | M | Embeds a base schedule; becomes a prefix reference |
| `continuation_branches` | U | |
| `signal_fault_branches` | U | |
| `promote_signal_fault_campaign_choices` | I | Attempt-phase input set by the caller; not captured today |
| `pending_live_network_prefix` | U | |
| `pending_held_host_outcomes` | U | |
| `launch_configs` | C | Derived from the inputs and the boundary |
| `block_bindings` | C | Rebuilt from the World on non-hot restore; the hot attachment carries it as an optimization |
| `ninep_bindings` | C | As `block_bindings` |
| `block_devices` | A | Shared map of live block devices |
| `failed_host_io` | M | Its fingerprint sample and execution binding are stripped |
| `storage_fault_observations` | M | Shared with the interceptor today; becomes the `storage-observations` table |
| `fault_runtime` | M | Shared with the interceptor and device coordinators today; its owner instance is authority and its pending and in-flight work is unsettled |
| `fault_replay_installed` | I | Derived from configuration; read only by the retention check |
| `fault_search_overrides_installed` | I | As `fault_replay_installed` |
| `node_indexes` | C | |
| `node_run_directories` | A | |
| `immutable_root_images` | C | Derived from the launch configuration; exact capture records immutable backing per target in the tier attachment |
| `node_generations` | A | Persisted in today's closure identity; moves to the tier attachment's expected proof in T-CAM-10.5 |
| `node_leases` | A | |
| `node_lease_cleanup_failed` | A | Sticky failure; also a blocked unsettled reason |
| `node_service_states` | M | |
| `lifecycle_journal` | A | Its phase and nodes are unsettled reasons |
| `lifecycle_persistence` | A | |
| `run_manifest` | A | Its staged processes are an unsettled reason |
| `scenario` | I | |
| `source` | I | |
| `config` | I and A | Immutable bounds and executables are inputs; store handles and the run-state root are authority; its bounded-preemption flight queue is a shared input consumed during the run and is recorded explicitly by T-CAM-10.2 |
| `checkpoint_targets` | C and U | `Published` entries cache the run-local catalog; `Preparing`, `CleanupPending` (which owns a live snapshot handle), and `PublicationIndeterminate` are unsettled |
| `exact_ram_parents` | C | Tier-attachment cache, valid only against QEMU's committed epoch |
| `repository_exact_ram_rebase` | C | Tier-attachment cache, cleared after the first capture |
| `recorded_controls` | M | Chunked; each record embeds a full schedule today and becomes a prefix reference |
| `signal_artifact_objects` | I | Immutable authored bytes |
| `fault_trace_segments` | A | Store handle; its contents are the `fault-trace` table |
| `debug_backend_paths` | C | Derived from authority |
| `debug_gateway` | A | Never rebound ([§16.12](#1612-non-goals)) |
| `debug_attach` | U | |
| `debug_gateway_teardown_required` | U | |
| `indeterminate_debug_candidate` | U | A whole second loop, including its authority |
| `debug_runtime_evidence` | C | Debug evidence; bounded by T-CAM-10.9 |
| `node_launcher` | A | |
| `_run_directory` | A | |
| `retained_hot_fork_disk_owners` | A | |
| `retained_resource_owners` | A | |
| `hot_fork_backing_files` | A | Backing identity becomes a slot recipe |

`inner` is decomposed the same way:

- `BackendQuantumLoop`: `committed_frontier` and the dispatch contract and
  held generations are M; `pending_network_outputs`,
  `frozen_network_output_times`, `pending_observations`, `preselection`,
  `held_host_continuation`, `continuation_poisoned`, the failed resolutions,
  and `pending_fixed_input` are U; `pause_before_live_network_choice` and
  `parallel_choice_free_boot` are I; `held_stop_controller` is A.
- `QemuNodeSet`: processes are A; `pending_selectable_requests`,
  `parked_campaign_markers`, and `retained_observable_events` are U; the
  selectable catalog plans are M (persisted today in `LifecycleWire`).
- `QemuNode`: `host_io_runtime`, the next fault and network-output sequence
  counters, and `last_observed_time` are M nested inside an authority object.
  T-CAM-10.4 moves them into the `host-io` and `node-continuation` tables,
  which is a crate-level change in `crucible-qemu`.
- `ProductionFaultNetworkInterceptor`: `effect_state`, `campaign_log`, and
  `cursor` are M; `topology`, `links`, and `resource_limits` are C; `runtime`
  and `observations` are aliases of the loop's fault runtime and storage
  observations.

State shared with QEMU servicer threads (the fault runtime, the storage
observations, the interceptor cursor, and the block devices) is confined behind
table handles owned by the run's single writer. A servicer thread reads a
frozen value or submits a mutation that the writer applies through the table's
barrier; it never holds a mutable alias.

### Continuation carriers and fill sites

T-CAM-10.2 replaces the five carriers of [§16.1](#161-problem) with one
`FrozenRunArena` plus a tier attachment, and deletes `try_clone_for_branch`
and `into_restore_parts` as adapters. The satellite copies go with them:
`ProductionVmLifecycleResumeState` (whose `resume_state` copies the retained
log) becomes a journal position, `ProductionVmDebugRuntimeEvidence` becomes the
bounded debug evidence stream of T-CAM-10.9, and debug replay's copy of
`recorded_controls` becomes a table clone. Test literals that construct the
loop or its carriers field by field (the checkpoint-store and hot-fork test
support) move to the frozen-arena builder.

### Capture-refusal checks

Today eight groups of checks refuse a capture:

1. `exact_checkpoint_ready` (`crates/crucible-api/src/vm_lifecycle/runtime.rs`):
   held host outcomes, live network preselection, campaign parks, pending
   branch-effect choices, signal-fault branches, pending network output,
   selectable catalogs not frozen, and per-node device-I/O and selectable-reply
   quiescence. It drains pending selectable requests as a side effect and
   returns "not yet", meaning retry after another quantum. Daemon traits expose
   it with about twenty fakes.
2. `require_published_host_continuation`: held host outcomes, a held host
   continuation, or a poisoned continuation.
3. `final_boundary_retainable` (source retention): branch-effect choices,
   signal-fault branches, four debug conditions, failed lease cleanup, a log
   retained from before the run's base (`retained_base_events() != 0`), and
   campaign-effect replay exhausted, fault replay exhausted, or search
   overrides consumed. The last four are admissibility conditions, not
   transients.
4. Exact capture inline: continuation branches, an unresolved QEMU candidate,
   and publication state. `Preparing` refuses, while `CleanupPending` and
   `PublicationIndeterminate` are resumed.
5. Hot capture inline: not ready, pending network output, continuation
   branches, four debug conditions, any non-`Published` checkpoint target,
   failed lease cleanup, lifecycle-journal nodes or phase, and staged run
   processes, plus a post-check that the source did not change during capture.
6. `SingleScheduler::checkpoint`: a held lock, fixed input in progress,
   application-random branch selections, or campaign parks.
7. The production fault runtime's checkpoint: pending QEMU fault events,
   pending node lifecycle or boot, lifecycle work or release in flight, pending
   search choices, and events that arrive during fingerprint capture.
8. The interceptor's checkpoint: an inconsistent observation journal.

### One predicate per purpose

Exact capture resumes publication states that hot fork refuses, and source
retention adds admissibility conditions that are not transients, so one
purpose-free predicate cannot express today's behavior. The run instead exposes
one predicate parameterized by purpose and a separate settle step:

```rust,illustrative
enum FreezePurpose { ExactCheckpoint, HotFork, Persist, SourceRetention }

enum UnsettledClass {
    /// The condition clears by running further quanta.
    RetryAfterQuantum,
    /// The condition cannot clear for this purpose in this run.
    Blocked,
}

impl Run {
    /// Performs side-effecting settle steps: drains pending selectable
    /// requests and, for exact capture, resumes an interrupted publication.
    fn settle(&mut self, purpose: FreezePurpose) -> Result<(), SettleError>;

    /// Returns every reason the run cannot be frozen for `purpose`, each with
    /// its class; empty means the run may be frozen for that purpose.
    fn unsettled(&self, purpose: FreezePurpose) -> UnsettledReasons;
}
```

The predicate reads the arena and the run's transients; it never mutates
either. `exact_checkpoint_ready` remains as a thin wrapper over `settle` and
`unsettled(ExactCheckpoint)` until its daemon-trait fakes migrate.

- **[ARENA-9]** A run MUST expose one `unsettled(purpose)` predicate for each
  purpose in {exact checkpoint, hot fork, persist, source retention}, returning
  typed reasons classed as retry-after-quantum or blocked. Every capture
  refusal, including purpose-specific admissibility conditions that are not
  transients, MUST be reported through it, and no other capture-refusal
  predicate may exist. Side-effecting settle steps MUST run in a separate
  `settle(purpose)` before the predicate and MUST NOT be part of it. Freeze for
  a purpose MUST refuse with the predicate's reasons while it is non-empty.

## 16.5 Run Journal

### Today's holders

| Holder | Today | Under the Run Journal |
| --- | --- | --- |
| Scheduler per-append segments and `EventLogOffset` | One non-decodable object per append, chained into the offset | Hash-only offset projection; no stored objects |
| Per-quantum outcome bytes and text | Copied per append | Borrowed views of the appended batch |
| Scheduler sealed segments | Attempt-format segments in the scenario-scoped scheduler store, not synchronized, not charged to quota | The Run Journal's segments in the executor segment store |
| Condition prefix | Every entry, refolded from every segment on restore | Bounded fold state and tail ([§15.4](15-segmented-event-log.md#154-bounded-evaluation-state)) |
| Driver and observer attempt logs | Separate writers and directories; the observer counts seal size from its first recorded sequence | Read views of the journal |
| `resume_state` and driver re-seal on resume and hot-fork start | Whole log copied, re-encoded, and moved | Journal position |
| Finding capture `complete_log` | Up to two complete logs per finding | Streamed reads through the journal handle |
| Session hub and debug history | Sealed views over the scheduler store; a complete condition prefix while a breakpoint is armed | Bounded tail windows over the journal |
| Scheduler continuation v10 | Offset, segment references, tail of at most 8 MiB | Journal position |
| Savepoint, observation, and causal digests | Count-prefixed whole-log hashes | Running projections |
| Prepared-result journal segments | Byte copies under `ContentId(Trace, 1)` | Placements of the same IDs |
| Repository trace leaves | Byte copies under `ContentId(Trace, 1)` | Placements of the same IDs ([CCOMP-29]) |
| Native closure segment list | Bare `ContentHash`, re-hashed at publication | `ContentId` references trusted by seal receipt |
| Campaign-root closure objects | Segment re-read to derive `ContentId(DeviceState, _)` | `ContentId(Trace, _)` placements, deduplicated with trace leaves |
| Fault trace at capture | Every referenced trace segment read into memory | Referenced, not read |

### One journal, one writer

Each run has one Run Journal: the attempt log of
[§15](15-segmented-event-log.md) extended to every consumer. It is an ordered
sequence of sealed segments followed by one open tail, chained as in
[§15.2](15-segmented-event-log.md#152-attempt-segments). The scheduler is its
only writer and appends each merged batch of a quantum once.

Every other consumer reads through a journal handle: a cheap, `Send + Sync`
snapshot of the position, shared references to the sealed segments, and a
shared view of the tail. The driver, the observer, the session and debug
planes, and the finding runner hold handles, not logs. A resumed or forked run
references its inherited prefix by position and appends its own segments; it
never copies inherited entries. This removes the `resume_state` copy, the
`from_entries` re-seal, `move_to_store`, and `complete_log`.

- **[RJRNL-1]** Each run MUST have exactly one Run Journal with one writer. It
  MUST be the only source of the run's event entries; every other durable copy
  of journal bytes MUST be a placement of one of its sealed segments.
- **[RJRNL-2]** The Run Journal MUST use the segment, chain, sealing, storage,
  and publication rules of [CCOMP-25] through [CCOMP-30], [CCOMP-33], and
  [CCOMP-42], and the evaluation and reader rules of [CMEAS-15], [CMEAS-16],
  [CMEAS-22], and [CMEAS-28]. The scheduler's event log and the executor's
  attempt logs MUST be the same journal with one segment encoding.
- **[RJRNL-3]** Every other consumer of event-log content MUST hold a bounded
  projection, a journal handle or position, or a byte-identical durable
  placement of a sealed segment. No consumer may hold a second encoding of
  entries or a complete in-memory copy of the log.

### Seal rule

Seal points depend only on size and the modeled attempt stop. The tail seals
before an entry would push its encoding past 8 MiB, and at the attempt's
modeled stop, which is a property of the execution rather than an executor
decision. Checkpoint, pause, fork, retention, and materialization never seal.

A capture position names the sealed prefix and carries the open tail, at most
8 MiB, by value outside the chain, as the single-scheduler continuation already
does ([CCOMP-33]). A restored or forked journal installs that tail as its open
tail and seals where the uninterrupted journal would. Segment identities, which
reach campaign observations through measurement evidence, are therefore the
same whether a run was paused, forked, restored, or ran straight through
([CCOMP-21]). A forked child's shared prefix is immutable because it is sealed;
the tail it inherits is a value.

- **[RJRNL-5]** Journal seal points MUST depend only on the entry sequence (the
  8 MiB tail rule) and the modeled attempt stop, as amended [CCOMP-26]
  requires; they MUST NOT depend on checkpoint, pause, fork, retention, or
  materialization decisions. A capture position MUST name the sealed prefix and
  carry at most one open tail by value. A restored or forked journal MUST seal
  where the uninterrupted journal would.

### Positions instead of copies

A checkpoint or hot-fork continuation names where the journal stood:

```text
JournalPosition
  entry count
  entry-prefix digest
  sealed segment count and chain hash      # the sealed prefix
  sealed segment references                # ContentId(Trace, segment schema)
  open tail                                # <= 8 MiB, by value, captures only
```

An exact closure references the sealed segments covering its position by
content ID, and publication places them before the root as it places every
other closure object. A hot-fork child shares its parent's sealed prefix by
reference. Resume continues from the position and the bounded fold state
([CCOMP-30], [CMEAS-16]). A capture's log work is writing one tail of at most
8 MiB and recording references. The references grow with the sealed segment
count, which the manifest bound of 4,095 segments limits.

- **[RJRNL-4]** Checkpoints, exact closures, and hot-fork continuations MUST
  reference a journal position and the sealed segments that cover it. They
  MUST NOT copy sealed entries. The log work of a capture MUST be independent
  of the journal's sealed bytes; its metadata MAY grow with the sealed segment
  count under the manifest bound.

### Segment identity and storage

A sealed segment has one identity everywhere: `ContentId(Trace,
ATTEMPT_LOG_SEGMENT_SCHEMA)`, the identity attempt logs and trace leaves
already use. Continuation references, native-catalog keys, the closure's
segment list, prepared-result journals, trace leaves, and campaign-root
placements all name that ID. At L3 a segment is placed as a `Trace` object,
so a closure and a published trace leaf of the same segment are one object.

The executor owns one **segment store** for Run Journal segments:

- **Durability and receipts.** Sealing writes the segment, synchronizes the
  file and its directory, and then writes a seal receipt binding the
  `ContentId` to the length. L2 persist and L3 publication trust the receipt:
  publication never reads a segment the destination already holds and never
  derives a segment's identity from its bytes; copying an absent segment
  streams it once.
- **Quota.** Each distinct segment is charged once against the attempt's
  `maximum_event_log_bytes` at its receipt ([CCOMP-28]); placements and
  inherited prefixes are not charged again.
- **Location.** The store lives in an executor namespace that startup does not
  retire, because paused raw roots and prepared results must survive restart
  and the native namespaces of
  [§15.3](15-segmented-event-log.md#153-retention-bound-and-storage) are
  retired. Per-attempt driver and observer directories are removed.
- **Write ordering.** A segment's receipt is durable before any reference to it
  is recorded, and a reference is recorded before the continuation, closure,
  prepared result, or trace leaf that names it.
- **Rooting and sweep.** Liveness follows [RJRNL-8]. After the assignment ledger
  is reconciled and before any worker starts, startup deletes every segment
  that no root reaches.

- **[RJRNL-9]** Every placement of a sealed journal segment MUST use the
  identity `ContentId(Trace, ATTEMPT_LOG_SEGMENT_SCHEMA)`. The executor segment
  store MUST synchronize a segment before writing its seal receipt, MUST charge
  each distinct segment once against `maximum_event_log_bytes`, and MUST
  survive daemon restart. L2 persist and L3 publication MUST trust seal
  receipts and MUST NOT re-hash or re-read a segment the destination holds. A
  reference MUST NOT be recorded before its receipt is durable, and startup MUST
  sweep unrooted segments before any worker starts.

### Identity-bearing encoding

Four journal values carry identity, each for one purpose.

1. **Canonical entry bytes.** Each entry has one canonical encoding: the
   attempt-segment CBOR form of `SchedulerEventLogEntry` under schema
   `crucible.attempt.event-log-segment` version 1. Segments frame those bytes
   without re-encoding them. Each entry's `content_hash` is the BLAKE3 hash of
   its [OBS-20] entry material. Determinism, replay, and measurement
   comparisons compare entries ([CCOMP-27]).
2. **Entry-prefix digest.** A running digest maintained on append:

   ```text
   digest_0 = H("crucible.run-journal.entry-prefix.v1", "empty")
   digest_n = H("crucible.run-journal.entry-prefix.v1", digest_(n-1),
                u64be sequence of entry n, content_hash of entry n)
   ```

   It depends only on entries, never on seal points or append boundaries. It
   is the journal component of the StateRoot and of every position used for
   equivalence, replay targets, and fork pairing, and it costs work
   proportional to each appended batch. It replaces these whole-log digests,
   each of which hashes the entry count first and so rescans the log:
   - `SavepointEventPrefixDigest` (savepoint replay proofs) and
     `ObservationPrefixDigest` (assertion-boundary evidence), which share the
     domain `crucible.savepoint-replay-event-prefix.v1`; the persisted
     savepoint replay proof format is bumped;
   - `ObservationEventLogProof.digest` in campaign observations, a campaign
     observation schema bump;
   - `EventLogCausalDigest`, which gains a running form over causal entries so
     checkpoint proofs need one pass instead of two; the persisted causal
     summary format is bumped.
3. **Segment chain.** The chain hash of
   [§15.2](15-segmented-event-log.md#152-attempt-segments) identifies a sealed
   log as evidence and authenticates segments in order. Under [RJRNL-5] it is
   the same on every tier, but it still never enters the StateRoot.
4. **Per-append offset chain.** `EventLogOffset` ([OBS-17]) stays an RFC-0010
   evidence identity. It is maintained as a hash-only projection: each append
   computes its per-append segment hash from the batch's entry material and
   chains it, and the per-append objects, the per-quantum appended bytes, and
   the text view are no longer stored. No RFC-0010 requirement changes.

- **[RJRNL-6]** Journal entries MUST have exactly one canonical encoding, and
  every durable placement of a segment MUST be byte-identical and addressed by
  the same content ID; copying MUST NOT re-encode. Entries MUST NOT contain host
  paths, wall time, daemon epochs, or placement data ([CMOD-2]). Equivalence and
  state identities MUST use the entry-prefix digest; only evidence identities
  MAY use the segment chain or the offset chain. An identity that hashes a
  vector of retained entries, or hashes the entry count before the entries,
  MUST be replaced by one that hashes a journal position.
- **[RJRNL-11]** The per-append offset chain MUST be maintained as a hash-only
  projection computed from each append's entry material. The executor MUST NOT
  store per-append segment objects or keep per-quantum appended bytes or text
  beyond the append that produced them.

### Projections

| Projection | State bound | Checkpoint encoding | Identity role | Restore validation |
| --- | --- | --- | --- | --- |
| Entry-prefix digest | 32 bytes and a count | In the position | StateRoot, pairing, replay targets | Recomputed over the carried tail and compared |
| Offset chain | One offset | In the position | Observation evidence ([OBS-17]) | Latest append recomputed from the tail |
| Causal digest, running form | One hasher state and counts | In the position | Causal summaries, checkpoint proofs | Compared against the position |
| Condition-prefix fold ([CMEAS-15]) | Declarations and one interval | Fold state | Trigger and assertion results | Authenticated against the checkpoint identity; never refolded ([CMEAS-16]) |
| Coverage fold | One bit per declared point | Fold state | Coverage projection | As the condition fold |
| Assertion proximity and network-fault marker index | Declarations | Fold state | Guidance and discovery | As the condition fold |
| Last entry and per-class counts | Constant | In the position | Stop checks, session summaries | Compared against the tail |
| Session and debug tail windows | Configured window | None | None | Rebuilt from the tail and sealed segments |

- **[RJRNL-10]** Every projection MUST have state bounded independently of run
  length, MUST be carried in a checkpoint as fold state or position fields, and
  MUST be authenticated on restore against the checkpoint identity without
  refolding sealed segments.

### Readers and retention

Readers follow [CMEAS-22]: they stream sealed segments in order and never
materialize a complete log. The session and debug planes keep a bounded tail
window for live subscribers; a subscriber that falls behind reads sealed
segments by reference.

- **[RJRNL-7]** Live tail windows for session, debug, and API subscribers MUST
  be bounded by configuration, independent of run length. A subscriber behind
  the window MUST read sealed segments by reference and MUST NOT cause the
  journal or its projections to retain additional entries.
- **[RJRNL-8]** A sealed segment MUST remain readable while a live Run Journal,
  an L2 catalog entry, a paused or promoting exact root, a pinned or selected
  exact root, a hot-checkpoint fallback, a prepared result, or a published
  trace leaf references it, and MUST otherwise be removed ([CCOMP-29]).
  Liveness MUST derive from those durable references, never from access time
  or in-process reference counts ([CSTORE-19]).

### Compatibility

Under current-only decoders ([CSEC-9], [CSEC-10]) the journal changes are
version bumps, and old objects are refused rather than rewritten:

- single-scheduler continuation version 11 names segments by `ContentId` and
  carries the running digests;
- production exact closure version 12 lists segments as `ContentId(Trace, _)`
  and trusts seal receipts; the campaign-root manifest and object schemas bump
  with it;
- the campaign observation schema bumps for `ObservationEventLogProof`, and the
  savepoint replay proof and causal summary formats bump;
- prepared-result journal state and its segment-set hash bump when their
  references change.

Existing `paused` records whose roots use a refused closure version are
re-executed from their origin, which is today's cancel-and-retry behavior.
Exact pins and hot-checkpoint fallbacks naming refused roots fall back to thin
replay ([HFORK-2]). Each format receives its schema-registry row when its
implementation lands.

## 16.6 Operations over the arena

### Freeze and snapshot

`freeze(purpose)` runs `settle(purpose)`, checks `unsettled(purpose)`,
harvests the values that live in QEMU, and returns an immutable frozen arena
that shares every table with L0 plus the journal position. It is the only
capture operation. The exact checkpoint set and the hot-fork continuation
become one frozen arena plus a tier attachment:

```text
FrozenRun
  frozen arena                (L1, shared)
  journal position
  tier attachment
    Exact { targets, immutable backing, repository restore,
            node generations and other expected proofs }
    Hot   { adopted nodes, I/O nodes, active host I/O, disk bases,
            node generations, cached bindings and root images }
```

**Harvest.** Freeze pulls a bounded set of values from live QEMU: execution
fingerprints, fault command and event sequences, selectable catalogs,
host-I/O projections bound to the scheduler identity, and per-node instruction
counters and times. Each harvested value is one of two kinds. Modeled values
(fault sequences that pass the v0 probe, selectable catalog plans, node
counters and times, the modeled part of host-I/O projections) are mirrored into
their tables when QEMU reports them, so freeze reads the table rather than
QEMU. Realization values (execution fingerprints, execution bindings,
instruction counters used as restore proofs) belong to the tier attachment's
expected proof. Harvest never mutates modeled state: an event that arrives
during harvest is a retry-after-quantum reason, as today's fault checkpoint
re-check is.

- **[ARENA-27]** Freeze MUST NOT read modeled state from QEMU at capture time:
  every modeled value QEMU reports MUST be mirrored into its table when
  reported, and every realization value MUST be carried only in the tier
  attachment's expected proof. Harvest MUST NOT mutate the arena; a concurrent
  report MUST make freeze return a retry-after-quantum reason. T-CAM-10.2 MUST
  record the kind of every harvested value.

### Persist

`persist` encodes the frozen arena's dirty chunks, writes chunks and table
nodes to L2, and writes the arena manifest. An exact closure then references
the arena manifest, the journal position and segments, and the tier
attachment's QEMU artifacts; L3 publication proceeds root-last as in
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure).

### Arena manifest

The arena manifest replaces the nested opaque byte vectors in today's closure
(the scheduler continuation, network adapter, fault, trigger, assertion,
lifecycle, and host-I/O encodings) with table roots:

```text
ArenaManifest
  arena schema version
  configuration ID
  journal position              # without the tail, which is its own object
  tables: ordered [(table ID, table schema version, table root,
                    record count, top node ContentId)]
  parent arena manifest         # optional; delta placement
```

The closure version that introduces it references the arena manifest, the
journal segment set, and the tier attachment (targets, immutable backing, and
generations as expected proof). Under the planned order T-CAM-10.3 has already
taken closure version 12, so the arena manifest arrives in the following
closure version. `ClosureManifest` and `ExactCheckpointClosureRecord` become
one definition in one crate. The closure's object inventory is the
Merkle-reachable set of the manifest, published as a delta against the parent
manifest, and GC traverses table trees from the manifest ([CSTORE-19]).
Introducing the manifest retires or bumps these registry rows: the production
exact closure, single-scheduler continuation, production fault runtime and
fault-runtime checkpoint, network adapter checkpoint, host-I/O checkpoint,
node continuation, event-graph state, and host-assertion continuation, plus
the daemon exact-checkpoint root, manifest, and object rows if their
inventories change.

- **[ARENA-28]** An exact closure MUST reference one arena manifest of table
  roots in place of nested subsystem encodings, and its object inventory MUST
  be the Merkle-reachable set of that manifest, published as a delta against
  its parent manifest. Process generations MUST appear only in the tier
  attachment. The native closure wire and the campaign-root closure record MUST
  share one definition.

### Introspect and diff

A frozen arena is a value. A debugger, status RPC, or offline tool reads it
from another thread without locking the quantum loop. A uniform table catalog
gives one generic browser: list tables, read a key range, decode a chunk. Two
arenas diff by comparing table roots and descending only into differing tree
nodes, so the cost of a diff is proportional to the difference. T-CAM-10.4
builds the browser and diff; T-CAM-10.7 exposes them through the executor's
read-only RPC.

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

### Debug reposition

Production debug `goto` builds a candidate and a verifier and replays both from
genesis. Under the arena it restores the nearest exact root at or before the
target and replays only the suffix, as [DBG-14] requires. The candidate and
verifier pairing remains: both start from the same restored frozen run, and the
pair is verified against the live execution's recorded evidence. Debug runtime
evidence becomes a bounded stream: at most 4,096 samples stay resident, and
older samples seal into content-addressed segments in the run's debug
namespace, read back by coordinate when a reposition needs them.

- **[ARENA-32]** Debug reposition MUST restore the nearest exact root at or
  before the target coordinate and replay only the suffix through the thaw
  constructor, MUST keep the candidate and verifier pairing, and MUST verify
  against the live execution's evidence. Resident debug runtime evidence MUST be
  bounded independently of run length; older samples MUST be sealed and read by
  reference.

## 16.7 Process and license boundary

The arena is Apache host code. QEMU guest RAM, device VMState, root overlays,
persistent fault rules, and execution fingerprints stay inside the GPL-side
process and reach the host only through the versioned snapshot and control
protocols. The arena refers to them by content ID inside a tier attachment and
never parses them, exactly as
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) already
requires of storage code. The `host-io` table stores plugin- and QEMU-produced
bytes (block transport continuations, fault and command VMState) only as
opaque content IDs. Ring, region-header, and console continuations are public
protocol data and may appear in host tables as such. The arena itself is never
placed in shared memory, and arena crates depend on neither the QEMU plugin
crates nor QEMU headers.

- **[ARENA-21]** Run Arena and Campaign Arena code MUST NOT link QEMU, include
  QEMU headers, or store QEMU-private structures, native pointers, callback
  tables, or Rust-native layouts in any table, chunk, or manifest. QEMU state
  MUST appear only as opaque artifacts referenced by content ID, and nothing may
  cross the process boundary except the versioned socket and shared-memory
  protocols.

## 16.8 Determinism and identity

The arena is a realization mechanism. It inherits every identity rule in
[§05.1](05-hot-fork-and-checkpoints.md#051-three-realization-tiers): tiers and
layers are caches ([HFORK-1], [HFORK-2], [HFORK-19]), materialization choice is
executor-owned ([CCOMP-3]), and the campaign product does not depend on where
or how an attempt ran ([CCOMP-21]).

The StateRoot gives those rules an executable check. A thin replay, an exact
restore, and a hot child of the same settled boundary must reach equal
StateRoots, and a resumed run must reproduce the uninterrupted run's StateRoot
sequence. This holds only once generations, execution bindings, and
seal-dependent chain fields are out of model state, which is why the v0 probe
precedes any StateRoot gate. Once the StateRoot exists, it is the natural host
continuation digest for template identity ([HFORK-7]) and child pairing
([HFORK-11]); adopting it there is a template schema version bump after
T-CAM-10.5.

Formats follow [CSEC-9] and [CSEC-10]. Each arena manifest, table schema,
chunk encoding, and journal encoding has one current version and a
current-only decoder, so every format change is a version bump and old objects
are not rewritten. The network adapter checkpoint and network state digest are
JSON today; T-CAM-10.4 re-encodes them canonically before they enter a table.

- **[ARENA-22]** For every supported checkpoint fixture, thin replay, exact
  restore, and a hot child of the same settled boundary MUST produce equal
  StateRoots once the v0 probe reports no variance. A mismatch is a correctness
  failure ([CPERF-7]).
- **[ARENA-23]** Observations, findings, and campaign facts MUST be identical
  whether a run used a retained hot world, an exact closure, thin replay, any
  layer, or any spill placement.
- **[ARENA-24]** Every arena manifest, table schema, chunk encoding, and journal
  encoding MUST carry an explicit version with a current-only decoder. A change
  to any of them MUST be a version bump.

## 16.9 Storage technology

The arena is built in this repository on safe Rust. The design rules below
follow from the workspace's `unsafe` policy, the hermetic build, and the
identity rules above.

- **Persistent collections from this repository first.** `crate::History` and
  `PersistentSet` (`crates/crucible/src/model/persistent_set.rs`) already give
  constant-time clones. `History` is extended first: its flat sealed-chunk index
  becomes a fixed-fanout tree of shared chunks, so sealing under sharing copies
  one path rather than the whole index, and a persistent ordered map is built
  beside `PersistentSet` on the same pattern. No third-party persistent
  collection is added without a separate decision; `imbl`, for example, is
  MPL-2.0. Identity never comes from in-memory node shapes, which depend on
  operation history; it comes from the canonical chunks and trees of
  [§16.3](#163-run-arena-model).
- **Chunked tables over the existing content store.** Sealed chunks are
  ordinary content-addressed objects, reusing envelope, verification, tiering,
  transfer, and GC. Chunks placed in the campaign store use that store's
  backends unchanged.
- **An optional evicting spill cache behind a trait.** Today's store tiers do
  not evict. The spill cache of
  [§16a.7](16a-run-authority-and-restart.md#16a7-spill-cache) evicts clean,
  already persisted chunks and may use a pure-Rust embedded store behind its
  trait. Replacing or deleting the backend changes no logical byte.
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

- **[ARENA-25]** Arena crates MUST NOT contain `unsafe` code, and arena-owned
  spill storage MUST NOT use memory-mapped or C/C++ storage engines. Chunks
  placed in the campaign content store use that store's configured backends
  unchanged. A spill backend MUST sit behind a trait and MUST NOT affect logical
  bytes, identities, or results; deleting its contents MUST be equivalent to a
  cache miss.

## 16.10 Relationship to resource-cap conversion

The resource-cap conversion work removes caps that end long attempts because
run-length data is held in memory. The arena is the general form of that
conversion. A growing buffered list becomes a chunked table whose sealed chunks
spill; a buffered copy of event-log content becomes a journal projection or
position. The limits that remain are storage limits, which are operational in
the sense of [CCOMP-28]: exhausting them ends the attempt as an operational
failure, never as a policy result or finding ([CSEC-12]). The 4,095-segment
manifest bound is such a limit; it follows from the 4,096-object evidence set
of one campaign record.

- **[ARENA-26]** No host component may bound a run by the in-memory size of
  state that grows with run length. Such state MUST be a chunked table, a reused
  segmented form, or a journal projection, and any remaining bound MUST be an
  operational storage limit that does not enter identity or policy.

## 16.11 Staged implementation

Each step is independently useful and leaves the tree consistent. Tasks are in
[§11.12](11-implementation-plan.md#1112-phase-10--run-arena-and-run-journal).
Steps are listed in implementation order.

| Order | Task | Change | Value on its own | Gates |
| --- | --- | --- | --- | --- |
| 0 | T-CAM-10.0 | Promotion-only resume admission and an explicit Raw/Promoted phase | Fixes a live admission defect; prerequisite of any drain | `gate:campaign-component-contract`, `gate:campaign-operational-continuity` |
| 1 | T-CAM-10.3 | Running digests; single writer and durable segment store; closure v12 trusting seal receipts, trace referenced at capture; stop storing per-append objects; bounded condition prefix (T-CAM-3.7); rooting and sweep | Capture and restore independent of journal bytes | `gate:campaign-replay`, `gate:content-address`, `gate:campaign-cold-continuity`, `gate:exact-closure-streaming`, `gate:hot-fork-equivalence`, `gate:campaign-performance` |
| 2 | T-CAM-10.2 | Regroup the loop into five classes with an exhaustive-destructure test; `FrozenRunArena` and tier attachment; one freeze; `settle` and `unsettled(purpose)` | One place to add a host field; one refusal predicate per purpose | `gate:hot-fork-equivalence`, `gate:exact-closure-streaming`, `gate:campaign-component-contract` |
| 3 | T-CAM-10.1 | Persistent representations for staging and rollback copies | Per-quantum work stops growing with the run | `gate:host-clone-cost`, `gate:campaign-performance` |
| 4 | T-CAM-10.4 | StateRoot v0 probe, then tables, write barriers, chunks, StateRoot, browser and diff | Incremental persist; executable equivalence checks | `gate:content-address`, `gate:hot-fork-equivalence` |
| 5 | T-CAM-10.5 | Arena manifest replaces nested blobs (closure version bump); delta placement | Persist cost proportional to dirty chunks | `gate:exact-closure-streaming`, `gate:campaign-store-composition` |
| 6 | T-CAM-10.6 | Authority journal and pre-retirement reconciliation, then resource slots and one rebind transaction | Crash-safe containment; uniform restore checks | `gate:hot-fork-isolation`, `gate:campaign-operational-continuity` |
| 7 | T-CAM-10.8 | Checkpoint-drain stop, exact demotion of published-boundary hot sources, restart StateRoot test | Graceful restart without losing running work | `gate:campaign-operational-continuity`, `gate:campaign-component-contract` |
| 8 | T-CAM-10.7 | Campaign Arena view, then the evicting spill cache | One operational status view; bounded resident memory | `gate:campaign-store-composition`, `gate:campaign-cold-continuity` |
| - | T-CAM-10.9 | Reachable exact hot-fork sources (before T-CAM-10.8's exact demotion); bounded restore-nearest debug reposition | Removes survey defects | `gate:hot-fork-equivalence`, `gate:e2e-determinism` |

Phase 10 overlaps open work elsewhere in the plan. The relationships are:

| Existing | Relationship |
| --- | --- |
| [CPERF-10], T-CAM-4.13 | [ARENA-3] refines CPERF-10 for staging copies. T-CAM-10.1 supersedes the staging part of T-CAM-4.13; CPERF-10 maps to both tasks. |
| T-CAM-7.3 | T-CAM-10.1 supersedes its clone part; its pairing part is unchanged. |
| [CCOMP-26], T-CAM-4.11 | CCOMP-26 is amended to the size-and-stop seal rule; [RJRNL-5] applies it to the journal. The "checkpoint- and fork-offset seals" remainder of T-CAM-4.11 is withdrawn, and chain-position resume moves to T-CAM-10.3. |
| T-CAM-3.7 | T-CAM-10.3 depends on it and schedules it as a sub-step; T-CAM-3.7 keeps [CMEAS-15] and [CMEAS-16]. |
| T-CAM-4.12, T-CAM-4.15, T-CAM-4.16 | T-CAM-10.3's journal handle is the reader their remaining items need; they keep their requirements and depend on it. |

Three test contracts are added to existing gates. Each registers an exact
selector in `crates/crucible-harness/src/campaign_gates.rs` and the matching
`tests/crucible/*.nix` aggregate, with its evidence keys, when it lands:

- **Long-horizon copy cost**, in `gate:host-clone-cost`: a deterministic test
  records bytes copied by staging and rollback per quantum at 10, 50, and 90
  percent of a horizon of at least 10^6 journal entries that ends with a long
  phase after a deep branch point, and fails when the 50- or 90-percent sample
  exceeds 1.25 times the 10-percent sample ([CPERF-10], [ARENA-3]). The
  existing sibling-sharing evidence stays, and its private-ledger evidence is
  redefined to prove isolation of private mutations rather than eager copying.
- **Restart equivalence**, in `gate:campaign-operational-continuity`: run a
  fixture to quantum `k`, pause, persist, stop the daemon, resume in a fresh
  process, and compare the StateRoot at every later settled boundary and the
  final observation with an uninterrupted run of the same attempt
  ([ARENA-17]). The test repeats for several `k`, including a boundary inside a
  long phase after a deep branch point.
- **Tier root equality**, in `gate:hot-fork-equivalence`: extend the
  [§10.8](10-performance-and-validation.md#108-equivalence-matrix) matrix so
  every path also compares StateRoots ([ARENA-22]), including a hot child of an
  exact-restore-created template. It records v0 probe observations until the
  probe reports no variance and fails on mismatch afterward.

The performance gates check flat resident memory and per-quantum time over a
long-horizon attempt ([CPERF-10]), capture log work independent of sealed
journal bytes ([RJRNL-4]), and persist bytes proportional to dirty chunks. The
license and ABI gates cover [ARENA-21] unchanged.

## 16.12 Non-goals

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
  semantics here. The debug gateway is never rebound, and a graceful restart
  ends attached sessions unless they are detached and captured first.

## 16.13 Known defects found during the survey

The survey behind this chapter found the following defects. Each is tracked by
a task. The RFC defects in the last two rows are corrected by this chapter's
revision.

| Defect | Where | Tracking |
| --- | --- | --- |
| Resume admission accepts an unpromoted paused root. `resume_after_validation` accepts any `Paused` record with a matching basis and never checks promotion, contrary to the `paused(promoted)` rule of [§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service). Submit also returns `AlreadyPaused` for a raw pause, and the coordinator then calls `resume_paused` at once, so the raw record moves to `Running` and its promotion work is lost before the worker rejects the root. "Promoted" is inferred from an absent promotion basis, which also means savepoint-capture completion. | `crates/crucible-daemon/src/executor_supervisor/admission.rs`, `crates/crucible-campaign/src/repository/executor_driver.rs` | T-CAM-10.0 |
| The demanded exact hot-fork source path is unreachable. The hot-first router tries hot fork only when the attempt has no resume checkpoint, while the world factory derives the exact-checkpoint source key only when it has one, and demand capture runs only for that key. | `crates/crucible-daemon/src/qemu_hot_first_router.rs`, `crates/crucible-daemon/src/qemu_hot_fork_world_factory.rs` | T-CAM-10.9 |
| The packaged executor deletes `run-state.json` unread. Startup retires the `campaign-workers` namespace and seven others before any worker lifecycle is built, so orphan quarantine from the prior run's process journal never runs for worker lifecycles; containment relies on `PR_SET_PDEATHSIG` and fail-closed cgroup and attempt-storage root checks. Baked genesis is captured before the GC exclusion and retirement, so the comment that ownership precedes any namespace mutation is inaccurate. | `crates/crucible-daemon/src/packaged_qemu_executor.rs` | T-CAM-10.6 |
| Production debug goto restores genesis instead of the nearest checkpoint ([DBG-14]); its candidate and verifier both replay from genesis. Debug runtime evidence grows without a bound, and each sample holds a materialized scheduler state. | `crates/crucible-api/src/vm_lifecycle/runtime.rs` | T-CAM-10.9 |
| Both captures read every referenced resolved-effect trace segment into memory. | `capture_fault_trace_objects` in `crates/crucible-api/src/vm_lifecycle/helpers.rs` | T-CAM-10.3 |
| Native publication re-hashes every present event-log segment, and campaign-root preparation reads every closure object to derive its identity. | `crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs`, `crates/crucible-daemon/src/exact_checkpoint_store/production/publication_format.rs` | T-CAM-10.3 |
| Exact resume and hot-fork start copy the whole retained log and re-seal it; automatic finding capture collects up to two complete logs, contrary to [CMEAS-22]. | `resume_state`, `crates/crucible-daemon/src/automatic_finding_runner.rs` | T-CAM-10.3 |
| The scheduler's segment store does not synchronize writes, is not charged to `maximum_event_log_bytes`, and is not reclaimed per attempt. | `crates/crucible/src/model/dag_store/local.rs` | T-CAM-10.3 |
| The observer's recorded log counts seal size from its first recorded sequence, so a resumed attempt's evidence seals at different points than the uninterrupted attempt, contrary to amended [CCOMP-26]. | `crates/crucible-daemon/src/qemu_campaign_lifecycle/evidence/store.rs` | T-CAM-10.3 |
| `History` copies its whole sealed-chunk index on each seal while a clone shares it. | `crates/crucible/src/history.rs` | T-CAM-10.1 |
| Process generations are part of the closure manifest and its identity. | `ClosureManifest` | T-CAM-10.5 |
| The network adapter checkpoint inside the fault continuation is JSON in an identity-bearing object. | `crates/crucible-api/src/vm_lifecycle/network_faults.rs` | T-CAM-10.4 |
| [CCOMP-26] required seals at checkpoint and fork offsets, which would put executor decisions into segment identities that reach campaign observations, and contradicted §15.12's size-only rule. CCOMP-26 is amended to the size-and-stop rule. | This RFC | Corrected |
| Stale RFC numbers: §05.5 and §04a named template schema 29, resource-stage schema 13, and fork schema 3 (the code uses 30, 14, and 4); §04a named attempt-state record v11 (the code uses v15); §05.9 named the closure version nine (the code uses eleven), two retired namespaces, and baked genesis as not retired (the packaged executor retires eight, including baked genesis). | This RFC | Corrected |

[DBG-14]: ../0010-crucible/36-time-travel-debugging.md#3641-there-is-no-reverse-engine--only-restore--deterministic-replay
[OBS-17]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
[OBS-20]: ../0010-crucible/19-observability-event-log.md#194-content-addressing-and-prefix-sharing
