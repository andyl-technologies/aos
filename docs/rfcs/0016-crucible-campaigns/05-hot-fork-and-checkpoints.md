# 05 — Hot QEMU forking and exact checkpoint tiers

Campaign throughput depends on reusing a paused world without serializing and
reloading its entire state for every child. This file defines a local hot-fork
path and keeps it semantically interchangeable with RFC-0014's durable exact
checkpoint and RFC-0010 thin replay.

Here **hot fork** names only the QEMU realization mechanism. It does not create
campaign meaning by itself. The campaign first admits a `BranchEdge`; the daemon
may then realize its `Attempt` by hot fork, exact restore, or thin replay. Two
process children that receive the same recorded selection are duplicate
realizations of one semantic edge, not two campaign branches.

## 05.1 Three realization tiers

| Tier | Representation | Primary uses |
| --- | --- | --- |
| **Hot** | Paused fork-template QEMU processes, OS copy-on-write RAM, isolated child disk overlays, cloned host continuation | High-fanout on-host exploration |
| **Exact** | Portable authenticated closure containing QEMU VM state, disk deltas, host continuation, scheduler/fault state, logs, and provenance | Hibernation, debugging, failure retention, offline maintenance transfer |
| **Thin** | Scenario, schedule, graph ancestry, and retained artifacts sufficient to replay from a valid ancestor | Source of truth and storage fallback |

All three denote one `ConfigurationId`. A materialization index may record which
tiers are currently available, but tier is not configuration identity.

The identities are deliberately distinct:

```text
ConfigurationId   H(scenario definition, semantic schedule)
ExactClosureId    H(authenticated exact-state manifest)
PageId/ExtentId   H(kind, schema, canonical plaintext bytes)
PackId/location   replaceable physical backend representation
```

An exact closure manifest maps stable public `(RAMBlockId, page-or-extent
index)` keys to logical page/extent IDs and compact zero, repeated, base, and
delta runs. Pack layout is not part of the manifest. QEMU exposes RAM-block and
extent metadata only through the versioned snapshot protocol; it never exposes
private structures to the Apache host.

- **[HFORK-1]** `instantiate(configuration)` MUST accept any admitted realization
  tier and return equivalent modeled state or fail with localized validation
  evidence.
- **[HFORK-2]** Hot and exact materializations are caches. Thin derivation and
  the replay oracle remain sufficient to validate them.

## 05.2 Why an explicit QEMU fork protocol is required

Calling `fork(2)` on arbitrary multithreaded QEMU is unsafe. Threads disappear
in the child while locks, RCU state, AIO contexts, bottom halves, device
callbacks, file descriptors, and shared mappings may reflect other threads.
Further, shared-memory rings are `MAP_SHARED` and would remain shared rather
than becoming private copy-on-write state.

Hot forking therefore requires a patched-QEMU **fork coordinator** that reaches
a stronger condition than ordinary stopped runstate:

```text
all vCPUs stopped at an authorized icount boundary
all device/AIO callbacks drained or parked
no QEMU lock held by a thread omitted from the child
no active RCU read-side section
timers and bottom halves in a checkpointable state
block graph at an external-snapshot boundary
plugin command/event channels frozen and acknowledged
host shared-memory rings frozen at authenticated cursors
QMP/control operation quiescent except the fork transaction
```

The coordinator forks only from its designated thread after every registered
subsystem acknowledges the barrier. Child startup reinitializes every declared
thread, lock, AIO, RCU, timer, and control resource before execution resumes.

- **[HFORK-3]** Hot fork MUST be a QEMU capability negotiated through the
  versioned control protocol. The Apache host MUST NOT infer safety from paused
  status or invoke a raw process fork externally.
- **[HFORK-4]** Every QEMU subsystem present in the supported launch profile MUST
  either implement the fork barrier/reinitialize contract or make that profile
  fail admission. Unknown devices and backends fail closed.

## 05.3 TCG-only initial scope

The initial hot-fork capability is limited to deterministic TCG/icount. A KVM VM
is represented partly by kernel objects whose file descriptors would refer to
the same kernel VM after a process fork; process copy-on-write does not clone
that state.

- **[HFORK-5]** KVM, HVF, WHPX, and other accelerator profiles MUST NOT advertise
  the initial hot-fork capability. Adding one requires a separate exact kernel
  state-cloning contract and conformance gate.

## 05.4 Fork-template lifecycle

A hot parent is a read-only execution template:

```text
running world
    |
reach a stable, hot-fork-capable branch boundary
    |
prepare exact host + QEMU continuation
    |
freeze as HotForkTemplate
    |\
    | +-- fork child A -> rebind -> select A -> run
    | +-- fork child B -> rebind -> select B -> run
    | +-- fork child C -> rebind -> select C -> run
    |
template remains paused and never advances
```

The template may have been created by normal execution or by restoring an exact
closure. Once promoted, it does not consume further modeled events. To continue
the original path, the daemon forks a default child rather than resuming the
template itself.

- **[HFORK-6]** A template MUST be immutable after publication. Any QMP command,
  plugin event, host ring write, disk write, or timer advance that changes it
  invalidates the template and all not-yet-admitted fork operations.
- **[HFORK-7]** Template identity MUST bind the configuration, exact boundary,
  QEMU/plugin capabilities, host continuation digest, disk base identities, and
  protocol versions.

## 05.5 Control protocol

The Apache host and GPL QEMU process communicate through new versioned messages:

```text
PrepareForkTemplate
  expected configuration and boundary identity
  child resource manifest shape

ForkTemplateReady
  authenticated QEMU state digest
  quiescence acknowledgements
  required child resource classes

ForkChild
  branch nonce for correlation only
  inherited-resource disposition table
  replacement control/shmem/disk descriptors

ForkChildReady
  child process identity for supervision
  restored configuration and state digest
  rebound-resource acknowledgements

ReleaseForkTemplate
```

Process IDs and host descriptors are operational response data and do not enter
configuration identity. Descriptor tables contain only public protocol roles,
flags, and indexes. QEMU-private pointers and structures never cross the socket.

All QEMU changes, including the coordinator and reinitialization callbacks, are
GPL-side and update the QEMU patch license/source ledger. The Apache host owns
campaign policy, storage, and world-transaction orchestration.

- **[HFORK-8]** Boundary changes MUST pass `gate:abi-conformance` and
  `gate:license-boundary`. The shared-memory ABI contains only fixed-layout
  public protocol values and checked offsets.

## 05.6 Child resource isolation

A fork child initially inherits the template's descriptors and mappings. It
must close, replace, or explicitly retain each resource according to a closed
manifest before it can report ready.

### Shared-memory rings

Command, event, network, block, 9p, coverage, and guest-doorbell rings cannot
remain backed by the template's writable `MAP_SHARED` objects. The host creates
new bounded memfd/shmem objects initialized from the frozen canonical bytes.
The child remaps them at protocol-defined roles and authenticates producer,
consumer, sequence, and generation cursors. The template retains its frozen
rings.

### Control sockets and QMP

The child closes inherited listening and connected sockets, creates a new
private control/QMP channel, and performs a generation handshake. The template
channel cannot accidentally command a child.

### Files and external services

Console logs, serial outputs, pidfiles, diagnostics, 9p exports, tap/socket
backends, and temporary files receive branch-private endpoints or are rejected
from the supported profile. The supported deterministic network path uses
Crucible's mediated device protocol, not an ambient host tap.

### Disk writes

Before template publication, each writable block root is frozen as an immutable
backing identity. Every child receives a fresh branch-private overlay referencing
that backing. No two running siblings write the same qcow2 file. Overlay
creation may use reflink or sparse metadata acceleration when available, but
correctness relies on immutable backing plus a distinct writable layer.

- **[HFORK-9]** Child readiness MUST fail if any inherited writable descriptor,
  shared ring, control endpoint, or disk layer lacks a closed disposition.
- **[HFORK-10]** A negative conformance gate MUST deliberately omit or alias each
  resource class and prove that the child is rejected before resume.

## 05.7 Host continuation cloning

RFC-0014's exact checkpoint closure identifies host-side state that QEMU
VMState alone cannot capture:

- scheduler frontier and deterministic event queue;
- signal programs, bindings, adapters, and search overrides;
- network, block, 9p, coverage, and guest-doorbell ring state;
- pending opportunities, completions, and outputs;
- per-node generation and service state;
- assertions, triggers, lifecycle state, and event-log cursors.

The daemon clones this continuation into an immutable parent plus branch-local
copy-on-write overlays. Persistent maps/vectors and content-addressed log
segments SHOULD make host clone cost proportional to future mutation, not total
history. A child QEMU is paired with exactly one cloned host continuation and
one selection proposal before it can run.

- **[HFORK-11]** A QEMU child without an authenticated matching host
  continuation MUST NOT resume. Pairing identity covers every node in the world.
- **[HFORK-12]** Host continuation clone and QEMU fork are one world transaction;
  partial publication is forbidden.

## 05.8 Atomic multi-node world fork

A scenario branch often contains several QEMU nodes. Forking it is an atomic
orchestration transaction:

1. stop the authoritative scheduler at a stable global boundary;
2. freeze every live node and every host/device continuation;
3. authenticate a common parent configuration and world-fork generation;
4. prepare child resource bundles for all nodes;
5. fork and rebind every node;
6. clone the host continuation;
7. verify every child reports the same parent and generation;
8. publish the child world session;
9. apply the proposed selection and resume under the scheduler.

If any node fails, every child created by the transaction is terminated, new
overlays/rings are discarded, and the parent template remains valid if its
state was not changed.

- **[HFORK-13]** A campaign branch is a world, not a bag of independently
  visible node forks. No consumer may observe a partially forked world.
- **[HFORK-14]** Permanently failed modeled nodes and non-VM I/O nodes must have
  explicit clone semantics in the host continuation even when no QEMU process
  exists for them.

## 05.9 Exact durable closure

The RFC-0014 exact closure is retained as the portable representation. It
contains a manifest and authenticated objects for scenario/configuration,
scheduler, logs, signal artifacts, trigger/assertion/lifecycle/fault state,
per-node snapshots, disk overlays, QEMU VMState, generations, and service state.

The single-host implementation chunks full overlay and VMState artifacts. It
keeps every running QEMU node paused after exact capture, hashes and streams the
run-directory overlay and VMState directly through bounded chunk buffers into
the content store, durably publishes the closure, then deletes the transient QMP
snapshot and resumes only nodes that were running. It does not create a second
full-file staging tree. Restore streams each authenticated file or chunk
sequence through a fixed 1 MiB buffer into an atomic destination-side staging
file, hashes the logical byte stream during that pass, and recreates zero runs
as sparse extents before durable publication. A corrupt, short, long, or
missing source leaves no partial destination. Cleanup attempts every captured
node even when one delete or resume fails. The remaining storage work is:

- represent disk state as immutable backing plus changed overlay objects;
- admit QEMU-emitted RAM dirty-page/extent manifests when the fork/snapshot
  capability is available;
- keep opaque device VMState as authenticated blobs;
- compact long delta chains without changing configuration identity;
- verify complete artifact length, chunk order, and whole-object digest.

The single-node exact-checkpoint foundation uses four registered immutable
objects. `crucible.qemu.vm-snapshot@device-state.2` is the owner-decoded
storage profile for canonical `QemuVmSnapshotV1` metadata and its projected
Apache state. `crucible.executor.scheduler-continuation@device-state.3` retains
the complete canonical `SingleSchedulerCheckpoint` required to continue all
scheduler, device, network, search, trigger, RNG, and event-log state.
Device-state version 1 remains reserved for opaque QEMU VMState, so the three
leaf roles cannot alias one logical content ID.
`crucible.qemu.vmstate@device-state.1` is the opaque QEMU qcow2 VMState byte
stream. `crucible.executor.exact-checkpoint-root@exact-manifest.3` is a generic
content envelope with exactly these sorted children:

```text
snapshot-metadata      -> crucible.qemu.vm-snapshot@device-state.2
scheduler-continuation -> crucible.executor.scheduler-continuation@device-state.3
qemu-vmstate           -> crucible.qemu.vmstate@device-state.1
```

Its fixed 88-byte body contains the 32-byte aggregate snapshot identity, the
32-byte materialized configuration identity, and big-endian `u64` metadata,
scheduler-continuation, and VMState byte lengths. The root therefore
authenticates one exact triple rather than independently reusable objects.
Preparation validates and hashes all children without writes. Publication
places metadata, scheduler continuation, and VMState first, requires durable
receipts for all three, and places the root last. The caller MUST
durably stage the expected root in its bounded assignment ledger before the
first put. The executor's `checkpoint-publishing`, `paused`, and
replay-validation `checkpoint-promoting(source,promoted)` records are the
retention roots across publication and restart. The promoting phase is
persisted before the first replacement write and retains both the raw source
and expected promoted root; only a fully authenticated exact raw-to-matching
pair may become `paused(promoted)`. A failed put may leave unreachable
immutable children for GC, but may not make an incomplete root visible. The
live session returns metadata, the scheduler continuation, and its reopenable VMState source
as one linear capture result, reaps QEMU, and hands that value to the fixed
worker pool. Preparation, root staging, publication, and paused-state
reconciliation each consume a distinct retryable phase token, so storage or
ledger failure never repeats guest execution or capture.

Raw paused-root replay validation uses the same guarded fat/thin comparison as
exact-pin validation, but its owner is the lineage-qualified attempt ledger.
The replacement reuses the source VMState content identity and rewrites only
the metadata/root carrying the matching oracle result. Restart can finish a
complete staged pair after authenticating both roots, shared VMState, and exact
metadata transition without rerunning QEMU. Missing/incomplete promoted bytes
leave the raw root retained for bounded validation/publication retry; stable
failure can explicitly restore `paused(raw)`.

The store admits only durable, conditional-create, streaming-read and
streaming-put backends. The VMState source is finite and reopenable and is
rejected from its declared length before it is opened when outside the exact
attempt ceiling. Restore copies the complete authenticated stream into staging
storage and may expose it to QEMU only after EOF, exact length, and digest have
all been observed. The first implementation streams the complete qcow2 object;
extent manifests and changed-state capture remain the required hot-path
optimization rather than a correctness precondition.

The complete multi-node production continuation uses version four of the same
typed root rather than flattening a potentially large object set into one
generic envelope. The registered leaves are the canonical
`crucible.production-exact-closure@device-state.4` manifest and exact opaque
production objects under
`crucible.executor.production-checkpoint-object@device-state.5`. Every object
retains its production BLAKE3 identity and declared length in a registered
`crucible.executor.production-checkpoint-index@exact-manifest.1` page. A page
contains at most 4,096 objects and has this canonical body and child mapping:

```text
"CRUCPIDX" || object_count:u32be
|| (production_content_hash:32 || logical_length:u64be)*

object-<production_content_hash_hex>
    -> device-state.5 CAS identity of those exact bytes
```

Non-final pages are full. The version-four root has one
`production-manifest` child and consecutive
`production-object-index-<eight-lowercase-hex-ordinal>` children. Its fixed
124-byte body is:

```text
production_closure_identity:32
|| scenario_identity:32
|| configuration_identity:32
|| manifest_bytes:u64be
|| object_count:u64be
|| aggregate_object_bytes:u64be
|| index_count:u32be
```

The page hierarchy preserves generic closure walking beyond the 65,536-child
envelope ceiling while the root still fits the common 64 MiB envelope bound.
Preparation streams every object through both its native production hash and
typed CAS hash without writes. Publication places the manifest, all objects,
and every index page before the root and requires exact durable receipts.
Loading authenticates the root, exact page sequence, global object order,
counts, lengths, and CAS mappings while leaving bodies lazy. Before QEMU launch,
the production-store installer reconstructs the canonical manifest/object
closure in private storage and applies the complete scenario-aware semantic
restore validator. It independently derives the manifest's closure identity,
scenario, and modeled configuration and requires all three to equal the claims
bound by the version-four root. The local configured checkpoint-byte ceiling applies to the
manifest plus deduplicated production-object bytes in addition to the authored
production resource bound. Before inventory allocation, the loader also
requires `object_count * 32 <= manifest_bytes`; every deduplicated object must
occur as at least one 32-byte identity in the canonical manifest, so this
conservative relation bounds hostile zero-length inventories by the 64 MiB
manifest ceiling.

The single-host restore transaction accepts either a current exact-pin
selection or the exact root retained by a paused execution origin. The latter
must name the attempt's pre-selection or post-selection configuration; a
foreign root is rejected before the first destination write. The transaction
pins the pre-provisioned run directory and VMState inode before copying. A
valid declared length is checked against the
attempt's aggregate writable-byte reservation before truncation. Beginning the
copy marks the destination unavailable for launch; only an exact-length,
authenticated, file-synchronized completion records the aggregate
`ExactCheckpointId` root binding, which covers `QemuVmSnapshot` metadata, the
complete scheduler continuation, and the opaque VMState child. The exact
launcher MUST require that binding
immediately before guarded spawn; metadata identity alone is insufficient. An
interrupted or failed copy remains
unready rather than falling back to the previously provisioned image, and a
replacement attempt restarts from byte zero. This operational binding is not a
new content identity and does not alter the immutable checkpoint root. Derive
`binding` by applying canonical `ContentHash` material hashing with domain
`crucible.executor.exact-vmstate-restore-binding.v1` to the lowercase
hexadecimal encoding of the typed `ExactCheckpointId`'s 32-byte digest.
The binding marker is process-local authority rather than trusted on-disk
metadata. After daemon restart, reopening the same pinned inode treats it as
unbound and repeats authenticated materialization from the retained root before
exact restore.

Version-two roots with only snapshot metadata and VMState and version-three
single-node roots remain readable for legacy authentication, migration, and
source-bound promotion. Version two is never resumable. Version three retains
the complete single scheduler continuation and remains useful for the existing
single-node oracle path, but it cannot represent the complete production
multi-node trigger/assertion/fault/network closure and MUST NOT be advertised as
packaged production resume. A version-four attempt resume must install and
validate the complete production closure described above before modeled guest
work; the concrete packaged capture/resume composition remains gated in the
implementation plan until that wiring is complete.

A newly captured exact root records replay-oracle state `NotRun` and is not
eligible for resume. The single-host owner authenticates the selected root and
compares that exact fat snapshot with an independently realized thin path. The
comparison returns a capability bound to the source snapshot identity rather
than an unbound boolean. A matching result publishes new snapshot metadata and
a new exact root while reusing the already-authenticated VMState child, then
atomically replaces the operational exact-pin selection. A mismatching,
foreign, stale, or unavailable comparison publishes nothing through this
promotion path and leaves the raw root non-resumable. Selection replacement
failure may leave only the newly published immutable root unreachable and
available for GC; it may not retarget the selection without a durable journal
commit. Real-QEMU comparison uses disjoint exact-target and thin-base launch
capabilities under one attempt-owned process/resource guard. The fat generation
is reaped before the thin generation launches, and the final thin generation is
reaped before promotion writes begin. A realization or reap failure transfers
the guard to quarantine and leaves the raw selection unchanged.

The public cross-process snapshot protocol may describe RAM blocks, page or
extent indexes, opaque artifact streams, and digests. It may not expose QEMU
private structures. Apache storage code treats QEMU blobs as opaque bytes.

- **[HFORK-15]** Durable capture SHOULD cost `O(changed state)` after a valid
  parent closure. A fallback full capture is correct but MUST be reported and is
  not the campaign hot path.
- **[HFORK-16]** Exact restore MUST authenticate the complete closure and pass
  the replay oracle before the restored runtime can become a fork template.

## 05.10 Hibernation, debugging, and offline maintenance transfer

### Hibernation

Pin the exact closure, release QEMU processes and hot pages, and retain the lazy
campaign continuation. Resume restores the closure and continues from the same
configuration.

### Failure retention

On critical failure, pin the nearest pre-failure exact closure, failing schedule
suffix, evidence, and post-failure closure when available. Arbitrary debugger
mutations create non-canonical derived sessions and never modify the retained
canonical state. A debugger selection at a declared branch point instead uses
an ordinary debugger-caused `BranchRequest` and remains canonical.

### Offline maintenance transfer

Quiesce the campaign, persist and pin the exact closure, ensure its complete
executable object closure in the destination store, validate
provenance/capabilities, restore during a separate operator action, optionally
promote it to a local hot template, and only then release the source
materialization. The campaign is not executing on both hosts and no distributed
scheduler is involved. The campaign ref may remain unchanged because location
is not identity.

- **[HFORK-17]** Migration failure MUST leave a valid source closure or process.
  Destructive source release occurs only after destination authentication.
- **[HFORK-18]** A destination with incompatible QEMU/plugin/protocol provenance
  MUST refuse restore and require a new lineage or an explicit offline migration
  format specified by a later RFC.

## 05.11 Fallback and capability policy

Hot fork is an acceleration, never a prerequisite for correctness. When the
launch profile, host kernel, QEMU device set, memory pressure, or fork gate does
not admit it, the daemon uses exact restore or thin replay. Status and telemetry
explain the fallback.

- **[HFORK-19]** Disabling hot fork MUST not change the configuration/finding set
  produced by a strict campaign under the same policy, budget, and observations.
- **[HFORK-20]** A hot-fork failure after a child is created but before child
  readiness is an operational retry. It MUST NOT create a temporal-graph edge or
  campaign reward.

## 05.12 Fork cost and memory-layout optimizations

Copy-on-write eliminates the eager copy of guest RAM bytes, but it does not make
a child free. Linux still duplicates virtual-memory metadata and page tables for
present mappings; QEMU and the host still need branch-private stacks, rings,
overlays, and thread state; and a write in any branch creates a private physical
page. Thousands of logical descendants are therefore practical, while the
number of simultaneously runnable children remains a resource-policy decision.

The supported launch profile optimizes the complete child-ready path:

- guest RAM uses private forkable mappings; a shared writable RAM backend is
  rejected or converted at template preparation into an authenticated immutable
  backing mapped privately by the template and children;
- QEMU marks reconstructible non-semantic scratch mappings `MADV_DONTFORK` when
  the platform supports it and recreates them before child readiness;
- shared protocol rings are small, frozen separately, and replaced rather than
  forcing the main RAM mapping to be shared;
- child sockets, memfds, overlay descriptors, directory identities, cgroup
  assignments, and protocol nonces are prepared before entering the shortest
  possible quiescent interval;
- one successful template preparation permits a sequence of child transactions
  without re-running guest setup or convergence; the coordinator repeats only
  the closed fork/rebind checks that can change between children;
- immutable file-backed pages, zero pages, code, and read-mostly QEMU heap state
  remain shared naturally until written;
- transparent huge-page, NUMA, page-table, allocator-arena, and dirty-page
  behavior are benchmarked as part of the capability profile rather than
  assumed beneficial; and
- pidfds or equivalent race-free process handles supervise children, while
  descriptor disposition uses a precomputed closed table instead of scanning
  ambient process state after resume.

`CLONE_VM` is not an alternative: it would share writable address space rather
than create isolated copy-on-write branches. Kernel same-page merging is not a
correctness mechanism and is not required. Reflinks are useful for file
materialization but do not substitute for distinct writable disk overlays.

A descendant that reaches another stable boundary may itself be frozen as a new
template. This produces a tree of local COW hubs that follows valuable deep
paths instead of repeatedly forking every descendant from genesis. Template
promotion is bounded by predicted reuse, prepare cost, memory pressure, depth,
and retention policy. Evicting any hub leaves its semantic node and exact/thin
realizations intact.

- **[HFORK-21]** Every writable mapping in a template capability profile MUST be
  classified as private-COW, replaced in the child, reconstructed in the child,
  or forbidden. `MAP_SHARED` inheritance is never presumed to become COW.
- **[HFORK-22]** The child MUST execute no guest instruction and emit no
  canonical event until RAM isolation, descriptor disposition, host
  continuation pairing, and protocol-generation authentication all succeed.
- **[HFORK-23]** Fork optimization MUST preserve a forced slow path for every
  platform-specific acceleration and prove equivalent state through the
  hot-fork gate.
- **[HFORK-24]** The daemon MUST enforce configurable limits for total hot
  template bytes, expected private dirty bytes, process count, vCPU count,
  descriptors, overlays, and fork rate. Pressure changes placement or
  realization tier, never semantic proposal priority in strict mode.
