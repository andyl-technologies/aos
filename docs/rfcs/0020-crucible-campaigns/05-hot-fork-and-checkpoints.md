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
| **Exact** | Portable authenticated closure containing QEMU VM state, disk deltas, host continuation, scheduler/fault state, logs, and provenance | Exact pause, debugging, failure retention, offline maintenance transfer |
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

Hot fork uses one closed QMP protocol owned by the patched QEMU process. The
Apache host may stage public descriptors and request transitions, but it cannot
manufacture QEMU readiness or infer it from process state. Unknown schema
versions, fields, resource classes, proof bits, and outcome variants fail
closed.

The current template protocol is schema 29. It has four operations:

```text
crucible-hot-fork-template prepare
crucible-hot-fork-template query
crucible-hot-fork-template abort
crucible-hot-fork-template adopt-child
```

`prepare` authenticates the exact deterministic TCG profile, paused instruction
boundary, device flush, block snapshot, and every retained subsystem barrier.
`query` is observational. `abort` rolls back a retained transaction and keeps
ownership until every barrier reports released. `adopt-child` consumes an
already authenticated paused child, assigns a fresh template generation, and
re-runs the complete preparation transaction so descendants use the same
contract as first-generation children.

Each template report carries a typed `failure-stage` and a UTF-8
`failure-detail` bounded to 255 bytes. QEMU retains the most recent preparation
or rollback failure and clears it only when a new preparation begins. The host
rejects unknown stages, oversized details, or details inconsistent with the
`none` stage.

The parent template proof bitmap has seven defined bits:

| Bit | Retained parent proof |
|---:|---|
| 0 | precise instruction counting |
| 1 | single-threaded deterministic TCG execution |
| 2 | exact paused and device-flushed boundary |
| 3 | complete asynchronous-worker barrier |
| 4 | complete RCU barrier |
| 5 | immutable block snapshot and writable-root binding |
| 6 | private plugin rings and complete plugin worker barrier |

The required bitmap is exactly bits 0 through 6. Descriptor and mapping
disposition and child-runtime reconstruction are child results; they cannot be
asserted by a retained parent. `ready` is true only for an active prepared
transaction with every required proof, no missing proof, and quiescent plugin,
RCU, asynchronous-worker, and block barriers.

The asynchronous-worker barrier closes admission across AioContexts, AIO
handlers, coroutines, bottom halves, and timers. The RCU barrier drains readers
and callbacks while retaining the exact coordinator reader. The block barrier
holds graph mutation, drains every admitted backend, and binds each writable
root to an immutable snapshot source. The plugin barrier parks every registered
producer, consumer, control, teardown, and fingerprint worker and applies
`MADV_DONTFORK` to the source mappings. Thread, mutex, RCU, AIO, timer, block,
descriptor, and mapping inventories are bounded and generation checked inside
the QEMU transaction; callers cannot promote an observational inventory into a
readiness proof.

Before `prepare` may report ready, the host stages one complete branch-private
resource set:

- a shrink-sealed memfd containing the canonical private plugin-ring image;
- distinct plugin control and wake endpoints;
- a private diagnostics stream, QMP stream, and console stream;
- the child process contract, runtime generations, and complete worker plan;
- sorted descriptor replacement and retention tables;
- sorted writable shared-mapping dispositions with authenticated backing
  descriptors; and
- branch-private block overlays, network endpoints, 9p endpoints, temporary
  files, and every other writable output in the supported profile.

Descriptors cross QMP only through standard `getfd` plus the typed Crucible
staging operations. QEMU independently duplicates and authenticates every
staged file description. Resource identity includes the relevant kernel
identity, size, seals, socket cookie, offset, target slot, and owning template
generation. Descriptor tables allow at most 4,096 replacements and 4,096
retained slots. Mapping authentication accepts at most 65,536 records, 8 KiB
per record, and 16 MiB in aggregate. Inputs must be strictly sorted,
nonoverlapping, pairwise non-aliasing where required, and complete in both
directions.

The public fork command uses schema 3 and binds the exact template and staged
resource generations:

```text
crucible-hot-fork(
    template generation,
    private-ring generation,
    diagnostics generation,
    child-QMP generation,
    child-console generation,
    monitor generation,
    plugin-endpoint generation,
    plugin-barrier generation,
    RCU-barrier generation,
    async-worker-barrier generation,
    block-barrier generation,
    parent-process generation,
    child-process generation,
    child-process-contract generation,
    child-files generation,
) -> fork outcome and authenticated child basis
```

Preparation, `fork(2)`, and parent disposition run on the designated QEMU main
loop through a notifier outside the barriers it parks. The child first arms
parent-death containment and proves its immediate parent generation. With
signal and descriptor admission closed, it applies the complete descriptor
table, authenticates every retained mapping, and reconstructs the process-local
thread, mutex, RCU, AIO, timer, block, plugin, monitor, QMP, console, and device
owners. It creates fresh branch-private workers and channels while guest input
remains held. Only after every disposition commits does it emit the private QMP
greeting, release QMP and console input, release guest execution, and publish
its readiness report.

Child QMP schema 8 acknowledges readiness only when the resource plan and
descriptor disposition are committed, runtime and plugin reconstruction are
complete, the greeting was sent, and replacement input was released. The host
must authenticate that report on the staged private QMP stream and match every
retained generation and kernel identity before constructing a child node. A
positive PID is correlation data, not daemon-owned process authority. The
parent QEMU retains direct-child status until the daemon transfers the exact
child generation into its cgroup, pidfd, resource-accounting, and lifecycle
owners.

The daemon pairs that child with exactly one copy-on-write host continuation.
The continuation carries the private plugin mapping and endpoints, console
observation spool, scheduler cursors, pending events, coverage, selectable
state, topology send authority, and branch-local device continuations. QEMU
readiness and host-continuation installation commit as one world transaction.
Any node failure before publication rolls back the entire candidate world; an
indeterminate fork, parent disposition, channel exchange, adoption, or cleanup
result quarantines the owning source generation.

A successful child may remain an ordinary running node, be retired, or be
paused and promoted through `adopt-child`. Promotion consumes inherited staging
state, allocates fresh process and template generations, validates the complete
supported-profile inventory again, and retains the ancestor process authority
chain until all descendants are retired. Direct reuse of an ancestor identity
is rejected.

Abort is explicit. It releases plugin, asynchronous-worker, RCU, and block
admission in the required order and retains coordinator ownership when a
release must be retried. Separately owned staged descriptors are released only
through their exact resource operations. Explicit rejection before `fork(2)`
leaves the source reusable. Any ambiguity after a child could exist is resolved
through the parent-owned retained-status protocol before retry, reap, or
quarantine; the host never creates `std::process::Child` authority from a
reported PID.

Process identifiers and descriptors are operational response data and do not
enter configuration identity. Public descriptor and mapping tables contain
only protocol roles, flags, indexes, checked offsets, and stable scalar
identities. QEMU-private pointers, structs, callbacks, and native enum layouts
never cross the process boundary.

All QEMU coordinator, inventory, fork, and reinitialization code is GPL-side.
The Apache host owns campaign policy, storage, world orchestration, and guest
assertion evaluation.

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

The current single-node transaction prepares both halves before asking QEMU to
fork. It copies the scheduler-owned shared-memory continuation onto the exact
private ring and reconstructs independent host block, 9p, and deterministic
accelerator devices from a checkpoint bound to the fork request and private
ring identity. Immutable block bases and 9p trees may be shared; writable
overlays, device queues, visibility state, directives, pending completions, and
transport cursors may not. A source signal coordinator is world authority, not
per-node cloneable state: the child remembers that coordinated servicing is
mandatory and rejects device work until the branch's atomic world transaction
installs a fresh coordinator. A live console uses an exact pre-staged
branch-private endpoint. Its QEMU generation is part of the sealed resource
plan and fork request, while its host reader and observation spool move only
into the successful child continuation. Multi-node pairing and publication
remain governed by §05.8 and are not implied by the single-node launch token.

The host prepares the branch-private ring, diagnostics stream, child QMP,
child console, and plugin control/wake endpoints through one composite node
operation. That operation accepts only an active template awaiting exactly the
plugin-ring/resource proof with no preexisting local stage, performs the six
descriptor operations in dependency order, and then compares QEMU's complete
prepared resource report with every node-owned proof. It does not accept raw
generation values and does not install process authority. The daemon's linear
launch owner subsequently obtains the exact target attempt's sealed process
contract, stages it against the authenticated template generation, and only
then invokes the fork. A proven pre-fork rejection rolls that contract stage
back before returning the source and target owners. Ambiguous or post-fork
failure retains the complete staged ownership for reconciliation or
quarantine. Thus neither a modeled driver nor a caller can omit, reorder, or
substitute a child resource or containment contract.

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

The current daemon implements the all-or-nothing admission half of this
transaction. It keeps each installed node child private until all running
nodes exact-match the captured installed-node, source-process, configuration,
event-prefix, private-channel, scheduler-node, and process-local
assembly-incarnation basis; partial assembly drop quarantines all children
already admitted. One bounded aggregate target owner now reserves every node
before its fork and keeps CPU, memory, writable storage, sticky cancellation,
and execution-quanta enforcement indivisible across the child set. An explicit
pre-fork rejection rolls back only the unused node reservation; every ambiguous
or post-fork failure quarantines the complete owner. Per-node reconciliation
may record exact child cleanup, but only the aggregate owner can release the
underlying attempt guard after all issued nodes finish. The lifecycle library
now exposes the all-or-nothing adoption boundary for that private child set. It
consumes the opaque host continuation and exactly one linear child process/lease
for every running or powered-off node, rejects partial Worlds, requires each
child generation to be the checked immediate successor of its source, and
reauthenticates every process incarnation before publication. The continuation,
rather than a new caller-supplied launch configuration, retains the source
lifecycle configuration, immutable root identities, and resolved block/9p
bindings; only a fresh durable run-state root is supplied at adoption. It also
retains a complete ordered inventory of the World's block and 9p nodes. Each
entry binds the I/O-node and owner identities, device family, immutable
artifact, owner service state, original execution binding, and canonical host
checkpoint identity. Running and powered-off owners carry independently cloned
host-I/O projections. Permanently failed owners carry the process-free host-I/O
checkpoint transferred when failure committed, together with the authentic
execution fingerprint sampled at that exact failure boundary. They have no QEMU
child or live block-device alias. Construction verifies the active/failed owner
partition and the complete World I/O inventory before adopting children, then
rechecks every active projection against the adopted runtime before publication.
Any backing change or unconsumed child-world state fails closed.

The daemon now invokes this constructor and transfers the aggregate attempt
owner into the resulting lifecycle. The production runner executes the captured
scheduler continuation and retains that lifecycle through durable result
publication and disposition-ordered cleanup. Its packaged executor captures
prepared worlds into the shared managed pool and routes compatible fresh work
through this path. Scripted regressions cover successful multi-node publication
and reuse, exact failed-node fingerprint retention, process-free failed-node
host I/O, a proven first-child rejection with exact source recovery, and failure
cases that retain or quarantine ownership. Scripted assembly also covers a
powered-off retained source. The real-QEMU atomic-world matrix remains mandatory
before T-CAM-7.4 is marked complete.

The aggregate guard provisions a separate pinned target run directory for each
child. QEMU copies the frozen source VMState and writable root overlay into
that directory, and the host seals their identities against the successful
child-file proof. Before adoption, the daemon revalidates both named files and
the directory path against its retained descriptor. Later lifecycle generation
ownership uses the adopted path while the supervisor-owned mode-`0700` attempt
root prevents the QEMU child from replacing its directory entry. Exact
checkpoint capture opens the writable overlay through the retained directory
descriptor and rejects a replaced named inode or symlink before reading bytes.
A missing or changed handoff quarantines the child before world publication.

- **[HFORK-13]** A campaign branch is a world, not a bag of independently
  visible node forks. No consumer may observe a partially forked world.
- **[HFORK-14]** Permanently failed modeled nodes and non-VM I/O nodes must have
  explicit clone semantics in the host continuation even when no QEMU process
  exists for them.

## 05.9 Exact durable closure

The RFC-0014 exact closure is retained as the portable representation. The
current schema is version nine. It contains a manifest and authenticated
objects for scenario/configuration, scheduler, logs, signal artifacts,
trigger/assertion/lifecycle/fault state, per-node snapshots, disk overlays,
QEMU direct-plus-delta RAM layers, final device state, generations, and service
state.

The single-host implementation stores QEMU RAM as a bounded direct layer
followed by bounded parent-relative delta layers. The final non-RAM device
state is a separate authenticated descriptor. A root overlay is represented as
immutable backing plus a canonical sparse changed-chunk map. Capture keeps
every running QEMU node paused, discovers allocated
overlay ranges with `SEEK_DATA`/`SEEK_HOLE`, canonicalizes allocated all-zero
chunks back to holes, and streams only nonzero changed chunks plus the
descriptor-backed QEMU state into the content store. A filesystem without
reliable extent discovery fails closed
rather than falling back to work proportional to the virtual disk. The closure
is durably published before transient QMP snapshots are deleted and only nodes
that were running are resumed. No second full-file staging tree is created.

Version-nine sparse overlay artifacts carry a logical `length`, no dense
`chunks`, and strictly ordered, nonoverlapping, nonadjacent extents. Each
extent contains a `start_chunk` and one or more consecutive BLAKE3 chunk
identities; chunks are 4 MiB except for a final partial logical chunk. Omitted
logical chunks are canonical zeroes. The sparse artifact identity is
`H("crucible.production-exact-sparse-artifact.v1",
hex(canonical_cbor({length, extents})))`; stored chunk bytes independently
authenticate against their named identities. This binds the exact logical byte
stream without hashing every omitted zero during capture.

Restore authenticates the extent geometry, identity, and every stored chunk,
then writes those chunks into a new destination-side staging file and creates
omitted ranges as holes. Each RAM and device-state object is materialized into
an already-open sealed descriptor, rewound, and bound into one v9 restore
request before QEMU starts. A corrupt, short, long, or missing source leaves no
partial destination. Cleanup attempts every
captured node even when one delete or resume fails. Hashing, chunk persistence,
portable closure validation, and campaign-store streaming observe attempt
cancellation between bounded I/O chunks; cancellation cannot bypass cleanup or
be misclassified as retryable store I/O. Production RAM capture bounds retained
chains at eight layers. When an eight-layer parent is committed, the next
capture is admitted as a complete direct capture. Its published manifest has
one direct layer, no parent-closure provenance, and the new QMP checkpoint,
target, and frontier identity. The prior CAS lease remains rollback authority
until durable publication and reconciliation select the replacement; successful
reconciliation then retires the ancestor leases. This capture-time rebase bounds
the runtime chain without changing configuration identity or requiring a
separate offline compaction path.

Only version-nine manifests are decoded and authenticated. There is no
alternate monolithic VMState reader or restore path.
`crucible.qemu.vmstate@device-state.1` is the opaque QEMU qcow2 VMState byte
stream. Production publication uses
`crucible.executor.exact-checkpoint-root@exact-manifest.5`. The root commits to
the version-nine closure manifest and its direct-or-delta RAM layers, device
state, scheduler continuation, immutable backing, fault checkpoint, and bounded
choice records discovered before the pause. The assignment ledger stages that
root before publication, and publication makes
the authenticated children durable before exposing the root. A process-local
replay claim is issued only by a completed guarded raw-to-promoted comparison;
persisted bytes alone cannot authorize restore, and reopening the store requires
the comparison to run again. Offline conversion returns authenticated data but
never process-launch authority. Sparse overlay restore authenticates the exact
extent manifest and every named chunk before atomically exposing a file whose
omitted ranges are zero holes.

The complete multi-node production continuation uses version nine of the same
typed root rather than flattening a potentially large object set into one
generic envelope. The registered leaves are the canonical
`crucible.production-exact-closure@device-state.9` manifest and exact opaque
production objects under
`crucible.executor.production-checkpoint-object@device-state.5`. Every object
retains its production BLAKE3 identity and declared length in a registered
`crucible.executor.production-checkpoint-index@exact-manifest.1` page. A page
contains at most 4,096 objects and has this canonical body and child mapping:

The current manifest carries strictly node-ordered selectable catalog plans in
the bounded lifecycle-continuation object. Each plan remains the canonical
`CRUCSCP3` process-neutral body, is at most 32 MiB, and must be frozen and bound
to a live checkpoint target. Every live target is bound to the BLAKE3 identity of
the immutable root-image bytes supplied to QEMU. Lifecycle construction hashes
the selected image, and capture includes that identity in both the target record
and target-manifest identity. Restore rejects a mismatch before launching QEMU.
The manifest uses the canonical sparse extent representation above for overlay
chunks while retaining dense device-state chunks. It additionally retains one
canonical process-free host-I/O checkpoint for every permanently failed VM. Its
strictly node-ordered manifest record binds the owner's original execution
binding, checkpoint object identity, fingerprint sample time, and execution
fingerprint hash. The current schema records each live target's exact checkpoint identity, ordered direct-plus-delta
RAM layers, shared topology identity, and final device-state object. Those
records participate in the closure identity, object inventory, byte budgets,
publication, and authentication. A permanently failed node without exactly one
matching record is rejected. Every noncurrent schema is rejected during decode.

```text
"CRUCPIDX" || object_count:u32be
|| (production_content_hash:32 || logical_length:u64be)*

object-<production_content_hash_hex>
    -> device-state.5 CAS identity of those exact bytes
```

Non-final pages are full. The version-five root has one
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
bound by the version-five root. The local configured checkpoint-byte ceiling applies to the
manifest plus deduplicated production-object bytes in addition to the authored
production resource bound. Before inventory allocation, the loader also
requires `object_count * 32 <= manifest_bytes`; every deduplicated object must
occur as at least one 32-byte identity in the canonical manifest, so this
conservative relation bounds hostile zero-length inventories by the 64 MiB
manifest ceiling. Noncurrent production closure versions are rejected during
decode; runtime restore requires the version-nine descriptor set.

For a packaged fresh attempt, the modeled driver yields checkpoint ownership
only at an exact safe boundary. The production lifecycle first retains the
complete portable source in its separately bounded native catalog. While that
lifecycle is still owned by the runner, the fixed pool authenticates the source
scenario, streams every native object to derive the version-five campaign root,
and persists `checkpoint-publishing(root)` before the first campaign-CAS put.
The runner then tears down the lifecycle and returns an opaque prepared token;
the pool publishes the immutable closure and moves to `paused(root)` without
repeating guest execution or capture. External models cannot construct the
opaque prepared phase, and idempotent staging never releases the active
reservation before teardown. The packaged single-host owner composes native
cleanup with those durable roots. After the campaign-CAS root is complete, it
renames the attempt-owned scenario catalog to a deterministic retired
generation, synchronizes the parent directory, removes that generation, and
synchronizes the parent again before the final paused-state CAS. Abort, stale,
and promotion-revert paths retain the same cleanup authority and retry without
guest work. At restart, the exclusive assignment-ledger writer first
authenticates the complete retained checkpoint-root inventory, then applies the
same crash-safe retirement protocol to the dedicated `campaign-workers` and
`campaign-checkpoint-promotions` namespaces before creating any worker. The
separate baked-genesis catalog is not retired by this recovery pass.

The single-host restore transaction accepts a current version-nine exact-pin
selection or the version-nine root retained by a paused execution origin. The
latter must name the attempt's pre-selection or post-selection configuration;
a foreign root is rejected before the first destination write. Before any
root-overlay write or memfd creation, the transaction checks the aggregate
overlay, RAM-layer, and device-state bytes against the checkpoint resource
ceiling. It then authenticates and seals every RAM and device descriptor,
rewinds them, and builds one request whose ordered layers, topology, target,
frontier, and checkpoint identity match the manifest. The launcher rechecks
that binding immediately before guarded spawn; metadata identity alone is
insufficient. An interrupted or failed materialization remains unready. It
cannot fall back to a provisioned image, a monolithic VMState file, or a
previous generation.

Production process reconstruction and resume-driver selection require a
version-nine manifest with descriptor-backed exact RAM and device state. The
installer requires the branch post-selection configuration (or the discovery
start) as an exact schedule prefix and rejects any later campaign branch edge
as a different attempt before native-catalog publication. The resume-only
admission rejects `NotRun` before native publication or resource installation,
restores the complete scheduler/evidence continuation, and never falls back to
fresh replay. The concrete node-specific replay factory shares one completely
authenticated compact target catalog, opens only the requested version-nine
snapshot, streams the selected exact and baked descriptor sets into separate
pinned generations under one attempt guard, and launches them through disjoint
exact and thin profile capabilities. Packaged startup captures that baked
source before binding the endpoint, installs one fixed promotion owner per
semantic worker, and advertises `ExactRestore` only when that nonempty owner set
contains a current version-nine root.
Assignment-root-aware cleanup of abandoned attempt and promotion native
catalogs is implemented by the crash-safe retirement protocol above. A
`checkpoint-publishing(root)` record interrupted before immutable publication
retains the expected content identity; restart deterministically recaptures and
must reproduce that root. Once the root is complete in campaign CAS, the native
catalog is redundant and may be retired without weakening recovery or GC
reachability.

A newly captured version-nine exact root records replay-oracle state `NotRun`
and is not eligible for resume. The single-host owner authenticates the
selected root and compares that descriptor-backed exact snapshot with an
independently realized thin path. The comparison returns a capability bound to
the source snapshot identity rather than an unbound boolean. A matching result
publishes new snapshot metadata and a new exact root while reusing the already
authenticated RAM-layer and device-state objects, then atomically replaces the
operational exact-pin selection. A mismatching,
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

## 05.10 Exact pause, debugging, and offline maintenance transfer

### Exact pause

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

- guest RAM uses private forkable mappings, which the template establishes by
  advising every RAM block `MADV_DOFORK` while it is retained; a shared
  writable RAM backend is rejected or converted at template preparation into
  an authenticated immutable backing mapped privately by the template and
  children;
- QEMU marks reconstructible non-semantic scratch mappings `MADV_DONTFORK` when
  the platform supports it and recreates them before child readiness;
- the live source protocol-ring mapping is now frozen and marked
  `MADV_DONTFORK` by the version-6 plugin barrier, then restored with
  `MADV_DOFORK` before the parent reopens. QEMU and the GPL plugin now register
  a fixed version-3 child-runtime operation that binds the staged template,
  private-ring, endpoint, and plugin-barrier generations; authenticated socket
  and eventfd identities; private-ring device, inode, length, and descriptor;
  the exact source setup-region VMA; replacement control and wake descriptor
  numbers; and sealed worker mask. Private-ring schema version 3 binds
  that source by its unique writable-shared device, inode, page-aligned length,
  zero file offset, and process-local address under the bounded procfs mapping
  profile. A duplicate, partial, missing, or mismatched source mapping fails
  staging, and standalone staging grants no source-range authority. Its plan
  additionally binds the template's exact nonzero process generation to its
  checked immediate successor. QEMU advances its fault/evidence lifecycle
  generation before reconstruction, the plugin independently advances its live
  device owner, and status echoes that exact process and resource basis. QEMU
  now exposes that registered runtime through the OOB version-3
  `query-crucible-hot-fork-child-runtime` observation. The exact report binds
  callback registration to the complete resource manifest and current process
  generation, carries the child phase, staged resource generations,
  authenticated endpoint identities, and worker state, and advances its
  checked process-local generation only when registration or observed status
  changes. The report also carries the exact source VMA start, length, and zero
  offset in both the initialization plan and persistent status. QEMU rejects a
  non-page-aligned, overflowing, differently sized, or nonzero-offset plan; the
  plugin independently requires that geometry to equal its retained mapping
  owner before installing the replacement. Repeated identical queries are
  stable and the report's readiness
  acknowledgement is always false. The
  plugin independently
  authenticates both replacement endpoint identities, installs the exact private
  mapping, revalidates the retained ABI/layout contract, replaces callback-held
  teardown routing, and reconstructs the held control, teardown, and optional
  fingerprint workers. The permissive shared-memory boundary supplies the
  exact-address Linux install primitive: it authenticates the non-aliasing
  destination device, inode, length, and shrink seal, requires the source VMA
  to be absent, and maps with `MAP_FIXED_NOREPLACE`. A real `fork(2)` regression
  proves the child writes the private backing while the parent's source mapping
  and backing identity remain unchanged. Stale, skipped, zero, and overflowed
  process generations fail before child admission. The QEMU fork transaction
  now has a prepared one-shot adapter that copies a valid plan and invokes the
  process-global registered runtime exactly once. It accepts completion only
  when the exact plan is echoed with callbacks held, the private mapping
  installed, every sealed worker parked, and no pending operation. The
  real-fork child-resource unit path composes that adapter with exact descriptor
  closure and mapping verification through a fake registered runtime; the
  plugin's actual callback remains covered separately by its exact-plan and
  remap tests. The retained template transaction derives that
  exact plan and copies it into the one-shot adapter before it admits the
  endpoint stage. Its report carries the checked parent/child generation pair
  and whether the unconsumed adapter still matches every retained resource
  field; replay requires the same plan and exact endpoint release clears the
  parent copy. The production fork transaction invokes this composition before
  it releases the child QMP input, including the closed descriptor table,
  non-plugin subsystem reconstruction, immutable host-continuation pairing,
  guest release, and the child-only mapping and reconstruction proofs;
- shared protocol rings are small, frozen separately, and replaced rather than
  forcing the main RAM mapping to be shared;
- child sockets, memfds, overlay descriptors, directory identities, cgroup
  assignments, and protocol nonces are prepared before entering the shortest
  possible quiescent interval;
- one successful template preparation permits a sequence of child transactions
  without re-running guest setup or convergence; the coordinator repeats only
  the closed fork/rebind checks that can change between children. Between
  children the host releases the stages the last fork consumed (plugin
  endpoints, child console, child QMP, diagnostics, private ring, then the
  reaped child record, the process contract, and the child-file plan) while
  the template stays retained at its barrier phase, and QEMU recomputes the
  template's readiness proofs from the stages that remain, returning it to the
  state the next child's staging requires; a release is refused only during a
  fork operation or a transitional template phase;
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
  realization tier, never semantic proposal priority in strict mode. Fork rate
  is measured over one configured fixed-duration monotonic host-time window;
  every admitted process-fork attempt is charged even when later preparation
  fails. The retained-pool owner MUST bind the selected fallback to an exact
  `ExactCheckpointId` or thin `ConfigurationArtifactId`, authenticate that
  identity before source transfer, reauthenticate it at the release boundary,
  and reap the idle source before releasing its accounting. Partial
  multi-source demotion failure MUST preserve completed releases, restore the
  failed source authority at its exact stable coordinate, and leave the
  candidate uninstalled.
