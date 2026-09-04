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

The Apache host and GPL QEMU process communicate through new versioned messages.
The host uses the bounded `query-crucible-hot-fork-readiness` QMP command to
read QEMU's own proof state; it never infers readiness from launch arguments or
ordinary paused status. The version-1 response is:

```text
CrucibleHotForkReadiness {
    schema-version: u32 = 1,
    required-proofs: u64 = 0x01ff,
    acknowledged-proofs: u64,
    ready: bool,
}
```

The nine low-order proof bits have this fixed meaning:

| Bit | QEMU-owned proof |
| --- | --- |
| 0 | precise icount is active |
| 1 | deterministic `sim` uses one round-robin TCG thread |
| 2 | QEMU is paused at an exact boundary and device flush completed |
| 3 | AIO contexts, bottom halves, and timers are drained or parked |
| 4 | relevant RCU callbacks and read-side sections are quiescent |
| 5 | writable block roots are at immutable external-snapshot boundaries |
| 6 | plugin command/event channels and shared-memory rings are frozen |
| 7 | every mapping and descriptor has a closed child disposition |
| 8 | every omitted thread and process-private resource has a child reinitializer |

`required-proofs` MUST equal `0x01ff`, `acknowledged-proofs` MUST be a
subset, and `ready` MUST equal exact bitmap equality. An unknown version,
changed required bitmap, unknown acknowledged bit, or contradictory boolean is
a protocol failure. The first QEMU-side checkpoint acknowledges only proofs it
can already derive from precise sim RR plus the authenticated VM-stop/device
flush boundary. Bits 3 through 8 remain clear, so hot fork remains unavailable,
until their subsystem-owned barriers and reinitializers land. The query is
observational and does not itself pause, prepare, fork, or mutate the VM.

Patched QEMU also exposes the versioned, bounded internal thread-registry
snapshot used to drive that future barrier:

```text
CrucibleHotForkThreadInventory {
    schema-version: u32 = 4,
    generation: u64,
    complete: bool,
    overflowed: bool,
    unclassified-threads: u32,
    threads: [
        {
            thread-id: positive i64,
            name: nonempty UTF-8 string of at most 256 bytes,
            name-valid: bool,
            joinable: bool,
            disposition:
                coordinator |
                unclassified |
                rcu-restart |
                monitor-restart |
                unclassified-aio,
        },
    ],
}
```

`threads` MUST contain at most 65,536 entries in strictly increasing thread-ID
order. `unclassified-threads` MUST equal the number of `unclassified` and
`unclassified-aio` dispositions, at most one coordinator may be present, and
`complete` MUST equal
`!overflowed && all(name-valid) && coordinator-count == 1`. The process-local
generation advances when a QEMU-created thread registers, unregisters, or
changes disposition. The first query registers the process-lifetime QMP
main-loop coordinator; later observational queries with no thread transition
return the same generation and body. Every thread created through
`qemu_thread_create()` is registered before its start routine and unregistered
through a cleanup handler. Threads created by linked libraries or raw pthread
calls are not silently treated as QEMU-owned.

Schema version 4 assigns the `call_rcu` worker to `rcu-restart`, the exact
internal QMP IOThread to `monitor-restart`, and every other QEMU `IOThread` to
`unclassified-aio` through calls made by the owning subsystems, not by matching
diagnostic names. The runtime transaction admits exactly one coordinator, one
RCU worker, and one monitor worker. It discards both inherited workers in the
child, registers one fresh callback worker after RCU reconstruction, and leaves
the already-bound child-QMP reinitializer to start the replacement monitor
worker while input remains held. Generic and other AIO workers remain fork
blockers and are counted in `unclassified-threads`; neither these
classifications nor the transaction acknowledges readiness bit 8. Plain
`unclassified` remains the fail-closed value for every other
`qemu_thread_create()` caller. Earlier schema versions are rejected rather than
silently interpreting their smaller disposition registry under version-4
semantics.

Patched QEMU also exposes the bounded observational RCU inventory used to
define the next subsystem-owned barrier:

```text
CrucibleHotForkRcuInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    registered-readers: u32,
    active-readers: u32,
    pending-callbacks: u64,
    drain-active: bool,
    readers: [ { thread-id: positive i64, active: bool } ],
}
```

`readers` MUST contain at most 65,536 entries in strictly increasing thread-ID
order. `registered-readers` and `active-readers` MUST match the retained body,
and `complete` MUST equal `!overflowed`; malformed IDs are protocol failures.
The process-local generation advances only when a reader registers or
unregisters. `pending-callbacks` is incremented before callback queue
publication and decremented only after callback return, so it conservatively
covers the callback worker's dequeue, grace-period, and execution interval.
Every retained reader MUST also appear in the matching QEMU thread inventory.

The inventory response remains only one lock-bounded observation. It does not
itself drive or hold quiescence and therefore MUST NOT acknowledge proof bit 4
or authorize a fork. Patched QEMU separately exposes the version-1 reversible
RCU admission barrier:

```text
CrucibleHotForkRcuBarrierAction = hold | query | release

CrucibleHotForkRcuBarrierState {
    schema-version: u32 = 1,
    generation: u64,
    owner-thread-id: i64,
    held: bool,
    complete: bool,
    registered-readers: u64,
    active-readers: u64,
    admissions-in-flight: u64,
    pending-callbacks: u64,
    drain-active: bool,
    quiescent: bool,
}
```

`hold` is accepted only at the authenticated exact paused/device-flush
boundary. It resets a process-lifetime release event, records the coordinator
thread, and publishes the held gate. Every new outer
`rcu_read_lock()` and `call_rcu()` submission must pass a two-phase admission:
an entry racing the hold either publishes its reader/callback state before
leaving `admissions-in-flight`, or backs out and parks on the release event.
Nested read locks remain part of their already-admitted outer section. The OOB
coordinator queries and releases the retained state without entering RCU.

`quiescent` MUST equal `held && complete && active-readers == 0 &&
admissions-in-flight == 0 && pending-callbacks == 0 && !drain-active`.
While released, `owner-thread-id` is zero and `quiescent` is false. Release
first reopens admission and then wakes every parked submitter. The held barrier
is proof for the parent RCU state only; the callback worker remains an omitted
thread requiring an exact child reinitializer before proof bit 8 can be set.

Patched QEMU also exposes the bounded observational AioContext activity used
to define the AIO/BH side of the next subsystem barrier:

```text
CrucibleHotForkAioInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    context-count: u32,
    assigned-contexts: u32,
    active-polls: u64,
    active-dispatches: u64,
    pending-bottom-halves: u64,
    active-bottom-halves: u64,
    queued-coroutines: u64,
    contexts: [
        {
            context-id: positive u64,
            home-thread-id: nonnegative i64,
            active-polls: u32,
            active-dispatches: u32,
            pending-bottom-halves: u32,
            active-bottom-halves: u32,
            queued-coroutines: u32,
            notify-pending: bool,
        },
    ],
}
```

`contexts` contains at most 65,536 records in strictly increasing
`context-id` order. Zero `home-thread-id` means the context has not yet run on
a home thread; every positive home thread MUST appear in the matching QEMU
thread inventory. The top-level counts are exact checked sums, and `complete`
equals `!overflowed && assigned-contexts == context-count`. The generation
advances on context creation, destruction, or home-thread reassignment.

Patched POSIX QEMU separately exposes every allocated `QEMUBH`, including
inert, pending, active, canceled, one-shot, and deferred-deletion instances:

```text
CrucibleHotForkBottomHalfInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    stable: bool,
    bottom-half-count: u32,
    pending-bottom-halves: u32,
    scheduled-bottom-halves: u32,
    deleted-bottom-halves: u32,
    active-callbacks: u64,
    bottom-halves: [
        {
            bottom-half-id: positive u64,
            context-id: positive u64,
            name: nonempty UTF-8 string of at most 128 bytes,
            name-valid: bool,
            pending: bool,
            scheduled: bool,
            deleted: bool,
            oneshot: bool,
            idle: bool,
            active-callbacks: u32,
        },
    ],
}
```

`bottom-halves` contains at most 65,536 records in strictly increasing
`bottom-half-id` order. Every `context-id` MUST appear in the matching
AioContext inventory. `scheduled` or `idle` implies `pending`; active and
deleted state may coexist with pending state because a callback can rearm or
delete itself. The top-level counts are exact checked sums. `complete` equals
`!overflowed && stable && all(name-valid)`. Creation, final free, enqueue,
dequeue, cancel, deletion, and callback begin/end transitions advance the
monotonic generation. Snapshotting serializes the allocation list and accepts
`stable` only when no lock-free state transition is active at either copy
boundary and that generation does not change during the bounded copy.
Diagnostic names are copied at creation rather than dereferencing callback
metadata during the query. The command is executed out of band after explicit
QMP OOB negotiation, so the query does not create and then observe its own
one-shot QMP-dispatch bottom half. A peer that cannot negotiate OOB MUST fail
closed rather than issue this inventory through ordinary in-band dispatch.

Patched POSIX QEMU also exposes every allocated POSIX AIO handler through an
out-of-band query:

```text
CrucibleHotForkAioHandlerInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    handler-count: u32,
    read-handlers: u32,
    write-handlers: u32,
    poll-handlers: u32,
    deleted-handlers: u32,
    active-callbacks: u64,
    handlers: [
        {
            handler-id: positive u64,
            context-id: positive u64,
            fd: nonnegative i64,
            deleted: bool,
            read-callback: bool,
            write-callback: bool,
            poll-callback: bool,
            poll-ready-callback: bool,
            poll-begin-callback: bool,
            poll-end-callback: bool,
            active-callbacks: u32,
        },
    ],
}
```

`handlers` contains at most 65,536 records in strictly increasing
`handler-id` order. Every `context-id` MUST appear in the matching AioContext
inventory, every non-deleted `fd` MUST appear in the exact process descriptor
inventory, and each entry MUST install at least one read, write, or poll
callback. The callback-class, deletion, and active-callback totals are exact
checked sums, and `complete` equals `!overflowed`. Allocation, final free,
deferred deletion, and poll-callback replacement advance the process-local
generation. Active callback counts are instantaneous and serialize with the
snapshot on the handler registry lock; they do not advance the generation
because the out-of-band query itself executes inside its QMP descriptor's read
callback. The command is executed out of band so its own QMP dispatch cannot
create an in-band bottom-half observation.

Patched QEMU also exposes every allocated `BlockBackend`, including hidden
backends, through an out-of-band query:

```text
CrucibleHotForkBlockBackendInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    backend-count: u32,
    named-backends: u32,
    rooted-backends: u32,
    device-backends: u32,
    writable-backends: u32,
    quiesced-backends: u32,
    in-flight: u64,
    backends: [
        {
            backend-id: positive u64,
            context-id: positive u64,
            reference-count: positive u32,
            name: UTF-8 string of at most 255 bytes,
            named: bool,
            name-valid: bool,
            root-present: bool,
            device-attached: bool,
            permissions: u64,
            shared-permissions: u64,
            write-permission: bool,
            permissions-disabled: bool,
            quiesce-depth: u32,
            in-flight: u32,
            request-queuing-disabled: bool,
        },
    ],
}
```

`backends` contains at most 65,536 records in strictly increasing
`backend-id` order. Every `context-id` MUST appear in the matching AioContext
inventory. `named` equals whether `name` is nonempty, and every complete report
requires `name-valid`. `write-permission` equals whether `permissions` contains
QEMU `BLK_PERM_WRITE` (`0x02`). All top-level counts and the checked in-flight
sum are exact. `complete` equals `!overflowed && all(name-valid)`. Allocation,
final free, reference-count, AioContext, monitor-name, root/device attachment,
permission, and permission-suppression changes advance the process-local
generation. Quiesce depth, in-flight I/O, and request-queue policy are
instantaneous atomic observations; the host therefore requires the entire
response to match across its procfs capture. Structural fields are copied into
a dedicated registry under the BQL transition that owns them, so the OOB query
does not dereference the live BQL-owned block graph.

This inventory is not the immutable writable-root proof. It does not enumerate
the complete `BlockDriverState` graph, freeze producers, drain I/O, create an
external snapshot, retain root identities across `fork(2)`, or define child
overlay reconstruction. It therefore MUST NOT acknowledge proof bit 5. The
future QEMU-owned coordinator must combine the complete backend registry with a
drained, retained block-graph/write-root barrier and exact child disposition.

Patched QEMU also exposes the first retained block-side prerequisite through a
normal main-loop QMP command:

```text
CrucibleHotForkBlockBarrierAction = hold | query | release

CrucibleHotForkBlockSnapshotBinding {
    backend-id: u64,
    backend-name: string,
    overlay-node-name: string,
    snapshot-node-name: string,
    snapshot-content-id: string,
}

CrucibleHotForkBlockSnapshotRoot {
    backend-id: u64,
    backend-name: string,
    overlay-node-name: string,
    snapshot-node-name: string,
    snapshot-content-id: string,
    virtual-size: u64,
    overlay-empty: bool,
    snapshot-read-only: bool,
}

CrucibleHotForkBlockBarrierState {
    schema-version: u32 = 3,
    generation: u64,
    owner-thread-id: i64,
    graph-barrier-generation: u64,
    graph-mutation-generation: u64,
    held-graph-mutation-generation: u64,
    graph-owner-thread-id: i64,
    held: bool,
    graph-held: bool,
    graph-writer-active: bool,
    graph-waiting-writers: u32,
    graph-stable: bool,
    snapshot-generation: u64,
    snapshot-backend-generation: u64,
    snapshot-graph-mutation-generation: u64,
    snapshot-owner-thread-id: i64,
    snapshot-bound: bool,
    snapshot-complete: bool,
    snapshot-roots: [CrucibleHotForkBlockSnapshotRoot],
    complete: bool,
    backend-count: u64,
    rooted-backends: u64,
    writable-backends: u64,
    writable-rooted-backends: u64,
    quiesced-rooted-backends: u64,
    in-flight: u64,
    quiescent: bool,
}
```

`crucible-hot-fork-block-barrier` closes block-graph writer admission and
retains QEMU's native all-block drain section. `hold` MUST start only at the
authenticated exact paused/device-flush boundary, on the main AioContext, and
outside replay-events mode. It first rejects any active graph writer, closes
later graph-writer admission, and captures the latest completed graph-mutation
generation before beginning native drain. It then quiesces new external block
clients and permits already-issued I/O to complete while a later OOB `query`
observes the retained section. Every writer is counted in
`graph-waiting-writers` from admission until it enters its critical section, so
`hold` cannot race an admitted writer that has not yet become active. A writer
arriving after the hold remains parked until release. `release` reopens graph
admission immediately before ending native drain in the same main-loop
callback. No parked writer can enter before that callback returns, and this
ordering lets native drain cleanup perform nested graph operations without
deadlock. The command uses normal `execute`, not negotiated `exec-oob`, because
hold and release require the BQL and main AioContext. The query operation
performs no main-loop-only drain transition, so the OOB template coordinator
can safely compose it; the standalone command remains in-band.

All backend counts MUST be bounded by 65,536 and match the block-backend registry:
`rooted-backends` and `writable-backends` are at most `backend-count`, and
`quiesced-rooted-backends` is at most `rooted-backends`.
`graph-mutation-generation` advances after every completed graph-write critical
section, while `graph-barrier-generation` advances on each hold and release.
`graph-stable` equals `graph-held && !graph-writer-active &&
graph-mutation-generation == held-graph-mutation-generation`.
`complete` additionally requires the native and graph barriers to agree about
whether they are held and, while held, to name the same positive owner and have
a stable graph generation. `quiescent` is true exactly when the barrier is
held, the combined registry/barrier state is complete, aggregate `in-flight`
is zero, and every rooted backend is quiesced. A released state has both owners
and `held-graph-mutation-generation` zero and is not quiescent. Waiting writers
may be nonzero during a released observation immediately after admission
reopens; they are not inside a graph critical section.

While this barrier is held and quiescent, schema version 9 of the template
coordinator additionally requires one complete
`CrucibleHotForkBlockSnapshotBinding` list in increasing `backend-id` order.
The list MUST name every writable rooted backend exactly once. Backend names
are QEMU identifiers of at most 255 bytes; overlay and snapshot node names are
QEMU identifiers of at most 31 bytes; and `snapshot-content-id` is exactly 64
lowercase hexadecimal characters containing the BLAKE3 identity already
authenticated by the Apache host. QEMU does not infer or trust the content ID:
it binds that supplied identity to the exact live backend and graph edge.

Binding succeeds only while the native drain and graph-writer barriers remain
owned by the same coordinator and their captured graph generation is stable.
Each named active root MUST be writable, MUST contain no allocated
guest-visible range above its immediate backing node, and MUST have that
immediate backing node open read-only at the same virtual size. QEMU records
the exact backend generation, graph generation, owner, root identities, size,
empty-overlay result, and read-only result. `snapshot-complete` is true exactly
while those values still match the retained barrier and the root list count
equals `writable-rooted-backends`. Release clears the binding before graph or
native-drain admission reopens.

An active transaction acknowledges proof bit 5 exactly while this complete
immutable writable-root binding is retained. The binding does not create the
snapshot bytes, rotate a preexisting writable root, reconstruct a child block
graph, or create a branch-private child overlay. The host MUST authenticate and
open the immutable snapshot plus empty active overlay before preparation;
child-side descriptor, graph, and overlay reconstruction remain proof bits 7
and 8.
It MUST acquire the block drain before the asynchronous-source barrier, because
draining may require AIO progress, and release the asynchronous-source barrier
before releasing the block drain. The standalone barrier command cannot bind a
root or acknowledge bit 5 by itself, and the remaining proof bits still prevent
`fork(2)`.

Patched QEMU and the loaded Crucible plugin additionally establish one sealed,
scalar plugin-resource inventory. The plugin registers this manifest only after
all callback families, the wake descriptor, and fault admission are installed,
and before it sends the successful setup acknowledgement. QEMU independently
records callback registration and exposes the joined state through an
out-of-band query:

```text
CrucibleHotForkPluginResourceInventory {
    schema-version: u32 = 2,
    generation: u64,
    registered: bool,
    complete: bool,
    process-generation: u64,
    plugin-id: u64,
    resource-mask: u64,
    callback-mask: u64,
    worker-mask: u64,
    observed-callback-mask: u64,
    callback-mask-consistent: bool,
    shmem-device: u64,
    shmem-inode: u64,
    shmem-length: u64,
    slot-index: u32,
    node-count: u32,
    control-fd: i64,
    wake-fd: i64,
    coverage: bool,
    whitebox: bool,
    fingerprint: bool,
    run-control-worker: bool,
    teardown-worker: bool,
    fingerprint-worker: bool,
    state-dump: bool,
    app-random: bool,
}
```

Resource-mask bits 0 through 9 are mandatory and respectively mean control
socket, shared-memory mapping, wake descriptor, time control, vCPU callbacks,
network callbacks, block callbacks, 9p callbacks, accelerator callbacks, and
fault transport. Optional bits 10 through 14 respectively mean coverage,
white-box, fingerprint, raw state dump, and app-random resources; no other bit
is valid. Callback-mask bits 0 and 2 through 11 are mandatory and respectively
mean vCPU initialization, idle/resume, control boundary, sim shared memory,
time advance, network, block submit/poll, block event/continuation, block wait,
9p, and accelerator callbacks. Bit 1 records the legacy TCG-execution hook when
installed; the current runtime deliberately leaves it clear. Optional bits 12
and 13 respectively mean TB translation and flush callbacks; no other bit is
valid. Coverage requires both feature callback bits, white-box requires TB
translation, and the five feature booleans MUST equal their resource bits.
Worker-mask bits 0 and 1 are mandatory and respectively seal the RUN control
reader and sole teardown worker. Bit 2 seals the fingerprint digest worker and
MUST be present exactly when the fingerprint resource bit and feature boolean
are present; no other worker bit is valid. The three worker booleans MUST equal
their corresponding mask bits.

A registered shape requires nonzero process/plugin identity, inode, mapping
length, and node count; a slot below that node count; two distinct nonnegative
descriptors; every mandatory mask bit; exact equality between plugin-declared
and QEMU-observed callback masks; and the optional relationships above.
`complete` MUST equal that full predicate. Before registration, every manifest
field and feature boolean is zero/false and `complete` is false. The host
requires the control and wake descriptors to exist in the exact process
inventory with Unix-socket and eventfd targets, and decodes `shmem-device` as
Linux `dev_t`. Every mapping of that device/inode MUST be writable and shared,
and their checked aggregate length MUST equal `shmem-length`.

The manifest is by-value GPL-side process state and the host receives only this
versioned QMP response; it does not place a Rust layout or native pointer in a
cross-process protocol. The response inventories installed resources and the
closed worker set that the barrier below parks. The manifest alone does not
freeze a ring, stop future callbacks, park a worker, or define child
dispositions. It therefore MUST NOT acknowledge proof bit 6 or authorize a
fork.

The next plugin checkpoint adds a distinct reversible callback barrier. The
plugin registers one process-lifetime operation only after every covered
callback owns the same admission counter. QEMU exposes the operation through
the out-of-band `crucible-hot-fork-plugin-barrier` command:

```text
CrucibleHotForkPluginBarrierAction = hold | query | release

CrucibleHotForkPluginBarrierState {
    schema-version: u32 = 6,
    generation: u64,
    registered: bool,
    manifest-consistent: bool,
    held: bool,
    teardown-closed: bool,
    mapping-dontfork: bool,
    in-flight: u64,
    ring-count: u64,
    rings-held: u64,
    ring-producers-in-flight: u64,
    ring-consumers-in-flight: u64,
    worker-mask: u64,
    parked-worker-mask: u64,
    pending-worker-mask: u64,
    worker-operations-in-flight: u64,
    quiescent: bool,
}
```

`hold` is accepted only at QEMU's authenticated exact paused/device-flush
boundary. It first atomically rejects later covered callbacks, then holds the
producer- and consumer-admission words in every ring in the validated
shared-memory layout.
It then closes admission to one bounded operation for every worker class in
the sealed `worker-mask`. Callbacks, ring publications, and worker operations
admitted before their respective holds remain counted in `in-flight`,
`ring-producers-in-flight`, `ring-consumers-in-flight`, and
`worker-operations-in-flight`. An idle worker sets its bit in
`parked-worker-mask`. A worker whose blocking receive returns during a hold
retains that parked bit and sets its bit in `pending-worker-mask` immediately
after the receive and before the item can be admitted or affect modeled/shared
state. The bit remains set until the item is discarded or the hold releases
and the worker atomically becomes active. QEMU therefore observes every item
retained at this explicit pre-admission boundary, but this accounting does not
itself define a child-side disposition for that item. After those admissions
are closed, the plugin applies `MADV_DONTFORK` to the exact live setup-region
mapping. Failure rolls back the worker, ring, and callback holds rather than
leaving a partial transaction. `query` observes all barriers and mapping state
without changing them. `release` first restores `MADV_DOFORK`; failure retains
every hold. Only then does release reopen ring consumers before producers,
then callbacks before it wakes workers, and
MUST NOT reopen callback admission after permanent teardown closure. A
registered response requires a nonzero `ring-count`, `rings-held` is either
zero or exactly `ring-count`, `held` equals both
`rings-held == ring-count` and `mapping-dontfork`, the
worker mask equals the sealed manifest, the parked mask is its subset, the
pending mask is a subset of the parked mask, and the sum of parked worker
classes plus admitted operations cannot exceed the sealed worker count.
`quiescent` equals `registered && manifest-consistent && held &&
!teardown-closed && in-flight == 0 && rings-held == ring-count &&
mapping-dontfork &&
ring-producers-in-flight == 0 && ring-consumers-in-flight == 0 &&
parked-worker-mask == worker-mask &&
pending-worker-mask == 0 &&
worker-operations-in-flight == 0`. The process-local generation is positive
after registration and advances when any barrier's observable state changes.
An unregistered response has generation zero and every other field zero or
false. `mapping-dontfork` is real Linux VMA state, not a future disposition
plan; the focused mapping regression observes the `dc` `VmFlags` bit appear on
hold and disappear on release.

This is a retained barrier over the callback classes covered by the sealed
manifest, every ABI-v20-or-newer shared-memory ring producer and consumer
including Apache host endpoints, and the mandatory RUN-control/teardown workers
plus the optional fingerprint digest worker. While this retained state is quiescent,
the host can now capture a bounded, versioned image of every ring-backed range
and restore it into an identical inactive branch-private mapping. The image
authenticates exact geometry, held endpoints, cursor capacity, queued bytes,
and fault payload arenas; restore keeps the destination held. It excludes node
slots and fingerprint samples by contract.

The production node adapter brackets capture with identical QMP plugin-barrier
and sealed plugin-resource reports. It requires the host mapping's retained
device, inode, and descriptor length to match the sealed resource manifest,
requires the exact source mapping to remain `MADV_DONTFORK`, and independently
requires the QEMU and host ring count, held count, and
producer/consumer admission totals to agree. Changed proof generations,
resource identity, or host barrier state reject the capture. This binds one
host image to one retained plugin barrier but still does not authorize fork.

The Linux host can materialize that capture into a fresh shrink-sealed memfd
without exposing raw descriptor or release authority to its caller. It first
requires the live node to reproduce the captured plugin-resource inventory,
setup-mapping identity, plugin-barrier generation, and host barrier. It
initializes the new mapping from the image's exact `RegionConfig`, thereby
resetting node slots and fingerprint samples, holds every fresh ring, restores
only the three canonical ring ranges, and recaptures an exact image/digest
match. Before returning the opaque mapping owner, it again requires the source
inventory, identity, and both barriers to be unchanged. The destination
device/inode must not alias the source and its producer and consumer endpoints
remain held.

The node can then consume that owner into a template-process descriptor stage.
Immediately before transfer it repeats the exact source inventory, source
mapping, QEMU barrier, host barrier, and destination image-digest checks. The
typed Unix QMP client sends standard `getfd` and exactly one `SCM_RIGHTS`
descriptor under this bounded name:

```text
crucible-hfork-rings-v1-<device:16-lower-hex>-<inode:16-lower-hex>-<image-digest:64-lower-hex>
```

Typed descriptor names contain 1 through 128 bytes from `[a-z0-9-]`. The
device/inode pair makes distinct still-live memfds non-aliasing, while the
digest binds the staged descriptor to the exact restored image. After `getfd`
acknowledges the monitor-owned entry, the OOB
`crucible-hot-fork-private-rings stage` command makes QEMU independently
duplicate that named descriptor. QEMU requires the same name, device, inode,
length, regular-file type, and `F_SEAL_SHRINK` before retaining the duplicate.
Its closed version-2 response reports the exact retained basis plus the
template generation that admitted it (or zero for the deliberately unbound
standalone primitive), and explicitly
sets `disposition-complete = false` and
`readiness-proof-acknowledged = false`. The node retains the original
descriptor, mapping, held ring endpoints, source proof, exact name, and image
digest. Only both acknowledgements yield the `installed` stage.

Release reverses the two ownership layers in order. The custom `release`
operation requires the same exact name/device/inode/length basis, first closes
QEMU's independently retained duplicate, and must report an absent stage.
Standard `closefd` then closes the monitor-owned entry under the same exact
name. Both acknowledgements are required before an installed mapping can leave
node ownership.

Any error once descriptor transfer or QEMU-owned adoption begins makes QEMU
ownership and the stream boundary indeterminate. The typed client permanently
poisons that QMP stream; the node retains the mapping as `transfer-uncertain`
and quarantines the QEMU generation. A failed custom release or `closefd`
likewise retains the installed mapping and quarantines the generation.
Pre-transfer validation failure returns the untouched mapping and leaves the
node running. This ordering prevents either a lost memfd owner or a caller from
treating an unacknowledged transfer as a definite rejection.

Once that private-ring stage is installed, the node may create one fresh
branch-private control/wake pair. The pair remains sealed in the source node and
cannot be borrowed or duplicated before the fork outcome is authenticated. A
successful fork consumes its host half into the linear branch-private plugin
continuation described below; rejection leaves the complete pair reusable, and
an indeterminate outcome quarantines the source. The control endpoint is a
connected empty AF_UNIX stream; the wake endpoint is an empty nonblocking
eventfd. Their standard-QMP names are distinct and bounded:

```text
crucible-hfork-control-v1-<SO_COOKIE:16-lower-hex>
crucible-hfork-wake-v1-<eventfd-id:16-lower-hex>
```

After two `getfd` acknowledgements, the OOB
`crucible-hot-fork-plugin-endpoints stage` command independently duplicates
both entries. QEMU authenticates the socket's Linux `SO_COOKIE`, the eventfd's
`/proc/self/fdinfo` identity, their empty state, and the current retained
private-ring generation. Standard QMP normalizes received descriptors to
blocking mode, so the custom stage sets the retained eventfd's shared open-file
description nonblocking and verifies that state before acceptance. The closed
version-4 state reports both identities, the same template generation as its
private-ring dependency, and the exact quiescent plugin-barrier generation and
sealed worker mask captured at template-bound staging. Acceptance requires no
pending worker-local item or operation. The recorded parent-resume and
child-reinitialize masks both equal the complete sealed worker mask. The state
also binds QEMU's two retained source descriptors to the exact, distinct
control and wake descriptor slots sealed in the plugin resource manifest. All
four slots are pairwise distinct and neither pair aliases the private-ring
descriptor. Descriptor numbers are process-local observations rather than
transferable capabilities. A future child transaction must atomically replace
both target file descriptions and then authenticate the resulting kernel
identities before invoking the registered plugin reinitializer. Patched QEMU
now contains a Linux-only internal helper for that exact two-slot replacement.
The helper validates the pairwise-distinct shape, preserves target descriptor
flags, retains both old targets until a caller-owned verifier authenticates the
installed pair, restores both on rejection, and reports a poisoned disposition
when rollback cannot be proved. It remains unwired: only the future
immediate-child coordinator may call it, and any nonzero result requires that
child to terminate or enter supervisor-owned quarantine. The endpoint state is
therefore still a plan rather than an applied child disposition, so it keeps
`disposition-complete` and
`readiness-proof-acknowledged` false. Private-ring release is rejected while
the pair retains its generation. Endpoint release first closes QEMU's
duplicates, then standard `closefd` closes wake and control names; the node
drops its original pairs only after all acknowledgements. Any transfer or
release ambiguity poisons QMP, retains the opaque pair, and quarantines the
QEMU generation.

The adjacent Linux-only child-identity primitive pins the exact parent process
generation in a pidfd before fork. In a child it requires that pinned live
generation to remain the direct parent while arming parent-death `SIGKILL`
before any disposition may proceed. A real-fork unit path proves that only the
immediate child can apply the two replacements and that the parent's descriptor
table remains unchanged. This is still an internal, unwired primitive: the
production coordinator does not call `fork(2)`, and the identity check alone
does not close the inherited descriptor table or acknowledge readiness.

The adjacent closed-table primitive advances that internal child path without
claiming readiness. It authenticates and consumes the immediate-child identity,
blocks every blockable signal, applies the exact two endpoint replacements, and
requires a strictly sorted final descriptor table of at most 4,096 slots. Linux
`close_range(2)` closes every gap and the complete suffix before a caller-owned
verifier authenticates the installed table. A real-fork regression proves an
unlisted inherited eventfd is closed in the child while the parent's table and
original endpoints remain unchanged. The operation is deliberately
destructive after authentication: any failure terminates or quarantines the
child rather than attempting to reconstruct an ambient descriptor table. It is
still unwired and does not classify mappings; therefore proof bit 7 remains
clear. An adjacent one-shot child transaction closes the remaining asynchronous
descriptor-admission window: it proves `close_range(2)` support, authenticates
the immediate child, blocks every blockable signal, and consumes the parent
anchor before the caller constructs the retain table. Closed-table application
then requires and consumes that exact child transaction. The real-fork
regression proves the signal mask precedes construction, while an inactive
transaction cannot mutate the table. Production fork composition and mapping
disposition remain open, so this does not acknowledge proof bit 7.

The mapping half now has an equally fail-closed, unwired child primitive. After
descriptor closure and branch-private remapping, it streams `/proc/self/maps`
without heap allocation under the same 65,536-record, 8-KiB-record, and 16-MiB
aggregate bounds used by the host audit. Private VMAs retain kernel COW
semantics; read-only shared VMAs cannot mutate a sibling; and every writable
shared VMA must exactly match one of at most 4,096 sorted, nonoverlapping
branch-private allowlist ranges in both directions. Each allowed range also
names one retained shrink-sealed regular-file descriptor and page-aligned file
offset. The scan authenticates the VMA's device, inode, and offset against that
descriptor, so a same-sized but different backing cannot satisfy the proof. A
real-fork path retains and admits one exact sealed memfd replacement; negative
regressions prove that omitting the VMA or substituting another valid memfd
rejects the child. The production fork coordinator has not yet composed this
result with the staged resource manifest, child reinitialization, and readiness
report, so proof bit 7 remains clear.

The internal child path now orders those operations through one composed
resource transaction. It preflights the complete retained descriptor and
writable-shared mapping tables before mutation, closes descriptor admission,
applies the exact endpoint replacements and descriptor table, invokes one
reinitializer that must leave recreated workers and callbacks held, and only
then authenticates the resulting mapping table. A real-fork regression
reconstructs one exact `MADV_DONTFORK` mapping after descriptor closure and
requires all three recorded phases. An unretained-backing preflight leaves the
active transaction and every endpoint unchanged and never calls the
reinitializer. The transaction now has a prepared one-shot adapter for QEMU's
registered plugin runtime, and the real-fork unit path composes that adapter
through a fake registered runtime. No production fork caller invokes it, and
the operation covers only the explicitly supplied resources. It neither
reconstructs every non-plugin subsystem, pairs the host continuation, nor
releases guest admission, so proof bits 7 and 8 remain clear.

At that checkpoint this was not yet the complete plugin-ring proof.
Template-bound staging rejects
a parked worker that retains a received trigger or queued fingerprint work,
but no fork child yet applies the complete worker plan together with its host
continuation. The plugin setup owner now retains the exact validated
`RegionLayout` and has a sealed transition that installs the distinct private
backing at the retained address, revalidates the current ABI and complete
layout, and updates the owned backing identity. Callback-held shutdown paths
also route through one quiescence-replaceable sender, so a retained callback
allocation can be rebound to a future child teardown receiver without retaining
the vanished parent receiver. Those internal transitions are not yet registered
or invoked by QEMU, do not recreate the control, teardown, or optional
fingerprint workers, and do not release the child barrier. Template-process
descriptor and endpoint retention plus the unwired two-slot helper are
therefore not child dispositions: they prove neither inherited-FD closure nor
complete child remap/rebind. That checkpoint kept readiness bits 6 through 8
clear; version 13 below composes bit 6 without claiming bits 7 or 8.

The next source checkpoint adds a process-lifetime reversible bottom-half and
timer-source barrier through the OOB
`crucible-hot-fork-bh-timer-barrier` command:

```text
CrucibleHotForkBhTimerBarrierAction = hold | query | release

CrucibleHotForkBhTimerBarrierState {
    schema-version: u32 = 2,
    generation: u64,
    owner-thread-id: i64,
    held: bool,
    complete: bool,
    bottom-halves-complete: bool,
    timers-complete: bool,
    admissions-in-flight: u64,
    bottom-half-count: u64,
    pending-bottom-halves: u64,
    scheduled-bottom-halves: u64,
    active-bottom-half-callbacks: u64,
    pending-timers: u64,
    active-timer-callbacks: u64,
    aio-context-count: u64,
    active-aio-polls: u64,
    active-aio-dispatches: u64,
    queued-coroutines: u64,
    aio-handler-count: u64,
    active-aio-handler-callbacks: u64,
    aio-contexts-complete: bool,
    aio-handlers-complete: bool,
    quiescent: bool,
}
```

`hold` is accepted only at the authenticated exact paused/device-flush
boundary. A race-closed two-phase admission gate prevents every later outer
AioContext poll or GLib dispatch, AioHandler mutation or callback, coroutine
schedule, bottom-half or timer creation, mutation, and callback dispatch from
entering the covered asynchronous-source operations. Producers wait until
release; event-loop dispatch uses nonblocking admission and leaves already
queued sources parked, so OOB QMP remains live. Work admitted before the hold
may finish and may make nested source mutations inside that admission.
`admissions-in-flight` exposes those outer operations until they drain.
Pending and scheduled bottom halves, armed timers, and queued coroutines are
retained parked state and need not be empty.

`bottom-halves-complete`, `timers-complete`, `aio-contexts-complete`, and
`aio-handlers-complete` require their bounded inventories to be stable and not
overflowed; timer and handler completeness is false on unsupported non-POSIX
builds. `complete` is their conjunction. `quiescent` equals `held && complete
&& admissions-in-flight == 0 && active-aio-polls == 0 &&
active-aio-dispatches == 0 && active-bottom-half-callbacks == 0 &&
active-aio-handler-callbacks == 0 && active-timer-callbacks == 0`. The owner is
positive only while held, and the generation advances on each hold and release
transition.

This barrier closes the in-process asynchronous-source admission and dispatch
races and is sufficient for proof bit 3 while retained and quiescent. It does
not choose child-side descriptor, context, coroutine, or clock disposition;
those obligations remain separately represented by proof bits 7 and 8.

The retained `PrepareForkTemplate` checkpoint is the version-23 OOB
`crucible-hot-fork-template` coordinator:

```text
CrucibleHotForkTemplateAction = prepare | query | abort

CrucibleHotForkTemplateOutcome =
    idle | draining | blocked | prepared | aborted

CrucibleHotForkTemplateResourceStageState {
    schema-version: u32 = 12,
    template-generation: u64,
    private-ring-staged: bool,
    private-ring-generation: u64,
    diagnostics-staged: bool,
    diagnostic-generation: u64,
    diagnostics-resource-plan-bound: bool,
    qmp-staged: bool,
    qmp-generation: u64,
    qmp-resource-plan-bound: bool,
    plugin-endpoints-staged: bool,
    plugin-endpoint-generation: u64,
    plugin-private-ring-generation: u64,
    plugin-barrier-generation: u64,
    worker-mask: u64,
    parent-resume-worker-mask: u64,
    child-reinitialize-worker-mask: u64,
    pending-worker-mask: u64 = 0,
    worker-disposition-bound: bool,
    transaction-bound: bool,
    parent-process-generation: u64,
    child-process-generation: u64,
    plugin-child-plan-bound: bool,
    plugin-child-resource-plan-bound: bool,
    readiness-proof-acknowledged: bool,
}

CrucibleHotForkTemplateState {
    schema-version: u32 = 23,
    generation: u64,
    outcome: CrucibleHotForkTemplateOutcome,
    transaction-active: bool,
    required-proofs: u64 = 0x007f,
    acknowledged-proofs: u64,
    missing-proofs: u64,
    plugin-barrier: CrucibleHotForkPluginBarrierState,
    rcu-barrier: CrucibleHotForkRcuBarrierState,
    bh-timer-barrier: CrucibleHotForkBhTimerBarrierState,
    block-barrier: CrucibleHotForkBlockBarrierState,
    resource-stage: CrucibleHotForkTemplateResourceStageState,
    rollback-complete: bool,
    ready: bool,
}

prepare(action, block-snapshot-bindings: [CrucibleHotForkBlockSnapshotBinding])
```

`prepare` starts only at the authenticated exact paused/device-flush boundary.
QEMU serializes the transaction and schedules block-graph writer exclusion and
native all-block drain acquisition on the main AioContext. OOB calls observe
`draining` while that transition is pending. Once the graph generation is
stable and block roots are quiesced, the coordinator schedules immutable-root
binding on the main AioContext. Every repeated `prepare` MUST carry the exact
same complete binding list; omission or mismatch fails closed. Once the binding
is complete, the coordinator acquires the RCU
admission barrier, the bottom-half/timer source barrier, and the plugin callback
barrier, and retains all four while previously admitted work drains. A repeated
`prepare` reevaluates the retained transaction. Once all four barriers are
quiescent, QEMU reports `prepared` only when all seven parent-side template
proofs are present in the same transaction. Otherwise the version-23 report
continues to report `draining` and retains the barriers so the host can capture
and stage branch-private resources without releasing the source-ring barrier.
Version 12 introduced the atomic resource report. It carries the exact
private-ring and endpoint mutation generations, the
endpoint-to-ring generation edge, their originating template generation, and
whether every retained resource is bound to the current active transaction.
For retained endpoints it also requires the captured barrier generation and
parent/child worker masks to match the exact current quiescent plugin barrier;
generation or worker-state drift clears both `worker-disposition-bound` and
`transaction-bound`.
Version 13 acknowledges plugin-ring proof bit 6 only when every required
retained resource stage, the shrink-sealed private ring, the endpoint-to-ring
edge, the exact quiescent
plugin-barrier generation, and the complete parent/child worker-disposition
plan all remain bound to the active template transaction. The nested
`readiness-proof-acknowledged` value and outer bit 6 are independently derived
from that basis and MUST agree; stale, partial, or cross-transaction state
clears both.
Version 14 additionally derives the complete registered plugin child-runtime
plan before endpoint ownership is committed. QEMU copies the exact template,
ring, endpoint, barrier, mapping, descriptor, kernel-identity,
process-generation, and worker basis into one unconsumed one-shot adapter. The
nested report exposes the checked adjacent parent and child process generations
only while that adapter still matches the active transaction. Idempotent
endpoint staging requires the same copied plan, and exact endpoint release
clears the parent-process adapter. This is a pre-fork plan binding, not evidence
that any descriptor was replaced or that the child runtime executed, so it
does not acknowledge proof bit 7 or 8.
Version 15 additionally converts the copied runtime plan and the retained
branch-private control and wake source descriptors into the exact plugin
portion of a future destructive child transaction. The nondestructive adapter
contains two source-to-target replacements, a strictly sorted retain set of
the private-ring, control, and wake targets, and one writable-shared mapping
allowlist entry backed by the retained private ring at the exact registered
source range and offset. `plugin-child-resource-plan-bound` is true only while
those tables, both source descriptors, and the copied runtime plan still match
the active retained transaction. QEMU now seeds one fixed-capacity canonical
child plan from that fragment. Additional subsystem contributions must supply
strictly sorted descriptor and nonoverlapping mapping tables; exact duplicates
are idempotent, while source retention, conflicting mappings, missing retained
backings, or either union exceeding 4,096 entries fails atomically. Sealing
revalidates the complete union, and the report requires the sealed plan to
contain the exact retained plugin fragment. The current transaction does not
yet register the remaining QEMU descriptor or mapping set, so proof bits 7 and
8 remain clear. An adjacent child-only adapter now consumes one inherited
sealed plan through the authenticated immediate-child transaction. It requires
the same unconsumed plugin reinitializer, revalidates the complete union, and
marks the plan attempted before descriptor mutation. The destructive path then
uses only that union for descriptor closure, held plugin reconstruction, and
writable-shared mapping authentication; exact success marks the plan applied.
Preflight mismatch leaves both linear owners available, while every failure
after consumption rejects that child. A real-fork regression retains one
independently contributed result descriptor and proves the parent's plan copy
remains unconsumed. This is still an unwired application primitive rather than
a complete supported-profile resource inventory or production fork owner.
Descriptor replacement composition now uses the same bounded union model as
retained descriptors and writable-shared mappings. The plugin pair is
canonicalized by target slot, and further subsystem contributions may merge up
to 4,096 source-to-target pairs. Every source and target is globally distinct,
every target is retained, exact duplicates are idempotent, and target
conflicts, source reuse, source/target cross-aliases, unsorted input, missing
targets, or over-limit unions fail before changing the accumulated plan. The
child transaction holds one fixed rollback record per replacement and consumes
only the sealed canonical table. Its real-fork regression now replaces an
independently contributed result endpoint rather than merely retaining that
source. QMP, block, AIO, and the other supported-profile owners do not
yet provide their concrete contributions, so this still cannot acknowledge
proof bit 7 or 8.
Version 16 adds the first non-plugin child contribution. The host creates a
fresh connected nonblocking Unix stream pair, retains its consumer endpoint,
and transfers the child endpoint through standard QMP `getfd`. The
`crucible-hot-fork-child-diagnostics` operation independently duplicates and
authenticates that endpoint by its Linux `SO_COOKIE`, requires the exact active
template and private-ring generation, and binds one source-to-stderr
replacement plus retained stderr target into the sealed child resource plan
before plugin endpoint staging can commit. The child application adapter
reauthenticates the resulting connected nonblocking stream after descriptor
replacement. Plugin endpoints must release first; diagnostics then release the
QEMU duplicate before the monitor name and host owners. The node exposes a
nonblocking host drain that retains at most 16 MiB cumulatively for one
diagnostics generation. Repeated drains do not reset that bound, and an
available byte beyond it fails the node closed instead of truncating the
stream. A known successful fork transfers the sole host consumer into the
linear child launch authority; explicit pre-fork rejection leaves it with the
reusable source. The daemon reconciliation owner drains it before every
child-QMP admission and source-parent status query, and the live-child
operational capability drains it before every cancellation check or
scheduler-quantum charge. A driver MUST use
that capability between bounded guest quanta and MAY request additional
nonblocking drains while idle. Diagnostic I/O or capacity failure is terminal
and transfers the indivisible child owner to quarantine before another status
query. Exact release shuts down the final source-owned writer, returns the
matching child-owned consumer, drains through EOF, and produces the complete
capture bound to the descriptor name, `SO_COOKIE`, and template generation.
This supplies
branch-private child diagnostics without enumerating the remaining QMP, block,
AIO, console, or filesystem resources, invoking `fork(2)`, or acknowledging
proof bit 7 or 8.
Version 17 adds a second non-plugin contribution for a fresh branch-private QMP
connection. After diagnostics staging, the host creates another connected
nonblocking Unix stream pair and transfers the child endpoint through standard
QMP `getfd`. The `crucible-hot-fork-child-qmp` operation duplicates
and authenticates that endpoint by Linux `SO_COOKIE`, requires the same active
template generation, rejects diagnostics aliasing, and retains the descriptor
in the sealed child plan before plugin endpoint staging can commit. QEMU and
the node retain both original endpoints but deliberately do not close the
inherited monitor, attach the private endpoint, reset parser state, or perform a
child generation handshake. Plugin endpoints release first, followed by the
child-QMP QEMU duplicate, monitor name, and node pair, then diagnostics and the
private ring. This contribution therefore preserves exact future monitor
authority without claiming that monitor reconstruction or child disposition
has occurred; proof bits 7 and 8 remain clear.
Version 18 and child-QMP schema version 2 additionally prepare a one-shot
child-monitor adapter bound to the exact retained descriptor, Linux socket
identity, template generation, and child-QMP mutation generation. A future
child runtime is accepted only if it reports that inherited monitors were
disposed, the dispatcher and private endpoint were rebuilt, parser and
capability state were reset, the QMP greeting was emitted, input remains held,
exactly one replacement monitor exists, and neither queued nor partial requests
remain. This is a fail-closed runtime contract, not the concrete monitor
implementation or its composition with the authenticated child transaction;
it does not invoke `fork(2)` or acknowledge proof bit 7 or 8.
Version 19, resource-stage version 9, and child-QMP schema version 3 admit that
endpoint only while QEMU observes the complete supported parent-monitor
profile: one OOB-enabled I/O-thread QMP monitor, no HMP monitor, suspension,
negotiation, queued request, partial parser, or unstable parser observation.
The exact positive monitor lifecycle generation is copied into the sealed QMP
resource contribution, the one-shot runtime basis and status, and the private
child-channel query. A changed or foreign generation therefore fails before
resource-plan composition or host-channel acceptance. This binds the audited
profile to the future child transaction; it still does not dispose or recreate
the inherited monitor.
Version 20, resource-stage version 10, and child-QMP schema version 4 retain the
exact admitted `MonitorQMP`, monitor `IOThread`, dispatcher coroutine, and
lifecycle generation as one QEMU-private child ownership basis. Staging checks
the basis against a fresh complete supported-profile inventory immediately
before commit, idempotent restage repeats that exact comparison, and release
clears it. The public report exposes only `monitor-basis-bound`, so native QEMU
pointers remain inside the GPL process. This makes future destructive monitor
reconstruction target exact retained owners; it does not perform that
reconstruction, invoke `fork(2)`, release input, or acknowledge proof bit 7 or
8.
Version 21, resource-stage version 11, and child-QMP schema version 5 extend
that private basis with the exact inherited `Chardev`. Staging requires it to
remain the admitted monitor's connected frontend, support GMainContext
dispatch, and expose both backend disconnect and add-client operations. Only
`monitor-disposition-bound` crosses QAPI. This proves that the retained owner
has the concrete endpoint operations required by a future child transition;
it does not invoke either operation, reconstruct the monitor, fork, release
input, or acknowledge proof bit 7 or 8.
Version 22, resource-stage version 12, and child-QMP schema version 6 further
retain the exact connected Unix-socket frontend, address, channel, socket,
listener, read and HUP sources, `GMainContext`, and positive monotonic
connection generation. Staging admits only the listening Unix profile and
rejects TLS, telnet, TN3270, WebSocket, reconnect and connect-task state,
queued descriptor transfer, replay mode, and non-GMainContext dispatch. The
complete private basis is checked under the chardev write lock at commit and
exact restage; disconnect or reconnect invalidates it. QAPI exposes only
`monitor-socket-resources-bound`. This binds the resources a future child
transition must consume without removing a source, disconnecting the socket,
reconstructing the monitor, forking, releasing input, or acknowledging proof
bit 7 or 8.
The following child-only checkpoint composes that exact socket replacement
with the first monitor-owned destructive protocol transition. Immediately
before mutation QEMU requires the retained single-monitor basis plus an empty
named-descriptor table, global fdset registry, output buffer, output watch,
mux/reset state, request queue, and parser. It then disposes the inherited
socket state, installs the
held private stream, replaces the JSON parser with a fresh empty parser, and
returns the monitor to capability negotiation with only the supported
I/O-thread OOB capability offered. No greeting is emitted and no input source
is attached. The next child-only step requires the copied dispatcher to be
idle, wakes it once with shutdown set so it exits through QEMU's normal
coroutine disposal path, and installs one fresh child dispatcher. Replacement
input remains held across that transition. The same child-only transaction now
binds the source monitor IOThread's exact Linux thread identity and retained
AIO/GLib contexts, rejects source-process or still-live-worker use, refreshes
the otherwise single-use initialization semaphore, and starts one replacement
worker. A following child-only operation runs synchronously on that exact
replacement worker, revalidates the complete held monitor and socket state,
and emits the replacement QMP open event while input remains held. The open
event emits exactly one greeting before the child reports its complete resource
state. Only after the complete child resource transaction commits may a
distinct operation flush that greeting and attach one read source and one HUP
source; it returns `-EAGAIN` without mutation while output remains buffered.
These operations remain unreachable from a production command; fork
coordination, post-commit input release, guest admission, and readiness bits 7
and 8 remain open.
The sealed QMP contribution now carries those exact template and child-QMP
generations alongside its descriptor and socket identity. The immediate-child
resource transaction requires both the plugin and QMP reinitializers to match
their complete sealed bases before descriptor mutation, then consumes them as
one linear reconstruction step. A same-endpoint adapter from another QMP
generation is rejected before mutation, and either runtime failure leaves the
child transaction fail-closed. Child-QMP schema version 7 now retains the exact
concrete monitor runtime and private monitor basis in that one-shot adapter
before fork; child application no longer accepts a runtime supplied after
descriptor mutation begins. Concrete child-only monitor disposal,
dispatcher/IOThread reconstruction, endpoint attachment, greeting, and input
release primitives now exist, but the production fork owner does not yet invoke
the composed callback or perform the post-commit private-stream release, and
proof bits 7 and 8 remain clear.

The QEMU thread and registered-`QemuMutex` inventories now also have an explicit
coordinator-owned fork transaction. Beginning the transaction serializes both
registries, rejects an in-flight `qemu_thread_create()` start, requires the
calling thread to be the exact registered coordinator, and requires every
bounded registered mutex to be initialized, ownership-valid, unlocked, and
free of recursive ownership, waiters, condition waiters, and an active unlock
transition. The parent releases the transaction only if its process, thread,
coordinator record, and registry generation are unchanged. The immediate child
instead reconstructs the copied thread registry around the sole surviving
coordinator and advances its process-local generation before releasing the
registry locks. A real-fork unit test proves the parent registry is unchanged,
the child contains exactly that coordinator, and a locked registered mutex
fails before fork. This transaction does not inventory raw `pthread` or GLib
locks, choose every subsystem disposition, or invoke `fork(2)` from a
production command. Those obligations remain part of the closed
supported-profile registry, so readiness bit 8 stays clear.

The fork runtime now composes that registry transaction inside exact retained
RCU and asynchronous-source transactions. The outer transactions close reader,
callback, reader-registry, AIO, GLib, coroutine, bottom-half, and timer admission;
require the exact coordinator reader and both complete callback states to be
quiescent; and bind the process, monitor-thread owner, inventory generations,
and barrier generations. An inner-registry acquisition failure releases the
transaction reservations without changing either already-held template
barrier. The parent releases the copied registry ownership but deliberately
leaves both reusable template barriers held.

The immediate child first reconstructs the thread and RCU registries, discards
vanished reader records, rebinds the coordinator reader, and resets the
proven-empty callback queue while inherited descriptor admission is still
closed. It then commits the complete descriptor disposition and only afterward
starts one fresh `call_rcu` worker. Plugin reconstruction follows, and a final
runtime phase releases the child's copied asynchronous-source barrier before
child-QMP activation starts the replacement monitor IOThread. The
registered-thread transaction admits exactly the coordinator, RCU worker, and
classified monitor worker, rejecting generic and other AIO workers before
fork. A real-fork regression proves the phase ordering, both parent barrier
retentions, child-only releases, and unchanged parent inventories;
active-reader, wrong-generation, and unsupported-worker regressions prove
fail-closed rollback. Raw and library-owned locks and the remaining subsystem
dispositions still keep readiness bit 8 clear.

QEMU also installs a Linux-only main-loop fork coordinator. A raw event notifier
is polled outside the asynchronous-source admission barrier, allowing one OOB
owner to submit an immutable prepare/parent/child operation while all covered
BH and AIO work is parked. Preparation, `fork(2)`, and parent disposition run on
the designated source main-loop thread. The immediate child closes and disables
the copied notifier before its callback and before main-loop work resumes. A
positive child PID is returned even when parent disposition fails, preserving
the caller's direct-child ownership obligation. The child callback MUST arm
parent-death containment and authenticate the immediate child before any
reconstruction or externally visible action. A real-fork unit test proves the
thread ownership and returned-PID contract.

Template contract version 24, resource-stage version 13, and fork-result schema
version 2 now expose that coordinator as the public `crucible-hot-fork` QMP
command. The request carries the exact template, private-ring, diagnostics,
child-QMP, child-console, monitor, plugin-endpoint, plugin-barrier,
descriptor-table, parent-process, child-process, child-process-contract, and
child-runtime generations. QEMU revalidates all fourteen fields on the source
main loop before forking. The child closes the inherited parent QMP channel,
commits the exact descriptor table, reconstructs the runtime, plugin, private
child-QMP, and child-console resources, and releases block, console, and QMP
input only after their owning transactions commit. The language-neutral command
contract is:

```text
crucible-hot-fork(
    template-generation: u64,
    private-ring-generation: u64,
    diagnostic-generation: u64,
    qmp-generation: u64,
    console-generation: u64,
    monitor-generation: u64,
    plugin-endpoint-generation: u64,
    plugin-barrier-generation: u64,
    rcu-barrier-generation: u64,
    bh-timer-barrier-generation: u64,
    block-barrier-generation: u64,
    parent-process-generation: u64,
    child-process-generation: u64,
    child-process-contract-generation: u64,
) -> CrucibleHotForkState

CrucibleHotForkState {
    schema-version: u32 = 2,
    outcome: forked | parent-disposition-failed,
    parent-status: i64,
    child-pid: i64 > 0,
    ...the exact fourteen request generations...
}
```

The parent response always returns
the positive child PID once a child exists, and distinguishes a successful
fork from a parent-disposition failure. That response is parent-only evidence:
the host MUST retain direct-child authority and authenticate the private child
channel before admitting the child.

The source QEMU also owns the bounded parent-side reap record for each forked
child:

```text
crucible-hot-fork-child-process(
    action: query | release,
    generation: u64 > 0,
) -> CrucibleHotForkChildProcessState

CrucibleHotForkChildProcessState {
    schema-version: u32 = 1,
    generation: u64,
    child-pid: i64 > 0,
    phase: running | exited | signaled,
    status: u8,
    retained: bool,
}
```

Before `fork(2)`, the source reserves the request's unique nonzero
`child-process-generation` in a fixed 4,096-record table. A duplicate
generation or full table rejects the fork before a child exists. A successful
fork binds the exact positive PID to that reservation. While the record is
`running`, each `query` or `release` performs at most one EINTR-safe,
nonblocking `waitpid(pid, WNOHANG)` operation in the source QEMU. Normal exit
retains its exit code; signal termination retains the nonzero signal number.
The record remains addressable after reap, so PID reuse cannot alter its
identity or result. `release` rejects a running child and is the only operation
that removes a reaped record; its returned state has `retained = false`.

This query-driven design deliberately installs no ambient child watcher or
callback that an immediate child could inherit during a later fork. The daemon
uses its independently retained pidfd/cgroup authority to observe or terminate
the process, then asks the source QEMU to reap and report the exact generation.
The numeric PID and retained status record are evidence, not daemon-owned
process authority.

The branch-private console stage uses this separate language-neutral contract:

```text
crucible-hot-fork-child-console(
    action: stage | query | release,
    fdname?: str,
    expected-socket-cookie?: u64,
) -> CrucibleHotForkConsoleState

CrucibleHotForkConsoleState {
    schema-version: u32 = 1,
    generation: u64,
    template-generation: u64,
    staged: bool,
    fdname?: str,
    socket-cookie: u64,
    retained-fd: i32,
    resource-plan-bound: bool,
    nonblocking-unix-stream: bool,
    console-basis-bound: bool,
    reinitializer-prepared: bool,
    reinitialized: bool,
    disposition-complete: bool,
    readiness-proof-acknowledged: bool,
}
```

`stage` requires one standard-QMP descriptor naming a connected nonblocking
Unix stream with the exact nonzero Linux `SO_COOKIE`; it independently
duplicates that stream and binds the inherited `crucible-console` frontend plus
one-shot child chardev reinitializer. `query` is observational. `release`
requires the exact descriptor name and cookie and rejects while the retained
template still owns the plan. It releases after the sealed plugin plan and
before its predecessor child-QMP endpoint. A successful child disposition
installs the replacement stream before console input becomes active.

The Rust host boundary now makes that ordering linear. The node operation
accepts an explicit child-process owner but no caller-supplied generation
tuple. It queries the prepared template, private ring, diagnostics, child QMP,
child console, and child-process contract, then queries the template again.
The two template reports MUST be identical, every intervening report MUST
match both the template resource stage and the node's corresponding linear
host authority, and only that checked basis may construct the fourteen-field
fork request. QEMU revalidates the same basis in the immediately following
fork command. The node returns a launch token only after the child-process
owner authenticates and retains the exact source PID, child PID, and request
basis. The token jointly owns the process
authority, the single branch-private QMP endpoint, and one host continuation.
That continuation retains the exact private-ring descriptor, branch-private
console observation spool, the
host control/wake endpoints, and an independent clone of every scheduler-owned
shared-memory cursor, pending event, coverage state, selectable continuation,
and the same scheduler-owned topology send-authorizer capability. The source retains
its own unchanged template state.
Explicit command rejection leaves the source node and endpoint reusable; every
indeterminate exchange, parent-disposition failure, missing endpoint, or
process-retention failure quarantines the complete source node. A positive PID
is never treated as a direct-child wait handle. The source console reader is
duplicated before the fork so an explicit command rejection remains retryable;
only a known successful transfer consumes the original endpoint. Attaching the
returned spool to the child keeps source and child console bytes isolated.
Other writable host-device continuations remain separate branch-local cloning
work; the console/plugin continuation does not claim to clone those owners.

This is an interface checkpoint, not the concrete daemon process owner. The
forked process is a direct child of the template QEMU rather than of the daemon.
The parent-QEMU `waitpid` and retained-status protocol now exists, but
production composition still requires a lifecycle-bound daemon cgroup/pidfd
authority for the reported child generation and an exact transfer into branch
resource accounting before child admission. Until that composition exists, no
implementation of the host owner may manufacture `std::process::Child`
authority from the reported PID or advertise the returned launch token as a
production campaign child.

Child-QMP contract version 8 reports `readiness-acknowledged` only when the
exact resource plan and descriptor disposition are committed, runtime and
plugin reinitialization are complete, the greeting was sent, and replacement
input was released. Explicit QMP command rejection before the fork leaves the
parent connection reusable. Any transport, framing, echo, or response failure
is fork-indeterminate and MUST poison the parent connection and transfer the
attempt to direct-child reconciliation. Daemon composition with the
parent-owned retained-status query, attempt-owned process guard,
child-generation cgroup/pidfd authority, resource accounting, private channel
authentication, and campaign observation remains required before this command
may serve a production campaign flight.

The version-3 child-QMP report first derived `disposition-complete` from that
exact accepted one-shot status instead of hard-coding false. Prepared but
unattempted, contradictory, failed, and reset adapters remain incomplete; the
accepted result must still match the retained descriptor, socket identity,
template generation, QMP generation, monitor generation, complete flags,
single monitor, and empty queued/parser state. This makes a future child query
accurately observable but does not invoke the retained concrete runtime or
acknowledge proof bit 7 or 8.
After successful child application, the immutable reinitializer and sealed-plan
bases now remain exactly queryable without making either one reusable. The host
records the child-QMP mutation generation in the staged proof and may transfer
its host-side socket endpoint exactly once only after plugin endpoint commitment
has sealed the complete resource plan. The child emits the ordinary QMP
greeting into the still-held connection before reporting its complete resource
state; after commit, opening the linear host endpoint observes that greeting and
performs capability negotiation before making
`crucible-hot-fork-child-qmp(query)` the first typed operation. The connection
is exposed as a child VMState control channel only when the response matches the
retained descriptor name, Linux `SO_COOKIE`, template generation, QMP
generation, monitor generation, applied resource-plan membership, and accepted
complete disposition. Any exchange or basis failure consumes the endpoint and
fails closed. This implements the host authentication half of the private-stream
generation handshake; the concrete child-only monitor operations exist but
their invocation from the production fork owner remains open, so proof bits 7
and 8 stay clear.
Endpoint staging rejects a private-ring stage from a different or already
aborted transaction. A new transaction starts only with an empty resource
stage. Private-ring, diagnostics, child-QMP, and plugin-endpoint staging during a
transaction is accepted only in the fully held phase, at the exact
paused/device-flush boundary, and while the retained plugin barrier is
quiescent. Those retained template resources do not acknowledge mapping and
descriptor proof bit 7 or child-reinitialization proof bit 8. After abort, the
resource report retains the immutable
origin generation while `transaction-bound` becomes false, so cleanup can
authenticate ownership without mistaking retained descriptors for a live
template proof.

The caller MUST explicitly `abort` an incomplete retained transaction before
resuming or abandoning the template. Abort rolls the four barriers back but
does not silently discard separately owned staged descriptors; those are
released through their exact resource operations after rollback.
Rollback releases plugin, asynchronous-source, and RCU admission before it
schedules graph and native block release on the main AioContext; this ordering
prevents new AIO work from entering while the block layer is still drained.
Graph admission reopens immediately before native drain cleanup inside that one
main-loop callback, so a parked outer writer cannot interleave with the cleanup.
`query` is observational. `abort` requests rollback and eventually reports `aborted`;
aborting an idle coordinator reports `idle`. Standalone mutation of any one of
the four barriers is rejected while any asynchronous transaction phase is
reserved. A failed release does not discard coordinator ownership: later
prepare/abort calls retry it, while query continues to observe the retained
draining state. `blocked` is reserved for a preparation path that must roll back
after a subsystem acquisition or retained-transition failure; missing future
proof classes alone do not trigger rollback.

`missing-proofs` MUST equal `required-proofs & ~acknowledged-proofs`.
`rollback-complete` is true exactly when no transaction is active and none of
the four barriers is held. `ready` is true exactly for an active `prepared`
transaction whose plugin, RCU, asynchronous-source, and block barriers are
quiescent and whose missing bitmap is zero.
Proof bit 4 is present exactly while the transaction remains active and its
complete RCU barrier is quiescent. Proof bit 3 is present exactly while the
transaction remains active and its complete asynchronous-source barrier is
quiescent. Proof bit 5 is present exactly while the transaction remains active
and its complete immutable writable-root binding remains retained by the
quiescent block barrier. Version 19 composes plugin-ring proof bit
6 from the exact transaction-bound frozen ring, diagnostics stream, retained
child-QMP stream and prepared reinitializer, endpoint pair, worker plan, and
plugin barrier. The resource-table binding remains nondestructive. Template
version 24 deliberately requires only bits 0 through 6: descriptor/mapping
proof bit 7 and child-reinitialization proof bit 8 are child-only results that
cannot truthfully exist in the retained parent template. A fully parent-bound
transaction may therefore report `prepared`; only the private child report can
prove the final two dispositions for a particular fork. The public command
composes those child-only operations for the supported QEMU profile, while
daemon-owned containment, reaping, accounting, and campaign publication remain
outside the template contract.

The standalone AioContext, AIO-handler, and block-backend responses remain
observational. The retained asynchronous-source barrier composes the context,
handler, coroutine, bottom-half, and timer admission classes and derives proof
bit 3 only while they are complete and quiescent. The coordinator now composes
the retained native block drain, graph-writer barrier, and exact immutable
writable-root binding to derive proof bit 5. It must retain the exact
descriptor/mapping and child reconstruction plans so the fork command can
consume them after the parent template is prepared.

Patched POSIX QEMU also exposes the bounded observational mutex inventory used
to define the process-private lock side of the child-reinitialization proof:

```text
CrucibleHotForkMutexInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    mutex-count: u32,
    recursive-mutexes: u32,
    owned-mutexes: u32,
    acquisition-waiters: u64,
    condition-waiters: u64,
    unlock-transitions: u32,
    invalid-mutexes: u32,
    mutexes: [
        {
            mutex-id: positive u64,
            owner-thread-id: nonnegative i64,
            recursion-depth: u32,
            acquisition-waiters: u32,
            condition-waiters: u32,
            recursive: bool,
            unlock-active: bool,
            ownership-valid: bool,
        },
    ],
}
```

`mutexes` contains at most 65,536 records in strictly increasing `mutex-id`
order. Owner zero and recursion depth zero are equivalent; every positive owner
MUST appear in the matching QEMU thread inventory; and a nonrecursive mutex
MUST have depth at most one. All top-level counts are exact checked sums.
`complete` equals `!overflowed && invalid-mutexes == 0`. The process-local
generation advances on mutex creation and destruction, while ownership and
waiter fields are instantaneous state. Instrumentation transitions and the
snapshot serialize on a private raw pthread mutex, so a response cannot contain
a half-updated owner/depth pair and the inventory lock cannot recursively enter
the `QemuMutex` registry it observes.

This response is still observational. It does not acquire all QEMU locks,
retain a barrier across `fork(2)`, prove that an omitted raw or library mutex is
safe, select a child disposition, or run a child reinitializer. It therefore
MUST NOT acknowledge proof bit 8. The future coordinator must retain the
appropriate subsystem barriers and explicitly account for every omitted
process-private resource before authorizing a fork.

Patched POSIX QEMU also exposes the bounded observational live-timer inventory
used to define the timer side of the AIO/BH barrier:

```text
CrucibleHotForkTimerInventory {
    schema-version: u32 = 1,
    generation: u64,
    complete: bool,
    overflowed: bool,
    timer-count: u32,
    pending-timers: u32,
    active-callbacks: u32,
    timers: [
        {
            timer-id: positive u64,
            timer-list-id: positive u64,
            clock: realtime | virtual | host | virtual-realtime,
            expire-time-ns: i64,
            scale: positive u32,
            attributes: u32,
            pending: bool,
            callback-active: bool,
        },
    ],
}
```

`timers` contains at most 65,536 records in strictly increasing `timer-id`
order. It contains every pending timer and every callback active at the
inventory instant; an initialized timer that is neither pending nor executing
is inert and is intentionally absent. `expire-time-ns` is nonnegative exactly
when `pending` is true and is otherwise `-1`. `pending-timers` and
`active-callbacks` are exact checked counts, and `complete` equals
`!overflowed`. Stable process-local timer and timer-list identities are assigned
at initialization. Pending-state and callback begin/end transitions advance the
generation. Pending records expose a registry-owned expiry copy rather than
racing the timer-list lock, and callback registry entries own copied metadata
rather than a timer pointer, so a callback may legally free its enclosing timer
before the inventory entry is removed.

This response is still observational. It does not prevent a timer from being
armed, canceled, or fired after the query, retain a timer-list or AIO barrier
across `fork(2)`, select a child disposition, or reinitialize clock state. It
therefore MUST NOT acknowledge proof bit 3. The version-6 coordinator supplies
the required retained timer and AIO/BH composition; this standalone inventory
still cannot promote the proof by itself.

The Phase 6 host audit complements that query with bounded operational evidence
for one exact Linux process generation. It accepts only while proof bit 2 is
set, brackets the procfs capture with two identical thread-registry, RCU,
AioContext, AIO-handler, block-backend, plugin-resource, bottom-half, mutex, and
timer snapshots inside two identical readiness reports,
authenticates the QEMU PID/start-time/executable identity before and after, and
rejects any incomplete QMP inventory before requiring two complete
process-inventory passes to match byte-for-byte. Every
bottom half MUST name a context in the matching AioContext inventory. Each
QEMU-registered thread MUST be present in that exact process generation.
Procfs threads absent from
the internal registry are reported separately as externally created blockers.
Each pass also records descriptor numbers and link targets and
`/proc/<pid>/maps` records, including writable/shared classification. A warm
pass occurs before the two compared passes so audit-allocation growth is not
mistaken for target drift in conformance fixtures.

The version-1 operational limits are 65,536 threads, 65,536 descriptors,
65,536 mappings, 256 bytes per thread name, 4 KiB per descriptor target, 8 KiB
per mapping record, and 16 MiB of aggregate retained record bytes. Every count,
length, numeric identifier, mapping grammar, and aggregate addition is checked
before retention. The aggregate limit applies to each pass; exact comparison
retains at most two bounded passes, and the warm pass is released first.
Exceeding a bound, changing process generation, readiness, or QEMU registry,
missing a registered thread from procfs, or observing different process passes
rejects the audit.
This observed fixed point is deliberately not a quiescence proof: it does not
retain a mutex or QEMU-internal AIO/BH/timer/plugin barrier, traverse the
BQL-owned block graph, inventory process-lifetime plugin heap ownership, resolve
external-thread dispositions, or run child reinitializers. The block inventory
cannot prove an immutable writable-root boundary. It cannot set any readiness
bit, prepare a template, or authorize `fork(2)`.
The thread registry identifies the live RCU callback and AIO-context workers
by subsystem-specific unresolved dispositions. The RCU inventory exposes the
exact observed reader and callback state, the AioContext inventory exposes
home-thread binding plus instantaneous poll, dispatch, bottom-half, coroutine,
and notification activity, the bottom-half inventory exposes every allocated
instance and its exact AioContext and lifecycle state, the mutex inventory
exposes instantaneous owner, recursion, waiter, and unlock-transition state,
and the timer inventory exposes every pending timer and active callback, while
any other non-coordinator remains plain `unclassified`. These observational
inventory values are not child dispositions or held barriers. The version-2
coordinator now separately retains the RCU admission/drain barrier; the other
proofs must be produced while later coordinator versions hold their
corresponding subsystem barriers.

Later template realization adds the remaining operations:

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
for every running node, rejects powered-off or partial Worlds, requires each
child generation to be the checked immediate successor of its source, and
reauthenticates every process incarnation before publication. The continuation,
rather than a new caller-supplied launch configuration, retains the source
lifecycle configuration, immutable root identities, and resolved block/9p
bindings; only a fresh durable run-state root is supplied at adoption. Any
backing change or unconsumed child-world state fails closed. Daemon invocation
of this constructor, transfer of the aggregate attempt owner into the resulting
lifecycle, the branch-private child root-overlay proof, and the real modeled
QEMU flight remain mandatory before this path is enabled or T-CAM-7.4 is marked
complete.

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

The single-host implementation stores VMState as a dense chunk sequence and a
root overlay as immutable backing plus a canonical sparse changed-chunk map. It
keeps every running QEMU node paused after exact capture, discovers allocated
overlay ranges with `SEEK_DATA`/`SEEK_HOLE`, canonicalizes allocated all-zero
chunks back to holes, and streams only nonzero changed chunks plus VMState into
the content store. A filesystem without reliable extent discovery fails closed
rather than falling back to work proportional to the virtual disk. The closure
is durably published before transient QMP snapshots are deleted and only nodes
that were running are resumed. No second full-file staging tree is created.

Version-seven sparse artifacts carry a logical `length`, no dense `chunks`, and
strictly ordered, nonoverlapping, nonadjacent extents. Each extent contains a
`start_chunk` and one or more consecutive BLAKE3 chunk identities; chunks are
4 MiB except for a final partial logical chunk. Omitted logical chunks are
canonical zeroes. The sparse artifact identity is
`H("crucible.production-exact-sparse-artifact.v1",
hex(canonical_cbor({length, extents})))`; stored chunk bytes independently
authenticate against their named identities. This binds the exact logical byte
stream without hashing every omitted zero during capture.

Restore authenticates the extent geometry, identity, and every stored chunk,
then writes those chunks into a new destination-side staging file and creates
omitted ranges as holes. Dense legacy artifacts stream through a fixed 1 MiB
buffer and authenticate their complete byte-stream hash. A corrupt, short,
long, or missing source leaves no partial destination. Cleanup attempts every
captured node even when one delete or resume fails. Hashing, chunk persistence,
portable closure validation, and campaign-store streaming observe attempt
cancellation between bounded I/O chunks; cancellation cannot bypass cleanup or
be misclassified as retryable store I/O. The remaining storage work is:

- admit QEMU-emitted RAM dirty-page/extent manifests when the fork/snapshot
  capability is available;
- compact and tier long delta chains without changing configuration identity.

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
attempt ceiling. Dense restore copies the complete authenticated stream into
staging storage and may expose it to QEMU only after EOF, exact length, and
digest have all been observed. Sparse overlay restore authenticates the exact
extent manifest and every named chunk before atomically exposing a file whose
omitted ranges are zero holes.

The complete multi-node production continuation uses version seven of the same
typed root rather than flattening a potentially large object set into one
generic envelope. The registered leaves are the canonical
`crucible.production-exact-closure@device-state.7` manifest and exact opaque
production objects under
`crucible.executor.production-checkpoint-object@device-state.5`. Every object
retains its production BLAKE3 identity and declared length in a registered
`crucible.executor.production-checkpoint-index@exact-manifest.1` page. A page
contains at most 4,096 objects and has this canonical body and child mapping:

Version five added the strictly node-ordered selectable catalog plans to the
bounded lifecycle-continuation object. Each plan remains the canonical
`CRUCSCP2` process-neutral body, is at most 32 MiB, and must be frozen and bound
to a live checkpoint target. The closure reader continues to accept a canonical
version-four manifest as an exact legacy identity; such a closure has no
selectable catalog plans and therefore cannot restore a selectable-bearing
scenario.

Version six additionally binds every live target to the BLAKE3 identity of
the immutable root-image bytes supplied to QEMU. Lifecycle construction hashes
the selected image, and capture includes that identity in both the target record
and target-manifest identity. Restore rejects a mismatch before launching QEMU.
Canonical version-four and version-five manifests remain readable with no backing claim;
they retain their original bytes and identities, while version-six and later
targets make the backing proof. Version seven replaces each dense overlay chunk
sequence with the canonical sparse extent representation above while retaining
dense VMState chunks. Canonical version-six manifests remain readable and retain
their original bytes and identities.

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
bound by the version-four root. The local configured checkpoint-byte ceiling applies to the
manifest plus deduplicated production-object bytes in addition to the authored
production resource bound. Before inventory allocation, the loader also
requires `object_count * 32 <= manifest_bytes`; every deduplicated object must
occur as at least one 32-byte identity in the canonical manifest, so this
conservative relation bounds hostile zero-length inventories by the 64 MiB
manifest ceiling.

For a packaged fresh attempt, the modeled driver yields checkpoint ownership
only at an exact safe boundary. The production lifecycle first retains the
complete portable source in its separately bounded native catalog. While that
lifecycle is still owned by the runner, the fixed pool authenticates the source
scenario, streams every native object to derive the version-four campaign root,
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
work. Packaged version-four capture and ledger handoff are implemented; exact
production semantic installation is now cancellation-bounded and authenticates
the restored configuration and scheduler continuation before launch authority
can exist. The installer requires the branch post-selection configuration (or
the discovery start) as an exact schedule prefix and rejects any later campaign
branch edge as a different attempt before native-catalog publication.
Version-four source-bound replay-oracle promotion is implemented over the
complete portable closure. It validates one exact raw-snapshot check per live
node, derives only matching snapshot and dependent manifest/root identities,
reuses unchanged chunked artifacts, and reauthenticates the exact raw/promoted
pair after restart before the paused-root CAS. Production-loop process
reconstruction and resume-driver selection are now composed in the packaged
worker: the resume-only admission rejects `NotRun` before native publication or
resource installation, restores the complete scheduler/evidence continuation,
and never falls back to fresh replay. The ordinary guarded lifecycle can now
capture a separate candidate at the exact scenario-genesis ready boundary
without executing a modeled quantum, tear QEMU down, and admit only a complete
version-four native closure whose live-node set exactly equals the World. That
capability is the authenticated bootstrap source for baked-genesis replay; it
does not publish a campaign root or advertise exact restore. The concrete
node-specific replay factory now shares one completely authenticated compact
target catalog, opens only the requested baked snapshot, streams the selected
fat and baked artifact pairs into separate descriptor-pinned generations under
one exact attempt guard, and launches them through disjoint exact and thin
profile capabilities. Packaged startup captures that baked source before
binding the endpoint, installs one fixed promotion owner per semantic worker,
and advertises `ExactRestore` only when that nonempty owner set exists.
Assignment-root-aware cleanup of abandoned attempt and promotion native
catalogs is implemented by the crash-safe retirement protocol above. A
`checkpoint-publishing(root)` record interrupted before immutable publication
retains the expected content identity; restart deterministically recaptures and
must reproduce that root. Once the root is complete in campaign CAS, the native
catalog is redundant and may be retired without weakening recovery or GC
reachability.

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
  changes. Version 3 also carries the exact source VMA start, length, and zero
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
  remap tests. The version-14 retained template transaction now derives that
  exact plan and copies it into the one-shot adapter before it admits the
  endpoint stage. Its report carries the checked parent/child generation pair
  and whether the unconsumed adapter still matches every retained resource
  field; replay requires the same plan and exact endpoint release clears the
  parent copy. No production fork caller invokes this composition, and complete
  non-plugin subsystem reconstruction, host-continuation pairing, guest release,
  and readiness bits 7 and 8 remain open;
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
