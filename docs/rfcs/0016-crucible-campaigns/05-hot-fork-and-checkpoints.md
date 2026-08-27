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
    schema-version: u32 = 2,
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
                unclassified-rcu |
                unclassified-aio,
        },
    ],
}
```

`threads` MUST contain at most 65,536 entries in strictly increasing thread-ID
order. `unclassified-threads` MUST equal the number of every disposition other
than `coordinator`, at most one coordinator may be present, and `complete` MUST equal
`!overflowed && all(name-valid) && coordinator-count == 1`. The process-local
generation advances when a QEMU-created thread registers, unregisters, or
changes disposition. The first query registers the process-lifetime QMP
main-loop coordinator; later observational queries with no thread transition
return the same generation and body. Every thread created through
`qemu_thread_create()` is registered before its start routine and unregistered
through a cleanup handler. Threads created by linked libraries or raw pthread
calls are not silently treated as QEMU-owned.

Schema version 2 assigns the `call_rcu` worker to `unclassified-rcu` and every
QEMU `IOThread` to `unclassified-aio` through calls made by the subsystem's own
thread entry point, not by matching diagnostic names. These values identify the
owner that must eventually provide the barrier and child reinitializer; they
remain included in `unclassified-threads`, remain fork blockers, and do not
acknowledge readiness bits 3, 4, or 8. Plain `unclassified` remains the
fail-closed value for every other `qemu_thread_create()` caller. Schema version
1 is rejected rather than silently interpreting its smaller disposition
registry under version-2 semantics.

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

The RCU response is still only one lock-bounded observation. Reader activity,
callback submission, and drain state may change immediately after it returns;
the query neither drives nor holds quiescence and therefore MUST NOT
acknowledge proof bit 4 or authorize a fork. The future coordinator must
establish and retain an RCU barrier across the actual process-fork operation.

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

Patched QEMU and the loaded Crucible plugin additionally establish one sealed,
scalar plugin-resource inventory. The plugin registers this manifest only after
all callback families, the wake descriptor, and fault admission are installed,
and before it sends the successful setup acknowledgement. QEMU independently
records callback registration and exposes the joined state through an
out-of-band query:

```text
CrucibleHotForkPluginResourceInventory {
    schema-version: u32 = 1,
    generation: u64,
    registered: bool,
    complete: bool,
    process-generation: u64,
    plugin-id: u64,
    resource-mask: u64,
    callback-mask: u64,
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
cross-process protocol. The response inventories installed resources but does
not count executing callbacks, freeze a ring, stop future callbacks, retain a
process-lifetime barrier, or define child dispositions. It therefore MUST NOT
acknowledge proof bit 6 or authorize a fork.

The next plugin checkpoint adds a distinct reversible callback barrier. The
plugin registers one process-lifetime operation only after every covered
callback owns the same admission counter. QEMU exposes the operation through
the out-of-band `crucible-hot-fork-plugin-barrier` command:

```text
CrucibleHotForkPluginBarrierAction = hold | query | release

CrucibleHotForkPluginBarrierState {
    schema-version: u32 = 1,
    generation: u64,
    registered: bool,
    manifest-consistent: bool,
    held: bool,
    teardown-closed: bool,
    in-flight: u64,
    quiescent: bool,
}
```

`hold` is accepted only at QEMU's authenticated exact paused/device-flush
boundary. It atomically rejects later covered callbacks and returns immediately;
callbacks admitted before the hold remain in `in-flight`. `query` observes the
counter without changing it. `release` removes only the reversible hold and
MUST NOT reopen admission after permanent teardown closure. `quiescent` equals
`registered && manifest-consistent && held && !teardown-closed && in-flight ==
0`. The process-local generation is positive after registration and advances
when the held/teardown flags change. An unregistered response has generation
zero and every other field zero or false.

This is a retained barrier over the callback classes covered by the sealed
manifest, including live device and coverage callbacks, but it is not the
complete plugin-ring proof. It does not prevent the Apache host from producing
new shared-memory commands, drain or park the fingerprint digest worker, freeze
the control-reader/teardown threads, clone ring bytes, or provide child-side
resource reconstruction. QEMU therefore keeps readiness bit 6 clear.

The first `PrepareForkTemplate` checkpoint is the version-1 OOB
`crucible-hot-fork-template` coordinator:

```text
CrucibleHotForkTemplateAction = prepare | query | abort

CrucibleHotForkTemplateOutcome =
    idle | draining | blocked | prepared | aborted

CrucibleHotForkTemplateState {
    schema-version: u32 = 1,
    generation: u64,
    outcome: CrucibleHotForkTemplateOutcome,
    transaction-active: bool,
    required-proofs: u64 = 0x01ff,
    acknowledged-proofs: u64,
    missing-proofs: u64,
    plugin-barrier: CrucibleHotForkPluginBarrierState,
    rollback-complete: bool,
    ready: bool,
}
```

`prepare` starts only at the authenticated exact paused/device-flush boundary.
QEMU serializes the transaction, acquires the plugin callback barrier, and
retains it while previously admitted callbacks drain. A repeated `prepare`
reevaluates the retained transaction. Once that barrier is quiescent, QEMU
either reports `prepared` only when all nine required bits are present in the
same transaction, or releases every acquired barrier and reports `blocked`.
`query` is observational. `abort` releases an active transaction and reports
`aborted`; aborting an idle coordinator reports `idle`. Standalone plugin hold
or release cannot mutate a barrier owned by the coordinator. A failed release
does not discard coordinator ownership: the command fails and the caller must
retry query/abort while QEMU continues to own the retained state.

`missing-proofs` MUST equal `required-proofs & ~acknowledged-proofs`.
`rollback-complete` is true exactly when no transaction is active and the
plugin barrier is not held. `ready` is true exactly for an active `prepared`
transaction whose plugin barrier is quiescent and whose missing bitmap is zero.
Version 1 intentionally owns only the plugin callback barrier. It does not yet
compose the remaining ring, AIO, RCU, block, descriptor/mapping, or child
reinitialization barriers; therefore it rolls a drained transaction back as
`blocked` and cannot advertise a usable hot-fork template.

The AioContext, bottom-half, AIO-handler, and block-backend responses are still
observational. They do not drain or park a context, prevent a producer from
enqueueing work after a query, hold a callback barrier, or hold quiescence
across `fork(2)`. They therefore MUST NOT acknowledge proof bit 3. The future
coordinator must establish and retain the AIO/BH/timer drain-and-park barrier
across the fork transaction.

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
therefore MUST NOT acknowledge proof bit 3. The future coordinator must retain
the timer and AIO/BH barriers across the fork transaction.

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
any other non-coordinator remains plain `unclassified`. None is a child
disposition or a
held barrier.
Those proofs must be produced while a later version of the QEMU coordinator
holds the corresponding subsystem barriers.

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
