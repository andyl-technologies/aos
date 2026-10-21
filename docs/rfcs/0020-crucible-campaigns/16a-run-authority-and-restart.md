# 16a — Run Authority, graceful restart, and Campaign Arena

[§16](16-run-arena-and-run-journal.md) defines the Run Arena that owns a run's
modeled host state and the Run Journal that owns its event history. This
chapter defines what owns everything else: the **Run Authority** over a run's
live operating-system resources, the durable record that lets a new daemon
contain what an old one left behind, the checkpoint-drain restart built from
those pieces, migration, the evicting spill cache for arena chunks, and the
read-only **Campaign Arena** view over the executor's operational records.

Code references name repository-relative paths and symbols as surveyed at the
time of writing; they locate today's behavior and are not normative.

## 16a.1 Run Authority and resource slots

Live operating-system resources are not state. A process handle, pidfd, cgroup,
memfd, shared-memory mapping, socket, lock, lease, temporary directory, or QMP
snapshot handle is authority held by one daemon process. It cannot be
serialized meaningfully, and copying it would alias it. The Run Authority owns
every such resource for one run. Its type implements neither `Clone` nor
`Serialize`, so a cloned or persisted arena cannot carry authority and every
consumer of a frozen arena must bind its own.

### Resources a run holds today

| Resource | Acquired by | Released by | On restore or adoption |
| --- | --- | --- | --- |
| QEMU process, joined to the attempt cgroup before exec, with `PR_SET_PDEATHSIG` | `crates/crucible-qemu/src/spawn.rs` through the lifecycle launcher | Node-set reap; dropping a node sends `SIGKILL` and waits up to 5 s; a failed launch goes to cgroup quarantine | New generation; instruction-counter and fingerprint checks in `construction.rs`; any failure quarantines and finishes |
| Plugin socketpair, shared-memory ring memfd, wake eventfd | `spawn.rs`, `host_setup.rs` | Closed with the node | Recreated per generation; a hot-fork private ring is re-authenticated |
| QMP and gdbstub sockets | Launch control channels | Removed with the run directory | Rebound |
| Debug gateway process and temporary directory | `crates/crucible-api/src/debug_gateway.rs` | Gateway shutdown or drop | Not restored |
| Per-generation lease | `crates/crucible-daemon/src/qemu_resource_guard/generation_resource.rs` | Lease finish; drop forces quarantine | The generation must exceed the last issued |
| Generation run directory | `crates/crucible-qemu/src/linux_attempt_storage.rs` | Launcher entry removal; bytes removed with attempt storage | New per generation |
| Attempt cgroup, watcher thread, cancellation eventfd | `linux_cgroup.rs`, `attempt_owner.rs` | Attempt owner finish; drop hands off to a quarantine thread | New per attempt |
| Attempt storage root, ext4 project quota, project-ID lease | `linux_attempt_storage.rs` | After process reap; drop leaks the descriptors | New per attempt |
| Durable `run-NNNN/` directory, `run-state.json` process journal (pid and start time), exit log | `vm_lifecycle.rs`, `persistence.rs` | Never deleted by the lifecycle | A new run directory each time |
| Hot-fork disk pins (open inodes) | Restore construction and hot-fork capture | After reap and before launcher finish, because the inodes count against quota | Reopened, not recreated; device, inode, and content checks |
| Image-helper children | The lifecycle launcher | Launcher finish | New |
| Retained external owners (resume workspace) | Lifecycle configuration and remote resume | Dropped last | Not applicable |
| Checkpoint staging | `run-NNNN/exact-checkpoints` and the scenario catalog | Checkpoint recovery | Recovered at construction |
| Hot-fork world guard, adopted-node lease, source world | `qemu_hot_fork_world_resource.rs`, `qemu_hot_fork_reconciliation/linux.rs` | Drop quarantines, then forgets; an unreconciled source is leaked | Child generation must be the source generation plus one |

`ProductionVmLifecycleLoop` has no `Drop`. Its explicit shutdown tears down in
this order: debug gateway, QEMU reap, node lease finish, hot-fork disk pins,
launcher finish, then a clean-shutdown record. Today "quarantine" means an
in-process leak or a retry thread; dozens of leak and forget sites exist across
`crucible-api` and `crucible-daemon`, and none of them survives process exit.

### Resource slots

What persists instead of a resource is a **resource slot**:

| Field | Meaning |
| --- | --- |
| `slot` | Stable semantic ID such as `(node, role)` or `(run, role)`; never a descriptor number, PID, or host path. |
| `kind` | Closed vocabulary below. |
| `mode` | `create` (built from the recipe), `reopen` (an existing immutable object opened and proven), or `adopt` (received from a hot-fork source and proven). |
| `dependency` | Slot IDs that must be released after this one, which orders teardown. |
| `recipe` | Deterministic construction inputs: an exact closure target, frozen canonical ring bytes and their protocol role, the launch profile, an immutable backing identity. |
| `expected` | The proof the bound resource must report: process incarnation and checked generation successor, instruction counter and execution fingerprint, private-ring identity, backing identity, or the identity proof below. |

The `kind` vocabulary is closed:

| Kind | Resource |
| --- | --- |
| `qemu-process` | One QEMU process generation |
| `process-channel` | Plugin socketpair, shared-memory ring memfd, and wake eventfd |
| `qmp-endpoint` | QMP control socket |
| `console-endpoint` | Console and gdbstub sockets |
| `cgroup` | Attempt cgroup with its watcher and cancellation eventfd |
| `attempt-storage` | Attempt storage root, project quota, and project-ID lease |
| `generation-run-dir` | Per-generation run directory |
| `run-journal-dir` | Durable run directory with its process journal and exit log |
| `disk-pin` | Open immutable backing inode |
| `image-helper` | Image-helper child process |
| `checkpoint-staging` | Checkpoint staging directory |
| `hot-fork-adoption` | Adopted hot-fork world guard and node lease |
| `qmp-snapshot` | QMP snapshot handle |
| `lease` | Per-generation resource lease |
| `debug-gateway` | Debug gateway process and directory; never rebound ([§16.12](16-run-arena-and-run-journal.md#1612-non-goals)) |

Resources that report nothing about themselves, such as directories, cgroups,
and quotas, prove their identity from descriptor-relative facts: the device and
inode of a directory opened relative to its parent, the ext4 project ID, and
the cgroup inode and name. A process proves its identity by PID and start time
held through a pidfd. An `adopt` slot's proof is the source generation plus one.

### Rebinding and teardown

Rebinding is one transaction. Today's per-node launch, which persists each
node's ownership after its launch and unwinds in order on failure
(`construction.rs`), is that transaction; slots make it uniform across
resource classes. Its commit point is the first guest instruction or canonical
event, whichever comes first, and every proof is verified before it. This is
the existing restore discipline of
[§05.6](05-hot-fork-and-checkpoints.md#056-child-resource-isolation) through
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) (launch through
exact preparation, counter and fingerprint verification, private-ring
authentication, and generation successor checks) stated once for every
resource class.

Teardown runs in reverse dependency order: processes are reaped before their
leases finish, disk pins are released after the reap, and attempt storage and
the cgroup go last. Slots give graceful shutdown one place to prove that every
resource was reaped.

A resource slot is a description, not a capability. Persisted bytes alone never
authorize a restore: a restore still requires a promoted root and its replay
claim ([§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure),
[HFORK-16]) and authority issued by the current daemon epoch.

- **[ARENA-10]** Run Authority MUST NOT be cloned, serialized, or included in
  the StateRoot. No persisted arena byte may contain a descriptor number,
  process ID, host path, socket name, daemon epoch, or lease handle.
- **[ARENA-11]** Every authority resource MUST be described by a resource slot
  with a closed-vocabulary kind, a mode, its dependencies, a recipe, and an
  expected proof; a resource without a self-report MUST prove its identity from
  descriptor-relative facts. Rebinding MUST be one all-or-nothing transaction
  whose commit point is the first guest instruction or canonical event, and MUST
  verify every proof before it. A mismatch MUST fail closed and quarantine every
  resource the transaction created. Teardown MUST run in reverse dependency
  order. A resource slot MUST NOT authorize a restore by itself.

## 16a.2 Authority journal and quarantine

Quarantine that ends with the process protects nothing after a crash. Today a
crash leaves attempt storage directories and cgroups behind: the next start
fails with `RootNotEmpty` when attempt storage finds its root occupied, a
leftover cgroup name makes creation fail, and the prior run's `run-state.json`
is deleted unread when the packaged executor retires its native namespaces
([§16.13](16-run-arena-and-run-journal.md#1613-known-defects-found-during-the-survey)).

Each run therefore keeps a durable **authority journal** in an executor
namespace that startup does not retire. Before a slot's resource is created,
the journal records the slot; once it exists, the journal records its live
identity (PID and start time, cgroup name and inode, project ID, storage
directory identity). Each record is synchronized before the run proceeds. A
reap or a quarantine updates the record.

Startup under a new daemon epoch reads every authority journal before it
retires any native namespace. For each recorded identity it verifies that the
resource is the one recorded and then kills and reaps processes, removes
cgroups, releases project IDs, and removes storage, in reverse dependency order.
A resource that cannot be reaped is recorded as quarantined and reported; it
blocks startup only while it is still live and conflicts with a resource the new
daemon needs. The process journal in `run-state.json` becomes part of this
record, so its orphan-quarantine path runs before retirement rather than never.

- **[ARENA-12]** The Run Authority MUST be the single owner of its resources'
  teardown. Ending a run, including a graceful daemon stop, MUST either reap
  every slot's resource or record it as quarantined in a durable per-run
  authority journal, and MUST report which. Startup under a new daemon epoch
  MUST read every authority journal and reap or re-quarantine its resources
  before retiring any native namespace. A quarantined resource MUST NOT block
  startup unless it is still live.

## 16a.3 Graceful daemon restart

The local executor already supports exact pause: a checkpoint request parks a
running attempt as `paused(root)`, the record survives restart, promotion work
is re-enumerated at startup, and `resume_paused` restores without guest replay.
Shutdown does not use it. A stop signal moves the pool to shutting-down, which
refuses checkpoint requests, signals cancellation to every active attempt and
promotion worker, and skips a promotion's final compare-and-swap. Workers get
30 seconds to clean up (`WORKER_SHUTDOWN_WAIT`), and the CLI host gives the
server a 1-second drain. Retained hot sources are reaped against the fallback
recorded at admission (exact for exact-boundary sources, thin for genesis and
published-boundary sources), and nothing is captured. Canceled attempts are
re-admitted when the coordinator resubmits them.

### Promotion-only admission

Graceful restart depends on resume admitting only promoted roots, and today it
does not ([§16.13](16-run-arena-and-run-journal.md#1613-known-defects-found-during-the-survey)).
The attempt-state record therefore carries an explicit phase, `Raw` or
`Promoted`, on every paused state, in a new record version, instead of
inferring promotion from an absent promotion basis, which also marks
savepoint-capture completion. While a record is `paused(raw)` or
`checkpoint-promoting`, submit and resume return `not-current` with the
retryable reason `promotion-pending`, distinct from the stable `not-current`
of a stale or foreign request. The coordinator retries with bounded backoff and
never treats `promotion-pending` as a reason to resubmit from origin. Submit
returns `already-paused` only for a promoted record. This change is
independent of the rest of the arena and lands first (T-CAM-10.0).

- **[ARENA-29]** The attempt-state record MUST carry an explicit `Raw` or
  `Promoted` phase for every paused state. Resume admission MUST accept only a
  `Promoted` record. Submit and resume for a `Raw` or promoting record MUST
  return the retryable `not-current(promotion-pending)` disposition, MUST NOT
  change the record, and MUST NOT lose its promotion work; submit MUST return
  `already-paused` only for a `Promoted` record.

### Drain

Graceful restart composes exact pause, promotion, and resume into a
checkpoint-drain stop. A new pool phase, `draining`, sits between running and
shutting-down:

```text
stop signal under the checkpoint-drain policy, deadline D
  pool -> draining
    submit and resume refused with retryable backpressure
    checkpoint requests served; cancellation deferred; promotions continue
  for each active attempt: request checkpoint      -> checkpoint-requested
    settle; unsettled(exact checkpoint) empty at a boundary
    freeze, persist, derive the L3 root            -> checkpoint-publishing(root)
    publish the root's closure, root last; durable -> paused(raw)
  published-boundary hot sources: demote (16a.4); genesis sources: discard
  at D, by ledger phase:
    running, checkpoint-requested                  -> cancel (resubmitted later)
    checkpoint-publishing(root)                    -> leave for deterministic
                                                      recapture at startup
    paused(raw)                                    -> promotion re-enumerated
                                                      at startup
    checkpoint-promoting                           -> completes or reverts as
                                                      on restart
    in-flight promotion comparisons                -> canceled
  pool -> shutting-down; reap or quarantine every Run Authority; exit

startup under a fresh daemon epoch
  reconcile authority journals (16a.2)
  open and reconcile the assignment ledger
  retire native namespaces; sweep unrooted journal segments
  enumerate promotion work; promote paused(raw) -> paused(promoted)
  coordinator resubmits: promotion-pending until promoted, then already-paused
  resume_paused: authenticate root, rebind slots, verify proofs, continue
```

A drain writes the L3 root: the native catalog is retired at startup, so a
root persisted only to L2 would not survive. A `checkpoint-publishing(root)`
record is never canceled at the deadline, because canceling during the
publication handoff discards the capture; startup recaptures it
deterministically, which re-executes up to the boundary and must reproduce the
recorded root. An attempt running in a hot-fork world is checkpointed like any
other attempt.

`D` plus the 30-second worker cleanup wait must be less than the service
manager's stop timeout, and the CLI host's drain grace must cover both, or the
service manager kills the daemon before the drain completes.

The drain is operational. It never writes a campaign pause fact: after restart
the campaign is still running, and the coordinator's ordinary resubmission
finds the paused attempts ([CMOD-2], [LAZY-9], [CCOMP-22]). An attempt that
cannot reach a settled boundary before the deadline, for example one with an
attached debugger, a pending branch choice, or a held host outcome, is canceled
and later re-executed from its origin, which is already the restart behavior.

- **[ARENA-15]** The executor SHOULD offer a checkpoint-drain stop mode with an
  operator deadline. In it the pool MUST enter a `draining` phase that refuses
  submit and resume with retryable backpressure, serves checkpoint requests
  through the ordinary request path and the ordering of
  [§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service),
  and lets promotions continue. At the deadline it MUST cancel running and
  checkpoint-requested attempts and MUST leave `checkpoint-publishing` records
  for deterministic recapture. The drain MUST NOT publish a campaign-truth
  transition, and a drained restart MUST NOT change any observation, finding,
  or campaign fact relative to cancel-and-retry.
- **[ARENA-17]** A run paused at a settled boundary, persisted, and resumed in a
  fresh daemon process MUST produce, at every later settled boundary, the same
  StateRoot as the uninterrupted run, and MUST produce the same observation.

## 16a.4 Hot sources across restart

The hot-fork source pool holds three classes of retained source:

| Class | World | Fallback today | On a drain |
| --- | --- | --- | --- |
| Genesis | Baked genesis | Thin | Discarded; recaptured at startup |
| Published-boundary | Thin attempt world at a published child configuration | Thin | Demoted to an exact fallback when its root can be published before the deadline |
| Exact-boundary | World restored from an `ExactCheckpoint` source; unreachable until T-CAM-10.9 | Exact | Keeps its existing exact fallback |

Demoting a published-boundary source captures a raw source root from the
retained source world. Promotion machinery is keyed by ledger attempt keys,
which sources do not have, so the raw root is tracked under a new **source
promotion key** and promoted by the same replay oracle. The hot-checkpoint
fallback record that names the root is its GC root. A demotion that cannot
publish before the deadline keeps the thin fallback.

After restart, a demoted source is restored and, once it passes the replay
oracle ([HFORK-16]), promoted again into a template without replaying from
genesis. That restore uses the demanded exact hot-fork source path, which is
unreachable today: the hot-first router tries hot fork only for attempts without
a resume checkpoint, while exact-checkpoint sources exist only for attempts with
one. Exact-resume attempts are routed through the hot-first router, so an
`ExactCheckpoint` source is captured on demand and used by later attempts that
resume from the same checkpoint (T-CAM-10.9); exact demotion depends on it.

- **[ARENA-16]** On a checkpoint-drain stop, the executor SHOULD demote retained
  published-boundary hot sources to exact fallbacks when their roots can be
  durably published before the deadline, tracking each raw source root under a
  source promotion key with its hot-checkpoint fallback record as its GC root.
  Exact-boundary sources MUST keep their exact fallbacks. A restored source MUST
  pass [HFORK-16] before it becomes a template.
- **[ARENA-33]** Exact-resume attempts MUST be routed through the hot-first
  router, so that a demanded `ExactCheckpoint` hot-fork source is captured and
  used for later attempts that resume from the same checkpoint. An attempt
  routed to an exact source MUST keep the exact fallback and MUST produce the
  observation the exact resume path would.

## 16a.5 Restart cost floor

Resume requires a promoted root.
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) makes a raw
root ineligible for resume,
[§04a.6](04a-coordinator-executor-contract.md#04a6-local-executor-service)
admits resume only from `paused(promoted)`, and [HFORK-16] applies the same
replay oracle before a restored runtime becomes a template. Promotion
authenticates the raw root and then compares each live node's exact snapshot
with an independently realized thin path, one node at a time, each replayed
from baked genesis to the boundary through its guarded replay oracle, on the
fixed promotion-worker set. A graceful restart therefore costs one capture, one
replay from scenario genesis per node, and one restore per paused attempt. It
saves the post-checkpoint guest work that cancel-and-retry would repeat and
keeps result identity stable, but it is not cheaper than retry in guest time
for the prefix.

The Run Arena makes the bookkeeping uniform; it does not remove this floor.
Three options are recorded as
[OQ-9](12-decisions-and-open-questions.md#oq-9-how-should-graceful-restart-pay-the-promotion-replay-floor):
keep the floor; promote incrementally from stride checkpoints taken while the
attempt runs, so a drained root needs only a suffix comparison against a
promoted ancestor (recommended); or accept closures produced by the same daemon
identity without a new comparison. The second and third options change
[§05.9](05-hot-fork-and-checkpoints.md#059-exact-durable-closure) and require an
RFC decision before implementation.

## 16a.6 Migration within the single-host scope

Moving a run between daemon processes on one host is the restart path above.
Moving it between hosts is the offline maintenance transfer of
[§05.10](05-hot-fork-and-checkpoints.md#0510-exact-pause-debugging-and-offline-maintenance-transfer):
archive transfer moves pinned exact closures, including their arena manifests,
chunks, and journal segments, as authenticated logical objects reachable from
their roots ([CSTORE-17]). A paused attempt's root is not pinned and does not
move, and the assignment ledger is local, so a paused attempt is re-executed at
the destination unless a later decision makes paused roots transferable. A
transferred promoted root must pass [HFORK-16] again at the destination before
it is resumed or becomes a template, unless OQ-9 decides otherwise.

- **[ARENA-18]** Run state MUST cross a process or host boundary only as an
  authenticated L3 closure or as an L2 manifest read by the same executor, under
  [HFORK-17] and [HFORK-18]. A transferred root MUST pass [HFORK-16] at the
  destination before use. Live migration, remote paging, and transferring Run
  Authority are not supported.

## 16a.7 Spill cache

Today's store tiers do not evict, so a run's resident chunk memory is bounded
only by what it has not yet persisted. The spill cache lets a chunked table
evict sealed chunks and reload them by identity:

```rust,illustrative
pub trait ChunkSpill: Send + Sync {
    /// Returns the chunk's bytes, authenticated against `id`, or `None` on a miss.
    fn get(&self, id: &ContentId) -> Result<Option<Bytes>, SpillError>;
    /// Stores a sealed chunk; idempotent for equal identities.
    fn put(&self, id: &ContentId, bytes: &[u8]) -> Result<(), SpillError>;
    /// Drops a chunk; a later `get` misses and the caller reloads from L2 or L3.
    fn evict(&self, id: &ContentId) -> Result<(), SpillError>;
}
```

Only clean chunks are evicted: a chunk whose `ContentId` is already durably
present at L2 or L3, so a miss can always be served from there. Frozen arenas
read through the same trait from other threads. The cache lives in an executor
namespace that is wiped at startup; it is never a GC root ([ARENA-20]). Its
byte budget comes from executor configuration and is charged to the attempt's
storage project quota, so exhausting it is an operational limit.

- **[ARENA-30]** The spill cache MUST sit behind a trait addressed by
  `ContentId`, MUST authenticate every read against its identity, and MUST
  evict only chunks durably present at L2 or L3. Its contents MUST be wiped at
  startup, MUST NOT be a GC root, and MUST be charged against a configured
  budget within the attempt's storage quota.

## 16a.8 Campaign Arena

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
| Authority journals | Live and quarantined resources | Yes |

The view answers operational questions in one place: what is resumable, what is
pinned and why, which roots the next GC plan will retain, and what a restart
would lose. It writes nothing.

The sources sit behind separate locks (the ledger writer lock, the exact-pin
lock, the hot-catalog lock, per-key prepared-result locks) and the in-memory
pool on the executor thread, so no atomic snapshot of all of them exists. The
view is served in-process through a read-only executor RPC. Each source is read
under its own lock or from an immutable record and stamped with its generation,
so the answer is consistent per source and says which generations it combines.
"Which roots the next GC plan will retain" runs the external-sort GC planner
and is bounded: the answer pages under a fixed bound, as the promotion queue
(65,536 keys) and the fallback catalog (65,536 slots) already are.

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
- **[ARENA-31]** The Campaign Arena view MUST be served through a read-only
  executor RPC that takes no writer lock longer than one source read, MUST stamp
  each joined source with the generation it read, and MUST bound every answer,
  including the GC-retention answer, by a fixed page size.
