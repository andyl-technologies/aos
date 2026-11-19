# Hot fork and exact checkpoints

Campaign throughput depends on reusing a paused world without serializing and
reloading its entire state for every child. **Hot fork** names only a QEMU
realization mechanism: the campaign first admits a branch edge, and the
executor may then realize its attempt by hot fork, exact restore, or thin
replay. Two process children given the same recorded selection are duplicate
realizations of one edge, not two branches.

The GPL-side mechanisms live in the patched QEMU
(`pkgs/emulation/qemu-patches/`). The host side lives in
`crucible_qemu_host::qmp::hot_fork` (typed QMP commands and response parsers)
and in `crucible-daemon` (`qemu_hot_fork_world*`, `hot_checkpoint_*`,
`qemu_hot_first_router`, `exact_checkpoint_store`, `exact_checkpoint_restore`,
`vm_lifecycle`).

## Realization tiers

| Tier | Representation | Primary use |
| --- | --- | --- |
| Hot | Paused fork-template QEMU processes, copy-on-write RAM, isolated child overlays, cloned host continuation | High-fanout on-host exploration |
| Exact | Portable authenticated closure: VM state, disk deltas, host continuation, scheduler and fault state, logs, provenance | Exact pause, debugging, failure retention, offline transfer |
| Thin | Scenario, schedule, ancestry, and retained artifacts sufficient to replay from a valid ancestor | Source of truth and storage fallback |

All three denote one `ConfigurationId`. A materialization index may record
which tiers exist, but tier is never identity. `instantiate(configuration)`
accepts any tier and returns equivalent modeled state or fails with localized
evidence; thin replay and the replay oracle are always sufficient to validate
the other tiers.

```text
ConfigurationId   H(scenario definition, semantic schedule)
ExactClosureId    H(authenticated exact-state manifest)
PageId/ExtentId   H(kind, schema, canonical plaintext bytes)
pack / location   replaceable physical representation
```

`qemu_hot_first_router` tries a whole-world retained hot source first and
delegates an explicit decline to the lower-tier runner. Durable checkpoint
resumes bypass hot fork. Hot fork is an acceleration, never a prerequisite:
when the launch profile, kernel, device set, memory pressure, or fork gate does
not admit it, the executor uses exact restore or thin replay, and status
explains the fallback. Disabling hot fork does not change the configuration or
finding set of a strict campaign.

## Why an explicit fork protocol

Calling `fork(2)` on multithreaded QEMU is unsafe. Threads disappear in the
child while locks, RCU state, AIO contexts, bottom halves, device callbacks,
descriptors, and shared mappings may reflect them. Shared-memory rings are
`MAP_SHARED` and would stay shared rather than becoming private. Hot forking
therefore requires a patched-QEMU fork coordinator that reaches a stronger
condition than a stopped runstate:

```text
all vCPUs stopped at an authorized icount boundary
device, AIO, timer, and bottom-half work drained or parked
no QEMU lock held by a thread omitted from the child
no active RCU read-side section
block graph at an external-snapshot boundary
plugin channels and host rings frozen at authenticated cursors
QMP and control operations quiescent except the fork transaction
```

The coordinator forks only from its designated thread after every registered
subsystem acknowledges the barrier. Child startup reinitializes every declared
thread, lock, AIO, RCU, timer, and control resource before execution resumes.
The host never infers safety from a paused status and never forks QEMU
externally. Any subsystem in a supported launch profile must implement the
barrier contract or make the profile fail admission.

Hot fork is limited to deterministic TCG with icount. A KVM VM is partly kernel
state whose descriptors would refer to the same kernel VM after a process
fork, so accelerator profiles do not advertise the capability.

## Templates

```text
running world
    |  reach a stable, hot-fork-capable branch boundary
    |  prepare exact host + QEMU continuation
    v
HotForkTemplate (paused, never advances)
    +-- fork child A -> rebind -> select A -> run
    +-- fork child B -> rebind -> select B -> run
    +-- fork child C -> rebind -> select C -> run
```

A template may come from normal execution or from restoring an exact closure.
Once promoted it consumes no modeled events; to continue the original path the
executor forks a default child. Any QMP command, plugin event, ring write, disk
write, or timer advance that would change a template invalidates it. Template
identity binds the configuration, exact boundary, QEMU and plugin capabilities,
host continuation digest, disk base identities, and protocol versions.

## Control protocol

Hot fork is one closed QMP protocol owned by the patched QEMU process. Unknown
schema versions, fields, resource classes, proof bits, and outcomes fail
closed. The template command has four operations:

| Operation | Effect |
| --- | --- |
| `prepare` | Authenticate the deterministic TCG profile, paused boundary, device flush, block snapshot, and every subsystem barrier |
| `query` | Observe the current transaction |
| `abort` | Roll back a retained transaction, keeping ownership until every barrier is released |
| `adopt-child` | Promote an authenticated paused child to a new template generation by re-running preparation |

A template report carries a typed failure stage and a bounded (255-byte)
failure detail. The parent proof bitmap has seven required bits:

| Bit | Retained parent proof |
| ---: | --- |
| 0 | precise instruction counting |
| 1 | single-threaded deterministic TCG |
| 2 | exact paused and device-flushed boundary |
| 3 | complete asynchronous-worker barrier |
| 4 | complete RCU barrier |
| 5 | immutable block snapshot and writable-root binding |
| 6 | private plugin rings and complete plugin worker barrier |

Descriptor and mapping disposition and child-runtime reconstruction are child
results; a parent cannot assert them.

Before `prepare` can report ready, the host stages one complete branch-private
resource set: a shrink-sealed memfd holding the canonical private plugin-ring
image, distinct plugin control and wake endpoints, private diagnostics, QMP,
and console streams, the child process contract, sorted descriptor replacement
and retention tables, writable shared-mapping dispositions, and branch-private
block overlays, network and 9p endpoints, and temporary files. Descriptors
cross QMP only through `getfd` and typed staging operations; QEMU independently
authenticates each one by kernel identity, size, seals, socket cookie, and
generation. Descriptor tables allow at most 4,096 replacements and 4,096
retained slots; mapping authentication accepts at most 65,536 records.

The fork command binds the exact template and every staged resource
generation. Preparation, `fork(2)`, and parent disposition run on the QEMU
main loop. The child arms parent-death containment, applies the descriptor
table with signal and descriptor admission closed, authenticates retained
mappings, reconstructs thread, mutex, RCU, AIO, timer, block, plugin, monitor,
QMP, console, and device owners, and only then sends its private QMP greeting
and releases guest execution. The host authenticates the child's readiness
report on the staged private QMP stream before constructing a child node. A
reported PID is correlation data, not process authority: the parent QEMU
retains child status until the daemon transfers that exact generation into its
cgroup, pidfd, and lifecycle owners.

QEMU-private pointers, structures, callbacks, and native enum layouts never
cross the process boundary. All coordinator, inventory, fork, and
reinitialization code is GPL-side; boundary changes must pass
`gate:abi-conformance` and `gate:license-boundary`.

## Child isolation

A child must close, replace, or explicitly retain every inherited resource
according to a closed manifest before it reports ready.

- **Shared-memory rings.** Command, event, network, block, 9p, coverage, and
  doorbell rings get new bounded memfd objects initialized from the frozen
  bytes; cursors and generations are authenticated. The template keeps its
  frozen rings.
- **Control sockets and QMP.** Inherited sockets are closed; the child gets a
  private channel and generation handshake, so the template channel cannot
  command a child.
- **Files and services.** Console, serial, diagnostics, 9p exports, and
  network backends get branch-private endpoints or are rejected from the
  supported profile. Deterministic networking uses Crucible's mediated device
  protocol, not a host tap.
- **Disks.** Each writable block root is frozen as an immutable backing before
  template publication, and each child gets a fresh private overlay. No two
  running siblings write the same file.

The child executes no guest instruction between creation and successful rebind.
Negative conformance tests omit or alias each resource class and require the
child to be rejected before resume.

## Host continuation

QEMU VM state alone does not capture the scheduler frontier and event queue,
signal programs and adapters, ring state, pending opportunities and
completions, per-node service state, assertions, triggers, and event-log
cursors. The daemon clones this continuation into an immutable parent plus
branch-local copy-on-write overlays. A child QEMU is paired with exactly one
cloned continuation and one selection before it runs; QEMU readiness and
continuation installation commit as one world transaction. Immutable block
bases and 9p trees may be shared; writable overlays, device queues, pending
completions, and transport cursors may not. A source signal coordinator is
world authority: the child rejects device work until its branch installs a
fresh coordinator.

## Multi-node world fork

Forking a multi-node scenario is atomic:

1. stop the scheduler at a stable global boundary;
2. freeze every node and host continuation;
3. authenticate a common parent configuration and world-fork generation;
4. prepare child resource bundles for every node;
5. fork and rebind every node and clone the host continuation;
6. verify every child reports the same parent and generation;
7. publish the child world and apply the selection under the scheduler.

If any node fails, every child of the transaction is terminated and no partial
session is published. An ambiguous fork, parent disposition, or cleanup result
quarantines the source generation. A hot-fork failure before child readiness
is an operational retry; it creates no graph edge or reward.

## Exact durable closure

The single-host closure stores QEMU RAM as a bounded direct layer followed by
parent-relative delta layers, and the non-RAM device state as a separate
authenticated object. Production capture bounds a RAM chain at eight layers;
when an eight-layer parent exists, the next capture is a complete direct
capture, which rebases the chain without changing configuration identity.

Writable disk roots are an immutable backing plus a sparse changed-chunk map.
Capture keeps every running node paused, discovers allocated overlay ranges
with `SEEK_DATA` and `SEEK_HOLE`, turns all-zero chunks back into holes, and
streams only nonzero changed 4 MiB chunks plus descriptor-backed QEMU state
into the content store. A filesystem without reliable extent discovery fails
closed. Sparse artifacts carry a logical length and strictly ordered,
nonoverlapping, nonadjacent extents of BLAKE3 chunk identities:

```text
sparse_id = H("crucible.production-exact-sparse-artifact.v1",
              hex(canonical_cbor({length, extents})))
```

Restore authenticates the extent geometry and every chunk, writes them into a
new staging file with omitted ranges as holes, materializes RAM and
device-state objects into sealed descriptors, and builds one restore request
before QEMU starts. A corrupt, short, or missing source leaves no partial
destination. Capture, hashing, and streaming observe cancellation between
bounded chunks.

The multi-node production continuation is published as a typed root
(`crucible_daemon::exact_checkpoint_store`). Every production object keeps its
BLAKE3 identity and length in index pages of at most 4,096 objects:

```text
page = "CRUCPIDX" || object_count:u32be
       || (production_content_hash:32 || logical_length:u64be)*
root = production_closure_identity:32 || scenario_identity:32
       || configuration_identity:32 || manifest_bytes:u64be
       || object_count:u64be || aggregate_object_bytes:u64be
       || index_count:u32be
```

The page hierarchy keeps generic closure walking possible beyond the
65,536-child envelope limit. Publication places the manifest, all objects, and
every index page before the root. Loading authenticates the root, page
sequence, object order, counts, lengths, and content-store mappings, and the
installer re-derives the closure identity, scenario, and configuration before
QEMU launch. The manifest also retains each node's frozen selectable catalog
plan and binds every live target to the BLAKE3 identity of its immutable root
image.

A packaged attempt yields checkpoint ownership only at an exact safe boundary.
The pool persists `checkpoint-publishing(root)` before the first content-store
write, publishes the closure, and moves to `paused(root)` without repeating
guest execution. A process-local replay claim is issued only after a guarded
raw-to-promoted replay comparison; persisted bytes alone never authorize a
restore.

## Exact pause, failure retention, and transfer

- **Exact pause.** Pin the exact closure, release QEMU processes and hot pages,
  and keep the lazy continuation. Resume restores the closure and continues
  from the same configuration.
- **Failure retention.** Pin the nearest pre-failure closure, the failing
  suffix, evidence, and the post-failure closure when available (see
  [findings](observability-and-findings.md#findings)). Debugger mutations
  create non-canonical sessions and never change retained canonical state.
- **Offline maintenance transfer.** Quiesce the campaign, persist and pin the
  exact closure, ensure its executable closure in the destination store,
  validate provenance and capabilities, restore during a separate operator
  action, and only then release the source. A failed transfer leaves a valid
  source; a destination with incompatible QEMU, plugin, or protocol provenance
  refuses to restore. The campaign reference may stay unchanged because
  location is not identity.

## Fork cost

Copy-on-write avoids copying guest RAM, but a child is not free: Linux
duplicates page-table metadata for present mappings, each child needs private
stacks, rings, overlays, and threads, and every write creates a private page.
Thousands of logical descendants are practical; the number of simultaneously
runnable children is a resource-policy decision.

The supported profile keeps guest RAM in private forkable mappings (advising
RAM blocks `MADV_DOFORK` while a template is retained, and converting a shared
writable backend into an immutable privately mapped backing), and marks
reconstructible scratch mappings and the live plugin-ring source
`MADV_DONTFORK` so they are recreated rather than inherited.

`hot_checkpoint_manager` accounts every retained hot source, ranks reuse value,
and prepares deterministic, generation-bound demotion plans when a new source
would exceed a host ceiling. Before a source is released its exact or thin
fallback is authenticated (`hot_checkpoint_fallback`) and recorded in a fixed
65,536-slot operational catalog that participates in GC roots. Hotness never
enters campaign evidence.
