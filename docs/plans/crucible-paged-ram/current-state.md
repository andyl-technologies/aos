# Historical source inventory and integration map

This chapter is informative. Paths refer to the source baseline in the
[source baseline](../../rfcs/0021-crucible-paged-ram/README.md). They identify code that must be audited or replaced;
they are not promises that the proposed behavior exists today. Links point to
whole files because source line numbers will move during implementation.

## 1.1 Allocation and host admission today

[QEMU launch](../../../crates/crucible-qemu/src/launch.rs) passes configured
guest RAM with `-m` and does not select a custom guest memory backend. Default
RAM is 512 MiB. The production `sim,thread=single` accelerator derives from
TCG, with instruction-counted virtual time, disabled wall-clock sleeping and
alignment, and a virtual RTC. Launch identity currently describes fresh RAM
as zeroed anonymous memory. That descriptor must become a logical reset
contract rather than a promise about a particular physical allocation.

[Linux cgroup placement](../../../crates/crucible-qemu/src/linux_cgroup.rs)
sets `memory.max` and explicitly sets `memory.swap.max` to zero. The current
attempt cgroup contains a multi-node world and its overhead; it is not a
per-guest RAM budget. Enabling ordinary host swap therefore requires both
policy changes and host swap capability checks. A global `vm.swappiness`
setting cannot provide the requested per-machine runtime contract.

Fresh-world admission conservatively sums configured guest RAM. Hot-source
accounting charges at least complete guest RAM, and expected child private
dirt includes a full-RAM allowance. Leased source children reserve the complete
source profile. This is safe for the present allocation model but prevents
meaningful density gains from externalized memory until admission is redesigned.

Relevant files include
[fresh admission](../../../crates/crucible-daemon/src/qemu_campaign_lifecycle/resource_admission.rs),
[hot-source usage](../../../crates/crucible-api/src/vm_lifecycle/hot_fork/resource_usage.rs),
and [source-pool leasing](../../../crates/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/pool.rs).
Cgroup charge ownership of shared COW pages can remain with the original
instantiating cgroup after a child moves. Neither child RSS nor a child
`memory.max` value measures all resources necessary to keep its source alive.

[Attempt resource limits](../../../crates/crucible-campaign/src/execution.rs)
are canonically encoded into assignment-related state. The executor has
reservation accounting, capacity advertisement, and a separately bounded
worker pool. New operational residency targets must fit that ownership model;
they cannot rewrite an already issued assignment's immutable identity.

## 1.2 RAM observations and dirty tracking today

The [atomic QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch)
contains several distinct RAM observation paths:

| Consumer | Baseline RAM behavior | Proposed integration |
| --- | --- | --- |
| Production execution fingerprint | Full SHA-256 traversal of ordinary writable RAM, excluding ROM and RAM-device blocks | Execution-scoped root, coherent boundary and new definition |
| Exact checkpoint RAM capture | Paused direct/delta capture into bounded descriptor outputs | Exact-scoped immutable page/tree closure |
| Instruction fault state | Independent complete RAM SHA-256 | Execution root plus explicitly separate selected-range digest where required |
| Lifecycle state/preconditions | Full RAM FNV digest over registered host blocks | Lifecycle-scoped root and complete source seal |
| Checkpoint RAM layer | Sorted migratable RAM, including device RAM, host page geometry in descriptors | Portable logical topology and exact-scoped root |

The differences in coverage matter. Replacing each digest with an identically
sized field would silently change semantics unless the definition and protocol
version also change. Registered RAMBlock enumeration order is not a portable
canonical region order. Host RAM page geometry must not leak into the logical
digest after the cutover.

There is an independent checkpoint dirty client and generation checking.
Device state is captured before the RAM dirty measurement because device
pre-save hooks may write RAM. Generation races conservatively force all-dirty
handling. Clearing a client re-arms translated stores for its next interval.
That mechanism is useful for changed-page discovery at coherent boundaries.
It does not create a per-store journal or prove safe asynchronous eviction:
already-dirty translated stores may continue on a fast path.

Restore performs reset, then copies bytes through `read`/`pread` directly into
QEMU RAM, then restores devices. These writes need explicit root installation
or tracking invalidation. Reset bulk writes, cached DMA mappings, device raw
pointers, debugger writes, modeled corruption, and direct initialization need
the same complete audit. A CPU plugin store callback alone is insufficient.

Current boundary memory mutations prepare selected-range before/after evidence
and require an all-or-nothing commit; see
[the fault transaction owner](../../../crates/crucible-qemu/src/fault_action_sink/transaction.rs)
and [RFC-0014's mutation contract](../../rfcs/0014-signal-driven-fault-model/14-qemu-fault-patches/03-memory-boundary-mutation.md).
Persistent retention/rowhammer and staged physical writes also occur in patched
`plugins/crucible-fault-node.c`. Its read transformations and `MemoryService`
continuation can affect guest execution without a physical RAM write. Host
population must not replay a modeled access or consume new fault opportunities.
The service host encoder and GPL decoder are separate integration surfaces,
including actor-field agreement; their static presence is not live qualification.

The execution fingerprint definition is in
[mapped quantum fingerprints](../../../crates/crucible-qemu/src/mapped_quantum/fingerprint.rs);
the harness has its own
[definition](../../../crates/crucible-harness/src/fingerprint/definition.rs).
Neither should acquire a separate subtly different Merkle construction.
Both bind a named scope and an explicitly versioned shared definition.

## 1.3 Forking and process lifetime today

The QEMU forkability helper calls `MADV_DOFORK` for RAM blocks and refuses KVM.
It does not implement a general transformation from writable shared RAM to
fork-private RAM. The actual safeguards are private launch allocation and the
closed writable-shared mapping inventory. Existing RFC prose describing
conversion must not be mistaken for implemented conversion support.

Fork staging retains RCU, block/AIO, plugin, thread, and mutex barriers. The
coordinator forks from the main loop, and the child joins its target cgroup
before reconstruction. QEMU has an internal approximately ten-second placement
wait separate from Rust-side budgets. Child subsystem and runtime rebinding
occurs before guest resume.

[Host fork preparation](../../../crates/crucible-qemu/src/node/hot_fork_preparation.rs)
and the [source pool](../../../crates/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/pool.rs)
already carry strong generation and lifecycle structure. Paging must join
that transaction. A cold page can be accessed by child reconstruction itself,
so preparing fault service immediately before the first guest instruction is
too late. A pager thread in the parent does not survive `fork` as a running
child thread. Waiting on a pager that needs a retained fork barrier would
deadlock.

## 1.4 Checkpoints and state transfer today

[Exact checkpoints](../../../crates/crucible/src/exact_checkpoint.rs) close over
more than RAM: CPU/device state, scheduler state, virtual time, disks, pending
host I/O, triggers, faults, and continuation state. The current direct/delta
RAM chain has a maximum depth of eight and rebases to a direct layer. RAM is
serialized and stored in existing multi-megabyte CAS chunks; chunk identity
does not equal logical page identity.

[Restore materialization](../../../crates/crucible-qemu/src/spawn/materialization/exact_restore.rs)
and its
[input contract](../../../crates/crucible-qemu/src/exact_checkpoint_input.rs)
fully stage RAM/device inputs in sealed memfds. QEMU requires complete seals
and rejects unsealed ordinary files. Lazy local restore must replace that
contract explicitly, not bypass its integrity protections.

Existing CAS supports representation identity, packing, closure validation,
retention, and transfer. Its limits were not selected for one object per
4 KiB page. A 512 MiB machine has 131,072 page positions before tree metadata,
which exceeds a 65,536-entry flat-object limit in the packed/envelope
paths when pages have distinct contents and per-page representations. Large closure planners also have eager sets and vectors. Those structures
must be bounded or paginated before page-granular durable state is advertised.

The relevant store interfaces are
[content storage](../../../crates/crucible-cas/src/content_store.rs),
[packed storage](../../../crates/crucible-cas/src/content_store/packed.rs),
[object envelopes](../../../crates/crucible-cas/src/content_envelope.rs),
and [repository transfer](../../../crates/crucible-campaign/src/repository/transfer.rs).
Transfer must authenticate destination possession, pin source closure,
cancel between bounded operations, and publish references only after durable
closure completion. A Merkle root helps select work; it does not itself
establish possession or retention.

## 1.5 Supervision and control today

The asynchronous QEMU driver has separate handshake, QMP, process-event,
and advance budget slots, but construction commonly populates all four with
the same remaining duration. A separate executor watchdog can cancel the
worker before a newly enlarged inner deadline completes. Other lifecycle
and restore paths have additional fixed or derived timeouts.

The authored host-completion watchdog participates in campaign policy
encoding. It is operational rather than modeled guest time, but it is not
absent from every identity. Runtime policy needs an explicit mutable operational
record and reservation journal, with an authorized outer-budget amendment
when required. Merely lengthening QMP timeout is insufficient.

Loopback executor control currently has no runtime RAM-policy update method.
Cancellation authority is intentionally narrow. New tuning authority must
remain separate, target the current execution incarnation and node generation,
and remain responsive while guest execution or QMP is blocked on a page fault.
Queue leasing uses explicit generations rather than an invented wall-clock
lease expiry.

## 1.6 Integration responsibilities

| Boundary | Required owner and integration outcome |
| --- | --- |
| QEMU memory/device/TCG | Complete writer audit, stable mapping ownership, coherent root capture |
| GPL-side pager | Fault addresses, page materialization/removal, generation checks, fork readiness |
| Public protocol/shmem | Versioned topology/root/control records; checked offsets; independent C/Rust vectors |
| Apache host orchestration | Resource reservations, policy updates, storage authorization, host failure reporting |
| Fingerprint/fault/harness | One complete-RAM identity edition with named scopes; independently versioned range evidence, atomic fault transactions, and preserved modeled service continuation |
| Hot-source pools | Shared ownership accounting, immutable source seal, child-specific mutable versions |
| Checkpoint/CAS | Durable page/tree closure, scalable index, exact-root publication |
| Repository transfer | Bounded tree differences, authenticated possession, resume journals and retention |
| Executor supervision | Operation classes, progress semantics, independent cancellation and cleanup |
| Packaging/release | Host capabilities, ABI/license gates, matching QEMU source and coordinated cutover |

The proposal changes these boundaries deliberately. It does not prescribe
passing QEMU pointers through a convenient new store API, importing host tools
into hermetic builds, or retaining incompatible historical readers.

## Additional historical integration inventories

The following blocks preserve source-oriented analysis extracted from the RFC.
They describe the stated historical baseline, not later implementation status.
Version numbers and source hooks must be rechecked against the actual release
revision before deployment.

### Ram observers and write tracking

## 03.1 Informative QEMU-SIM source baseline

The current
[QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch)
adds `DIRTY_MEMORY_CRUCIBLE_CHECKPOINT`, a fourth QEMU dirty-memory client,
and `GLOBAL_DIRTY_CRUCIBLE_CHECKPOINT`. In patched `system/memory.c`,
`memory_region_get_dirty_log_mask()` adds this client to globally tracked
migratable RAM and IOMMU regions. Patched `system/physmem.c` updates its bitmap
through dirty flags, dirty ranges, imported little-endian bitmaps, RAM remapping,
and discard operations. A checkpoint generation also detects relevant writes
and topology changes during candidate validation.

Patched `system/crucible-checkpoint.c` captures direct or delta RAM records at
an exact paused simulator boundary. Candidate capture retains exclusive
migration/raw-state authority until commit, abort, or invalidation. Commit
validates RAM generation, topology, and device state before clearing its own
bitmap. Clearing calls `physical_memory_dirty_bits_cleared()` to rearm translated
writes. A detected violation restores an all-dirty checkpoint bitmap before
refusing commit. This ordering is useful groundwork for the new tracker.

The current fingerprint path is different. Patched `plugins/api.c`
`qemu_crucible_guest_ram_sha256()` hashes complete ordinary writable RAM using
`crucible.qemu.guest-ram.v1`. It includes RAMBlock names and lengths, excludes
ROM and RAM-device blocks, and follows RAMBlock traversal order. Aggregate
fingerprint capture copies this material into a sealed memfd while holding the
authorized exact boundary. The
[plugin sampler](../../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs)
and [digest worker](../../../crates/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker.rs)
then hash the detached material and publish the matching request generation.
Offloading SHA-256 does not eliminate the full RAM copy or its residency cost.

Checkpoint topology instead includes migratable RAM-backed device memory,
sorts names, and records `qemu_ram_pagesize()`. Its existing topology digest is
therefore not the new logical RAM digest. Execution, exact, and lifecycle scopes
remain explicit; they must not be collapsed into one assumed universal scope.

There is also a distinct whole-RAM hash in patched
`plugins/crucible-fault-instruction.c`, which calls
`qemu_crucible_guest_ram_sha256()` while constructing instruction-fault state.
Updating only the aggregate plugin sampler would leave this scan intact.

Lifecycle observation has a third RAM hash surface. Patched `plugins/api.c`
`qemu_crucible_ram_hash()` performs an FNV-style traversal of every RAMBlock
with a host pointer, including its ID, length, and complete bytes. Patched
`plugins/crucible-fault-lifecycle.c` combines that value with device state in
`crucible_lifecycle_snapshot()` for lifecycle preconditions. This coverage is
broader than the execution SHA-256 path. Its replacement uses the explicitly
declared lifecycle scope and participates in the coordinated cutover below;
it cannot retain the old scan merely because the plugin sample uses a new root.

Exact restore in patched `system/crucible-checkpoint-restore.c` reads directly
into `qemu_ram_get_host_addr()` before establishing checkpoint authority.
Consequently, intercepting ordinary dirty-marking calls alone cannot maintain
a correct cached tree. Restore needs an explicit content-state transition.

### Version cutover inventory

The implementation review must enumerate every affected version, including
unchanged schemas whose contents incorporate changed identities. The following
table is a current-source inventory, not a promise of exact future version
numbers. The release MUST allocate and record one consistent new version set.

| Surface | Current source contract | Cutover obligation |
|---|---|---|
| Logical RAM digests | Flat writable-RAM SHA-256 domain `crucible.qemu.guest-ram.v1` | Adopt chapter 02's unkeyed BLAKE3-256 scoped Merkle schema and bind its version and coverage. |
| Production fingerprint | `crucible.qemu.black-box-execution-fingerprint.v1` | Change domain and define the RAM scope; never relabel an old digest. |
| Harness fingerprint | Definition v2; full-memory algorithm v1 | Replace definition and algorithm identity together. |
| Trace plugin | Trace-fingerprint v7 | Version fields and aggregate semantics containing the new RAM root. |
| Shared/control protocol | Shared-memory ABI 30; control protocol 3 | Bump changed semantics and negotiate new records before mapping or execution. |
| Instruction/hardware evidence | `CRUCIEV1`, `crucible.instruction-state.v1`, before/after full RAM SHA-256 | Version evidence, system digest and selectors/preconditions that name them. |
| Lifecycle evidence | `CRUCLFS1` with full-RAM FNV contribution | Version snapshot semantics and affected precondition/result evidence. |
| Memory mutation evidence | Separate mapping, translation, dirty and range-content contracts | Preserve valid unchanged meanings; version any changed scope or generation semantics. |
| QMP checkpoint | Schema 2; CRUCRAM direct/delta representation | Replace or version the RAM representation and validate full identity bindings. |
| Portable exact closure | Closure v9, root envelope v5, production objects v5, index v1 | Version the manifest/representation and every enclosing semantic contract affected. |
| Hot-fork protocol | Multiple template, barrier, resource and child-runtime schemas | Inventory changes for pager/tree ownership and quiescence; bump affected schemas. |
| Worker/replay authority | Pinned build, ABI inventory, exact closure and guarded comparison | Bind the new RAM contract; expire incompatible process-local authority. |

Sources for this inventory are listed in
[01-current-system-and-integration.md](../../rfcs/0021-crucible-paged-ram/01-current-system-and-integration.md).
The current instruction evidence verifies combined state digests independently
on both sides; both implementations and canonical vectors must change together.
Serialized artifact SHA-256 and CAS `ContentId` remain representation
authentication and MUST NOT be replaced by a logical root without a new
specified representation contract.

### Source reference inventory

## 13.3 Source baseline

The [integration map](../../rfcs/0021-crucible-paged-ram/01-current-system-and-integration.md) and consumer
chapters link the relevant implementation. They were researched against
`9d8ab78dff67348bbb38e2eda609eca67e413561` and are informative historical
references. Particularly important evidence includes:

- [Atomic QEMU integration patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch):
  memory observers, dirty clients, pre-save ordering, restore writes, fork
  barriers, mapping disposition, and child reconstruction.
- [Guest launch](../../../crates/crucible-qemu/src/launch.rs) and
  [cgroups](../../../crates/crucible-qemu/src/linux_cgroup.rs): present anonymous
  memory setup, deterministic timing profile, and disabled attempt swap.
- [Exact checkpoint closure](../../../crates/crucible/src/exact_checkpoint.rs):
  complete machine continuation and present direct/delta layer rules.
- [CAS storage](../../../crates/crucible-cas/src/content_store.rs),
  [packing](../../../crates/crucible-cas/src/content_store/packed.rs), and
  [envelopes](../../../crates/crucible-cas/src/content_envelope.rs): existing
  canonical serialized object identity, indices, limits, and closure ownership.
- [Repository transfer](../../../crates/crucible-campaign/src/repository/transfer.rs):
  transfer planning, closure validation, and publication integration.
- [Campaign performance qualification](../../../tests/crucible/phase9-campaign-performance.nix):
  baseline approval remains blocked at this revision; no new performance result
  is asserted by this design record.

### Qemu writer entry points

| Writer or transition | Current source entry point | Required coverage evidence |
| --- | --- | --- |
| Translated CPU stores | Patched `accel/tcg/cputlb.c` and `system/physmem.c` in the [QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch) | Scalar, vector, atomic, unaligned, and cross-page writes; already-dirty fast paths; rearming after epoch rotation |
| DMA through address spaces | Patched `system/physmem.c`, `flatview_write_continue_step()` | Every successful written subrange, including fault-transformed values and partial completion |
| Cached DMA and mapped buffers | Patched cached-access declarations and helpers in `include/system/memory.h`, plus address-space map/unmap users | Direct pointer writes, cached stores, bounce buffers, and delayed unmap reporting |
| Device-owned RAM and ROM backing | Migratable RAM inventory, device callbacks, and ROM-device dirty/flush APIs | CPU-inaccessible and read-only-to-guest bytes that the device can mutate; explicit scope ownership |
| Debugger and management writes | QEMU debugger/physical-memory write entry points and admitted QMP mutation commands | Dirty accounting while paused, including writes to already-dirty pages |
| Boundary memory mutations | Patched `plugins/crucible-fault-memory.c`, `memory_region_fault_commit_ram()` | Atomic prepared mutations, branch-private authoritative versions, all affected dirty consumers; suppressed writes do not manufacture content changes |
| Persistent fault-model mutations | Patched `plugins/crucible-fault-node.c` retention, rowhammer, and staged fetch paths | Cold victims and delayed physical writes; tracking and translated-code invalidation for every committed subrange |
| Modeled memory service | Patched `plugins/crucible-fault-node.c`, `qemu.memory.service.v3`, and x86 CPU memory-service tickets | Deferred stores and frozen loads preserve grant/ready coordinates, access sequence, ordering, and replay state through host faults |
| Hardware-error reporting | Admitted QEMU hardware-error delivery and guest-RAM record writers | Reporting writes such as GHES records enter tracking; reporting alone is not proof of a data mutation or guest handling |
| Instruction fault state observation | Patched `plugins/crucible-fault-instruction.c` | Observes the correct pre- or post-action root without modifying tracker state inconsistently |
| Reset, boot loading, and device post-load | System reset/load paths and participating device reset/post-load callbacks | Establishes tracked initial content and invalidates overwritten bytes before root reuse |
| Exact checkpoint restore | Patched `system/crucible-checkpoint-restore.c`, `crucible_restore_parse_layer()` | Direct restored writes explicitly install or invalidate page identities |
| Resize, removal, remap, and discard | Patched `qemu_ram_resize()`, `qemu_ram_free()`, `qemu_ram_remap()`, `ram_block_discard_range()` | Distinguishes topology changes, content changes, and content-preserving paging |
| Hot fork and child repair | [hot-fork lifecycle](../../rfcs/0021-crucible-paged-ram/06-hot-fork-and-lifecycle.md) and patched fork coordinator | Child-private metadata, inherited immutable identities, and explicit repair writes |

### Retained qemu source inventory

The current [RFC-0020 hot-fork contract](../../rfcs/0020-crucible-campaigns/05-hot-fork-and-checkpoints.md)
retains an exact paused boundary, frozen block sources, quiescent plugin, RCU,
and asynchronous-worker barriers, and authenticated child resources. The
coordinator executes `fork(2)` on QEMU's designated main-loop thread. Child
startup migrates into its target cgroup, establishes process containment,
reconstructs process-local runtime state, applies descriptor dispositions, and
authenticates the resulting writable shared mappings. Host continuation and
QEMU child readiness commit as one candidate world.

The [QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch)
implements `qemu_crucible_hot_fork_ram_set_forkable()` by advising each RAMBlock
with `MADV_DOFORK` or `MADV_DONTFORK`. This helper does not change a shared
writable RAM mapping into a private mapping or construct immutable file backing.
The existing child mapping-table scan rejects writable shared VMAs that do not
match the closed authenticated disposition table. The RFC-0020 description of
rejecting or converting shared RAM is therefore not evidence that conversion
exists in the implementation.

Current admission is also conservative. The
[source resource measurement](../../../crates/crucible-api/src/vm_lifecycle/hot_fork/resource_usage.rs)
charges at least full guest RAM as template bytes and another full guest-RAM
allowance in expected private dirties. The
[managed pool](../../../crates/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/pool.rs)
reserves another source profile for a child lease. Paging does not increase
admitted concurrency until those policies change explicitly.

### Qemu pager launch inventory

The current launch supplies `-m` without an explicit backend, the cgroup guard
sets `memory.swap.max` to zero, and launch admission reserves the guest-RAM
baseline as resident memory. The QEMU patch makes RAM forkable using
`MADV_DOFORK`. These are integration points, not implementations of this chapter.
See [Chapter 01](../../rfcs/0021-crucible-paged-ram/01-current-system-and-integration.md) for the evidence map.

### Checkpoint layer inventory

The current production format has a direct RAM layer followed by up to seven
parent-relative layers. A ninth capture rebases through another complete direct
image. The current constant and representation are in
[the exact-checkpoint relations](../../../crates/crucible/src/exact_checkpoint.rs);
capture selection is in
[the checkpoint capture loop](../../../crates/crucible-api/src/vm_lifecycle/quantum_loop/checkpoint_capture.rs).
Those links describe the baseline, not the new format.

### Storage index capacity inventory

The baseline packed backend has a 65,536-object index limit. Incompressible
512 MiB RAM has 131,072 logical 4096-byte pages before metadata or checkpoint
history. Its
[packed backend](../../../crates/crucible-cas/src/content_store/packed.rs)
therefore cannot serve as the unchanged page-object implementation. Likewise,
the current
[content envelope](../../../crates/crucible-cas/src/content_envelope.rs)
limits one envelope to 65,536 children, and production exact roots already use
bounded inventory index pages.

### Restore staging inventory

The baseline restore fully copies RAM layer streams into sealed memfds before
launch, then QEMU validates and applies the direct/delta records. See
[exact restore materialization](../../../crates/crucible-qemu/src/spawn/materialization/exact_restore.rs)
and [sealed inputs](../../../crates/crucible-qemu/src/exact_checkpoint_input.rs).
This duplicates full-image staging and live RAM pressure despite bounded copy
buffers. The new path replaces that RAM contract with authenticated immutable
catalogs and leased local page sources.

### Campaign archive and maintenance transfer baseline

The current implementation provides campaign archive transfer and offline
maintenance transfer. The archive primitive streams logical objects between
configured content stores, verifies destination content, obtains durable
receipts, and publishes destination refs. The durable owner installs independent
source and destination GC journals before copying. See
[archive transfer](../../../crates/crucible-campaign/src/repository/transfer.rs)
and [transfer ownership](../../../crates/crucible-daemon/src/campaign_transfer.rs).
The current documented maintenance workflow exactly pauses the campaign,
transfers its complete executable closure, and restores through a separate
operator action.
