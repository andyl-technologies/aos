# 01 - Current system and integration map

This chapter is informative. Paths refer to the source baseline in the
[overview](README.md). They identify code that must be audited or replaced;
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
| Fingerprint/fault/harness | One logical hash edition, named scope, publication ordering |
| Hot-source pools | Shared ownership accounting, immutable source seal, child-specific mutable versions |
| Checkpoint/CAS | Durable page/tree closure, scalable index, exact-root publication |
| Repository transfer | Bounded tree differences, authenticated possession, resume journals and retention |
| Executor supervision | Operation classes, progress semantics, independent cancellation and cleanup |
| Packaging/release | Host capabilities, ABI/license gates, matching QEMU source and coordinated cutover |

The proposal changes these boundaries deliberately. It does not prescribe
passing QEMU pointers through a convenient new store API, importing host tools
into hermetic builds, or retaining incompatible historical readers.
