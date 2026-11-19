# Shared-memory co-simulation ABI

Crucible runs every guest in its own patched QEMU process. The host scheduler,
the in-QEMU plugin, and the host I/O executors exchange virtual-time state and
frame payloads through one shared-memory region per run. This page specifies
that region: its byte layout, ordering rules, wake protocol, snapshot formats,
and the conformance machinery that keeps every language view identical.

The region is a public process protocol, not an FFI surface. It is the data
plane that lets the Apache-licensed host and the GPL-side QEMU plugin
cooperate without linking to each other; see the
[Crucible/QEMU process boundary](../../legal/licensing.md#crucibleqemu-process-boundary).
The setup-time control socket that hands the region to the plugin is described
in [control-protocol.md](control-protocol.md).

## Source of truth

| Artifact | Path |
| --- | --- |
| Rust definitions (mechanically checked source) | `crates/crucible/crucible-qemu-shmem/src/` |
| ABI version include | `crates/crucible/crucible-qemu-shmem/src/abi_version.in` |
| Interface manifest | `crates/crucible/crucible-qemu-shmem/interface/crucible-shmem-abi.toml` |
| Generated C header (committed) | `crates/crucible/crucible-qemu-shmem/include/crucible_shmem_abi.h` |
| Header generator | `crates/crucible/crucible-qemu-shmem/src/abi_header.rs` |
| Golden fixture | `crates/crucible/crucible-qemu-shmem/tests/fixtures/shmem_abi_golden.fixture` |

The crate is dual-licensed `MIT OR Apache-2.0` and has no dependency on QEMU
headers or symbols. The Rust `#[repr(C)]` structs are the mechanically checked
schema; the C header, the golden fixture, and this page are derived from or
checked against them. No second hand-maintained copy of the layout exists.

The interface manifest records the identity and policy of the protocol:
`name = "crucible-shmem"`, `abi_version = 30`, `magic_ascii = "CRUCSHM1"`,
`target = "x86_64-unknown-linux-gnu"`, `byte_order = "little"`. Its
`[representation]` table allows only fixed-width integers, fixed-size byte
arrays, region-relative byte offsets, and shared atomic integers, and forbids
native pointers, function pointers, callback tables, QEMU-private structures,
Rust-native enum layouts, and compiler-dependent bitfields. Every cross-region
reference is a checked offset from the region base.

## Why shared memory

A message bus would make guest-visible ordering depend on the order in which
messages arrive on a socket, which is a host-scheduling artifact. In the
region, every frame carries its delivery coordinate in band, and the consumer
decides deliverability by comparing that coordinate with its own clock. The
moment of the write is irrelevant, so visibility is a pure function of two
integers. Shared memory with a futex wake is also the cheapest per-quantum
handshake: a ceiling publication is a store plus a wake, with no socket round
trip or payload copy.

The region is the only channel for virtual-time advancement state and
cross-node frame payloads. The control socket carries setup and shutdown only.
The plugin eventfd carries only a wake counter that tells QEMU to re-read
shared memory; it never carries timing state or payload.

This is a no-round-trip design, not a zero-syscall one. The current scheduler
issues a non-private futex wake on every ceiling publication, even when no
waiter is parked, and writes the plugin eventfd at least once per quantum.
Frame delivery and service/backpressure producer release add futex wakes;
unchanged-icount retries and serviced host I/O add eventfd writes. A
waiter-armed optimization that skips unnecessary wakes is not implemented.

## Units

Fields whose names end in `_icount` or `_tick` hold exact logical ticks, not
raw retired instructions. The constants are in `src/lib.rs`:

| Constant | Value | Meaning |
| --- | --- | --- |
| `TICKS_PER_NS` | `1_000` | Ticks per QEMU virtual nanosecond (one tick is one picosecond). |
| `TICKS_PER_INSTRUCTION` | `50` | Tick progress for one retired guest instruction. |

`current_ns` is the derived floor `current_icount / 1000`. Scheduling and
delivery use exact ticks. `logical_time_raw_icount` is the separate raw QEMU
retired-instruction sample; a consumer must not infer raw retirements from a
tick field. Every publication that carries both checks
`raw_icount * TICKS_PER_INSTRUCTION <= logical_tick` and rejects raw time ahead
of logical time (`NodeSlotError::RawRetirementAhead`). See
[virtual-time.md](virtual-time.md) for the time model.

## Target pinning

The layout is pinned to `LAYOUT_TARGET_TRIPLE = "x86_64-unknown-linux-gnu"`.
`LAYOUT_TARGET_SUPPORTED` is true only for `target_arch = "x86_64"`,
`target_abi = ""`, `target_endian = "little"`, `target_env = "gnu"`,
`target_os = "linux"`, `target_pointer_width = "64"`, and
`validate_layout_target()` returns `RegionLayoutError::UnsupportedTarget`
elsewhere. All multi-byte fields are little-endian and all sizes and offsets
are fixed constants that do not depend on pointer width or packing heuristics.
Big-endian and 32-bit hosts are unsupported.

The futex wait and wake paths are Linux-only. Off Linux they compile to no-ops
(`FutexWaitOutcome::Noop`, zero waiters woken) so the pure layout and SPSC
logic can be unit-tested on developer machines; no simulation host runs there.

## Region layout

The region is a fixed header, a fixed array of node slots, and a sequence of
ring sections whose offsets are derived from the header geometry, the VM
count, and ABI constants. `RegionLayout::for_config` in
`src/shmem/region/layout.rs` is the single layout computation.

```text
offset 0                     RegionHeader                  256 B, align 128
offset 256                   NodeSlot[MAX_NODES = 32]      256 B each, align 128
ring_hdr_off   = 8448        RingHeader[ring_count]        directed frame rings
ring_data_off                FrameEntry[ring_count * queue_capacity]
align128 -> coverage         RingHeader[vm] + CoverageEntry[vm * 65536]
align128 -> fingerprint      FingerprintSampleSlot[vm]     640 B each
align128 -> whitebox marker  RingHeader[vm] + WhiteboxMarkerEntry[vm * 1024]
align128 -> fault command    RingHeader[vm] + FaultCommandSlotV1[vm * 4096]
           align128          FaultPayloadArenaHeader[vm] + arena[vm]
align128 -> fault result     RingHeader[vm] + FaultResultSlotV2[vm * 4096]
           align128          FaultPayloadArenaHeader[vm] + arena[vm]
align128 -> fault event      RingHeader[vm] + FaultEventSlotV1[vm * 4096]
           align128          FaultPayloadArenaHeader[vm] + arena[vm]
align128 -> guest introspect RingHeader[vm * 2] + GuestIntrospectionEntry[vm * 2 * 64]
align128 -> accelerator      RingHeader[vm * 2] + AcceleratorEntry[vm * 2 * 128]
align128 -> selectable reply RingHeader[vm] + WhiteboxMarkerEntry[vm * 1]
region_size
```

`vm` is `RegionConfig::vm_node_count`. Each section starts at the previous
section's end rounded up to 128 bytes (`checked_align_up`); every size and
offset is computed with checked arithmetic and an overflow is
`RegionLayoutError::GeometryOverflow`. `RegionLayout` exposes every derived
offset (`coverage_ring_hdr_off`, `fingerprint_sample_off`,
`whitebox_marker_ring_hdr_off`, `fault_command_ring_hdr_off`, ...,
`selectable_reply_ring_data_off`, `region_size`).

`RegionLayout::for_config` rejects:

| Condition | Error |
| --- | --- |
| `vm_node_count > MAX_VM_NODES` (29) | `TooManyVmNodes` |
| `queue_capacity` zero or not a power of two | `InvalidQueueCapacity` |
| `ticks_per_ns != 1000` | `InvalidTicksPerNs` |
| fault arena outside `2_106_448..=33_563_728` bytes | `InvalidFaultPayloadArenaBytes` |

Worked example (the geometry in the golden header): `vm_node_count = 2`,
`queue_capacity = 8`, default fault arena `2_106_448` bytes gives
`ring_count = 12`, `ring_hdr_off = 8448`, `ring_data_off = 9984`, coverage at
`455_424`, fingerprint samples at `8_844_288`, marker rings at `8_845_568`, and
`region_size = 42_026_112`. The coverage ring, fault arenas, and marker ring
dominate the size.

### Physical slots and directed rings

`MAX_NODES = 32` is a physical-layout constant of this crate only. The three
highest slots are reserved executor endpoints:

| Constant | Slot | Kind |
| --- | --- | --- |
| `SLOT_NET_ROUTER` | `MAX_NODES - 1` = 31 | `KIND_NET` (1) |
| `SLOT_BLK_IO` | `MAX_NODES - 2` = 30 | `KIND_BLK` (2) |
| `SLOT_9P_IO` | `MAX_NODES - 3` = 29 | `KIND_9P` (3) |

`RESERVED_SLOTS = 3` and `MAX_VM_NODES = MAX_NODES - RESERVED_SLOTS` = 29.
Logical VMs occupy slots `0..vm_node_count` with `KIND_VM` (0). The header's
`node_count` is always `MAX_NODES`; the VM count is recovered as
`ring_count / 6`. At allocation, VM and executor slots start `STATUS_IDLE`;
unused VM slots start `STATUS_DONE`.

`directed_rings` in `src/shmem/region/helpers.rs` allocates exactly two rings
per (VM, executor) pair, in deterministic order: for each VM slot `v`, for
each executor in `[NetRouter, BlockIo, NineP]`, the outbound ring
`v -> executor` and then the inbound ring `executor -> v`. Ring `i` therefore
belongs to VM `i / 6`, and `ring_count = vm_node_count * RESERVED_SLOTS * 2`.

Each I/O class has its own reserved slot because each ring must have exactly
one producer and one consumer; multiplexing network, block, and 9p traffic onto
one ring would break the SPSC discipline. The router executor re-stamps
`delivery_icount` per the link model. None of these slots or `MAX_NODES`
appears in the engine's logical topology: the logical-to-physical mapping is
made at allocation time, and exceeding the slot capacity is an allocation
error of this layer. The region-layout check scans for `MAX_NODES` escaping
the shmem crates. See [io-subnodes.md](io-subnodes.md).

## RegionHeader

`RegionHeader` (`src/shmem/region/header.rs`), `#[repr(C, align(128))]`,
256 bytes:

```text
offset  size  field                       type
0       8     magic                       atomic u64  = "CRUCSHM1" (LE)
8       4     abi_version                 atomic u32  = 30
12      4     node_count                  atomic u32  = MAX_NODES
16      4     queue_capacity              atomic u32  directed-ring entries
20      4     ring_count                  atomic u32  directed rings
24      8     ring_hdr_off                atomic u64  first directed RingHeader
32      8     ring_data_off               atomic u64  first FrameEntry
40      8     entry_stride                atomic u64  = size_of FrameEntry
48      8     region_size                 atomic u64  total mapped bytes
56      4     ticks_per_ns                atomic u32  = 1000
60      1     pause_requested             atomic u8
61      1     shutdown_requested          atomic u8
62      2     _control_padding            zero
64      4     fault_payload_arena_bytes   atomic u32  per direction, per VM
68      188   _reserved                   zero
```

`REGION_MAGIC = u64::from_le_bytes(*b"CRUCSHM1")`, which the C header spells
`UINT64_C(0x314d485343555243)` so the ASCII appears verbatim in a hex dump.

### Setup validation

`validate_setup_region_header(snapshot, region_len)` is the only way a mapper
accepts a region. It runs before any slot or ring is touched and rejects, in
order:

1. `region_len < 256` (`RegionTooSmall`).
2. `magic != REGION_MAGIC` (`InvalidMagic`).
3. `abi_version != ABI_VERSION` (`AbiVersionMismatch`).
4. `ticks_per_ns != 1000` (`TicksPerNsMismatch`).
5. `region_size != region_len` (`RegionLengthMismatch`).
6. Geometry that the current layout model cannot recompute exactly:
   `ring_count` zero or not a multiple of 6 (`InvalidRingCount`), an invalid
   recomputed layout, or any mismatch in `node_count`, `ring_hdr_off`,
   `ring_data_off`, `entry_stride`, or the recomputed `region_size`.

There is no layout inference and no partial mapping: a noncurrent peer is a
hard failure. `mmap_setup_region` additionally checks that the descriptor's
backing length is at least `region_len` and, on Linux, that a sealable
descriptor carries `F_SEAL_SHRINK`, then maps it `MAP_SHARED`.

## NodeSlot

Each node owns one `NodeSlot` (`src/shmem/frame_node/layout.rs`),
`#[repr(C, align(128))]`, 256 bytes. The 128-byte alignment (two cache lines
on the pinned target) keeps slots written by different processes off shared
cache lines.

```text
offset  size  field                                    writer
0       8     current_icount                           node
8       8     current_ns                               node
16      8     max_advance_icount                       scheduler
24      8     idle_wake_icount                         node
32      4     wake_signal                              wakers (futex word)
36      1     status                                   node
37      1     kind                                     allocator
38      1     device_io_active                         node
39      1     advance_stop_condition                   scheduler
40      4     publish_gen                              node (seqlock)
44      4     control_boundary_ack                     host even / plugin odd
48      8     device_completion_deadline_tick          host
56      8     preemption_at_tick                       scheduler
64      8     preemption_deadline_tick                 scheduler
72      8     preemption_ceiling_tick                  scheduler
80      4     preemption_published_sequence            scheduler
84      4     preemption_consumed_sequence             plugin
88      4     preemption_arg0                          scheduler
92      4     preemption_arg1                          scheduler
96      1     preemption_kind                          scheduler
97      7     _pad2                                    zero
104     8     logical_time_raw_icount                  node
112     8     logical_time_restore_target              host
120     4     logical_time_restore_request             host
124     4     logical_time_restore_ack                 plugin
128     8     control_boundary_fault_command_frontier  host
136     4     control_boundary_capture_request         host
140     4     _pad3                                    zero
144     8     timer_witness_generation                 plugin
152     8     timer_witness_deadline_ps                plugin
160     8     timer_witness_deadline_tick              plugin
168     8     timer_witness_armed_raw_icount           plugin
176     8     timer_witness_fired_expire_ps            plugin
184     8     timer_witness_fired_virtual_ps           plugin
192     8     timer_witness_fired_raw_icount           plugin
200     4     timer_witness_completed                  plugin
204     4     timer_witness_reserved                   plugin
208     8     advance_publication_sequence             scheduler (seqlock)
216     40    _pad4                                    zero
```

Constants:

| Name | Value |
| --- | --- |
| `STATUS_RUNNING` / `STATUS_IDLE` / `STATUS_DONE` | 0 / 1 / 2 |
| `KIND_VM` / `KIND_NET` / `KIND_BLK` / `KIND_9P` | 0 / 1 / 2 / 3 |
| `ADVANCE_STOP_CONDITION_CEILING` | 0 |
| `ADVANCE_STOP_CONDITION_NEXT_AUTHENTICATED_IDLE` | 1 |
| `PREEMPTION_KIND_NONE` / `_VCPU_SWITCH` / `_INTERRUPT_AT` | 0 / 1 / 2 |
| `FUTEX_PRIVATE` | `false` |

`NodeSlot::new` zeroes every field except `status = STATUS_IDLE` and
`control_boundary_ack = 1`. In particular,
`max_advance_icount` MUST initialize to 0, so no node can advance before the
scheduler's first ceiling publication; the boot barrier depends on this.

### Multi-vCPU nodes

A VM with `N > 1` vCPUs runs single-threaded round-robin TCG under one
aggregate clock and is represented by a single `NodeSlot`. `current_icount`,
`max_advance_icount`, and `idle_wake_icount` are node aggregates, and
`idle_wake_icount` is the minimum over the vCPUs' armed deadlines.
`device_io_active` and the round-robin subdivision of a quantum are
node-scoped. The ABI has no per-vCPU fields or slots, so the vCPU count does
not change the region shape or `ABI_VERSION`. Virtual time is a node property;
exposing a vCPU dimension would leak a plugin-internal detail into the
scheduler, the ABI, and the total order for no benefit. Per-vCPU state is
folded into the fingerprint instead (see below and
[execution-model.md](execution-model.md)).

### Slot seqlock: `publish_gen`

The node mutates several related fields (`current_icount`, `current_ns`,
`status`, `idle_wake_icount`, `logical_time_raw_icount`, `device_io_active`,
the restore acknowledgement, and the timer witness) without a lock while the
scheduler or a snapshotter reads them from another process. `publish_gen` is a
seqlock that makes torn reads detectable:

```text
writer (node)                            reader (scheduler / snapshotter)
publish_gen.fetch_add(1, AcqRel)  # odd  loop:
store fields (Release)                     g0 := publish_gen.load(Acquire)
...                                        if g0 is odd: retry
publish_gen.fetch_add(1, AcqRel)  # even   read fields (Acquire)
                                           g1 := publish_gen.load(Acquire)
                                           accept iff g1 == g0 and even
```

`NodeSlot::snapshot()` implements the reader and returns a `NodeSlotSnapshot`.
It loads `control_boundary_ack` before the fields it orders, because the
acknowledgement is released by the plugin after the boundary publication; a
later load could pair a new acknowledgement with stale fields. A reader must
never consume a read bracketed by an odd or unequal generation.

The host also uses `publish_gen` as a freshness fence: a quantum completes
only after a publication that supersedes the generation observed before the
scheduler released input (`QemuAdvanceCompletionFence` in
`crates/crucible/crucible-qemu-host/src/async_driver.rs`). A pre-existing
`STATUS_IDLE` is therefore never mistaken for an acknowledgement.

### Scheduler advance tuple

`max_advance_icount` and `advance_stop_condition` form one tuple published
under a second seqlock, `advance_publication_sequence`, which belongs to the
scheduler. `publish_scheduler_advance(ceiling, stop_condition)`:

1. Rejects a ceiling below the published `current_icount`
   (`CeilingBeforePublishedCurrent`).
2. Compare-exchanges the sequence from even to odd.
3. Stores the pair in a mode-dependent order: for `NextAuthenticatedIdle` the
   stop condition first, then the ceiling, so a peer that sees the raised
   ceiling also sees that it must not authorize the idle deadline; for
   `Ceiling` the ceiling first, then the cleared mode, so a peer that sees the
   cleared mode also sees the clamp that bounds renewed execution.
4. Stores the even successor (Release), then increments `wake_signal` and
   issues a non-private `FUTEX_WAKE`.

`load_scheduler_advance()` returns a stable `(ceiling, AdvanceStopCondition)`
pair and rejects an unknown encoding with
`NodeSlotError::InvalidAdvanceStopCondition`; unknown values never acquire
forward-compatible meaning. The separate sequence excludes both a torn pair
and a ceiling -> next-idle -> ceiling ABA during the read.

`AdvanceStopCondition::Ceiling` completes an advance at the ceiling or at an
idle park that cannot reach it. `NextAuthenticatedIdle` completes it at the
next all-vCPU idle publication, without authorizing that idle deadline.

### Advance-ceiling handshake

The per-node ceiling is how the scheduler bounds a VM to its conservative
horizon (see [scheduling.md](scheduling.md)). Only the scheduler writes it;
only the governed node reads it, and a node never raises its own ceiling.

1. The node publishes `current_icount` and `current_ns` under `publish_gen` as
   it runs (`publish_reached_icount`), checking
   `check_node_may_advance_to(next)` against the acquire-loaded ceiling; a
   target above the ceiling is `NodeAdvancePastCeiling`.
2. The scheduler computes the horizon in exact ticks and publishes it with
   `publish_scheduler_advance`, which also wakes the node.
3. At the ceiling, the node calls `publish_idle(reached, idle_wake)`, which
   requires `idle_wake >= reached`, publishes `STATUS_IDLE` with the wake
   deadline, and returns a `FutexWait` decision.
4. After a raised ceiling or delivered frame, the node wakes, reloads the
   ceiling, and marks itself running (`mark_running`).

`publish_scheduler_inbox_and_advance` (and
`RegionAllocation::publish_scheduler_inputs_and_advance`) validates the
ceiling, each frame's source slot, and the inbox capacity before publishing
anything, then enqueues every input frame, then publishes the ceiling, and
only then wakes the node. A node that wakes for a ceiling therefore already
sees every input that ceiling admits.

## Futex and eventfd wake

A node parked at its ceiling waits on its slot's `wake_signal` with a
non-private `FUTEX_WAIT`. The futex must be non-private
(`FUTEX_PRIVATE = false`, no `FUTEX_PRIVATE_FLAG`) because the waiter (QEMU)
and the waker (the host) are different processes sharing the word through the
mapping.

Waiting uses the publish-precondition / read-counter / re-check / wait idiom:

```text
waiter (node)                         waker (host)
publish idle_wake_icount, STATUS_IDLE store new state (Release)
v := wake_signal.load(Acquire)        wake_signal.fetch_add(1, Release)
if runnable: do not wait              FUTEX_WAKE(&wake_signal, 1)
FUTEX_WAIT(&wake_signal, v)           eventfd write (at least once per quantum)
```

`prepare_futex_wait()` reads the counter and returns `FutexWait::Runnable`
when the node can already proceed (status not idle, or a `Ceiling`-mode
ceiling at or past `idle_wake_icount`); otherwise `FutexWait::Wait { expected }`.
`futex_wait_nonprivate` re-checks with `futex_wait_still_valid` immediately
before the syscall. There is no lost-wake window: an increment before the read
is caught by the re-check, and an increment between the read and the syscall
makes `FUTEX_WAIT` return `EAGAIN` (`FutexWaitOutcome::ValueChanged`). `EINTR`
is `Interrupted`.

Every event that can make a parked node runnable increments the target slot's
`wake_signal` with a release add and issues `FUTEX_WAKE`, whether or not
anyone is parked:

- a scheduler ceiling publication (`publish_scheduler_advance`);
- frame delivery into one of the node's inbound rings
  (`wake_for_frame_delivery`);
- release of a device-I/O hold or backpressured producer
  (`wake_for_device_io_release`);
- a control-boundary request (`request_control_boundary`);
- a pause or shutdown request (wake-all, below).

QEMU's vCPU-kick bridge is an internal producer of the same word while the
plugin has an idle wait armed: after a stop, unplug, interrupt, or queued-work
producer publishes its QEMU-side predicate, `qemu_cpu_kick()` increments the
word and issues a non-private wake. That increment is an operational nudge
only; it authorizes no guest execution, delivery, or time advance, and forces
the round-robin loop to rescan. See [qemu-patch.md](qemu-patch.md).

The plugin eventfd complements the futex. The futex word and shared state are
the source of truth; the eventfd rouses QEMU's main loop between quanta. The
plugin must register the eventfd with QEMU before acknowledging setup
(`send_ready_setup_ack` refuses otherwise). The host writes an 8-byte counter
value of 1 (`QemuHostPluginSetup::signal_plugin_wake`).

### Global pause and shutdown

`RegionHeader::request_pause(slots)` release-stores `pause_requested = 1` and
then wakes every slot; `request_shutdown(slots)` does the same for
`shutdown_requested`. A woken node acquire-loads
`RegionHeader::control_action()`, which returns `Shutdown` if
`shutdown_requested` is set, else `Pause` if `pause_requested` is set, else
`Continue`. Shutdown takes priority.

On `Pause`, a node quiesces at its current boundary and publishes
`publish_pause_quiesced(reached, raw)`: `STATUS_IDLE`,
`idle_wake_icount = current_icount`, and the paired raw icount in one seqlock
transaction. On `Shutdown`, a parked node wakes, publishes `STATUS_DONE`
(`mark_done`), and exits. `clear_pause` only clears the flag; the caller must
republish scheduling state and wake nodes (futex and eventfd) to resume them.

### Control-boundary token

`control_boundary_ack` is an exact request/acknowledgement token for one QEMU
main-loop boundary, separate from the slot seqlock. Odd values are
acknowledged; the initial value is 1.

- The host calls `request_control_boundary(frontier, capture_request)`. If the
  token is odd, it stores the fault-command frontier and the fingerprint
  capture request (relaxed) and compare-exchanges the token to its even
  successor (release). If an even request is already outstanding, a repeat
  with the same frontier and capture request is idempotent and a different one
  is `ControlBoundaryRequestChanged`. A nonzero even capture request is
  rejected. The call then wakes the node futex; the caller also writes the
  eventfd.
- QEMU drains the eventfd, runs pending device bottom halves, and invokes the
  plugin's control callback. The plugin republishes the exact logical and raw
  coordinate under `publish_gen` (`publish_control_boundary`), then
  `acknowledge_control_boundary()` stores the odd successor (release).
  Acknowledging with nothing pending is a no-op.

`publish_control_boundary` rejects a coordinate above the ceiling. When the
node sits exactly at a `Ceiling`-mode ceiling, it publishes an exact idle
boundary: it keeps an existing future `idle_wake_icount` if already idle, or
uses the current coordinate if it was running. Below the ceiling it preserves
the previous status classification, because an arbitrary main-loop yield is
not proof of scheduler idleness. `device_io_active` is independent. Tokens
wrap through zero; the host accepts the immediate odd successor or a later odd
token in wrapping serial order.

### Preemption mailbox

Bytes 56..104 of each VM slot are a single-outstanding scheduler-to-plugin
mailbox (`src/shmem/frame_node/preemption_mailbox.rs`). A command names an
exact `at_tick`, an inclusive authorization window
`deadline_tick <= at_tick <= ceiling_tick`, and either a vCPU switch
(`PREEMPTION_KIND_VCPU_SWITCH`, `arg0` = from, `arg1` = to) or an interrupt
(`PREEMPTION_KIND_INTERRUPT_AT`, `arg0` = target vCPU, `arg1` = vector).

- `publish_preemption_command` validates the window, refuses to overwrite an
  unconsumed command (`CommandOutstanding`), stores the fields relaxed, and
  release-stores `preemption_published_sequence + 1`.
- `pending_preemption_command` acquire-loads the sequences, decodes the kind
  (unknown kinds fail), and revalidates the window.
- `acknowledge_preemption_command(seq)` release-stores
  `preemption_consumed_sequence` only for the currently outstanding sequence
  (`AcknowledgeMismatch` otherwise), and only after QEMU accepts the
  injection.

Neither side clamps, defers, or silently drops an out-of-window command; all
such cases are deterministic run failures. See [qemu-plugin.md](qemu-plugin.md).

### Logical-time restore

After a VMState load, QEMU's raw icount is restored but the plugin's logical
offset is not. The restore is a shared-memory transaction on the slot:

1. While QEMU is stopped, the host calls `arm_logical_time_restore(target)`.
   It requires `request == ack`, chooses `request + 1` (skipping 0), stores
   the target, then release-stores the new request generation.
2. The host resumes QEMU only far enough to reach a plugin callback. The
   plugin reads `pending_logical_time_restore()`, reconstructs its offset as
   `target - raw`, and `acknowledge_logical_time_restore` publishes, in one
   seqlock transaction, `current_icount = target`, `idle_wake_icount = target`,
   the raw icount, `STATUS_IDLE`, and `logical_time_restore_ack = generation`.
   A changed request, a target mismatch, or raw time ahead of logical time is
   rejected.
3. The host confirms the matching acknowledgement and an independent native
   QEMU stop before clearing the pause and resuming. Any failure terminates and
   reaps the new QEMU process; a partially restored node is never exposed.

Coverage reset is bound to the same transaction (below). The control socket
is not used. See [time-travel-debugging.md](time-travel-debugging.md).

### Device completion deadline and timer witness

`device_completion_deadline_tick` is host-written: the exact tick at which a
pending device completion for this VM will be delivered, or 0 for none. A
plugin whose guest is blocked on device I/O idle-jumps to it. It is distinct
from `idle_wake_icount` so the two directions never share a field.

The timer witness fields record one plugin-validated actual QEMU
`QEMU_CLOCK_VIRTUAL` callback: the armed expiry in picoseconds and logical
ticks, the raw icount when armed, and the expiry, virtual time, and raw icount
observed when the callback actually ran. `publish_virtual_timer_witness`
writes them inside a `publish_gen` transaction, storing
`timer_witness_generation` last; generation 0 means no witness.

## SPSC rings

Every ring section uses the same header (`src/shmem/ring_coverage.rs`):

```text
RingHeader (size 128, align 128)
offset  size  field
0       8     read_idx         consumer-owned
8       8     consumer_state   bit 63 held, bits 0..62 admitted consumers
16      48    _pad_read        zero (fills the consumer cache line)
64      8     write_idx        producer-owned
72      8     producer_state   bit 63 held, bits 0..62 admitted producers
80      48    _pad_write       zero (fills the producer cache line)
```

Each ring is a Lamport single-producer/single-consumer queue. Indices are
monotonically increasing 64-bit counters (wrapping arithmetic); the slot for
counter `i` is `i & (capacity - 1)`. Capacity is a non-zero power of two. The
live count is `write_idx - read_idx`; empty is `0`, full is `capacity`, and a
count above capacity is `SpscRingError::CorruptIndices`.

Ordering rules (no `SeqCst` on the data path):

| Operation | Own index | Peer index | Publish |
| --- | --- | --- | --- |
| `enqueue` (producer) | `write_idx` Relaxed | `read_idx` Acquire | write entry, then `write_idx` Release |
| `dequeue` (consumer) | `read_idx` Relaxed | `write_idx` Acquire | copy entry, then `read_idx` Release |
| `peek`, `peek_delivery_icount` | `read_idx` Relaxed | `write_idx` Acquire | none |

`enqueue` returns `QueueFull` without overwriting. `peek_delivery_icount`
returns the head frame's `delivery_icount` without consuming it, so the
scheduler can compute the node's next inbound horizon.

### Hot-fork admission

`producer_state` and `consumer_state` implement a reversible admission barrier
used when a running world is forked. Every mutating producer operation enters
through `enter_producer`, and every operation that can advance `read_idx`
through `enter_consumer`; read-only peeks do not. Entry compare-exchanges the
count up unless bit 63 is set (`ProducerBarrierHeld` / `ConsumerBarrierHeld`),
and the admission guard decrements it on return. `hold_hot_fork_producers` /
`hold_hot_fork_consumers` set bit 63; a ring is quiescent when held with zero
in flight. These counts are process-local coordination, not logical content:
cloning a `RingHeader` resets both state words to 0.

### Ring classes

| Section | Rings per VM | Capacity | Entry | Producer -> consumer |
| --- | --- | --- | --- | --- |
| Directed frames | 6 | `queue_capacity` (default `DEFAULT_QUEUE_CAPACITY` = 64) | `FrameEntry` | VM or executor, per direction |
| Coverage | 1 | `COVERAGE_QUEUE_CAPACITY` = 65,536 | `CoverageEntry` | plugin -> host |
| White-box marker | 1 | `WHITEBOX_MARKER_QUEUE_CAPACITY` = 1,024 | `WhiteboxMarkerEntry` | plugin -> host |
| Fault command | 1 | `DEFAULT_FAULT_COMMAND_CAPACITY` = 4,096 | `FaultCommandSlotV1` + arena | host -> plugin |
| Fault result | 1 | 4,096 | `FaultResultSlotV2` + arena | plugin -> host |
| Fault event | 1 | `DEFAULT_FAULT_EVENT_CAPACITY` = 4,096 | `FaultEventSlotV1` + arena | plugin -> host |
| Guest introspection | 2 | `GUEST_INTROSPECTION_QUEUE_CAPACITY` = 64 | `GuestIntrospectionEntry` | request host -> plugin, response plugin -> host |
| Accelerator | 2 | `ACCELERATOR_QUEUE_CAPACITY` = 128 | `AcceleratorEntry` | request plugin -> host, completion host -> plugin |
| Selectable reply | 1 | `SELECTABLE_REPLY_QUEUE_CAPACITY` = 1 | `WhiteboxMarkerEntry` | host -> plugin |

For the two-ring classes the ring index is `vm_slot * 2 + offset`:
`GUEST_INTROSPECTION_REQUEST_RING_OFFSET = 0`,
`GUEST_INTROSPECTION_RESPONSE_RING_OFFSET = 1`,
`ACCELERATOR_REQUEST_RING_OFFSET = 0`, `ACCELERATOR_COMPLETION_RING_OFFSET = 1`.

### FrameEntry and deliverability

`FrameEntry` (`src/shmem/frame_node/frame_entry.rs`), `#[repr(C)]`, align 8,
`32 + MAX_FRAME_DATA` = 4,640 bytes:

```text
offset  size  field                          owner
0       8     delivery_icount                producer
8       4     src_node                       producer
12      4     seq                            producer (per (src, dst) pair)
16      2     len                            producer, 0..=MAX_FRAME_DATA
18      1     delivery_state                 consumer (atomic u8)
19      1     _pad                           zero
20      4     delivery_attempts              consumer (atomic u32)
24      8     last_delivery_attempt_icount   consumer (atomic u64)
32      4608  data                           only data[..len] is valid
```

`MAX_FRAME_DATA = 4608` (9 x 512): a standard Ethernet frame plus VLAN and
framing headroom, and a 4 KiB block response with its header, without
truncation. `FrameEntry::new` rejects a larger payload
(`PayloadLengthExceedsCapacity`); frames are never truncated.

A frame becomes visible to its consumer iff
`delivery_icount <= consumer.current_icount` (`is_deliverable_at`). The
wall-clock moment of the producer's release store and of the consumer's poll
are irrelevant. When several inbound frames are deliverable at once, the
consumer orders them by `FrameDeliveryKey { delivery_icount, src_node, seq }`
(`deliverable_frames_at` sorts by `delivery_key()`), never by ring-arrival
order. This key is the per-consumer projection of the scheduler's global
canonical order; see [determinism.md](determinism.md).

Because ceilings never exceed the conservative lookahead, a frame's delivery
coordinate cannot already be behind its consumer. `validate_frame_delivery_is_future`
returns `LookaheadGateError::DeliveryAlreadyPassed` when
`delivery_icount < consumer_current_icount`; that is a determinism defect and
fails loudly rather than delivering late.

### Retained frames

`delivery_state` is `FRAME_DELIVERY_PENDING` (0) at publication and both
attempt fields are zero. Only the sole consumer may transition the live ring
head to `FRAME_DELIVERY_RETAINED` (1), and only after a real QEMU RX
backpressure result (`mark_delivery_retained`, idempotent). Any other state
byte is invalid (`FrameDeliveryStateError::UnknownState`).

`record_delivery_attempt(current, limit)` requires `current >=
delivery_icount`, a strictly increasing coordinate after the first attempt,
and fewer than `limit` prior attempts. The ABI bound is
`MAX_FRAME_DELIVERY_ATTEMPTS = 1_024`; the attempt after that fails with a
typed terminal error. A retained head's next wake coordinate is
`last_delivery_attempt_icount + FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT`
(4,000,000) in the same tick coordinate (`inbound_frame_wake_icount` in
`crates/crucible/crucible-qemu-host/src/quantum/inbound_delivery.rs`). A
retained head proves that it and its blocked same-ring successors may remain
due after the current coordinate; a retained non-head or inconsistent attempt
state fails closed. Successful guest acceptance dequeues the frame normally.

### Coverage ring

`CoverageEntry`, `#[repr(C, align(64))]`, 64 bytes:

```text
0   8   current_icount   raw icount immediately before the TB's first instruction
8   8   guest_pc
16  8   map_index
24  4   vcpu_index
28  4   block_len
32  32  _reserved        zero
```

The plugin enqueues only the first zero-to-nonzero transition of a map byte,
and the capacity equals the 65,536-entry coverage map, so a correct producer
cannot overflow within one restore generation. The TB callback never
allocates, locks, blocks, performs I/O, or evicts; `QueueFull` is an invariant
failure that aborts the run. The host drains only after a completed quantum
boundary (and once before teardown), validates each entry
(`CoverageEntry::validate` rejects a bad block length, an out-of-range map
index, or nonzero reserved bytes), requires FIFO icounts nondecreasing and not
past the published boundary, rejects a repeated map index, and appends the
batch to the unified event log before the next step. See
[event-log.md](event-log.md).

Coverage reset on a warm restore is bound to the logical-time restore
transaction. While QEMU is stopped, the plugin validates the ring,
release-publishes `write_idx = read_idx` (`discard_coverage_at_restore`),
clears its novelty map, and zeroes every `(vcpu, map_index)` entry of the
retained QEMU scoreboard before acknowledging. The scoreboard is never
replaced, because translated callbacks hold pointers into it. After the exact
acknowledgement and native pause, the host requires `read_idx == write_idx`,
adopts that cursor, and clears its own novelty state. Any partial or
conflicting reset fails the realization before authoritative execution.

### Fingerprint sample slots

`FingerprintSampleSlot` (`src/shmem/fingerprint_sample.rs`),
`#[repr(C, align(128))]`, 640 bytes, one per VM:

```text
0   4      sample_gen        seqlock generation
4   4      capture_request   odd = host request, even = plugin acknowledgement
8   69*8   words             little-endian payload words
```

The 69 words are 21 header words (sample icount, vCPU count, round-robin
cursor and quantum, component failures, RAM and device-state sizes, and three
32-byte digests) plus six words for each of up to
`FINGERPRINT_SAMPLE_MAX_VCPUS = 8` vCPUs (register digest, register-file size,
retired-instruction count). The host publishes an odd capture generation
(repeated requests coalesce) and binds it to a control-boundary request; the
plugin publishes the exact boundary sample under `sample_gen`, then
compare-exchanges that exact odd value to its even successor before
acknowledging the boundary. The host reads the slot only while the VM is
quiescent.

### White-box marker and selectable-reply entries

`WhiteboxMarkerEntry`, `#[repr(C, align(64))]`, 4,672 bytes:

```text
0     8     current_icount   pre-instruction tick of the trap
8     4     vcpu_index
12    2     kind             marker kind
14    2     payload_len      <= 4608
16    4608  payload          canonical marker body
4624  48    _reserved        zero
```

The marker ring is observational: separate from every causal ring, drained
only at completed quantum boundaries, decoded by the canonical white-box
decoder, and appended to the event log. Malformed entries, unsupported kinds,
regressing or future icounts, and overflow fail the run; nothing falls back
to a causal ring or the control socket. See
[guest-host-channel.md](guest-host-channel.md).

The selectable-reply ring reuses the same entry layout as a fixed envelope,
distinguished by kind `0xff07` (`WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY`) and a
canonical `SelectionReplyV1` payload; its header carries the stopped trap tick
and vCPU. Capacity is one because a catalog permits only one pending request,
so a second entry would be invalid pipelining. The host validates the reply
sequence, reservation capacity, and paused coordinate before publishing; the
plugin consumes at vCPU resume, matches its pending request, zero-fills the
guest reservation, writes the reply, and only then completes catalog
accounting.

### Guest-introspection and accelerator entries

`GuestIntrospectionEntry`, align 64, 4,672 bytes: `sequence` u64 at 0
(nonzero, directional), `len` u16 at 8, zero pad at 10, one complete bounded
`CRGI` record in `data[4608]` at 16, `_reserved[48]` at 4624. Entries carry no
pointer, descriptor, callback, or QEMU-private value. A full ring applies
backpressure and never overwrites; malformed entries fail closed.

`AcceleratorEntry`, align 64, 4,736 bytes: `sequence` u64 at 0, `generation`
u64 at 8, `device_id[32]` at 16, `class`, `job_kind`, `queue_id`, `status`,
`protocol_version`, `flags` (u16 each) at 48..60, `data_len` u32 at 60,
`service_units` u64 at 64, `output_capacity` u32 at 72, `data[4608]` at 76,
`_reserved[52]` at 4684. `ACCELERATOR_PROTOCOL_VERSION = 1`.

### Fault transports

Each VM has three fault transports (command, result, event). Each is a ring of
fixed slots plus an SPSC byte arena of `fault_payload_arena_bytes`, so large
payloads travel without enlarging the slots:

```text
FaultCommandSlotV1 / FaultResultSlotV2 / FaultEventSlotV1 (align 64)
0    8    reservation_start   logical arena cursor
8    8    payload_start       logical arena cursor
16   8    reservation_end     logical arena cursor
24   N    encoded header      216 (command) / 196 (result) / 320 (event)
...       _reserved           zero; slot = 256 / 256 / 384 bytes

FaultPayloadArenaHeader (size 128, align 128)
0    8    read_cursor
8    56   padding
64   8    write_cursor
72   56   padding
```

Cursors increase monotonically; one payload is always physically contiguous
and the producer accounts for a skipped tail in its reservation. The
reservation fields sit outside the authenticated envelope so the consumer can
release arena space even for a malformed command, which is then rejected. The
envelopes, capability manifests, and evidence formats belong to the fault
model; see the fault pages in this directory.

## Snapshot and restore

### Directed-ring snapshots

`RingHeader::snapshot` and `RingHeader::restore` are valid only while both
endpoints are quiescent; they are not concurrency-safe. `snapshot` copies
live entries in `read_idx..write_idx` order into an `SpscRingSnapshot` of
compact `SnapshotFrameEntry` records (metadata plus only the valid payload
bytes). `restore` writes them from slot 0 and normalizes `read_idx = 0`,
`write_idx = len`.

`SpscRingSnapshot::canonical_bytes` is a padding-independent little-endian
encoding, so equal logical ring states content-address identically:

```text
u64  frame_count
repeat frame_count:
  u64  delivery_icount
  u32  src_node
  u32  seq
  u16  len
  u8   delivery_state
  u32  delivery_attempts
  u64  last_delivery_attempt_icount
  [u8; len] payload
```

Padding and the unused tail of `data` are excluded. Each frame is validated:
`len <= MAX_FRAME_DATA`; pending frames have zero attempts and coordinate;
retained frames have `1..=1024` attempts and a coordinate not before
`delivery_icount`. `from_canonical_bytes(bytes, max_frames)` rejects a
declared count above `max_frames`, checks that the input holds at least the
minimum 31 bytes per declared frame before reserving, uses fallible
reservation, and rejects truncation and trailing bytes. A hostile checkpoint
therefore cannot amplify a zero-payload frame into a 4,640-byte slot before
restore.

### Hot-fork ring image

`HotForkRingImage` (`src/mapped_setup_region/hot_fork/image.rs`) copies held
queue storage into a branch-private mapping. It is operational transfer
material, not configuration identity, and does not replace the semantic host
continuation. Canonical little-endian layout:

```text
[u8; 8]  magic = "CRHFRI02"
u32      schema_version = 2        (HOT_FORK_RING_IMAGE_SCHEMA_VERSION)
u32      abi_version
u64      region_size
u32      vm_node_count
u32      queue_capacity
u32      ticks_per_ns
u32      fault_payload_arena_bytes
3 x { u64 offset, u64 length, [u8; length] }
[u8; 32] digest
```

The three segments are fixed by the validated `RegionLayout`:
`ring_hdr_off..coverage_ring_hdr_off` (directed rings),
`coverage_ring_hdr_off..fingerprint_sample_off` (coverage), and
`whitebox_marker_ring_hdr_off..region_size` (marker, fault, guest
introspection, accelerator, and selectable-reply rings). Node slots and
fingerprint samples are not image bytes; they are separate continuation or
child-reinitialization obligations. The digest is BLAKE3 with derive-key
context `crucible.shmem.hot-fork-ring-image.v2` over every field after the
magic except the digest. It provides transfer integrity only.

Capture requires every source ring held with zero admitted operations.
Restore requires an identical, inactive, branch-private destination whose
rings are already held and drained; every encoded ring header must retain both
held bits, zero admission counts, and a live count within that ring class's
capacity. Malformed input is rejected before the first destination write, and
the total canonical size is checked against a caller bound before segment
allocation. See [time-travel-debugging.md](time-travel-debugging.md) for how
forks use it.

## Generated C header

`generated_c_header()` (`src/abi_header.rs`, re-exported from the crate root)
emits `crucible_shmem_abi.h` from the Rust constants. The example
`examples/crucible-shmem-abi-header.rs` prints it, and the committed copy
lives in `include/`. The header:

- starts with `/* Generated by crucible-shmem. Do not edit by hand. */`;
- requires GCC or Clang (`CRUCIBLE_SHMEM_ALIGNED(N)` uses
  `__attribute__((aligned(N)))`);
- defines every constant (`CRUCIBLE_SHMEM_REGION_MAGIC`,
  `CRUCIBLE_SHMEM_ABI_VERSION 30u`, `CRUCIBLE_SHMEM_TICKS_PER_NS 1000u`, slot
  and capacity constants, `CRUCIBLE_SHMEM_FUTEX_PRIVATE 0`) and every field
  offset (`CRUCIBLE_SHMEM_NODE_SLOT_CURRENT_ICOUNT_OFFSET 0u`, ...);
- declares `crucible_shmem_region_header`, `crucible_shmem_node_slot`,
  `crucible_shmem_ring_header`, `crucible_shmem_frame_entry`,
  `crucible_shmem_coverage_entry`, `crucible_shmem_fingerprint_sample_slot`,
  `crucible_shmem_whitebox_marker_entry`, the fault slot and arena structs,
  `crucible_shmem_guest_introspection_entry`, and
  `crucible_shmem_accelerator_entry`, using `_Atomic` for shared atomics;
- carries `CRUCIBLE_SHMEM_STATIC_ASSERT` (`_Static_assert`) checks on the
  `sizeof`, alignment, and `offsetof` of every field;
- provides checked-arithmetic helpers that recompute the guest-introspection
  geometry in C.

The Rust side carries the matching `const _: () = assert!(...)` checks on the
size, alignment, and offset of every shared struct and field, so a layout
change that is not reflected on both sides fails to build on at least one
side. The patched QEMU build installs the committed header at
`include/aos/crucible/crucible_shmem_abi.h` and the QEMU-side code includes it
instead of declaring the structs by hand (`pkgs/emulation/qemu.nix`). See
[qemu-patch.md](qemu-patch.md).

## Versioning and compatibility

`ABI_VERSION = 30` (`src/lib.rs`, asserted equal to `src/abi_version.in`). The
same value appears in the interface manifest, the generated header, and the
golden fixture. Version 30 binds selectable marker and reply coordinates to
picosecond ticks; raw retirement remains in the versioned pending payload.

Compatibility rules:

- Exactly one version is accepted. A mapper rejects any other `abi_version`
  before touching a slot or ring, and the control handshake rejects a plugin
  compiled against a different version (see
  [control-protocol.md](control-protocol.md)).
- Any change to a field's offset, size, type, or meaning, or to an ordering
  rule, bumps `ABI_VERSION` and regenerates the C header and golden fixture in
  the same change. Changes that move offsets update every consumer in that
  change.
- Additive fields consume reserved space (`RegionHeader::_reserved`,
  `NodeSlot::_pad4`) without moving existing offsets, and still bump the
  version.
- Reserved and padding bytes are zero-initialized at creation. Header, slot,
  ring-header, and frame padding is ignored on read. Coverage, white-box
  marker, guest-introspection, and fault entries reject nonzero reserved bytes,
  because each entry is untrusted cross-process input validated before
  admission.
- Unknown enumerated values (`advance_stop_condition`, `delivery_state`,
  `preemption_kind`) are rejected, never reinterpreted.

The license-boundary rules on top of this (no QEMU dependency in this crate,
pointer-free contents, required gates for boundary changes) are in
[licensing.md](../../legal/licensing.md#a-public-shared-memory-protocol).

## Conformance

`gate:abi-conformance` covers the region. In this crate it runs
`tests/gate_abi_conformance.rs`:

- `generated_header_matches_committed_copy` compares `generated_c_header()`
  with `include_str!("../include/crucible_shmem_abi.h")`, and
  `generated_header_carries_static_asserts_for_every_shared_struct` checks the
  assertions;
- `rust_golden_vector_round_trip_matches_fixture` encodes a live golden image
  and requires it to equal the frozen fixture byte for byte, then decodes and
  re-encodes it;
- `golden_vector_negative_control_detects_layout_drift` proves the comparison
  catches a perturbed layout.

The fixture is a compact synthetic image of 19,424 bytes: one `RegionHeader`
(describing a 2-VM, capacity-8 region), one `NodeSlot`, one `RingHeader`, one
`FrameEntry` (payload `PING`, retained, 3 attempts), and one coverage,
white-box marker, guest-introspection, and accelerator entry, all populated
with known values. Its text format is a `# ...` comment, `abi_version=30`,
`total_len=19424`, and sparse `offset=hexbytes` lines; every unlisted byte is
zero. It is regenerated only by an intentional, reviewed ABI change.

The Nix check `tests/crucible/phase2-shmem-abi-conformance.nix` also regenerates
the header with the example binary and `diff`s it against the committed copy.
Related checks in `tests/crucible/`:

| Check file | Covers |
| --- | --- |
| `phase2-shmem-region-layout.nix` | constants, offsets, target pinning, `MAX_NODES` confinement |
| `phase2-shmem-generated-header.nix` | header generation and C assertions |
| `phase2-shmem-handoff-futex.nix` | ceiling handshake, seqlock, futex wait/wake |
| `phase2-shmem-control-flags.nix` | pause/shutdown flags and wake-all |
| `phase2-shmem-deliverability.nix` | deliverability and `FrameDeliveryKey` order |
| `phase2-shmem-snapshot-restore.nix` | quiescent snapshot and canonical bytes |
| `phase2-shmem-multi-vcpu-node-slot.nix` | node-scoped slot for multi-vCPU VMs |
| `phase2-spsc-concurrency.nix`, `phase2-shmem-spsc-abi-conformance.nix` | SPSC ordering model |

SPSC ordering is certified by a checked-in exhaustive producer/consumer
ordering model and an exhaustive operation-trace corpus in
`crates/crucible/crucible-qemu-shmem/tests/gate_layer1_injection.rs`
(`assert_spsc_ring_exhaustive_ordering_model`,
`assert_spsc_ring_exhaustive_trace_properties`), plus a seeded property
corpus. Deliberately weakened orderings (relaxed everywhere, a missing
consumer acquire, a missing producer acquire) are negative controls that the
model must reject. It checks no lost, duplicated, or reordered frame and
correct full/empty behavior. The model is built entirely from the workspace
rather than `loom` or `proptest`, which would add large proc-macro dependency
trees to the hermetic bootstrap without enlarging the bounded state space.
See [testing-and-gates.md](testing-and-gates.md).
