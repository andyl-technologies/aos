# 13 — The shared-memory co-simulation ABI

This file is an **ABI specification**, not prose about an ABI. The shared-memory
region defined here is a *versioned product surface* (per [G-8]): its byte layout,
field offsets, alignments, atomic-ordering rules, and queue protocol are a binding
contract between the Rust host engine and the C QEMU side, and a change to any of
them is a versioned, conformance-gated event. Treat every number in this file as
normative.

It is also a public process protocol, not a channel for either implementation's
private objects. The region's semantics must be independently implementable;
the additional license-boundary constraints are normative in
[`37-licensing-process-boundary.md`](37-licensing-process-boundary.md).

Requirement IDs in this file use the prefix `SHM`. Gate names referenced here
(`gate:abi-conformance`, `gate:layer1-injection`, `gate:content-address`,
`gate:qemu-inert`, `gate:replay-oracle`) are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). The
producer/consumer of this region are specified in
[`11-qemu-patches.md`](11-qemu-patches.md) (the QEMU patch series that maps and
reads the region from C) and [`12-qemu-plugin.md`](12-qemu-plugin.md) (the in-VM
plugin that owns virtual time and drives the per-node fields). The injection
semantics this ABI enforces are the Contract B requirements of
[`04-determinism-contract.md`](04-determinism-contract.md) §4.4
([DET-11]–[DET-14], [DET-34]); the scheduler that *sets* the per-node ceiling is
[`08-scheduling.md`](08-scheduling.md); the time mapping is
[`09-virtual-time-icount.md`](09-virtual-time-icount.md).

The code blocks in this file are illustrative `#[repr(C)]` sketches per the
conventions in [`00-conventions.md`](00-conventions.md): they show the intended
field set, ordering, and padding so the spec is concrete, but the authoritative
statement is the prose requirement plus the normative offset/size table in §13.4.
A sketch that disagrees with a requirement is a defect in the sketch.

## 13.1 Purpose

### What the region is for

Crucible runs each VM in its own QEMU process, and runs each I/O sub-node
([`15-io-subnodes.md`](15-io-subnodes.md)) either in the host engine or in its
own helper. The single authoritative scheduler ([INV-8]) lives in the host engine
process. Those processes must agree, instruction-for-instruction, on three
things:

1. **What virtual time each node is at** — so the scheduler can compute the
   minimum-horizon node and advance the simulation as a conservative parallel
   discrete-event system (CMB; [`08-scheduling.md`](08-scheduling.md)).
2. **How far each node is permitted to advance** — the per-node *advance ceiling*
   the scheduler sets to bound a VM to its horizon, so no node ever runs past an
   icount at which an input could become visible to it ([DET-12]).
3. **What frames are in flight between nodes, and the exact virtual time at which
   each becomes visible** — carried in lock-free SPSC rings so cross-node delivery
   is a join of two pure quantities (a frame's delivery icount and the consumer's
   current icount), never a wall-clock race ([DET-13], [DET-34]).

A single shared-memory region — one `mmap` of an anonymous or `memfd`-backed
file, mapped into every participating process — carries all three. Cross-node
synchronization therefore happens through **atomic reads and writes of shared
memory plus one cross-process futex**, not through IPC round-trips. There is no
request/response on the hot path: a VM advancing virtual time reads its ceiling
with a single relaxed-or-acquire load; the scheduler raising a ceiling does a
single store plus the current unconditional non-private futex wake. A future
waiter-armed optimization may make the wake conditional when it can reliably
prove that no peer is parked.

- **[SHM-1]** Crucible MUST carry all hot-path cross-node synchronization state
  (per-node clocks, per-node status, per-node advance ceilings, and frame queues)
  in a single shared-memory region mapped into the host engine process and every
  participant process. The hot path (a node reading its ceiling, advancing its
  clock, enqueueing/dequeueing frames) MUST NOT require an IPC round-trip; it MUST
  be expressible as atomic memory operations plus, at most, one futex syscall to
  park or wake a node. *Gate:* `gate:layer1-injection`. *Spec:* §13.1.

- **[SHM-2]** The shared-memory region MUST be the *only* channel through which
  virtual-time advancement and cross-node frame delivery are coordinated; there is
  no second source of timing truth ([INV-8]). The IPC protocol
  ([`14-protocol.md`](14-protocol.md)) MAY carry control-plane setup, teardown,
  and the region handle, but MUST NOT carry per-quantum timing or per-frame
  delivery decisions. *Gate:* `gate:layer1-injection`. *Spec:* §13.1.

### Why shared memory, not a message bus

A message bus would reintroduce the very nondeterminism Crucible eliminates: the
order in which two producers' messages arrive on a socket is a host-scheduling
artifact. By contrast, a frame written into a shared ring carries its
**delivery icount** in-band, and the consumer decides deliverability by comparing
that stamp against its own current icount — a pure function of two integers, with
the moment of the write irrelevant ([DET-13]). The shared region is the substrate
that makes Contract B (§4.4) implementable: the only thing that crosses between
processes is bytes-at-an-address, and the *semantics* of those bytes are defined
entirely in virtual time.

## 13.2 Single source of truth for the layout

The single most important correctness property of this file is that **the Rust
and C views of the region cannot drift**. The region is touched by two languages:
Rust (the host engine, and the I/O sub-node helpers) and C (the QEMU patch series
and, where the plugin is C, the in-VM plugin). If their notions of a field's
offset, size, or alignment ever disagree, every guarantee built on the region
silently collapses — a scheduler ceiling read from the wrong offset, a frame's
delivery icount parsed as its length.

- **[SHM-3]** The Rust `#[repr(C)]` definitions in the `crucible-shmem` crate are
  the **mechanically checked source** of the publicly specified region layout.
  The normative field semantics, offsets, ordering rules, compatibility policy,
  and golden vectors MUST be sufficient for an independent implementation.
  Every other language view of
  the region — the generated C header consumed by the QEMU patches, any
  documentation table, any test vector — MUST be derived from, or checked against,
  those Rust definitions. No hand-maintained second copy of the layout is
  permitted. *Gate:* `gate:abi-conformance`. *Spec:* §13.2, forward-ref
  [`11-qemu-patches.md`](11-qemu-patches.md), [`12-qemu-plugin.md`](12-qemu-plugin.md).

- **[SHM-3A]** Shared fields MUST be protocol values and MUST NOT contain native
  pointers, QEMU private structures, function/callback tables, Rust trait
  objects or compiler-selected enum layouts, or shared ownership of a
  process-private object. References within the region MUST be checked offsets
  from its base. *Gate:* `gate:abi-conformance`, `gate:license-boundary`.
  *Spec:* §13.2, 37/[BOUND-6].

- **[SHM-4]** `crucible-shmem` MUST emit a generated C header
  (`crucible_shmem_abi.h`) describing every shared struct, its fields, and the ABI
  version, produced mechanically from the Rust definitions during the build. The
  QEMU patch series ([`11-qemu-patches.md`](11-qemu-patches.md)) MUST include this
  generated header rather than declaring the structs by hand. A build in which the
  committed header differs from the freshly generated one MUST fail.
  *Gate:* `gate:abi-conformance`, `gate:qemu-inert`. *Spec:* §13.2.

- **[SHM-5]** Both language views MUST carry **static layout assertions** that
  fail to compile if the layout drifts. On the Rust side, every shared struct MUST
  carry `const _: () = assert!(...)` checks on `size_of`, `align_of`, and the
  byte `offset_of!` of every field. On the C side, the generated header MUST carry
  the corresponding `_Static_assert(sizeof(...) == N, ...)` and
  `_Static_assert(offsetof(...) == K, ...)` for every field. A layout change that
  is not reflected in *both* sets of assertions MUST fail to build on at least one
  side. *Gate:* `gate:abi-conformance`. *Spec:* §13.2, §13.4.

- **[SHM-6]** The region layout MUST be **deterministic and target-pinned**: it
  MUST NOT depend on host pointer width beyond the pinned target
  (`x86_64-unknown-linux-gnu`), on compiler struct-packing heuristics, or on
  enum-discriminant sizing. All multi-byte fields are little-endian; all sizes and
  offsets are fixed constants. The ABI does NOT support a big-endian or 32-bit
  host. *Gate:* `gate:abi-conformance`. *Spec:* §13.2, §13.6.

The mechanism is belt-and-suspenders on purpose: the generated header ([SHM-4])
keeps the C declarations *honest by construction*, and the bilateral static
assertions ([SHM-5]) catch the residual cases (a hand-edit to the header, a
compiler that lays a struct out differently than expected) at *compile time on
both sides*, before any byte is exchanged. The golden-vector conformance test
(§13.8) is the third leg: it checks the *runtime* bytes match a checked-in
fixture, catching any disagreement the compile-time checks miss.

## 13.3 The layout

The region is laid out as a fixed-size header followed by a fixed-size array of
per-node slots, followed by the directed-frame SPSC rings and their frame-entry
storage, one fixed-capacity plugin-to-host coverage ring per VM, one fingerprint
sample slot per VM, and one bounded plugin-to-host white-box marker ring per VM.
The header and slots are fixed-size so their offsets are compile-time constants.
Frame-ring geometry is recorded in the header; ABI v5 derives every trailing
section from that frame extent, the VM count, and ABI-fixed constants, so no
process-local pointer or host-layout fact crosses the ABI.

```text
  +--------------------------------------------------+  offset 0
  | RegionHeader     (256 bytes, align 128)          |
  +--------------------------------------------------+  offset 256
  | NodeSlot[0]      (128 bytes, align 128)          |
  | NodeSlot[1]                                       |
  | ...                                              |
  | NodeSlot[MAX_NODES-1]                            |
  +--------------------------------------------------+  header.ring_hdr_off
  | RingHeader[0]    (128 bytes, align 128)          |   = one per directed
  | ...                                              |     (src,dst) pair in use
  +--------------------------------------------------+  header.ring_data_off
  | FrameEntry[ ... ]  (entry_stride bytes each)     |   = capacity entries per ring
  | ...                                              |
  +--------------------------------------------------+  align_up(frame data end, 128)
  | Coverage RingHeader[vm_node_count]               |   = one SPSC ring per VM
  +--------------------------------------------------+
  | CoverageEntry[vm_node_count][65536]              |   = one slot per map index
  | ...                                              |
  +--------------------------------------------------+  align_up(coverage data end, 128)
  | FingerprintSampleSlot[vm_node_count]             |   = latest boundary sample
  +--------------------------------------------------+  align_up(fingerprint data end, 128)
  | Whitebox Marker RingHeader[vm_node_count]        |   = one SPSC ring per VM
  +--------------------------------------------------+
  | WhiteboxMarkerEntry[vm_node_count][1024]         |   = decoded guest markers
  | ...                                              |
  +--------------------------------------------------+  header.region_size
```

### 13.3.1 Region header

The region header carries the identity and shape of the region: a magic number,
the ABI version, the configured node count and queue capacity, the computed
frame sub-region offsets, and the global pause flag. ABI v5 mappers derive the
coverage, fingerprint-sample, and white-box marker tail sections from that
validated frame extent, the VM count, and fixed ABI constants. The header is
the first thing a mapper reads and the thing
the handshake ([`14-protocol.md`](14-protocol.md)) validates before any node
touches a slot.

```rust
/// Eight-byte ASCII magic identifying a Crucible shared-memory region.
/// Spelled out as bytes so it appears verbatim in a hex dump.
pub const REGION_MAGIC: u64 = u64::from_le_bytes(*b"CRUCSHM1");

/// Current ABI version. Bumped on any layout or semantics change (§13.6).
pub const ABI_VERSION: u32 = 5;

/// Compile-time maximum number of node slots in the region.
/// An ABI detail (§13.5); the engine's topology model MUST NOT depend on it.
pub const MAX_NODES: usize = 32;

/// Reserved executor slot indices (§13.5). These are routing/I/O endpoints,
/// not logical nodes. They occupy the high slot indices.
pub const SLOT_NET_ROUTER: usize = MAX_NODES - 1;
pub const SLOT_BLK_IO: usize = MAX_NODES - 2;
pub const SLOT_9P_IO: usize = MAX_NODES - 3;

/// Number of slots reserved for executors; logical VM nodes use 0..MAX_VM_NODES.
pub const RESERVED_SLOTS: usize = 3;
pub const MAX_VM_NODES: usize = MAX_NODES - RESERVED_SLOTS;

#[repr(C, align(128))]
pub struct RegionHeader {
    /// MUST equal `REGION_MAGIC`; validated before any other field is trusted.
    pub magic: AtomicU64, // @ 0
    /// MUST equal `ABI_VERSION`; the handshake rejects a mismatch (§13.6).
    pub abi_version: AtomicU32, // @ 8
    /// Number of node slots actually configured for this run (<= MAX_NODES).
    pub node_count: AtomicU32, // @ 12
    /// Capacity (entries) of every SPSC ring in this region; power of two.
    pub queue_capacity: AtomicU32, // @ 16
    /// Number of directed (src,dst) ring pairs allocated in this region.
    pub ring_count: AtomicU32, // @ 20
    /// Byte offset from region base to the first RingHeader.
    pub ring_hdr_off: AtomicU64, // @ 24
    /// Byte offset from region base to the first FrameEntry backing slot.
    pub ring_data_off: AtomicU64, // @ 32
    /// Byte stride between consecutive FrameEntry slots (== size_of::<FrameEntry>()).
    pub entry_stride: AtomicU64, // @ 40
    /// Total size of the mapped region in bytes.
    pub region_size: AtomicU64, // @ 48
    /// The fixed `-icount shift=N` value mapping instructions to virtual ns.
    /// Recorded so any mapper converts between icount and ns identically (09).
    pub icount_shift: AtomicU32, // @ 56
    /// Global coordinated-pause request: set by the scheduler, observed by every
    /// node before it advances past its current quantum (§13.7).
    pub pause_requested: AtomicU8, // @ 60
    /// Global teardown flag: set when the run is ending so parked nodes wake and
    /// observe DONE rather than spinning.
    pub shutdown_requested: AtomicU8, // @ 61
    // @ 62..256 reserved, zero-initialized, for forward-compatible additions
    // that do not change existing offsets. New fields take reserved space and
    // bump ABI_VERSION (§13.6).
    pub(crate) _reserved: [u8; 194],
}

const _: () = assert!(core::mem::size_of::<RegionHeader>() == 256);
const _: () = assert!(core::mem::align_of::<RegionHeader>() == 128);
```

- **[SHM-7]** The region MUST begin with a `RegionHeader` carrying, at minimum: a
  magic number, the ABI version, the configured node count, the per-ring queue
  capacity, the ring count, the byte offsets and stride locating the ring headers
  and frame-entry storage, the region size, the fixed icount shift, and the global
  pause and shutdown flags. A mapper MUST be able to locate every sub-region from
  the header alone, with no out-of-band parameters. *Gate:* `gate:abi-conformance`.
  *Spec:* §13.3.1, §13.4.

- **[SHM-8]** The region header MUST carry the **fixed icount shift** ([SHM-7]),
  so that any process converts between a node's icount and virtual-time
  nanoseconds using the *same* mapping ([`09-virtual-time-icount.md`](09-virtual-time-icount.md)).
  No process may assume a shift value not present in the header. *Gate:*
  `gate:abi-conformance`, `gate:layer1-injection`. *Spec:* §13.3.1.

### 13.3.2 Per-node slot

Each node owns one cache-line-pair-aligned slot. The slot is the rendezvous point
between the node (which publishes its current clock and status, and parks on its
futex word) and the scheduler (which reads the clock and writes the advance
ceiling). It is `align(128)` — two cache lines on the pinned target — so that two
slots updated by two different processes never land on the same cache line, and
false sharing between nodes is impossible.

```rust
/// Node status: actively retiring instructions (VM) or processing (I/O node).
pub const STATUS_RUNNING: u8 = 0;
/// Node status: idle, waiting for a wake (timer, frame, or raised ceiling).
pub const STATUS_IDLE: u8 = 1;
/// Node status: simulation complete; the slot no longer participates.
pub const STATUS_DONE: u8 = 2;

/// Node kind: a QEMU guest VM.
pub const KIND_VM: u8 = 0;
/// Node kind: a network-link / routing I/O node.
pub const KIND_NET: u8 = 1;
/// Node kind: a block-device I/O node.
pub const KIND_BLK: u8 = 2;
/// Node kind: a 9p-filesystem I/O node.
pub const KIND_9P: u8 = 3;

#[repr(C, align(128))]
pub struct NodeSlot {
    /// Canonical per-node clock: executed-instruction count at the last
    /// translation-block boundary. The authoritative clock (09); `current_ns`
    /// is the derived view. Published by the node, read by the scheduler.
    pub current_icount: AtomicU64, // @ 0
    /// Virtual-time view of `current_icount` via the header's icount shift.
    /// Carried as a convenience for the scheduler's horizon math; MUST be
    /// consistent with `current_icount` under the fixed shift.
    pub current_ns: AtomicU64, // @ 8
    /// Per-node advance ceiling, in icount, set by the scheduler (§13.6 below,
    /// 08). The node MUST NOT retire an instruction whose post-icount exceeds
    /// this value without a fresh authorization. Initialized to 0 so a node
    /// cannot advance before the scheduler's first ceiling write.
    pub max_advance_icount: AtomicU64, // @ 16
    /// If `status == STATUS_IDLE`, the earliest icount at which this node
    /// expects to wake (earliest of: next timer, next inbound frame delivery
    /// icount, or a raised ceiling). The scheduler treats an idle node as
    /// effectively at this time when computing the minimum horizon.
    pub idle_wake_icount: AtomicU64, // @ 24
    /// Cross-process futex word (§13.7). Every targeted wake (the scheduler
    /// raises `max_advance_icount` to/above `idle_wake_icount`, or a frame is
    /// delivered into this node's inbound ring) increments this counter and
    /// issues FUTEX_WAKE. The node publishes its precondition, then FUTEX_WAITs
    /// on this word.
    pub wake_signal: AtomicU32, // @ 32
    /// Node status (`STATUS_RUNNING` / `STATUS_IDLE` / `STATUS_DONE`).
    pub status: AtomicU8, // @ 36
    /// Node kind (`KIND_VM` / `KIND_NET` / `KIND_BLK` / `KIND_9P`).
    pub kind: AtomicU8, // @ 37
    /// Nonzero while a device-I/O burst is active. While set, the node's idle
    /// callback suppresses spurious HZ-tick advancement between submit and the
    /// computed completion so timer ticks cannot slip mid-burst (it does NOT
    /// freeze virtual time; the requester is still fast-forwarded to the
    /// computed delivery icount, 15). Written by the I/O device path, read by
    /// the node's idle callback (15).
    pub device_io_active: AtomicU8, // @ 38
    // @ 39 one byte padding to align the next 8-byte field.
    pub(crate) _pad0: u8, // @ 39
    /// Seqlock generation counter the node bumps around each publish of its
    /// multi-field `(current_icount, current_ns, status, ...)` state, letting a
    /// reader/snapshotter detect a torn or in-progress publish without locking
    /// (the seqlock protocol, §13.3.4). Even == stable, odd == write in progress.
    pub publish_gen: AtomicU32, // @ 40
    pub(crate) _pad1: [u8; 4], // @ 44
    /// Host-published exact completion icount, or zero when none is pending.
    pub device_completion_deadline_icount: AtomicU64, // @ 48
    /// Exact icount at which the plugin must apply the pending preemption.
    pub preemption_at_icount: AtomicU64, // @ 56
    /// Inclusive lower bound of the preemption authorization window.
    pub preemption_deadline_icount: AtomicU64, // @ 64
    /// Inclusive upper bound of the preemption authorization window.
    pub preemption_ceiling_icount: AtomicU64, // @ 72
    /// Sequence release-published by the scheduler after command fields.
    pub preemption_published_sequence: AtomicU32, // @ 80
    /// Sequence release-published by the plugin after QEMU accepts the command.
    pub preemption_consumed_sequence: AtomicU32, // @ 84
    /// Kind-specific first argument: source or target vCPU.
    pub preemption_arg0: AtomicU32, // @ 88
    /// Kind-specific second argument: target vCPU or interrupt vector.
    pub preemption_arg1: AtomicU32, // @ 92
    /// Command kind: none, vCPU switch, or interrupt injection.
    pub preemption_kind: AtomicU8, // @ 96
    // @ 97..128 reserved, zero-initialized (forward-compatible additions only).
    pub(crate) _reserved: [u8; 31],
}

const _: () = assert!(core::mem::size_of::<NodeSlot>() == 128);
const _: () = assert!(core::mem::align_of::<NodeSlot>() == 128);
```

- **[SHM-9]** Each node MUST own exactly one `NodeSlot`, aligned to 128 bytes (two
  cache lines on the pinned target) so that slots written by different processes
  never share a cache line. The slot MUST carry: the node's current icount, the
  derived current virtual-time ns, the scheduler-set advance ceiling, the
  idle-wake icount, the futex wake-signal word, the status, the kind, the
  device-I/O-active flag, and a publish-generation counter. *Gate:*
  `gate:abi-conformance`. *Spec:* §13.3.2, §13.4.

- **[SHM-10]** A node's canonical clock in the slot MUST be `current_icount`
  (executed-instruction count); `current_ns` is a *derived* view obtained by the
  fixed shift and MUST be consistent with `current_icount`. Cross-node delivery
  decisions and the advance ceiling MUST be expressed in icount (or, equivalently,
  the virtual time the plugin converts to icount via the fixed shift), never in
  host wall-clock units. *Gate:* `gate:layer1-injection`, `gate:abi-conformance`.
  *Spec:* §13.3.2, §4.4.

- **[SHM-11]** `max_advance_icount` MUST initialize to 0 so that a node cannot
  advance its virtual clock before the scheduler has authorized a ceiling. The
  scheduler raises it to the rendezvous target before releasing the boot barrier
  (§13.6). A node MUST NOT retire an instruction whose resulting icount would
  exceed `max_advance_icount`. *Gate:* `gate:layer1-injection`. *Spec:* §13.3.2,
  §13.6.

- **[SHM-37]** A multi-vCPU VM node (one running `N > 1` vCPUs single-threaded
  under round-robin TCG + icount; [DET-5], [DET-23], 09) MUST be represented by a
  **single** `NodeSlot` carrying the node's *aggregate* clock
  (`current_icount`/`current_ns`), its *aggregate* advance ceiling
  (`max_advance_icount`), and its *aggregate* `idle_wake_icount`. Per-vCPU icount
  or per-vCPU state MUST NOT appear in the ABI — it is plugin-internal. The node's
  `idle_wake_icount` MUST be the **minimum over its vCPUs' armed deadlines** (the
  node aggregate of [TIME-24]); `device_io_active` and the RR sub-division of a
  quantum are node-scoped, not per-vCPU. Because no per-vCPU fields are added,
  `ABI_VERSION` is **unchanged** for N-vCPU nodes. Per-vCPU fingerprint state
  ([DET-29]) is routed over QMP / plugin introspection (12), NOT over this shmem
  region. *Gate:* `gate:abi-conformance`, `gate:layer1-injection`. *Spec:*
  §13.3.2, forward-ref [`12-qemu-plugin.md`](12-qemu-plugin.md), 09.

### 13.3.3 SPSC ring header and frame entry

Frames between nodes flow through single-producer/single-consumer rings: one ring
per directed `(src, dst)` pair in use. The ring header carries only the head and
tail indices, on separate cache lines; the frame-entry backing storage lives in
its own contiguous sub-region so the entries (which are large) do not bloat the
header array and pollute the cache lines that carry the indices.

```rust
/// Maximum payload bytes per frame entry. Sized to hold a standard Ethernet
/// frame (MTU 1500 + 14-byte header + 4-byte FCS = 1518) plus headroom for
/// VLAN tags and any internal framing, rounded up to a cache-line multiple.
/// I/O sub-node wire payloads (block responses, 9p messages) also ride these
/// entries; the constant is chosen to hold a 4 KiB block response with its
/// small response header without truncation.
pub const MAX_FRAME_DATA: usize = 4608; // 9 * 512, sector-aligned, >= 4 KiB + hdr

/// Default per-ring capacity (entries). Power of two so `idx % cap` is a mask.
pub const DEFAULT_QUEUE_CAPACITY: u32 = 64;

#[repr(C, align(128))]
pub struct RingHeader {
    /// Consumer-owned read index, monotonically increasing (never wraps in the
    /// counter; the slot is `read_idx % capacity`). On its own cache line.
    pub read_idx: AtomicU64, // @ 0
    pub(crate) _pad_read: [u8; 56], // @ 8..64  (fill the consumer cache line)
    /// Producer-owned write index, monotonically increasing. On its own cache
    /// line so the producer's store never invalidates the consumer's line.
    pub write_idx: AtomicU64, // @ 64
    pub(crate) _pad_write: [u8; 56], // @ 72..128 (fill the producer cache line)
}

const _: () = assert!(core::mem::size_of::<RingHeader>() == 128);
const _: () = assert!(core::mem::align_of::<RingHeader>() == 128);

#[repr(C)]
pub struct FrameEntry {
    /// The virtual time, in icount, at which this frame becomes architecturally
    /// visible to the consumer. The crux of injection determinism (§13.9): the
    /// consumer delivers iff `delivery_icount <= consumer.current_icount`.
    pub delivery_icount: u64, // @ 0
    /// Source node id (slot index) that emitted the frame.
    pub src_node: u32, // @ 8
    /// Per-(src,dst) monotonic sequence number; ties at equal delivery_icount
    /// are broken by `(node_id, seq)` per INV-3.
    pub seq: u32, // @ 12
    /// Length of valid bytes in `data` (0..=MAX_FRAME_DATA).
    pub len: u16, // @ 16
    // @ 18..24 padding to 8-byte-align the payload start.
    pub(crate) _pad: [u8; 6], // @ 18
    /// Frame payload; only `data[..len]` is valid.
    pub data: [u8; MAX_FRAME_DATA], // @ 24
}

const _: () = assert!(core::mem::size_of::<FrameEntry>() == 24 + MAX_FRAME_DATA);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == 24);
```

- **[SHM-12]** Each directed `(src, dst)` node pair that can exchange frames MUST
  have its own `RingHeader` and its own contiguous run of `queue_capacity`
  `FrameEntry` slots. The ring is single-producer (the `src` node) /
  single-consumer (the `dst` node); the head (`read_idx`) and tail (`write_idx`)
  counters MUST sit on separate cache lines to prevent producer/consumer false
  sharing. The capacity MUST be a power of two so index-to-slot is a mask
  operation. *Gate:* `gate:abi-conformance`. *Spec:* §13.3.3, §13.4.

- **[SHM-13]** A `FrameEntry` MUST carry, in this field order: the
  `delivery_icount` (the virtual time at which the frame becomes visible to the
  consumer), the `src_node` id, the per-pair `seq`, the valid `len`, and a
  fixed-size `data` payload of `MAX_FRAME_DATA` bytes. `MAX_FRAME_DATA` MUST be at
  least a standard Ethernet frame (1518 bytes) plus headroom, and large enough to
  hold the largest I/O sub-node wire payload (a 4 KiB block response with its
  header) without truncation. A frame whose `len` exceeds `MAX_FRAME_DATA` MUST be
  rejected at enqueue, never silently truncated. *Gate:* `gate:abi-conformance`,
  `gate:layer1-injection`. *Spec:* §13.3.3, §13.4.

### 13.3.4 The `publish_gen` seqlock: torn-free snapshots of a slot

A node's slot holds *several* fields that must be read as a consistent set —
`current_icount`, the derived `current_ns`, `status`, and the idle/kind/flags —
yet the node mutates them without taking a lock, and the scheduler (or a
checkpoint snapshotter) reads them concurrently from another process. A plain
multi-field read can observe a **torn** state: `current_icount` from after a
write but `status` from before it. The `publish_gen` counter is a classic
**seqlock** that makes such a read detectable and retryable, so a reader always
obtains a self-consistent picture of the slot without blocking the writer.

The discipline is the standard seqlock idiom:

- **Writer (the node)** bumps `publish_gen` to the next **odd** value with a
  release store *before* mutating the slot's multi-field state, writes the fields,
  then bumps `publish_gen` to the next **even** value with a release store
  *after*. While a publish is in progress the counter is odd.
- **Reader (scheduler / snapshotter)** loads `publish_gen` with acquire ordering
  into `g0`; if `g0` is odd, a write is in progress, so it retries. It then reads
  the fields (acquire), re-loads `publish_gen` with acquire into `g1`, and
  **retries the whole read** if `g1 != g0` (a write straddled the read). Only a
  read bracketed by an equal, even generation is accepted.

```text
  writer (node)                          reader (scheduler / snapshotter)
  ----------------------------------     ---------------------------------------
  g := publish_gen
  store publish_gen = g+1 (odd, rel)     loop:
  store current_icount  (release)          g0 := load publish_gen (acq)
  store current_ns      (release)          if g0 is odd: continue   # write in flight
  store status          (release)          read current_icount/ns/status (acq)
  ...                                       g1 := load publish_gen (acq)
  store publish_gen = g+2 (even, rel)       if g1 == g0 (even): accept snapshot
                                            else: continue           # torn; retry
```

- **[SHM-36]** The `publish_gen` field MUST implement a **seqlock** over the
  node's multi-field slot state. The writing node MUST bump `publish_gen` to an
  **odd** value (release) before mutating `current_icount`/`current_ns`/`status`
  (and any other field published together), and to the next **even** value
  (release) after. A reader or snapshotter MUST read `publish_gen` (acquire),
  require it **even** (retry while odd), read the fields (acquire), re-read
  `publish_gen` (acquire), and **retry** if the value changed or was odd —
  accepting the snapshot only when bracketed by an equal, even generation. This
  guarantees a torn-free, lock-free, consistent snapshot of a slot; a reader MUST
  NOT consume a slot read whose bracketing generation is odd or unequal. *Gate:*
  `gate:abi-conformance`, `gate:layer1-injection`. *Spec:* §13.3.4.

### 13.3.5 Plugin-to-host coverage rings

ABI v5 retains the ABI-v2 coverage section: one SPSC ring per logical VM. The QEMU plugin is
the sole producer; the host adapter is the sole consumer. `CoverageEntry` is a
fixed 64-byte record containing the raw icount immediately before the covered
TB's first instruction, the guest PC, the fixed-map index, the vCPU index, and
the translated block length. The plugin writes the complete record before a
release store to `write_idx`; the host acquire-loads `write_idx` before reading
and release-stores `read_idx` only after copying the record.

The ring capacity and coverage-map cardinality are both 65,536. The callback
enqueues only the first transition of a map byte from zero, so a conforming
producer can publish at most 65,536 records over its process lifetime. It never
allocates, locks, blocks, performs I/O, evicts an older record, or writes a
second output stream in the TB callback. `QueueFull` is therefore an invariant
failure and aborts the run loudly; it is not routine backpressure.

The host drains only after a completed quantum boundary (and once more before
coverage-aware teardown). It validates every entry, requires FIFO icounts to be
nondecreasing and no later than the published boundary, rejects a repeated map
index, and appends the complete batch to the scheduler's unified observational
event log before another backend step. A final teardown drain is returned from
the backend quantum loop, admitted with the same dense event-log sequence
validation, and published by the session actor before shutdown completes. No
host-side coverage collection is a persistent record parallel to that log.

- **[SHM-38]** Each logical VM MUST own exactly one coverage ring with the
  QEMU plugin as sole producer and host adapter as sole consumer. Publication
  and reclamation MUST use the same release/acquire SPSC ordering as frame
  rings. *Gate:* `gate:abi-conformance`, `gate:layer1-injection`. *Spec:*
  §13.3.5, §13.4.

- **[SHM-39]** Coverage capacity MUST equal the fixed coverage-map cardinality
  (65,536), and the producer MUST enqueue only a map index's first hit. A full
  queue or duplicate novelty MUST fail the run without eviction, overwrite, or
  blocking in the callback. *Gate:* `gate:layer1-injection`,
  `gate:basic-block-coverage`. *Spec:* §13.3.5.

- **[SHM-40]** The host MUST drain coverage only at a published completion
  boundary, reject invalid/future/regressing/duplicate entries, and append the
  FIFO batch to the unified event log before the next step or teardown. *Gate:*
  `gate:basic-block-coverage`. *Spec:* §13.3.5, forward-ref
  [`19-observability-event-log.md`](19-observability-event-log.md).

### 13.3.6 Fingerprint sample slots

ABI v5 retains the additive ABI-v3 fingerprint section: one 640-byte,
128-byte-aligned `FingerprintSampleSlot` per logical VM. The plugin publishes
the latest completed-boundary sample under the slot's generation seqlock and
the host reads it only while the VM is quiescent. The section begins at the
coverage-data end rounded up to 128 bytes; its VM count and fixed stride
determine the following marker-ring offset.

### 13.3.7 Plugin-to-host white-box marker rings

ABI v5 retains the ABI-v4 SPSC marker ring per logical VM after the fingerprint sample
slots. The QEMU plugin is the sole producer and the host adapter is the sole
consumer. Each fixed 4,672-byte `WhiteboxMarkerEntry` carries the exact trap
icount, vCPU index, decoded doorbell kind, bounded marker-body length, marker
body, and zeroed reserved bytes. Publication uses the same release/acquire SPSC
ordering as frame and coverage rings.

The marker ring is observational: it is distinct from every causal
network/block/9p ring, is drained only at a completed quantum boundary, and
cannot alter scheduling or delivery order. The host validates each copied
entry, decodes it through the canonical white-box protocol decoder, and admits
the resulting event to the unified event log. Invalid entries, unsupported
marker kinds, future or regressing icounts, and queue overflow fail the run
loudly. The control socket remains setup/control-only and MUST NOT carry
run-phase marker frames.

- **[SHM-41]** Each logical VM MUST own exactly one ABI-v4 white-box marker ring
  with the QEMU plugin as sole producer and host adapter as sole consumer.
  Publication and reclamation MUST use release/acquire SPSC ordering. *Gate:*
  `gate:abi-conformance`. *Check:*
  `checks.crucible.phase4.guestHostMarkerObservability`. *Spec:* §13.3.7,
  §13.4.

- **[SHM-42]** Marker entries MUST preserve the exact trap icount, vCPU, kind,
  and canonical bounded payload. Queue overflow, malformed entries, and
  unsupported run-phase kinds MUST fail without eviction, overwrite, blocking,
  or fallback to a causal ring or control socket. *Check:*
  `checks.crucible.phase4.guestHostMarkerObservability`. *Spec:* §13.3.7.

- **[SHM-43]** The host MUST drain markers only at a published completion
  boundary and append validated decoded events to the unified event log before
  the next step or teardown. *Check:*
  `checks.crucible.phase4.guestHostMarkerObservability`. *Spec:* §13.3.7,
  forward-ref
  [`19-observability-event-log.md`](19-observability-event-log.md).

### 13.3.8 Scheduler-to-plugin preemption mailbox

ABI v5 assigns the remaining fixed `NodeSlot` tail to a single-entry,
scheduler-to-plugin mailbox. A command names an exact aggregate node icount, an
inclusive authorization window, and either a `(from_vcpu, to_vcpu)` switch or a
`(target_vcpu, irq)` interrupt injection. The scheduler writes all command
fields with relaxed stores and then release-publishes a new wrapping
sequence. The plugin acquire-loads that sequence before reading the command,
validates the kind and window, asks QEMU to apply it at the exact commanded
icount, and release-publishes the same consumed sequence only after QEMU
accepts the operation.

The mailbox permits exactly one outstanding command. A scheduler MUST NOT
overwrite an unconsumed command, and the plugin MUST NOT acknowledge an unknown
or already-consumed sequence. A command is valid only when
`deadline_icount <= at_icount <= ceiling_icount`; neither side may clamp,
advance, defer, or silently discard an out-of-window command. These failures,
unknown kinds, and QEMU rejection are deterministic run failures.

- **[SHM-44]** Each VM `NodeSlot` MUST carry one ABI-v5, single-outstanding
  scheduler-to-plugin preemption mailbox with the exact fields and offsets in
  §13.4. Kind `1` carries a vCPU switch and kind `2` carries an interrupt;
  zero denotes no initialized command. *Gate:* `gate:abi-conformance`,
  `gate:layer1-injection`. *Spec:* §13.3.8, §13.4.

- **[SHM-45]** The scheduler MUST initialize command fields before
  release-publishing `preemption_published_sequence`; the plugin MUST
  acquire-load that sequence before reading them and MUST release-publish the
  matching `preemption_consumed_sequence` only after QEMU accepts the command.
  Neither producer may overwrite an outstanding command or acknowledge the
  wrong sequence. *Gate:* `gate:abi-conformance`, `gate:layer1-injection`.
  *Spec:* §13.3.8, §13.6.

- **[SHM-46]** Both endpoints MUST reject a reversed authorization window or a
  commanded icount outside its inclusive bounds. The live path MUST apply the
  command at exactly `at_icount`, without clamping, early injection, deferral,
  or fallback to a control socket. *Gate:* `gate:layer1-injection`. *Spec:*
  §13.3.8, forward-ref [`12-qemu-plugin.md`](12-qemu-plugin.md).

## 13.4 Normative offset and size table

The following constants are the binding ABI for `ABI_VERSION = 5` on
`x86_64-unknown-linux-gnu`. The generated C header ([SHM-4]) and the Rust static
assertions ([SHM-5]) MUST both reproduce these exactly. The golden-vector test
(§13.8) checks the runtime bytes against a fixture built from this table.

```text
RegionHeader  (size 256, align 128)
  @  0  magic              u64
  @  8  abi_version        u32
  @ 12  node_count         u32
  @ 16  queue_capacity     u32
  @ 20  ring_count         u32
  @ 24  ring_hdr_off       u64
  @ 32  ring_data_off      u64
  @ 40  entry_stride       u64
  @ 48  region_size        u64
  @ 56  icount_shift       u32
  @ 60  pause_requested    u8
  @ 61  shutdown_requested u8
  @ 62  _reserved[194]

NodeSlot      (size 128, align 128)
  @  0  current_icount     u64
  @  8  current_ns         u64
  @ 16  max_advance_icount u64
  @ 24  idle_wake_icount   u64
  @ 32  wake_signal        u32
  @ 36  status             u8
  @ 37  kind               u8
  @ 38  device_io_active   u8
  @ 39  _pad0              u8
  @ 40  publish_gen        u32
  @ 44  _pad1[4]
  @ 48  device_completion_deadline_icount u64
  @ 56  preemption_at_icount              u64
  @ 64  preemption_deadline_icount        u64
  @ 72  preemption_ceiling_icount         u64
  @ 80  preemption_published_sequence     u32
  @ 84  preemption_consumed_sequence      u32
  @ 88  preemption_arg0                   u32
  @ 92  preemption_arg1                   u32
  @ 96  preemption_kind                   u8
  @ 97  _reserved[31]

RingHeader    (size 128, align 128)
  @  0  read_idx           u64
  @  8  _pad_read[56]
  @ 64  write_idx          u64
  @ 72  _pad_write[56]

FrameEntry    (size 24 + MAX_FRAME_DATA, align 8)
  @  0  delivery_icount    u64
  @  8  src_node           u32
  @ 12  seq                u32
  @ 16  len                u16
  @ 18  _pad[6]
  @ 24  data[MAX_FRAME_DATA]

CoverageEntry (size 64, align 64)
  @  0  current_icount     u64
  @  8  guest_pc           u64
  @ 16  map_index          u64
  @ 24  vcpu_index         u32
  @ 28  block_len          u32
  @ 32  _reserved[32]

FingerprintSampleSlot (size 640, align 128)
  @  0  sample_gen         u32
  @  4  _reserved          u32
  @  8  words[68]          u64

WhiteboxMarkerEntry (size 4672, align 64)
  @  0  current_icount     u64
  @  8  vcpu_index         u32
  @ 12  kind               u16
  @ 14  payload_len        u16
  @ 16  payload[4608]
  @4624 _reserved[48]

Constants
  REGION_MAGIC            = "CRUCSHM1" (LE u64)
  ABI_VERSION             = 5
  MAX_NODES               = 32
  RESERVED_SLOTS          = 3
  MAX_FRAME_DATA          = 4608
  DEFAULT_QUEUE_CAPACITY  = 64
  COVERAGE_QUEUE_CAPACITY = 65536
  WHITEBOX_MARKER_QUEUE_CAPACITY = 1024
```

- **[SHM-14]** The offsets, sizes, and alignments in the §13.4 table are the
  normative ABI for `ABI_VERSION = 5`. The build MUST verify, on both the Rust and
  C sides, that the compiled layout matches this table; any deviation MUST fail
  the build. Header and slot offsets MUST be compile-time constants.
  Directed-ring and frame-entry offsets MUST be computed from the header
  geometry. Coverage-ring, fingerprint-slot, and marker-ring offsets MUST be
  derived deterministically from the preceding section and the ABI constants,
  with one of each per VM.
  *Gate:* `gate:abi-conformance`. *Spec:* §13.4.

- **[SHM-15]** Reserved bytes (`RegionHeader::_reserved`, `NodeSlot::_reserved`,
  the ring-header pad regions, `FrameEntry::_pad`, and
  `CoverageEntry::_reserved`) MUST be zero-initialized at region creation.
  Existing control/frame reserved space MUST be ignored on read at
  `ABI_VERSION = 5`; coverage and white-box marker entries MUST reject non-zero
  reserved bytes because each entry is untrusted plugin output validated before
  event-log admission.
  Reserved space exists so a future version can add fields without moving
  existing offsets (§13.6). *Gate:*
  `gate:abi-conformance`. *Spec:* §13.4, §13.6.

## 13.5 Decoupling logical topology from physical layout

The ABI has a compile-time maximum node count (`MAX_NODES`) and reserves a few
high slot indices for executor endpoints (network routing, block I/O, 9p I/O).
These are *physical-layout* facts. They MUST NOT leak into the engine's logical
topology model ([`06-spatial-graph.md`](06-spatial-graph.md)): the spatial graph
describes nodes and links abstractly, and the number of routing/disk/9p executor
endpoints is an implementation detail of how frames are physically routed, not a
concept a scenario author reasons about.

- **[SHM-16]** `MAX_NODES` is an ABI constant of this layer ONLY. The engine's
  logical topology model ([`06-spatial-graph.md`](06-spatial-graph.md)) MUST NOT
  reference `MAX_NODES`, MUST NOT cap a scenario's node count at it as a *model*
  rule, and MUST NOT expose it in any user-facing API. The mapping from logical
  nodes to physical slot indices is performed at region-allocation time and is
  invisible above this layer. (If a scenario's node count plus reserved slots
  exceeds `MAX_NODES`, that is an allocation-time error reported by this layer, not
  a topology-model constraint.) *Gate:* `gate:abi-conformance`. *Spec:* §13.5,
  forward-ref [`06-spatial-graph.md`](06-spatial-graph.md).

- **[SHM-17]** The reserved executor slots (`SLOT_NET_ROUTER`, `SLOT_BLK_IO`,
  `SLOT_9P_IO`) are ABI details: they are physical frame-routing/I/O endpoints in
  the slot array, not logical nodes in the spatial graph. A VM emits an outbound
  frame by enqueueing into the ring `(vm_slot -> SLOT_NET_ROUTER)` and receives
  inbound frames from `(SLOT_NET_ROUTER -> vm_slot)`; the router executor performs
  topology-driven delivery and re-stamps `delivery_icount` per the link model
  (ns→icount via the [TIME-4] ceil map).
  Block and 9p I/O use their own reserved slots so their rings never contend with
  the network router's. The logical model MUST NOT name these slots. *Gate:*
  `gate:abi-conformance`. *Spec:* §13.5, forward-ref [`15-io-subnodes.md`](15-io-subnodes.md).

- **[SHM-18]** Separating I/O endpoints onto distinct reserved slots (rather than
  multiplexing one) is REQUIRED so that the SPSC single-producer/single-consumer
  discipline holds per directed pair: each ring has exactly one writer and one
  reader. Multiplexing distinct I/O classes onto a shared ring would violate the
  SPSC invariant. *Gate:* `gate:abi-conformance`. *Spec:* §13.5, §13.6.

## 13.6 SPSC queue mechanics

Each ring is a classic Lamport single-producer/single-consumer queue. The
producer owns `write_idx` (the tail); the consumer owns `read_idx` (the head).
Both are monotonically increasing 64-bit counters that never wrap in practice
(64 bits at any realistic frame rate); the physical slot for counter value `i` is
`entries[i % capacity]`, and because `capacity` is a power of two the modulo is a
mask. The queue holds `write_idx - read_idx` entries; it is empty when
`read_idx == write_idx` and full when `write_idx - read_idx == capacity`.

The operations the ABI defines:

- **enqueue** (producer): load `write_idx` relaxed (the producer owns it), load
  `read_idx` acquire; if `write_idx - read_idx >= capacity` return *full*;
  otherwise write the `FrameEntry` fields into `entries[write_idx % capacity]`,
  then store `write_idx + 1` with **release** ordering to publish the entry.
- **peek-delivery-time** (consumer): load `read_idx` relaxed, load `write_idx`
  acquire; if empty return *none*; otherwise read (without consuming)
  `entries[read_idx % capacity].delivery_icount`. This lets the consumer (or the
  scheduler on its behalf) ask "when does my next frame become visible?" without
  dequeuing.
- **dequeue** (consumer): load `read_idx` relaxed (the consumer owns it), load
  `write_idx` acquire; if empty return *none*; otherwise copy out
  `entries[read_idx % capacity]`, then store `read_idx + 1` with **release**
  ordering to free the slot.
- **snapshot / restore** (checkpointing): with both producer and consumer quiesced
  (a coordinated pause, §13.7), copy every live entry `read_idx..write_idx` out
  (snapshot), or reset both indices and re-enqueue a saved sequence (restore).
  These are only valid under quiescence — they are NOT concurrency-safe and MUST
  NOT run while either endpoint is live.

```rust
/// Enqueue one frame; `Err(QueueFull)` if the ring is full.
/// Producer-only. The release store on `write_idx` publishes the entry's
/// fields written before it.
pub fn enqueue(&self, entries: &mut [FrameEntry], e: &FrameEntry) -> Result<(), QueueFull> {
    let cap = entries.len() as u64;
    let tail = self.write_idx.load(Ordering::Relaxed);
    let head = self.read_idx.load(Ordering::Acquire);
    if tail.wrapping_sub(head) >= cap {
        return Err(QueueFull);
    }
    let slot = &mut entries[(tail % cap) as usize];
    slot.delivery_icount = e.delivery_icount;
    slot.src_node = e.src_node;
    slot.seq = e.seq;
    slot.len = e.len;
    slot.data[..e.len as usize].copy_from_slice(&e.data[..e.len as usize]);
    self.write_idx.store(tail + 1, Ordering::Release); // publish
    Ok(())
}
```

- **[SHM-19]** Each ring MUST be a Lamport SPSC queue with exactly one producer
  (the `src` node) and one consumer (the `dst` node) per directed pair. The
  producer owns `write_idx`; the consumer owns `read_idx`. Neither endpoint may
  write the other's index. Capacity MUST be a power of two; the live count is
  `write_idx - read_idx`. *Gate:* `gate:abi-conformance`, `gate:layer1-injection`.
  *Spec:* §13.6.

- **[SHM-20]** The atomic ordering rules MUST be: the producer publishes an entry
  with a **release** store of `write_idx` after writing the entry fields, and the
  consumer reads `write_idx` with **acquire** before reading the entry (so the
  entry's bytes are visible). Symmetrically, the consumer frees a slot with a
  **release** store of `read_idx`, and the producer reads `read_idx` with
  **acquire** before overwriting. An endpoint reading *its own* index MAY use
  **relaxed** ordering. No `SeqCst` is required. *Gate:* `gate:abi-conformance`.
  *Spec:* §13.6.

- **[SHM-21]** The ABI MUST define `enqueue`, `dequeue`, `peek_delivery_icount`,
  `snapshot`, and `restore` with the semantics in §13.6. `peek_delivery_icount`
  MUST return the next entry's `delivery_icount` without consuming it, so the
  scheduler can compute a node's next inbound-frame horizon. `snapshot`/`restore`
  MUST be used only under quiescence and MUST reproduce a ring's live entries
  exactly (for content-addressed checkpointing). *Gate:* `gate:abi-conformance`,
  `gate:replay-oracle`. *Spec:* §13.6, forward-ref [`07-temporal-graph.md`](07-temporal-graph.md).

- **[SHM-22]** `snapshot` of a ring MUST produce a byte-deterministic
  serialization of its live entries (in `read_idx..write_idx` order), so that two
  equal ring states content-address identically ([INV-6]); `restore` MUST be its
  exact inverse, re-establishing the same live sequence with `read_idx`/`write_idx`
  normalized. The padding bytes inside each entry MUST be excluded from (or
  canonicalized in) the serialization so they cannot perturb the content hash.
  *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §13.6.

- **[SHM-23]** The SPSC implementation MUST be covered by property-based and
  `loom`-style concurrency tests that exhaust the producer/consumer interleavings
  permitted by the ordering rules, verifying no entry is lost, duplicated, torn,
  or read before its release-store publish. *Gate:* `gate:abi-conformance`.
  *Spec:* §13.6, forward-ref [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

### The per-node advance ceiling handshake

The advance ceiling is the mechanism by which the scheduler ([`08-scheduling.md`](08-scheduling.md))
bounds a VM's advancement to its horizon. The handshake, per quantum, is:

1. The VM publishes `current_icount` (and the derived `current_ns`), bumping
   `publish_gen`, as it crosses translation-block boundaries.
2. The scheduler computes the node's horizon — `min(next exact local event,
   conservative network lookahead)` — converts it to an icount via the fixed
   shift, and **stores it into `max_advance_icount`** with release ordering.
3. The VM runs forward, checking `current_icount < max_advance_icount` at each TB
   boundary. When it reaches the ceiling, it publishes `idle_wake_icount`
   (the ceiling, or an earlier timer), sets `status = STATUS_IDLE`, reads
   `wake_signal`, and **FUTEX_WAITs** on it (§13.7).
4. When the scheduler later raises the ceiling (or a frame is delivered), it
   stores the new value and increments `wake_signal` with a `FUTEX_WAKE`. The VM
   wakes, re-reads `max_advance_icount`, sets `status = STATUS_RUNNING`, and
   resumes.

- **[SHM-24]** The advance ceiling MUST be set *only* by the scheduler and read
  *only* by the node it governs; a node MUST NOT raise its own ceiling. The
  scheduler MUST store the ceiling with release ordering after computing the
  node's horizon, and the node MUST load it with acquire ordering before deciding
  whether to advance. The published `current_icount` (the node's side of the
  handshake) MUST be a release store the scheduler reads with acquire. *Gate:*
  `gate:layer1-injection`. *Spec:* §13.6, forward-ref [`08-scheduling.md`](08-scheduling.md).

- **[SHM-25]** The ceiling handshake MUST guarantee a node never advances past an
  icount at which an input could become visible to it without scheduler
  authorization ([DET-12]). Because the scheduler sets the ceiling no further than
  the conservative inbound-link-latency lookahead, any frame's `delivery_icount`
  is in the consumer's future at the moment the frame is computed; a node found to
  have already passed a frame's `delivery_icount` is a contract violation and MUST
  fail loudly, never deliver late. *Gate:* `gate:layer1-injection`,
  `gate:divergence-bisect`. *Spec:* §13.6, §4.4.

## 13.7 Cross-process futex wake

A node that reaches its ceiling with nothing else to do parks. It must be woken
when, and only when, something actionable happens for it: the scheduler raises its
ceiling, or a frame is delivered into one of its inbound rings. The wake mechanism
is a **cross-process futex** on the slot's `wake_signal` word.

The futex is *non-private* (`FUTEX_WAKE`/`FUTEX_WAIT` without `FUTEX_PRIVATE_FLAG`)
because the waiter (the in-VM plugin / node process) and the waker (the host
scheduler process) live in *different processes* sharing the word via the mmap. A
private futex would only work within one address space and is forbidden here.

The protocol is the standard race-free futex idiom: the waiter publishes its
precondition (sets `idle_wake_icount`, sets `status = STATUS_IDLE`), reads the
current `wake_signal` value `v`, re-checks whether the wake condition is already
visible, then `FUTEX_WAIT(&wake_signal, v)` only if it still has nothing to do.
The waker increments `wake_signal` (so a wait that started after the increment
returns `EAGAIN` immediately) and issues `FUTEX_WAKE`. There is no lost-wake
window: if the waker bumps the counter before the waiter's read, the re-check
observes the actionable state and skips the wait; if it bumps the counter between
the read of `v` and `FUTEX_WAIT`, the wait returns at once because the observed
word no longer equals `v`.

```text
  waiter (node)                      waker (scheduler)
  ------------------------------     -----------------------------------
  publish idle_wake_icount
  status := STATUS_IDLE  (release)
  v := load(wake_signal)             store max_advance_icount (release)
  if runnable: skip wait
  FUTEX_WAIT(&wake_signal, v) -----> fetch_add(wake_signal, 1) (release)
                            <-------- FUTEX_WAKE(&wake_signal, 1)
  status := STATUS_RUNNING
  reload max_advance_icount (acq)
```

- **[SHM-26]** A node parked at its ceiling MUST park via `FUTEX_WAIT` on the
  slot's `wake_signal` word, using the race-free publish-precondition /
  read-counter / re-check / wait idiom in §13.7 so there is no lost-wake window.
  The futex MUST be the **non-private** (cross-process) variant, because the
  waiter and waker are different processes sharing the word through the mapping.
  The `wake_signal` futex is the **source of truth** for the wake; an auxiliary
  primitive (e.g. the wake eventfd of [`14-protocol.md`](14-protocol.md) §3.4) MAY
  be used to integrate the wait with a host event loop but MUST NOT replace it —
  a futex-only waiter and an eventfd-driven waiter rendezvous on the same
  `wake_signal`. *Gate:* `gate:layer1-injection`. *Spec:* §13.7.

- **[SHM-27]** Every event that can make a parked node runnable — the scheduler
  raising `max_advance_icount` to or past `idle_wake_icount`, or a frame being
  enqueued into one of the node's inbound rings — MUST increment the target node's
  `wake_signal` with a release add and issue `FUTEX_WAKE`. A wake MUST be issued
  even if no waiter is currently parked (the increment makes a concurrent
  about-to-wait return immediately); the wake is cheap when no one waits. *Gate:*
  `gate:layer1-injection`. *Spec:* §13.7.

- **[SHM-28]** The futex mechanism is **Linux-specific**, and Crucible's host
  target is Linux; the ABI MUST NOT depend on a portable wake primitive. On a
  non-Linux build (developer tooling only, never a simulation host) the
  wake/wait functions MUST compile to no-ops and MUST NOT be exercised on any
  blocking path — only the pure atomic-layout and SPSC logic is portable for
  unit testing off-Linux. *Gate:* `gate:abi-conformance`. *Spec:* §13.7.

- **[SHM-29]** The global `pause_requested` and `shutdown_requested` header flags
  MUST be observed by every node at a well-defined point (each quantum boundary):
  on `pause_requested`, a node MUST quiesce at its current TB boundary and park so
  the scheduler can take a coordinated snapshot; on `shutdown_requested`, a parked
  node MUST wake, set `status = STATUS_DONE`, and exit. Setting either flag MUST be
  accompanied by a wake of every parked node. *Gate:* `gate:layer1-injection`.
  *Spec:* §13.7, forward-ref [`20-session-control-plane.md`](20-session-control-plane.md).

## 13.8 Versioning and conformance

The region carries an ABI version in its header. The handshake
([`14-protocol.md`](14-protocol.md)) validates it before any node trusts a byte of
the region. ABI v2 is intentionally incompatible with v1 because v2 adds the
coverage tail: a v2 host rejects a v1 plugin/region, and a v2 plugin rejects a
v1 host acknowledgement/region. There is no legacy-tail inference or partial
mapping. Golden vectors pin the layout so an accidental change is caught.

- **[SHM-30]** The `RegionHeader` MUST carry `abi_version`, and the
  handshake ([`14-protocol.md`](14-protocol.md)) MUST reject a region whose
  `magic != REGION_MAGIC` or whose `abi_version != ABI_VERSION` compiled into the
  mapping process, before any slot or ring is accessed. A version mismatch MUST be
  a hard, loud failure, never a best-effort partial map; this includes both
  v2-to-v1 mismatch directions. *Gate:*
  `gate:abi-conformance`, `gate:qemu-inert`. *Spec:* §13.8, forward-ref
  [`14-protocol.md`](14-protocol.md).

- **[SHM-31]** The ABI MUST be covered by a **golden-vector conformance test**: a
  checked-in fixture encoding the byte layout (a populated region with known field
  values) that both the Rust and the C views decode to identical logical state,
  and that the current build re-encodes byte-for-byte. The fixture is regenerated
  only by an intentional, reviewed ABI change. `gate:abi-conformance` runs this
  test plus the generated-header diff ([SHM-4]) and the bilateral static
  assertions ([SHM-5]). *Gate:* `gate:abi-conformance`. *Spec:* §13.8, §13.2.

- **[SHM-32]** The ABI change policy MUST be: any change to a field's offset,
  size, type, or meaning, or to an ordering rule, REQUIRES bumping `ABI_VERSION`,
  regenerating the C header and golden vectors, and a recorded entry in the
  decision register ([`31-decision-register.md`](31-decision-register.md)).
  Additive changes that consume reserved space without moving existing offsets are
  a version bump but compatible-by-construction with the assertion machinery;
  changes that move offsets are breaking and MUST update every consumer in the
  same change. *Gate:* `gate:abi-conformance`. *Spec:* §13.8, §13.6.

## 13.9 Producer→consumer visibility is icount-not-wallclock

This is the crux of injection determinism and the reason the whole region is
shaped the way it is. A frame's deliverability is decided by **virtual time**, not
by when the producer's store landed in shared memory.

- **[SHM-33]** A frame in a ring becomes architecturally visible to its consumer
  **iff `frame.delivery_icount <= consumer.current_icount`** (equivalently, the
  delivery virtual time, converted via the fixed shift, has been reached by the
  consumer). The wall-clock moment at which the producer's release-store published
  the entry, and the wall-clock moment at which the consumer happens to poll the
  ring, are both irrelevant to *when the guest sees the frame*. This is Contract B
  ([DET-13], [DET-34]) made physical: delivery is a pure function of two icounts.
  *Gate:* `gate:layer1-injection`, `gate:content-address`. *Spec:* §13.9, §4.4,
  forward-ref [`08-scheduling.md`](08-scheduling.md),
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

- **[SHM-34]** When two or more frames in a consumer's inbound rings are
  simultaneously deliverable (all with `delivery_icount <= current_icount`), their
  visibility order MUST be the deterministic total order
  `(delivery_icount, src_node, seq)` of [INV-3], resolved identically across runs
  regardless of which producer's store landed first. A consumer MUST NOT deliver
  frames in ring-arrival order. This key is the **per-consumer projection** of the
  global canonical order defined in [`08-scheduling.md`](08-scheduling.md) §8.6
  (`(delivery_virtual_time, consumer_node_id, producer_node_id, sequence)`): the
  consumer dimension is implicit because a consumer merges only its own inbound
  rings, `src_node` is the `producer_node_id`, and `delivery_icount` is the
  `delivery_virtual_time` under the fixed shift. *Gate:* `gate:layer1-injection`.
  *Spec:* §13.9, §4.4.

- **[SHM-35]** Because deliverability is `delivery_icount <= current_icount` and
  the scheduler holds every node's ceiling at or below its conservative lookahead
  ([SHM-25]), a frame's `delivery_icount` MUST be strictly in the consumer's
  future at the instant the frame is enqueued; enqueueing a frame whose
  `delivery_icount` the consumer has already passed is a determinism defect and
  MUST fail loudly via the divergence path, never be delivered late. This is the
  property that makes a two-VM run bit-identical across adversarial host timing
  (the `gate:layer1-injection` two-VM run-twice-and-diff). *Gate:*
  `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §13.9, §4.4.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the shared-memory ABI, tracked here by [PLAN-3].

- [x] **T-SHM-1** Define the `#[repr(C)]` `RegionHeader`, `NodeSlot`,
  `RingHeader`, and `FrameEntry` in `crucible-shmem` with the field set, order,
  and padding of §13.3, and the constants of §13.4; make the region the only
  channel for virtual-time advancement and cross-node frame delivery (the IPC
  protocol carries no per-quantum timing or per-frame delivery decisions). —
  satisfies [SHM-1], [SHM-2], [SHM-7], [SHM-9], [SHM-12], [SHM-13]; spec §13.1,
  §13.3, §13.4.
- [x] **T-SHM-2** Add Rust `const _: () = assert!(size_of/align_of/offset_of...)`
  for every shared struct and field per §13.4. — satisfies [SHM-5], [SHM-14];
  spec §13.4.
- [x] **T-SHM-3** Generate `crucible_shmem_abi.h` mechanically from the Rust
  definitions, with `_Static_assert` on every size and offset, and a build step
  that fails if the committed header differs from the regenerated one. —
  satisfies [SHM-3], [SHM-4], [SHM-5]; spec §13.2.
- [x] **T-SHM-4** Pin the layout to `x86_64-unknown-linux-gnu`, little-endian,
  fixed offsets; reject other targets in the layout module. — satisfies [SHM-6],
  [SHM-15]; spec §13.2, §13.4.
- [x] **T-SHM-5** Implement region creation: header init (magic, version, counts,
  computed sub-region offsets, icount shift), slot init (ceiling 0, status, kind),
  and ring/entry storage allocation. — satisfies [SHM-7], [SHM-8], [SHM-11];
  spec §13.3.1, §13.3.2.
- [x] **T-SHM-6** Implement the Lamport SPSC `enqueue`/`dequeue`/
  `peek_delivery_icount` with the §13.6 acquire/release ordering. — satisfies
  [SHM-19], [SHM-20], [SHM-21]; spec §13.6.
- [x] **T-SHM-7** Implement `snapshot`/`restore` under quiescence with a
  byte-deterministic, padding-canonicalized serialization for content addressing.
  — satisfies [SHM-21], [SHM-22]; spec §13.6.
- [x] **T-SHM-8** Implement the advance-ceiling handshake helpers (publish
  current icount + gen; scheduler-only ceiling store; node-side acquire load +
  advance check), with the `publish_gen` seqlock writer/reader discipline for
  torn-free multi-field slot snapshots. — satisfies [SHM-10], [SHM-24], [SHM-25],
  [SHM-36]; spec §13.6, §13.3.4.
- [x] **T-SHM-9** Implement the cross-process (non-private) futex
  `wait`/`wake` on `wake_signal` with the race-free idiom, plus the
  raise-ceiling and frame-delivered wake triggers. — satisfies [SHM-26],
  [SHM-27]; spec §13.7.
- [x] **T-SHM-10** Implement the off-Linux no-op shim for the futex path so the
  pure atomic/SPSC logic unit-tests off-Linux. — satisfies [SHM-28]; spec §13.7.
- [x] **T-SHM-11** Implement global `pause_requested`/`shutdown_requested`
  observation and the wake-all-on-flag behavior. — satisfies [SHM-29]; spec
  §13.7.
- [x] **T-SHM-12** Implement the logical-node → physical-slot allocator, with the
  reserved executor slots, and assert no `MAX_NODES` reference escapes this layer.
  — satisfies [SHM-16], [SHM-17], [SHM-18]; spec §13.5.
- [x] **T-SHM-13** Implement deliverability (`delivery_icount <= current_icount`)
  and the `(delivery_icount, src_node, seq)` total order on the consumer side. —
  satisfies [SHM-33], [SHM-34], [SHM-35]; spec §13.9.
- [x] **T-SHM-14** Wire `gate:abi-conformance`: generated-header diff +
  bilateral static asserts + golden-vector round-trip. — satisfies [SHM-30],
  [SHM-31], [SHM-32]; spec §13.8.
- [x] **T-SHM-15** Add property-based and `loom`-style SPSC concurrency tests
  (no loss/dup/tear/early-read) feeding `gate:abi-conformance`. — satisfies
  [SHM-23]; spec §13.6, forward-ref §24.
- [x] **T-SHM-16** Represent a multi-vCPU node with a single `NodeSlot` carrying
  the node's aggregate clock/ceiling/idle-wake (node `idle_wake_icount` = min over
  its vCPUs' deadlines; `device_io_active` and the RR sub-division node-scoped);
  keep per-vCPU icount/state out of the ABI so `ABI_VERSION` is unchanged for
  N-vCPU nodes; route per-vCPU fingerprint state over QMP/plugin introspection,
  not shmem. — satisfies [SHM-37]; spec §13.3.2.
- [x] **T-SHM-17** Add one coverage SPSC ring per logical VM, fix its
  capacity to the coverage-map cardinality, publish only first-hit entries, and
  make the host validate and append each completion-boundary batch to the
  unified event log before the next step or teardown. Treat overflow,
  regression, future icounts, and duplicate novelty as fatal invariant errors.
  — satisfies [SHM-38], [SHM-39], [SHM-40]; spec §13.3.5, §13.4, §13.6.
- [x] **T-SHM-18** Add one ABI-v4 white-box marker SPSC ring per logical VM,
  publish decoded guest markers without callback allocation or I/O, and make
  the host validate, canonically decode, and append each completion-boundary
  batch to the unified event log. Treat overflow, malformed entries,
  unsupported kinds, regression, and future icounts as fatal invariant errors.
  — satisfies [SHM-41], [SHM-42], [SHM-43]; spec §13.3.7, §13.4, §13.6.
  Completed by `checks.crucible.phase2.shmemAbiConformance`,
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`, and
  `checks.crucible.phase4.guestHostMarkerObservability`: the ABI-v4 layout and
  C/Rust vectors freeze the per-VM marker ring, the live plugin publishes the
  exact trap icount and payload without allocation or I/O, and the mapped host
  consumer rejects full, malformed, unsupported, regressing, or future entries
  before appending each boundary batch to the unified observational event log.
- [x] **T-SHM-19** Add the ABI-v5 single-outstanding scheduler-to-plugin
  preemption mailbox to each VM `NodeSlot`, including exact switch/interrupt
  payloads, inclusive authorization-window validation, release/acquire
  publication, post-QEMU acknowledgement, generated C-header/static-offset
  coverage, and golden-vector round-trip tests. Reject overwrite, wrong
  acknowledgement, unknown kinds, and out-of-window commands. — satisfies
  [SHM-44], [SHM-45], [SHM-46]; spec §13.3.8, §13.4, §13.6.
  Completed by `checks.crucible.phase2.shmemAbiConformance`: the ABI-v5 C/Rust
  layouts and golden vector freeze the mailbox, while the Rust mailbox gate
  covers publication, exact round-trip, acknowledgement, and negative cases.
