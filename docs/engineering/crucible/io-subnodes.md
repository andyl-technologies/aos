# I/O sub-nodes

Crucible models block storage, a 9p filesystem, and directed network links as
deterministic simulation sub-nodes. The I/O semantics never depend on host
timing. A device computes the exact logical tick at which its response becomes
visible to the requester and schedules the response as an exact event. It
does not pause virtual time while host I/O runs.

The device models live in `crates/crucible/crucible-device`. The engine binds
them to the scheduler in `crates/crucible/crucible-engine/src/device_subnode.rs`.
Host servicers run them against live QEMU rings in
`crates/crucible/crucible-qemu-host/src/supervision/`. The QEMU plugin side of
the same rings lives in `crates/crucible/crucible-qemu-plugin/src/block_io.rs`
and `ninep_io.rs`. For the ring and slot layout see [shmem-abi.md](shmem-abi.md).
For the scheduler horizon see [scheduling.md](scheduling.md). Signal-driven
storage, 9p, and network faults have their own pages in this folder. This page
covers only the fault-free device model and the transforms it exposes.

## Why I/O is a scheduled event

One alternative is to freeze the guest clock while the host performs I/O and
then resume it. That design has two problems. Modeled latency is always zero,
and once two operations overlap, their completion order depends on host
timing. Crucible instead treats each device as a node with its own logical
clock and a completion model that is a pure function of request state. This
gives three properties:

- I/O latency is modeled and is part of the deterministic timeline.
- A completion is an exact local event. The scheduler can fast-forward an idle
  requester to the event with no conservative slack.
- Disk, 9p, and network deliveries go through the same total order,
  `(delivery_icount, src_node, seq)`. That order is the shared-memory
  `FrameDeliveryKey` from `crucible-qemu-shmem`.

```text
tick t      VM emits a block request -> SLOT_BLK_IO request ring
(host)      device COMPUTEs status+payload now (any wall-clock instant)
            delivery_icount = t + latency_ns * TICKS_PER_NS
-- wait --  guest halts or polls; the scheduler sees the completion as the
            requester's next exact local event and may jump straight to it
tick t'     consumer frontier reaches delivery_icount; the response becomes
            visible at exactly that tick
```

`TICKS_PER_NS` is `1_000` (`crates/crucible/crucible-qemu-shmem/src/lib.rs`).
`VirtualClock::add_ns` in `crucible-device/src/clock.rs` performs the
conversion with checked arithmetic. Overflow returns
`DeviceError::CompletionOverflow` and the value never wraps. Because the
interval is added to the exact request tick, the fractional phase of the
request is preserved.

## The uniform lifecycle: `IoSubNode` and `IoCore`

`crucible-device/src/subnode.rs` defines the shared abstraction:

- `IoSubNode` is the device half. It provides `compute(&Request)` (the COMPUTE
  step), its `LatencyModel`, and checkpoint/restore of its own COMPUTE state so
  that a failed transaction rolls back.
- `IoCore` is the reusable engine. It owns the `VirtualClock`, a request inbox
  and response outbox (`BoundedQueue`s for in-process use), the delivery-ordered
  `InflightQueue`, and the shared-memory bridge to real `RingHeader` /
  `FrameEntry` rings.

```text
enqueue_request(t)              ARRIVE   request lands in the inbox
process_inbox(device)           COMPUTE  (status, payload) = device.compute(req)
                                         delivery = t + latency_ns * TICKS_PER_NS
                                PENDING  inflight.insert(PendingResponse{key, ..})
next_exact_local_event()                 = inflight head delivery_icount
advance_to(limit)               DELIVER  clock -> limit;
                                         outbox <- inflight.drain_due(limit)
```

The design depends on the split between COMPUTE and visibility. A device may
touch the overlay or the served tree at any wall-clock instant during COMPUTE.
Architectural visibility is decided only by `delivery_icount`. Host compute
latency therefore never reaches the guest instruction stream.

Lifecycle invariants:

- `PendingResponse.key` is a `FrameDeliveryKey { delivery_icount, src_node,
  sequence }`. The `InflightQueue` orders by that key, so its head is the
  sub-node's `next_exact_local_event`. The device and the shared-memory
  transport therefore break ties identically.
- `IoCore::advance_to(limit)` drains exactly the responses whose
  `delivery_icount <= limit`, in key order, and moves the clock to `limit`.
  A `limit` below the current clock returns `DeviceError::ClockRegression`.
- Backpressure is a deterministic function of capacity and live depth.
  `BoundedQueue` mirrors the SPSC ring: power-of-two capacity, `QueueFull` when
  full, and a rejected push hands the item back instead of dropping it. When the
  outbox fills partway through a drain, the undelivered responses go back in
  flight at their original delivery icounts. Backpressure never drops, reorders,
  or retimes a response.

### Shared-memory form

`IoCore::process_shmem_inbox` drains the VM-to-device ring in FIFO order,
computes each request into the in-flight queue, and wakes the producer slot
once slots are freed. `IoCore::advance_to_shmem` (and
`advance_to_shmem_with_commit_status`) publishes due responses as `FrameEntry`
values whose `FrameEntry.delivery_icount` is the computed completion icount. It
then wakes the consumer with `NodeSlot::wake_for_frame_delivery`. If the response
ring is full, that response and every later due response are requeued at their
original icounts. The commit-status variant reports how many frames were
published before a failure, so a transactional caller can tell a failure before
publication from one after it.

The plugin poll side checks visibility directly. In
`PluginBlockIo::poll_response`, a head frame with
`head.delivery_icount > current_icount` returns `BlockPoll::NotReady`. It also
rejects frames whose `src_node` is not the reserved block slot.

## Block device sub-node

`crucible-device/src/block/` composes `IoCore` with a block-specific COMPUTE.

### Base image and copy-on-write overlay

`block/overlay.rs` contains the CoW overlay pattern:

- `BaseImage` is a read-only, content-addressed base image. It holds
  `bytes: Vec<u8>` and the BLAKE3 `hash: [u8; 32]` of those bytes. It exposes
  `bytes()` for reading only and has no mutating accessor.
- `CowOverlay` is an in-memory 4 KiB CoW page overlay (`PAGE_SIZE = 4096`):
  `pages: BTreeMap<u64, [u8; PAGE_SIZE]>` keyed by page base, plus
  `dirty: BTreeSet<u64>`. Ordered collections give every captured delta and
  every materialize pass one iteration order. No default-hasher order appears.

```text
page_base(off) = off - off % 4096
read(off, len):  for each page in [off, off+len):
                   overlay page if present, else base page (zero-filled past EOF)
write(off, data):for each page in [off, off+len):
                   page = pages.entry(pb).or_insert_with(|| base.read_page(pb))
                   patch page; dirty.insert(pb)
dirty_delta():   copy of each page in `dirty`, ascending page base
materialize():   base.bytes().to_vec(), then overwrite every overlay page
```

A read or write whose range overflows or extends past the base length fails
with `DeviceError::OutOfRange`. The device never truncates or extends.
`flush` succeeds without doing anything, because the overlay is the durable
store inside the simulation. `get_length` returns the base size.

Dirty tracking records only the dirty pages since the last checkpoint
boundary. `BlockDevice::snapshot` captures `overlay_delta:
self.overlay.dirty_delta()`. `BlockDevice::checkpoint_boundary` then calls
`self.overlay.clear_dirty();` so the next snapshot carries a disjoint delta.
`OverlayDelta::page_hashes` provides per-page BLAKE3 keys for deduplication.

### Block wire ABI (version 4)

`block/codec.rs` (`BlockRequest`, `BlockResponse`, `BLOCK_ABI_VERSION = 4`)
defines the format. The plugin side mirrors it in
`crucible-qemu-plugin/src/block_io.rs` (`BLOCK_WIRE_VERSION`,
`BLOCK_REQUEST_HEADER_LEN = 28`, `BLOCK_RESPONSE_HEADER_LEN = 20`), and so does
the QEMU `crucible-shmem` block driver. Fields use fixed little-endian field
order, and reserved bytes are zero on emit and rejected on decode.

```text
BlockRequest (VM slot -> SLOT_BLK_IO), header = 28 bytes
  off 0   u8   op          0=read 1=write 2=flush 3=get_length 4=discard
  off 1   u8   version     = 4
  off 2   u16  _reserved   zero on emit, rejected when nonzero
  off 4   u64  epoch       transport generation
  off 12  u32  request_id  correlation id within the epoch
  off 16  u64  offset      byte offset (read/write/discard)
  off 24  u32  count       byte count  (read/write/discard)
  off 28  [count bytes]    payload, write only

BlockResponse (SLOT_BLK_IO -> VM slot), header = 20 bytes
  off 0   u8   status      see table below
  off 1   u8   version     = 4
  off 2   u16  _reserved   zero on emit, rejected when nonzero
  off 4   u64  epoch       echoes the request epoch
  off 12  u32  request_id  echoes the request id
  off 16  u32  count       response data length
  off 20  [count bytes]    success data, or exactly one typed-error byte
```

| Status byte | `BlockStatus`            | Meaning                                  |
|-------------|--------------------------|------------------------------------------|
| 0           | `Ok`                     | Terminal success                         |
| 1           | `Error`                  | Terminal failure; one `BlockErrorCode`   |
| 2           | `TransportReset`         | Controller reset event                   |
| 3           | `DuplicateIgnored`       | Duplicate request identity, ignored      |
| 4           | `DuplicateProtocolError` | Duplicate identity is a protocol error   |
| 5           | `RetryPreserveId`        | Reset disposition: retry with same id    |
| 6           | `RetryNewId`             | Reset disposition: retry with new id     |
| 7           | `DropCompletion`         | Reset disposition: drop the completion   |

`BlockErrorCode` wire bytes run from 1 to 11: `Offline`, `ReadOnly`,
`InvalidRange`, `Busy`, `Timeout`, `MediumError`, `IntegrityError`, `IoError`,
`NoSpace`, `NotFound`, `Stale`. The epoch, reset, discard, and typed-error
fields exist for the signal-driven storage fault model. The pages on that model
describe their semantics.

The decoder rejects malformed input without reading past its bounds. Each case
produces a typed error (`BlockCodecError` in the device crate,
`BlockWireError` in the plugin): short headers, an unsupported version,
unknown operation or status, a nonzero reserved field, a count larger than the
payload, and a count/payload mismatch or trailing bytes. The plugin variants
include `BlockWireError::NonZeroReserved`, `BlockWireError::UnknownOperation`,
`RequestCountExceedsPayload`, `RequestCountPayloadMismatch`, and
`ResponseCountPayloadMismatch`. The decoder accepts only the current version.
It has no alternate decode path and never downgrades silently. Encoded
messages ride in `FrameEntry.data`. `MAX_FRAME_DATA` is 4608 bytes, so the
largest read the device serves is `MAX_READ_BYTES = MAX_FRAME_DATA -
RESPONSE_HEADER_LEN`. The device answers a larger read with an error status
rather than building a frame it cannot transport.

Block traffic uses only the `SLOT_BLK_IO` shared-memory rings and has no
per-request side channel. `PluginBlockIo` checks that its outbound ring is
`(vm_slot -> SLOT_BLK_IO)` and its inbound ring is `(SLOT_BLK_IO -> vm_slot)`
before it accepts them. It stamps each submitted frame with
`FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)`.

### Completion model

`BlockLatency` fields are `read_base_ns`, `write_base_ns`, `flush_ns`,
`get_length_ns`, and `per_byte_ns`. The model is:

```text
read     read_base_ns  + per_byte_ns * count
write    write_base_ns + per_byte_ns * count
discard  write_base_ns + per_byte_ns * count
flush    flush_ns
get_len  get_length_ns
```

The model uses saturating integer arithmetic and no floating point. A payload
that fails to decode uses the read floor with a zero count, so its error
response still completes at a deterministic tick. The latency parameters come
from the `World`, and a snapshot restores them, so completions after a restore
match an uninterrupted run.

### Snapshot, restore, materialize

A `BlockSnapshot` holds the device half of a checkpoint:

| Field            | Content                                                    |
|------------------|------------------------------------------------------------|
| `core`           | `IoCoreSnapshot`: clock, queues, in-flight responses       |
| `base_hash`      | BLAKE3 of the omitted base image                           |
| `device_length`  | Base size in bytes                                         |
| `overlay_delta`  | Dirty pages since the last checkpoint boundary             |
| `full_pages`     | Complete overlay, for parent-free restore                  |
| `dirty`          | Dirty set at snapshot time                                 |
| `storage_faults` | `BlockFaultState` (signal-driven storage fault state)      |
| `latency`        | `BlockLatency` parameters                                  |

A snapshot never carries base image bytes. `BlockDevice::restore(snapshot,
base, parent)` rejects a base whose hash differs (`DeviceError::BaseMismatch`)
or whose length differs. With a parent overlay it runs
`overlay.apply_delta(&snapshot.overlay_delta)` and then
`overlay.set_dirty(snapshot.dirty.clone())`. The dirty set is restored exactly
as captured, so the next checkpoint emits the delta an uninterrupted run would.
Without a parent it rebuilds the overlay from `full_pages`. `restore_snapshot`
replaces a live device in place over its admitted base.
`to_canonical_bytes` encodes snapshots canonically, bounded by
`MAX_BLOCK_SNAPSHOT_BYTES` (1 GiB).

`BlockDevice::materialize` returns `self.overlay.materialize(&self.base)`:
`let mut image = base.bytes().to_vec();` with every overlay page copied on top.
The result is a standalone raw image. The base image is never mutated.

## 9p filesystem sub-node

`crucible-device/src/ninep/` implements a read-only 9P2000.L server over an
immutable content tree. Every reply is a pure function of the tree and the
request.

### Determinism by construction

Each source of host nondeterminism is removed where it would enter:

1. **QIDs are path-hashed, not inode numbers.** `qid_path(path)` feeds BLAKE3
   with the component count, then each component as a `u64` length prefix
   followed by its bytes. It returns the low 8 digest bytes as a little-endian
   `u64`. The encoding is injective. The 64-bit truncation is
   collision-resistant but not collision-free. The QID version is the fixed
   `Qid::FIXED_VERSION` (1).
2. **Enumeration is sorted.** Directory children live in a `BTreeMap`, so
   `readdir` yields lexicographic name order and offsets follow that order.
3. **Attributes are fixed or derived from content.** `getattr` reports
   uid=gid=0, all timestamps zero, permission bits `0o555` (no write bits),
   `BLOCK_SIZE = 4096`, and `blocks = ceil(size / 512)`. `statfs` reports a
   fixed synthetic filesystem: `STATFS_MAGIC = 0x53465039` (`"9PFS"`) and
   `STATFS_NAMELEN = 255`.

`validate_component` rejects stored names that are empty or that contain `/`
or NUL. It also rejects `.` and `..`, which stay traversal tokens on the wire
and cannot become unreachable stored children.

### Served-tree artifact format

The `World` references the tree by content hash. `FsTree::canonical_bytes` and
`FsTree::from_canonical_bytes` use this format:

```text
magic = "crucible.device.ninep.fs-tree.v1\0"
node  = tag:u8 payload
tag 0 = child_count:u64le { name_len:u64le name:utf8 node }*   directory
tag 1 = content_len:u64le content:bytes                         file
tag 2 = target_len:u64le target:utf8                            symlink
```

Directory entries must be strictly sorted. The decoder rejects wrong magic,
truncation, overflow, nesting deeper than 1024, illegal, duplicate, or
unsorted names, invalid UTF-8, unknown tags, and trailing bytes. Engine
instantiation (`instantiate_world_io_sub_nodes` in `device_subnode.rs`) loads
the bytes by hash from the content-addressed store and decodes them. A decode
failure surfaces as `WorldIoInstantiationError::NinePArtifactDecode` before any
device exists.

### Message set and the read-only boundary

The frame is `size[4] type[1] tag[2] body` in little-endian (`HEADER_LEN = 7`).
Strings are `len[2] data`, and a QID is 13 bytes: `type[1] version[4]
path[8]`. `NinepServer::handle` dispatches as follows:

```text
served:    Tversion Tattach Twalk Tlopen Tread Treaddir Tgetattr
           Treadlink Tclunk Tstatfs Tflush Txattrwalk Tfsync
EROFS:     every mutating message (Tlcreate Twrite Tmkdir Tunlinkat
           Trenameat Tsetattr Tsymlink Tmknod Trename Tlink
           Txattrcreate Tlock Tgetlock ...)
ENOSYS:    unknown message types
EINVAL:    malformed body (tag recovered from the header when present)
EMSGSIZE:  request frame larger than the negotiated msize (tag NOTAG),
           or a reply that would exceed msize
```

Request-side failures always come back as a well-formed `Rlerror`.
`handle` returns `Err` only when the reply frame itself cannot be encoded,
which indicates an internal bug.

Version negotiation is fixed. A client that sends exactly `9P2000.L` gets
`msize = clamp(client_msize, MIN_MSIZE, MAX_MSIZE)`. Negotiation also resets
the fid table. Any other version string is answered with `"unknown"` and leaves
live state unchanged. `MAX_MSIZE` equals `MAX_FRAME_DATA`, so a reply always
fits in one frame. `MIN_MSIZE` is computed at compile time as the largest
fixed-shape reply: a maximum-length `Rreaddir` entry, a 16-QID `Rwalk`, or an
`Rgetattr`. Every reply can therefore be encoded, and `readdir` always makes
progress.

### Fid state and snapshots

The fid table is a `BTreeMap<u32, FidEntry>` that maps a fid to its canonical
path and open state. `NinepServerSnapshot` holds `msize`, `negotiated`, and
`fids` as `(fid, entry)` pairs in ascending order. Restore reconstructs open
file handles and cached directory listings from the read-only tree, which is
exact because their content is a pure function of the tree.

`NinepSnapshot` adds the `IoCoreSnapshot`, the `NinepLatency` parameters, and
the signal-driven 9p state: request directives, visibility state, virtual fids,
and the session epoch. It is bounded by `MAX_NINEP_SNAPSHOT_BYTES` (512 MiB).
`NinepLatency` is `control_ns` or `data_ns` (for read and readdir) plus
`per_byte_ns * frame_len`, computed with saturating arithmetic.

## Network link sub-node

`crucible-device/src/netlink/` models a directed edge `A -> B`. `NetLink`
stamps deliveries through the reserved router slot (`LINK_SLOT =
SLOT_NET_ROUTER`). The live transport that drains and fills those rings runs in
the network servicer in `crucible-qemu-host`. The device type owns only
deterministic scheduling and the frame transforms.

```text
emit(frame, t):
  eff_lat     = max(base_latency + faults.added_latency_ticks, floor)
  delay       = eff_lat + serialization_delay(len, bandwidth caps)
              + jitter_shift(draw) + reorder_shift(draw)
  delivery    = t + delay
  if delivery <= consumer_frontier: PastDeliveryPolicy (fail loud or clamp)
  loss?       no delivery
  duplicate?  second delivery at delivery + duplicate gap
  corrupt?    mutate payload bytes
advance_to(limit): drain deliveries with delivery_icount <= limit
```

Block and 9p completions are exact local events. The link is the source of
conservative uncertainty: whether `A` sends depends on instructions `A` has not
executed yet. The link's base latency sets the scheduler's lookahead bound.
This places several rules at the link:

- Base latency must be strictly positive and at least `MIN_LINK_LATENCY`, which
  is one virtual nanosecond (`SimDuration { ticks: 1_000 }`). A base latency
  below the floor is rejected at construction. A zero-latency link would give a
  peer zero lookahead and force single-instruction lockstep.
- A latency fault that would lower the effective latency below the floor is
  clamped up to the floor and is never rejected. A fault cannot break scheduler
  liveness. A fault that raises latency only widens lookahead.
- When the conservative minimum latency changes, `NetLink` raises a one-shot
  flag (`take_lookahead_recompute`).
  `SingleScheduler::schedule_link_latency_recompute` applies the change to the
  directed lookahead edge at a quantum boundary and never during a run. Jitter,
  reorder, and bandwidth add a minimum delay of zero, so they do not move the
  scalar lookahead edge.
- A jitter or reorder shift that would land at or before the consumer frontier
  is never delivered late. `PastDeliveryPolicy::FailLoud` returns
  `DeviceError::DeliveryReorderedIntoPast`. `ClampToFuture` moves the delivery
  to `consumer_frontier + 1` and keeps a duplicate's gap relative to the
  clamped primary.

`LinkFaults` is the flat effective-effect table: `partitioned`,
`added_latency_ticks`, jitter and reorder windows, bandwidth caps in bits per
second, loss probabilities (any one firing is enough), duplicate probability
and gap, and corruption. Probabilities are exact integer fractions
(`Probability`), and the model uses no floating point. The signal-driven
network fault model decides when these values are active. See the network
fault pages in this folder and
[../../users/crucible/network-faults.md](../../users/crucible/network-faults.md).

## Device randomness

Probabilistic transforms take injected draw values. `FrameDraws` carries them
for links, and `DeviceRng` produces them in a fixed order using SplitMix64.
Each device has its own stream, forked by name hash in the
`DECISION_RNG_DEVICE_STREAM_DOMAIN` domain
(`"crucible.decision-rng.device-stream.v1"`) through
`RngStreamId::for_device` / `device_stream_id`. A device and a VM node with the
same name therefore never share a stream, and adding or renaming one device
does not change another device's draws. The engine records link draws as
`Decision::RngDraw` entries (`crucible-engine/src/device.rs`), and the stream
cursor is part of the snapshot. A restored link resumes the same draw sequence.

No ordering-significant collection on a response path uses a default hasher.
Overlay pages, dirty sets, fid tables, directory children, and in-flight queues
all use `BTreeMap`, `BTreeSet`, or an explicit key order.

## Scheduler integration

`DeviceSchedulingSubNode` in `crucible-engine/src/device_subnode.rs` wraps a
block or 9p `IoCore` with its scheduling identity:

- **Horizon term.** `next_exact_local_event` is the final delivery icount of
  the in-flight head. The scheduler folds it into the owning VM's
  `ExactLocalEvent::IoCompletion` term. An idle requester is therefore advanced
  exactly to its next completion.
- **Delivery.** `deliver_due(consumer_icount)` emits `IoCompletion` events in
  `(delivery_icount, src_node, seq)` order, together with any decisions
  buffered for them. Signal-driven storage and 9p effects are applied by the
  production adapters before completions reach this bridge. This bridge has no
  second fault table.

The `World` declares I/O nodes (`WorldIoNodeKind::Block` and
`WorldIoNodeKind::NineP`) with their owning VM, content-addressed artifact, and
latency parameters. The declaration does not include ring capacities or
completion-order source numbers, which belong to the physical transport.
`WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy)` assigns source
numbers from canonical node order and applies the capacity policy at
instantiation time. The defaults are `DEFAULT_WORLD_IO_INBOX_CAPACITY` and
`DEFAULT_WORLD_IO_OUTBOX_CAPACITY`, both 256. Changing that policy therefore
cannot change the identity of the World, a device, or a scenario.

## Live QEMU path: dispatch, hold, and advance

### Synchronous kick dispatch

Before any device sub-node sees a request, the guest's virtqueue kick must be
observed at the instruction that issued it. Upstream QEMU can dispatch kicks
through ioeventfd or a host notifier, which defers the request to the main
loop. Under the sim accelerator the vCPU could then run past the kick, so the
request's coordinate would depend on host dispatch. A 9p mount could also block
forever before any request reached `SLOT_9P_IO`. The atomic QEMU patch
(`pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch`) closes this gap at
two points, both active only for the `sim` accelerator with icount:

- `virtio_pci_ioeventfd_enabled` returns false for virtio-rng, virtio-blk,
  virtio-net, and virtio-console (`virtio_pci_ioeventfd_policy`).
- `virtio_queue_notify` skips the host notifier for virtio-9p, virtio-blk, and
  virtio-net, and calls the queue handler inline on the requesting vCPU thread.

The request is observed at the guest's exact kick icount. Completion still
belongs to each device's deterministic delivery path. Plain TCG, sim without
icount, and every other virtio device keep the upstream behavior. See
[qemu-patch.md](qemu-patch.md) for the patch layout.

### Device-I/O hold

While block or 9p requests are in flight, the plugin's `PluginDeviceIoFreeze`
(`crucible-qemu-plugin/src/device_io.rs`) sets the node slot's
`device_io_active` flag and keeps a pending count. The idle path then
suppresses guest HZ timer deadlines, so a gap in host timing cannot advance
virtual time. Each submit returns a non-`Copy` token. Exactly one completion
or failure must consume it, so the count cannot drift. The 9p path brackets a
whole device invocation with `burst_start` and `burst_done` and holds the node
for the entire burst. A block request uses `begin_independent_submit`, which
contributes to the hold without blocking an unrelated 9p burst from reaching
`burst_done`. The block submit marks the hold active before it publishes the
frame to the ring. If the enqueue fails, the token is failed immediately.

### Device-completion advance

The host servicers (`QemuLiveBlockIoServicer`, `QemuLive9pIoServicer`) compute
each completion and publish the earliest outstanding deadline with
`NodeSlot::store_device_completion_deadline_tick` (zero means none pending).
They then signal the node's wake fd. This host-owned field is distinct from the
plugin-published `idle_wake_icount`, so the two directions never share a field.

When the QEMU `crucible-shmem` block driver polls and finds the response
pending, it calls the callback registered through
`qemu_plugin_register_blk_wait_cb` and parks its coroutine. The plugin
(`on_block_wait` in `runtime/live_callbacks.rs`) reads the published deadline
and limits the target to the current scheduler ceiling. It then queues an idle
advance using the same virtual-time mapping that produced the host deadline,
so there is no second rounding domain. Once QEMU commits the advance, it wakes
device waiters and the coroutine retries the poll. Consider the case where the
deadline is not yet published, or virtual time already admits the response but
the ring write has not physically landed. The callback returns, and the next
host wake retries the poll at the same logical icount. Host timing can change
only how long QEMU waits. It never changes the delivery coordinate the guest
sees.

The callback is registered only for an active Crucible sim session. Without
registration the QEMU callback pointer is null, so ordinary QEMU devices never
enter this path.

## Idle versus busy-poll

The fast path assumes a guest halts (HLT) while it waits for I/O, which lets
the scheduler jump to the completion. A guest that busy-polls retires
instructions throughout the wait. That costs wall-clock time, but the
completion still lands at its exact icount. Correctness never depends on the
guest halting. `idle_busy_poll_equivalence` in `crucible-device/src/harness.rs`
runs the same script with one-shot idle advance and with one-tick-at-a-time
advance, and requires byte-identical delivery logs. `BUSY_POLL_SPIKE` records
three conclusions: correctness does not depend on poll mode, busy-polling
affects only performance, and any mitigation must preserve exact delivery.

## Verification

| Check or test                                         | Covers                                   |
|-------------------------------------------------------|------------------------------------------|
| `checks.crucible.phase3.ioSubnodeTrait`               | `IoSubNode` / `IoCore` lifecycle         |
| `checks.crucible.phase3.blockSubnodeOverlay`          | Base image, CoW overlay, dirty tracking  |
| `checks.crucible.phase3.blockCowOverlayPattern`       | Overlay source pattern and ordered maps  |
| `checks.crucible.phase3.blockWireAbi`                 | Block wire ABI on both sides             |
| `checks.crucible.phase3.blockCompletionModel`         | `BlockLatency` and delivery order        |
| `checks.crucible.phase3.blockSnapshotRestore`         | Snapshot, restore, materialize           |
| `checks.crucible.phase3.ninePSubnodeServer`           | QIDs, enumeration, attributes, msize     |
| `checks.crucible.phase3.ninePSessionLifecycle`        | Message set, EROFS, fid snapshots        |
| `checks.crucible.phase3.ninePWireAbi`                 | 9p golden vectors and fuzzing            |
| `checks.crucible.phase3.networkLinkSubnode`           | Link model                               |
| `checks.crucible.phase2.qemu9pSyncKick`               | Inline 9p kick dispatch in the patch     |
| `checks.crucible.phase2.qemuPluginNinePIo`            | 9p rings, backpressure, burst hold       |
| `checks.crucible.phase2.qemuDeviceCompletionAdvance`  | Block-wait advance in the patch          |
| `checks.crucible.phase2.qemuLiveBlockRealization`     | Live Linux block I/O through the rings   |
| `crucible-device/tests/device_harness.rs`             | Run-twice identity, divergence, idle/busy|
| `crucible-device/tests/io_subnode_lifecycle.rs`       | Real-ring full/retry and wake paths      |

`gate:abi-conformance` covers the block and 9p wire formats. The plugin's
`io_wire_fuzz` channels, for example `IoWireFuzzChannel::BlockRequest`, feed
arbitrary bytes to each decoder and assert that decoding never panics and never
reads out of bounds. See [testing-and-gates.md](testing-and-gates.md).
