# 15 — I/O sub-nodes: disk, 9p, and network links as first-class scheduling nodes

This file specifies how Crucible models **I/O** — block storage, a 9p
filesystem, and inter-VM network links — as **uniform simulation sub-nodes**.
The central design correction this file makes precise is that **I/O completion
is a scheduled event, not a pause of virtual time**: a device does not "freeze
the clock while the host disk seeks." It computes the exact virtual time at
which a response becomes visible to its requester and schedules that response as
an *exact local event* ([`08-scheduling.md`](08-scheduling.md) §8.4.1), so the
requester's horizon is tightened exactly and the run stays a pure function of
`(ScenarioDef, Seed, Schedule)` ([INV-1]).

Requirement IDs in this file use the `IO` prefix (see
[`00-conventions.md`](00-conventions.md)). The sub-nodes specified here are the
producers of the I/O-completion events the scheduler resolves
([`08-scheduling.md`](08-scheduling.md) §8.9.4, [SCHED-29]); they ride the
shared-memory transport and reserved executor slots of
[`13-shmem-abi.md`](13-shmem-abi.md) (`SLOT_BLK_IO`, `SLOT_9P_IO`,
`SLOT_NET_ROUTER`); their per-device CoW overlay and RNG are the device half of
a Checkpoint's `MaterializedState` ([`07-temporal-graph.md`](07-temporal-graph.md)
§3, [TEMP-7], [TEMP-9]); their probabilistic behavior is drawn from the seeded
decision RNG of [`04-determinism-contract.md`](04-determinism-contract.md); and
the faults that perturb them are the fault taxonomy of
[`17-fault-injection.md`](17-fault-injection.md). The wire formats defined here
are versioned, fuzzed boundary ABIs in the sense of [G-8], conformance-gated by
`gate:abi-conformance` ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)).

The code blocks in this file are illustrative `rust`/`text` sketches per
[`00-conventions.md`](00-conventions.md) §"Code sketches in this RFC": they show
the intended type and wire shapes so the spec is concrete, but the authority is
the prose requirement. A sketch that disagrees with a requirement is a defect in
the sketch.

## 15.1 The uniform sub-node model

The single idea that organizes this whole file: **a disk, a 9p server, and a
network link are each a scheduling node**, exactly like a VM node, differing
only in that they process *requests* and emit *responses* rather than retiring
guest instructions. Each I/O sub-node has:

- its own **icount-derived virtual clock** ([INV-4],
  [`09-virtual-time-icount.md`](09-virtual-time-icount.md)), advanced only by the
  single authoritative scheduler ([INV-8], [SCHED-4]);
- a **request inbox** and a **response outbox** carried over the shared-memory
  SPSC rings of [`13-shmem-abi.md`](13-shmem-abi.md);
- a **deterministic completion model** that, given a request emitted at the
  requester's icount `t`, computes the *exact* virtual time `t + latency` at
  which the response becomes visible;
- a **seeded per-device RNG** (forked by name-hash, [`04-determinism-contract.md`](04-determinism-contract.md))
  for any probabilistic behavior, whose position is part of `MaterializedState`
  ([TEMP-7]).

The logical World declaration carries the I/O node id, owning VM, clock shift,
content-addressed immutable artifact, and deterministic latency parameters. It
does **not** carry a completion-order source number or request/response ring
capacity: those are physical transport layout. `WorldIoInstantiationLayout`
derives unique source numbers from canonical logical node order and applies a
`WorldIoLayoutPolicy` only while the live session resolves artifacts and builds
concrete scheduling sub-nodes. Changing that physical policy cannot change the
World, `DeviceId`, scenario, or scheduler configuration identity ([SPAT-14],
[SPAT-15]). Each logical `LinkDef` likewise has one deterministic `Network`
scheduling identity in `WorldStaticTopology`; the production scheduler consumes
that complete VM/device/link projection.

The flow of a single disk read, end to end, is the canonical illustration of
"completion is a scheduled event, not a freeze":

```text
  icount t        VM emits BlockRequest{read, off, len}  →  blk sub-node inbox (13)
  (host-side)     blk sub-node computes completion_vt = vt(t) + latency_model(req)
                  blk sub-node schedules BlockResponse with delivery_icount = ic(completion_vt)
  ── during the wait ──
                  the VM has no runnable work for this request; it idles (HLT) or
                  busy-polls (15.8). If it idles, the scheduler fast-forwards its
                  clock to its next exact local event (SCHED-28) — which is exactly
                  this completion (it is the requester's next_exact_local_event, 08).
  icount t'       VM's frontier reaches delivery_icount; RESOLVE makes the response
                  visible at EXACTLY that icount (SCHED-29, SHM-33). No wall-clock
                  ever entered the calculation.
```

The completion time is *computed by the host from state the scheduler already
holds*, so it is an **exact local event** ([SCHED-10]): no other node's
un-executed instructions can move it, and so it tightens the requester's horizon
with no conservative slack. This is the whole reason I/O is modeled as
sub-nodes — it gives the scheduler the exact next-attention instant for an
otherwise-idle requester, which is both correct and fast.

- **[IO-1]** Each disk, 9p filesystem, and network link MUST be modeled as a
  first-class **scheduling sub-node** with its own icount-derived virtual clock
  ([INV-4]), advanced only by the single authoritative scheduler ([INV-8],
  [SCHED-4]), and MUST interact with the rest of the system solely through the
  shared-memory transport ([`13-shmem-abi.md`](13-shmem-abi.md)) and the
  scheduler's event resolution ([SCHED-29]). An I/O sub-node MUST NOT advance any
  clock, deliver any response out of band, or consult host wall-clock. *Gate:*
  `gate:layer1-injection`, `gate:layer0-determinism`. *Spec:* §15.1; cross-ref
  08, 13.

- **[IO-2]** An I/O completion MUST be a **scheduled event**: given a request
  observed at the requester's icount `t`, the sub-node MUST compute a
  deterministic completion virtual time `completion_vt = vt(t) + latency(req)`,
  convert it to the consumer's `delivery_icount` via the fixed shift
  ([`09-virtual-time-icount.md`](09-virtual-time-icount.md); ns→icount via the
  [TIME-4] ceil map), and emit the
  response so it becomes visible **at exactly that icount** ([SCHED-29],
  [SHM-33]). Crucible MUST NOT implement I/O by pausing or "freezing" virtual
  time during a host I/O operation; the freeze-time approach is forbidden because
  it makes the completion icount a function of host timing rather than of virtual
  time ([DET-19], [INV-1]). *Gate:* `gate:layer1-injection`,
  `gate:e2e-determinism`. *Spec:* §15.1; cross-ref §8.4.1.

- **[IO-3]** An I/O completion time MUST be the **requester's next exact local
  event** for the duration of the wait, with no conservative network bound
  applied ([SCHED-10]): the sub-node's computed `completion_vt` is a pure
  function of host-held state and depends on no other node's un-executed
  instructions, so the scheduler MUST be able to advance the otherwise-idle
  requester *exactly* to the completion ([SCHED-28] fast-forward) at zero
  wall-clock cost. *Gate:* `gate:scheduler-liveness`, `gate:single-vm-fingerprint`.
  *Spec:* §15.1; cross-ref §8.9.3.

- **[IO-4]** Every sub-node's completion time and every probabilistic device
  choice MUST be a deterministic function of `(request icount, modeled latency,
  per-device RNG draw)` only; no field of any response (status, payload,
  delivery icount) may depend on host wall-clock, host scheduling, host
  filesystem ordering, or host inode numbers. *Gate:* `gate:layer1-injection`,
  `gate:adversarial-determinism`. *Spec:* §15.1; cross-ref §15.6.

### 15.1.1 The request/response lifecycle and in-flight tracking

A sub-node holds a queue of **in-flight responses**: responses it has *computed*
(their payload and `delivery_icount` are fixed) but not yet *delivered* (the
consumer's clock has not reached `delivery_icount`). The queue is kept ordered by
`delivery_icount` so the sub-node's *next exact local event* — what the scheduler
reads to bound the requester's horizon ([SCHED-9]) — is the head of the queue.
The lifecycle of one request:

```text
  1. ARRIVE   request lands in the inbox (13) at the requester's emit icount t
  2. COMPUTE  the sub-node computes status + payload now (host FS/overlay access),
              and computes delivery_icount = ic(vt(t) + latency) — the EXACT
              completion time. The host work happens at COMPUTE; the VISIBILITY
              is gated on virtual time (IO-2), so the host's COMPUTE latency is
              invisible to the guest.
  3. PENDING  the response is inserted into the in-flight queue, ordered by
              delivery_icount; the head's delivery_icount is the sub-node's
              next_exact_local_event (08) — also the requester's, transitively.
  4. DELIVER  when the consumer's frontier reaches delivery_icount, RESOLVE
              dequeues the response and makes it visible at exactly that icount
              (SCHED-29, SHM-33), in (delivery_icount, src_node, seq) order.
```

The COMPUTE/VISIBILITY split is the crux: the sub-node may touch the host
filesystem or overlay *whenever it likes* in wall-clock (at COMPUTE), because the
*architectural visibility* of the result is pinned to a virtual-time icount
(at DELIVER). Host I/O latency therefore never leaks into the guest's instruction
stream — the opposite of the freeze-time hack, which makes the guest's perceived
latency a function of host timing.

- **[IO-31]** A sub-node MUST maintain an **in-flight response queue ordered by
  `delivery_icount`**, computed at request-arrival time and delivered at the
  consumer's matching icount. The head's `delivery_icount` MUST be reported as the
  sub-node's `next_exact_local_event` ([SCHED-9], [SCHED-10]) so the scheduler can
  bound the requester's horizon exactly. The wall-clock instant of the host
  COMPUTE (filesystem/overlay access) MUST NOT influence the response's
  `delivery_icount` or any payload byte ([IO-2], [DET-19]). *Gate:*
  `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §15.1.1.

- **[IO-32]** When a sub-node's inbound request ring or a consumer's response ring
  is **full** ([SHM-19] capacity), the producing side MUST apply deterministic
  backpressure (the producer blocks at its current TB boundary and is woken when
  space frees, via the futex mechanism of [SHM-26]); a full ring MUST NOT cause a
  request or response to be dropped, reordered, or delivered at a different icount
  ([SHM-13] rejects over-`MAX_FRAME_DATA` frames, not full-ring frames). The
  backpressure point MUST be a pure function of virtual time and queue depth,
  never of host scheduling. *Gate:* `gate:layer1-injection`,
  `gate:abi-conformance`. *Spec:* §15.1.1; cross-ref 13 §13.6, §13.7.

## 15.2 The block device sub-node

The block device sub-node sits between a VM node and its disk image. It serves
**read**, **write**, **flush**, and **get-length** operations against a
**read-only, content-addressed base image** plus an **in-memory copy-on-write
overlay** of 4 KiB pages, with **dirty-page tracking** so a checkpoint stores
only the pages dirtied since its parent ([`07-temporal-graph.md`](07-temporal-graph.md)
§5, [TEMP-15]).

### 15.2.1 Base image, overlay, and CoW reads

The base image is the read-only `World` artifact
([`06-spatial-graph.md`](06-spatial-graph.md)), referenced by content hash and
**never mutated** ([INV-5], [TEMP-9]). All writes land in the overlay; all reads
consult the overlay first and fall back to the base image page by page:

```text
  read(off, len):
    for each 4 KiB page spanning [off, off+len):
      if page in overlay:  copy from overlay
      else:                copy from base image (read-only)
  write(off, data):
    for each 4 KiB page spanning [off, off+len):
      page = overlay.entry(page_base).or_insert(read_base_page_or_zero(page_base))
      patch page[page_off..] := data
      mark page_base dirty
```

- **[IO-5]** The block sub-node MUST serve reads from an **in-memory
  copy-on-write overlay of 4 KiB pages layered over a read-only base image**:
  a read resolves each page from the overlay if present, else from the base
  image; a write copies the affected base page into the overlay (if not already
  present) and patches it there. The base image MUST be opened read-only and MUST
  NOT be mutated by any operation ([INV-5], [TEMP-9]). *Gate:* `gate:any-guest`,
  `gate:content-address`. *Spec:* §15.2.1; cross-ref 06, 07.

- **[IO-6]** The block sub-node MUST support the operations **read**, **write**,
  **flush**, and **get-length**: read returns the requested byte range (overlay
  over base); write applies to the overlay only; flush is a no-op success (the
  overlay is the durable store within the simulation); get-length returns the
  base image's total size in bytes. A read or write whose range extends past the
  device length MUST return an error status, never silently truncate or extend.
  *Gate:* `gate:abi-conformance`. *Spec:* §15.2.1, §15.2.3.

- **[IO-7]** The block sub-node MUST track the set of **dirty overlay pages**
  (pages written since the last checkpoint boundary) so that a checkpoint's
  device overlay is captured as a delta of *only* the pages dirtied since its
  parent ([TEMP-15], [TEMP-16]). The dirty set MUST be cleared at a checkpoint
  boundary after the delta is captured, so successive checkpoints capture
  disjoint, content-addressed page deltas. *Gate:* `gate:content-address`,
  `gate:replay-oracle`. *Spec:* §15.2.1; cross-ref §15.5, 07 §5.

### 15.2.2 The block wire protocol (request/response over shmem)

Block requests and responses ride the SPSC frame rings of
[`13-shmem-abi.md`](13-shmem-abi.md) §13.3.3 between the VM's slot and
`SLOT_BLK_IO`; the wire payload is carried in a `FrameEntry`'s `data` field
(sized so a 4 KiB read response plus its header fits without truncation,
`MAX_FRAME_DATA = 4608`, [SHM-13]). The on-wire layout is a versioned ABI:

```text
BlockRequest  (VM slot -> SLOT_BLK_IO)
  u8   type        -- 0=read, 1=write, 2=flush, 3=get_length
  u8   version     -- block wire ABI version (= 2)
  u16  _reserved   -- zero
  u32  request_id  -- correlates response to request
  u64  offset      -- byte offset (read/write)
  u32  count       -- byte count (read/write)
  [count bytes]    -- payload, write only

BlockResponse (SLOT_BLK_IO -> VM slot)
  u8   status      -- 0=ok, 1=error
  u8   version     -- block wire ABI version (= 2)
  u16  _reserved   -- zero
  u32  request_id  -- echoes the request
  u32  count       -- response data length
  [count bytes]    -- success data; exactly one typed-result byte on error
```

Version 2 defines the closed error payload used by signal-driven storage
faults. The one-byte values and their guest-visible errno mapping are listed in
[`14-block-typed-errors.md`](../0012-signal-driven-fault-model/14-qemu-fault-patches/14-block-typed-errors.md).
Version 1 is not accepted by a version 2 endpoint; there is no legacy decode or
silent downgrade path.

- **[IO-8]** The block request/response wire format MUST be a **versioned
  boundary ABI** ([G-8]): every message MUST carry an ABI version byte and a
  fixed field order; all multi-byte integers MUST use a single fixed endianness
  declared in this section; reserved bytes MUST be zero on emit and rejected on
  receive until a future ABI version assigns them meaning. A request whose
  declared `count` exceeds the available payload bytes,
  or whose type is unknown, MUST be rejected as malformed and answered with an
  error-status response, never parsed past its bounds. *Gate:*
  `gate:abi-conformance`. *Spec:* §15.2.2; cross-ref 13 §13.3.3.

- **[IO-9]** Block requests and responses MUST be carried in the shared-memory
  SPSC rings between the VM node's slot and the reserved `SLOT_BLK_IO` executor
  slot ([SHM-17], [SHM-18]); the block sub-node MUST NOT use a separate IPC data
  channel for per-request delivery ([SHM-2], [PROTO-1]). Each response's
  `FrameEntry.delivery_icount` MUST be the computed completion icount ([IO-2]),
  so deliverability is decided by `delivery_icount <= consumer.current_icount`
  ([SHM-33]). *Gate:* `gate:layer1-injection`, `gate:abi-conformance`. *Spec:*
  §15.2.2; cross-ref 13 §13.9.

### 15.2.3 The deterministic completion model

A block request's completion time is a deterministic function of the request and
a fixed latency model; the model MAY differentiate read/write/flush and MAY
include a per-request component (e.g. proportional to `count`), but every term
MUST be a pure function of the request and the per-device parameters, never of
the host device's measured timing.

- **[IO-10]** The block sub-node's completion time MUST be
  `completion_vt = vt(request_icount) + latency(op, count, params)`, where
  `latency` is a deterministic function of the operation, the byte count, and the
  device's configured latency parameters (part of the `World`,
  [`06-spatial-graph.md`](06-spatial-graph.md)). The measured wall-clock time the
  host actually spent reading the page MUST NOT appear in `latency` ([DET-19]).
  Responses MUST be made visible in the deterministic total order
  `(delivery_icount, src_node, seq)` when several fall on the same icount
  ([SHM-34], [SCHED-15]). *Gate:* `gate:layer1-injection`. *Spec:* §15.2.3.

### 15.2.4 Snapshot, restore, and materialize

A block sub-node's contribution to a Checkpoint's `MaterializedState`
([`07-temporal-graph.md`](07-temporal-graph.md) §3) is **the overlay delta plus
the device RNG state plus the set of in-flight (computed-but-not-yet-delivered)
responses** — never the base image ([TEMP-9]). Two complementary operations
serve checkpointing, and a third serves handing a forked state to a real-time
QEMU:

```text
  snapshot  -> DeviceOverlayDelta {
                 dirty_pages: BTreeMap<page_base, page_bytes>,  // CoW delta since parent (07 §5)
                 device_rng:  per-stream RNG position (04),
                 inflight:    Vec<PendingResponse{ delivery_icount, response }>,
                 clock_icount, length,
               }
  restore   -> stack this delta over the parent's overlay; re-seed RNG to the saved
               position; re-arm inflight responses. The denoted state equals an
               uninterrupted run (07 INV-2 / replay oracle).
  materialize(out) -> write base image, then apply every overlay page on top,
               producing a standalone raw image a real-time QEMU can mount (22).
```

- **[IO-11]** A block sub-node MUST be **snapshot/restore-able** as the device
  half of a `MaterializedState` ([TEMP-7]): the snapshot MUST capture the
  copy-on-write overlay **as a delta over the parent** (only the pages dirtied
  since the parent, BLAKE3-keyed and deduplicated, [TEMP-15], [TEMP-16]), the
  device RNG stream position ([IO-21]), the set of in-flight responses with their
  delivery icounts, and the device clock and length. It MUST NOT capture the base
  image ([TEMP-9]). Restore MUST stack the delta over the parent's overlay and
  reproduce a state byte-identical to an uninterrupted run, validated by the
  replay oracle ([INV-2], [TEMP-18]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §15.2.4; cross-ref 07 §3, §5, §6.

- **[IO-12]** The block sub-node MUST support **materialize-to-image**: writing
  the read-only base image followed by every live overlay page on top, producing
  a standalone raw disk image that a real-time QEMU (outside the simulation) can
  mount directly when a forked checkpoint is handed off to real-time mode
  (forward-ref [`22-advanced-features.md`](22-advanced-features.md)).
  Materialization MUST NOT mutate the base image ([INV-5]); it produces a new
  output artifact. *Gate:* `gate:any-guest`. *Spec:* §15.2.4; forward-ref 22.

## 15.3 The 9p filesystem sub-node

The 9p sub-node is a **read-only Plan 9 filesystem server** speaking 9P2000.L,
serving a content-addressed directory tree from the `World`
([`06-spatial-graph.md`](06-spatial-graph.md)) to a VM. Its defining property is
that it is **deterministic by construction**: every value it returns is a pure
function of the served tree's content and the request, with no host-filesystem
nondeterminism (inode numbers, directory enumeration order, timestamps) leaking
into the guest.

### 15.3.1 Determinism design

Three sources of host-filesystem nondeterminism are eliminated at the source:

1. **QIDs are path-hashed, not inode numbers.** A 9p QID's `path` field (the
   64-bit file identifier the guest caches) is derived from a fixed hash of the
   file's path within the served tree, **not** from the host's inode number
   (which varies across hosts and mounts). The QID `version` is a fixed constant.
2. **Directory enumeration is sorted.** `readdir` returns entries in a fixed
   order (lexicographic by name), not in host-`readdir` order (which is
   filesystem- and allocation-dependent). Offsets are assigned after sorting.
3. **Attributes are fixed/derived, not host-observed.** `getattr` returns a
   fixed epoch for all timestamps, root uid/gid, a fixed block size, and a
   deterministic block count derived from the file size — never the host's atime/
   mtime/ctime, uid/gid, or device-specific block accounting.

The component-vector encoding fed to BLAKE3 is length-delimited and injective,
but the QID is a 64-bit truncation and therefore is described as
collision-resistant, not mathematically collision-free. Stored tree components
reject empty names, `/`, NUL, `.` and `..`; the latter two remain traversal tokens
on the wire and cannot masquerade as unreachable stored children.

The immutable tree itself is an artifact with an explicit canonical format:

```text
magic = "crucible.device.ninep.fs-tree.v1\0"
node  = tag:u8 payload
tag 0 = child_count:u64le { name_len:u64le name:utf8 node }*
tag 1 = content_len:u64le content:bytes
tag 2 = target_len:u64le target:utf8
```

Directory entries must already be strictly sorted. The artifact resolver rejects
wrong versions, truncation, overflow, excessive nesting, illegal/duplicate/
unsorted names, invalid UTF-8, unknown tags, and trailing bytes before building a
concrete 9p device; it then rechecks the canonical bytes against the World hash.

```text
  qid.path    = stable_hash(path_within_served_tree)   // NOT host inode
  qid.version = 1                                       // fixed
  qid.type    = {dir | symlink | file} from content
  readdir     = entries sorted by name; offsets = 1..N after sort
  getattr     = { mode from content; uid=gid=0; *time = FIXED_EPOCH;
                  blksize = 4096; blocks = ceil(size/512) }
```

- **[IO-13]** The 9p sub-node MUST be a **read-only 9P2000.L server** whose every
  returned value is a deterministic function of the served tree's content and the
  request. It MUST derive a file's QID `path` from a **stable hash of the file's
  path within the served tree**, never from the host inode number, and MUST use a
  **fixed QID `version`**, so the identifiers the guest caches are identical
  across runs and hosts ([INV-4], [DET]). *Gate:* `gate:any-guest`,
  `gate:adversarial-determinism`. *Spec:* §15.3.1.

- **[IO-14]** The 9p sub-node MUST enumerate directories in a **fixed, sorted
  order** (lexicographic by entry name), assigning entry offsets after the sort,
  so `readdir` results never depend on host-filesystem enumeration order.
  Repeated `readdir` of the same directory snapshot MUST yield byte-identical
  results. *Gate:* `gate:adversarial-determinism`. *Spec:* §15.3.1.

- **[IO-15]** The 9p sub-node's `getattr`/`statfs` MUST return **fixed or
  content-derived** attribute values — a fixed epoch for all timestamps, fixed
  root uid/gid, a fixed block size, a block count derived deterministically from
  the file size, and a synthetic statfs — never the host's observed timestamps,
  ownership, or device accounting. *Gate:* `gate:adversarial-determinism`.
  *Spec:* §15.3.1.

- **[IO-16]** The 9p sub-node MUST negotiate a **fixed protocol version**
  (`9P2000.L`) and a deterministic `msize` (the minimum of the client's request
  and the server's fixed maximum), so version negotiation is itself
  reproducible. *Gate:* `gate:abi-conformance`. *Spec:* §15.3.1, §15.3.2.

### 15.3.2 The 9p message set and the read-only boundary

The sub-node implements the read-and-traverse subset of 9P2000.L; every mutating
operation is answered with `EROFS`. The header is `size[4] type[1] tag[2]`
(little-endian, Plan 9 convention), strings are `len[2] data[len]`, and QIDs are
13 bytes (`type[1] version[4] path[8]`).

```text
  served (read/traverse):
    Tversion Tattach Twalk Tlopen Tread Treaddir Tgetattr
    Treadlink Tclunk Tstatfs Tflush Txattrwalk
  rejected with EROFS (write/mutate):
    Tlcreate Twrite Tmkdir Tunlinkat Trenameat Tsetattr
  unknown type -> ENOSYS ; malformed body -> EINVAL/EIO
```

- **[IO-17]** The 9p sub-node MUST implement the read/traverse message subset
  (version, attach, walk, lopen, read, readdir, getattr, readlink, clunk,
  statfs, flush, xattrwalk) and MUST answer **every mutating message**
  (lcreate, write, mkdir, unlinkat, renameat, setattr) with **`EROFS`**, so the
  guest cannot mutate the served tree ([INV-5], read-only export). An unknown
  message type MUST return `ENOSYS`; a malformed message body MUST return a 9p
  error (`EINVAL`/`EIO`), never a panic or an out-of-bounds parse. *Gate:*
  `gate:abi-conformance`, `gate:any-guest`. *Spec:* §15.3.2.

- **[IO-18]** The 9p wire format MUST be a **versioned, fuzzed boundary ABI**
  ([G-8], forward-ref [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)):
  it MUST be covered by golden-vector conformance tests and by a fuzzer that
  feeds arbitrary byte sequences as 9p messages and asserts the server never
  panics, never reads out of bounds, and always returns a well-formed response or
  a 9p error. A message larger than the negotiated `msize` MUST be rejected, not
  processed. *Gate:* `gate:abi-conformance`. *Spec:* §15.3.2; forward-ref 24.

- **[IO-19]** The 9p sub-node MUST manage **fid state** deterministically: a fid
  maps to a path (and, once opened, a file handle or a cached, sorted directory
  enumeration); walk derives new fids from existing ones; clunk releases a fid.
  The fid table MUST be snapshot/restore-able as part of the device's
  `MaterializedState` contribution — persisting fid→path bindings and the
  negotiated `msize`, with open handles and directory caches reconstructed on
  restore from the read-only tree (their content is a pure function of the tree,
  so reconstruction is exact). *Gate:* `gate:replay-oracle`. *Spec:* §15.3.2;
  cross-ref 07 §3.

## 15.4 The network link sub-node

A **link** is the sub-node that carries frames between two VM nodes. Logically it
is the directed edge `A → B` of the spatial graph
([`06-spatial-graph.md`](06-spatial-graph.md)); physically, frames flow
`A_slot → SLOT_NET_ROUTER → B_slot` ([SHM-17]), and the router executor applies
the link model when it re-stamps each frame's `delivery_icount`. The link is
**where most network faults live** ([`17-fault-injection.md`](17-fault-injection.md)):
it models latency, jitter, loss, reorder, duplication, corruption, and bandwidth
as **deterministic perturbations of a frame's delivery icount and/or payload**.

### 15.4.1 The link model

For a frame emitted by `A` at virtual time `T_emit` over link `A → B` with
base latency `L(A→B)`, the link computes the delivery virtual time and the
delivered payload as a deterministic function of the frame, the link parameters,
and seeded RNG draws:

```text
  base delivery_vt = T_emit + L(A→B)                       // SCHED-16; L > 0 (SCHED-20)
  + bandwidth      delivery_vt += serialization_delay(len, bandwidth_bps)
  + jitter         delivery_vt += rng_uniform(0 ..= jitter_window)        // seeded
  + reorder        delivery_vt += rng_uniform(0 ..= reorder_window)       // seeded; can pass a peer
  + loss           if rng_bernoulli(loss_rate): DROP (no delivery)        // seeded
  + duplicate      if rng_bernoulli(dup_rate):  emit a second frame       // seeded
  + corrupt        if rng_bernoulli(corrupt_rate): flip seeded bits in payload
```

Each probabilistic decision is a draw from the **seeded decision RNG**, consumed
in the deterministic total order of [SCHED-30], and recorded as a `Decision` in
the `Schedule`, so the link's behavior is reproducible and forkable.

- **[IO-20]** A network **link** MUST be a sub-node that models inter-VM frame
  delivery as a **deterministic perturbation of the frame's delivery icount and/
  or payload**: base latency sets `delivery_vt = T_emit + L(A→B)` ([SCHED-16]),
  and latency/jitter/reorder/bandwidth faults **shift `delivery_vt`** while
  loss **drops the frame**, duplication **emits an additional frame**, and
  corruption **mutates the payload** ([`17-fault-injection.md`](17-fault-injection.md)).
  The link is the locus of network fault injection; it MUST apply the effective
  fault table for the link when RESOLVE delivers a frame ([SCHED-29]). *Gate:*
  `gate:layer1-injection`. *Spec:* §15.4.1; cross-ref 08 §8.9.4, 17.

### 15.4.2 Why the link is the one source of conservative uncertainty

The block and 9p sub-nodes produce **exact local events** — the completion time
is computed the instant the request arrives, so it tightens the requester's
horizon with no slack ([IO-3], [SCHED-10]). The network link is fundamentally
different and is, in fact, *the only genuine source of cross-node uncertainty*
([SCHED-10]): whether and when peer `A` emits a frame to `B` depends on
instructions `A` has not executed yet, which the host cannot compute in advance.
This is exactly the dependency the conservative CMB lookahead bounds, and the
link's base latency `L(A→B)` is what *sets* that bound: `lookahead(B)` is the
minimum inbound link latency over `B`'s live links ([SCHED-6]).

This is why the minimum link-latency floor ([SCHED-20]) lives at the link: a
zero-latency link would give a peer zero lookahead and collapse the system to
single-instruction lockstep. A fixed **latency fault that raises** a link's
conservative minimum effective latency only *increases* lookahead (safe — more
parallelism); a fault that would *lower* a link's latency below the floor MUST be
clamped to the floor, and any change to that scalar conservative bound MUST
trigger the scheduler's lookahead recompute at the quantum boundary ([SCHED-37])
so the guarantee is never violated by a stale bound. Jitter, reorder, and
bandwidth faults still shift individual frame deliveries, but their minimum
additional delay is zero, so they do not widen the scheduler's scalar lookahead
edge.

- **[IO-33]** A network link's **base latency MUST be strictly positive and at or
  above the minimum link-latency floor** ([SCHED-20]); the link is what supplies
  the conservative lookahead bound to the scheduler ([SCHED-6]). A fixed latency
  fault that *raises* a link's conservative minimum effective latency MUST be
  honored as-is (it only widens lookahead); a fault that would lower it below the
  floor MUST be clamped to the floor; and any change to that scalar effective
  latency bound MUST trigger the scheduler's lookahead/horizon recompute at the
  quantum boundary ([SCHED-37]), never mid-RUN. Jitter, reorder, and bandwidth
  remain per-frame delivery shifts, not changes to the minimum lookahead bound.
  *Gate:* `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §15.4.2;
  cross-ref 08 §8.7, §8.11.

- **[IO-34]** A **reorder** fault on a link (a per-frame seeded delivery-icount
  shift that may move one frame's delivery past another's) MUST keep every
  resulting `delivery_icount` within the consumer's future at the instant the
  frame is enqueued ([SHM-35]); a reorder MUST NOT produce a `delivery_icount`
  the consumer has already passed. If a modeled reorder would land in the
  consumer's past, it MUST be clamped to a deliverable future icount or the run
  MUST fail loudly via the divergence path ([INV-10]), never deliver late.
  *Gate:* `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §15.4.2;
  cross-ref 13 §13.9.

## 15.5 Determinism of devices

Every device's behavior is a pure function of `(request icount, modeled latency,
seeded RNG draws)`, and every piece of device state that could influence a future
response is part of the checkpoint's `MaterializedState`.

- **[IO-21]** Each I/O sub-node MUST own a **seeded per-device RNG** for any
  probabilistic behavior, with its stream **forked by name-hash** from the root
  seed ([`04-determinism-contract.md`](04-determinism-contract.md)), so adding or
  renaming an unrelated device does not perturb another device's draw sequence.
  Every probabilistic device choice MUST be a draw from this RNG, consumed in a
  deterministic order, and (for choices the scheduler resolves) recorded as a
  `Decision` ([SCHED-30]). *Gate:* `gate:layer0-determinism`,
  `gate:harness-lint`. *Spec:* §15.5; cross-ref 04, 08 §8.9.4.

- **[IO-22]** Every completion/response time a sub-node emits MUST be a
  **deterministic function of the request icount plus the modeled latency**
  ([IO-2], [IO-10], [IO-20]); no completion time may be derived from the host
  device's measured latency, the host clock, or host scheduling ([DET-19],
  [INV-1]). Two runs of the same `(ScenarioDef, Seed, Schedule)` MUST produce
  byte-identical device responses at byte-identical delivery icounts. *Gate:*
  `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §15.5.

- **[IO-23]** A sub-node's **device RNG state MUST be part of its
  `MaterializedState` contribution** ([`07-temporal-graph.md`](07-temporal-graph.md)
  §3, [TEMP-7]): the stream position is captured on snapshot and restored exactly
  on resume, so the next probabilistic draw resolves identically after a pause as
  it would have without one ([EXEC-13]). A `MaterializedState` that omits a
  device's RNG position MUST fail the replay oracle ([TEMP-10], [TEMP-20]).
  *Gate:* `gate:replay-oracle`. *Spec:* §15.5; cross-ref 07 §3, §6.

- **[IO-24]** No I/O sub-node MAY use an unordered-collection iteration order, a
  default/randomized hasher, or any host nondeterminism source on a path that
  produces a response field or a completion icount ([INV-9]). All
  ordering-significant collections (overlay page maps captured for a delta,
  directory enumerations, in-flight response queues) MUST be deterministically
  ordered. *Gate:* `gate:harness-lint`. *Spec:* §15.5; cross-ref 08 §8.6.

## 15.6 Fault injection on I/O is uniform with network faults

The fault model for block and 9p I/O is **the same model as the network link**:
a fault perturbs the modeled completion/response, never the host I/O. This is the
unification that lets the fault taxonomy of
[`17-fault-injection.md`](17-fault-injection.md) cover disk, filesystem, and
network with one vocabulary.

```text
  fault           on a network link            on a block/9p request
  ───────         ──────────────────           ─────────────────────
  latency         shift delivery_vt later       shift response delivery_vt later
  jitter          shift delivery_vt (seeded)     shift response delivery_vt (seeded)
  loss/failure    drop the frame                 return an error-status response (or drop)
  reorder         shift delivery_vt past a peer   shift one response past another
  duplicate       emit a second frame            emit a second (duplicate) response
  corrupt         flip seeded bits in payload     flip seeded bits in read data
  bandwidth       add serialization delay        add transfer delay ∝ count
```

- **[IO-25]** I/O fault injection on block and 9p sub-nodes MUST be **uniform
  with network-link fault injection**: a latency or jitter fault MUST shift the
  response's `delivery_icount`; a failure/loss fault MUST return an error-status
  response (or drop the response per the fault's semantics); a reorder fault MUST
  shift one response's delivery past another's; a duplicate fault MUST emit an
  additional response; a corruption fault MUST flip seeded bits in the read
  payload; a bandwidth limit MUST add a transfer delay proportional to the byte
  count. Every such perturbation MUST be applied to the **modeled completion/
  response**, never to the host I/O, and MUST be drawn from the seeded device RNG
  ([IO-21]). *Gate:* `gate:layer1-injection`. *Spec:* §15.6; cross-ref 17.

- **[IO-26]** I/O faults MUST be expressed in the **same fault taxonomy and
  activation mechanism** as network faults ([`17-fault-injection.md`](17-fault-injection.md)):
  a fault is activated by the Plan at an exact virtual time ([SCHED-29] fault
  activation), targets a device by its content-addressed identity, and is healed
  by its tag. The set of active I/O faults MUST be part of the scheduler state
  captured in `MaterializedState` ([TEMP-7], [TEMP-10]). *Gate:*
  `gate:layer1-injection`, `gate:replay-oracle`. *Spec:* §15.6; cross-ref 07 §3,
  17.

## 15.7 Devices are testable against the in-process double

Because each device is a node with a request inbox and a response outbox, it is
**testable without a real QEMU**: the in-process QEMU test double of
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §"in-process
double" drives a device by enqueueing requests and advancing its clock,
asserting the responses and their delivery icounts directly. This is the layer
at which most device determinism is proved in milliseconds, before any real-VM
run.

- **[IO-27]** Each I/O sub-node MUST be exercisable by the **in-process test
  double** ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)):
  a test MUST be able to construct a sub-node, enqueue a sequence of requests,
  advance its clock to a limit, and assert the emitted responses, their delivery
  icounts, and the resulting overlay/fid state — all in-process, with no real
  QEMU and no host VM. The device's `advance_to(limit_icount)` MUST drain exactly
  the responses whose `delivery_icount <= limit` and advance the clock to the
  earlier of `limit` or the next pending completion. *Gate:*
  `gate:layer0-determinism`, `gate:layer1-injection`. *Spec:* §15.7; cross-ref
  24.

- **[IO-28]** Each sub-node MUST satisfy a **run-twice determinism test** under
  the in-process double: two independent constructions driven through the same
  request sequence and the same seed MUST produce byte-identical responses,
  delivery icounts, overlay deltas, and RNG end-positions. A divergence MUST
  localize to the first differing response via the divergence path ([INV-10],
  `gate:divergence-bisect`). *Gate:* `gate:layer1-injection`,
  `gate:divergence-bisect`. *Spec:* §15.7; cross-ref 24.

## 15.8 Spike: does the guest idle or busy-poll during a blocking I/O?

The model above assumes that while a blocking disk/9p read is outstanding **the
requesting guest has no runnable work and idles (HLT)**, so the scheduler can
fast-forward it to the exact completion ([IO-3], [SCHED-28]). That assumption is
**load-bearing for performance, not for correctness**, and it has a known risk
that this section flags as a spike.

The two guest behaviors during a blocking I/O wait:

- **Idle (HLT).** The guest issues the request, then halts the vCPU until an
  interrupt (the I/O completion) wakes it. The scheduler sees the requester's
  next exact local event *is* the completion, fast-forwards its clock to that
  instant at zero wall-clock cost, and the run is both correct and fast. This is
  the common, desirable case (a Linux guest blocking on a synchronous read does
  exactly this).

- **Busy-poll.** The guest spins on a status register or a completion flag
  instead of halting (some drivers, some polled-I/O configurations, some
  firmware paths do this). This is **still perfectly deterministic** — the spin
  retires a deterministic number of instructions, and the completion still lands
  at its exact icount — but it **defeats idle fast-forward**: the scheduler
  cannot collapse the wait to a single jump, because the guest is retiring
  instructions the whole time, so the wait costs real wall-clock proportional to
  the spin. **This is a performance problem, not a correctness problem.**

The spike is therefore: *characterize how common busy-polling is for the guest
configurations Crucible targets, and decide whether a mitigation is warranted*
(e.g. detecting a tight poll loop on an I/O-status address and electing to
fast-forward it). The mitigation, if any, MUST preserve exactness — it may only
collapse a span the guest would have spun through with a deterministically
identical outcome. This is forward-referenced to
[`30-risks-spikes.md`](30-risks-spikes.md).

- **[IO-29]** Crucible MUST remain **bit-correct regardless of whether a guest
  idles (HLT) or busy-polls** while a blocking I/O is outstanding: the completion
  lands at its exact computed icount either way ([IO-2]). The idle-during-I/O
  assumption ([IO-3]) is a **performance optimization only** — when the guest
  idles, the scheduler fast-forwards it to the completion ([SCHED-28]); when the
  guest busy-polls, the run is slower but identical. A correctness claim MUST NOT
  depend on the guest halting. *Gate:* `gate:single-vm-fingerprint`,
  `gate:e2e-determinism`. *Spec:* §15.8; forward-ref 30.

- **[IO-30]** The prevalence and performance impact of guest busy-polling during
  blocking I/O MUST be characterized as a **spike** ([`30-risks-spikes.md`](30-risks-spikes.md)),
  and any busy-poll fast-forward mitigation it motivates MUST preserve exactness
  — it may collapse only a span whose deterministic outcome is provably identical
  to running it instruction-by-instruction. No mitigation may change which
  instruction observes the completion. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §15.8; forward-ref 30.

## 15.9 Summary

```text
I/O is a UNIFORM scheduling sub-node (disk / 9p / net link), each with:
  its own icount-derived clock (IO-1) advanced only by the one scheduler (08)
  completion = a SCHEDULED EVENT, not a virtual-time freeze (IO-2)
    completion_vt = vt(request_icount) + modeled latency
    = the requester's next EXACT LOCAL EVENT, fast-forwardable (IO-3, SCHED-28)
block:  read-only content-addressed base + 4 KiB CoW overlay + dirty tracking (IO-5..7)
        read/write/flush/get-length over a versioned wire ABI on shmem (IO-6,8,9)
        snapshot = overlay delta + RNG + inflight (07 §3); materialize-to-image (IO-11,12)
        base image NEVER mutated (INV-5)
9p:     read-only 9P2000.L; path-hashed QIDs, sorted readdir, fixed attrs (IO-13..16)
        read/traverse subset; writes -> EROFS; versioned+fuzzed ABI (IO-17,18,19)
request lifecycle: COMPUTE (host FS/overlay, any wall-clock) then DELIVER at the
        exact icount; in-flight queue head = next exact local event (IO-31)
        full ring => deterministic backpressure, never drop/reorder (IO-32)
net link: latency/jitter/loss/reorder/dup/corrupt/bandwidth as deterministic
        perturbations of delivery icount / payload, seeded (IO-20)
        link = the ONE conservative-uncertainty source; supplies lookahead;
        latency floor + recompute on change; reorder stays in the future (IO-33,34)
determinism: seeded per-device RNG forked by name-hash; RNG state in
        MaterializedState; all times pure fns of request icount + latency (IO-21..24)
faults: I/O faults are UNIFORM with network faults — perturb the modeled
        completion/response, never host I/O (IO-25,26)
testing: every device is a node, run-twice-diffable against the in-process
        double without real QEMU (IO-27,28)
spike:  guest HLT vs busy-poll during I/O — busy-poll stays correct but defeats
        fast-forward (perf, not correctness) (IO-29,30)
```

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is I/O sub-nodes, tracked here by [PLAN-3]. They
> populate Phase 1 (the determinism / harness / transport foundation), sequenced
> after the L1 shmem ABI and scheduler primitives and before any L3+ feature.

- [x] **T-IO-1** Define the uniform I/O sub-node trait (icount-derived clock,
  request inbox / response outbox over shmem, `advance_to(limit_icount)` draining
  due responses, snapshot/restore) shared by disk, 9p, and net-link nodes; make
  every completion time and probabilistic device choice a deterministic function of
  `(request icount, modeled latency, per-device RNG draw)` only, with no host
  wall-clock/scheduling/FS/inode dependence. — satisfies [IO-1], [IO-2], [IO-3],
  [IO-4]; spec §15.1.
  Completed by `checks.crucible.phase3.ioSubnodeTrait`.
  `IoSubNode` is the shared lifecycle contract for disk, 9p, and network-link
  scheduling sub-nodes: `enqueue_request` computes deterministic completions from
  request icount, modeled latency, fixed shift, and an already-recorded
  per-device RNG draw; `advance_to(limit_icount)` drains only due responses into
  the response outbox while monotonically advancing the sub-node clock;
  `next_exact_local_event` reports the head in-flight delivery icount; and
  `snapshot`/`restore` preserve and validate the current icount, in-flight
  queue, and outbox state.
  The reusable `DeterministicIoSubNode` gate model rejects non-I/O scheduler
  nodes, invalid icount shifts, backward clock movement, forged snapshots, and
  deterministic queue overflow without dropping or reordering work; keeps the
  response outbox sorted by delivery icount, sub-node, and sequence across
  multiple advances; converts completions into scheduler `IoCompletion` payloads
  at exact delivery icounts; and has no host wall-clock, scheduling,
  filesystem-order, or inode input in its completion calculation.
  Summary: no host wall-clock, scheduling, filesystem-order, or inode input can
  affect completion icounts, payload bytes, or ordering.
  Summary: response outbox sorted by delivery icount, sub-node, and sequence
  after every advance.
- [x] **T-IO-2** Implement the block sub-node base+overlay: read-only
  content-addressed base image, in-memory 4 KiB CoW page overlay, page-wise read
  (overlay-over-base) and write (copy-up to overlay), dirty-page tracking; assert
  the base image is never mutated. — satisfies [IO-5], [IO-6], [IO-7]; spec
  §15.2.1.
  Completed by `checks.crucible.phase3.blockSubnodeOverlay`.
  `BlockBaseImage` stores an immutable content-addressed base image whose
  supplied bytes must hash to the advertised `ContentAddressedBlobRef`.
  `BlockSubNodeOverlay` layers deterministic, ordered 4 KiB copy-on-write overlay pages
  over that base: reads resolve overlay pages before falling back
  to the base, writes copy the whole base page into the overlay before patching
  it, `flush` is a no-op success, and `get_length` reports the fixed base size.
  Dirty tracking records only the dirty pages since the last checkpoint boundary,
  captures full 4 KiB pages in ascending page offset order, and clears the dirty
  set after capture so successive deltas remain disjoint. Range checks reject
  overflow and any read or write beyond the fixed device length without
  truncating or extending the device.
  Summary: the base image is never mutated; all guest writes land only in the
  in-memory overlay.
- [x] **T-IO-3** Implement the block wire ABI (versioned request/response codec,
  fixed field order/endianness, reserved-byte rules, bounds-checked decode) and
  carry it over the `SLOT_BLK_IO` shmem rings with `delivery_icount` set to the
  computed completion. — satisfies [IO-8], [IO-9]; spec §15.2.2.
  Completed by `checks.crucible.phase3.blockWireAbi`.
  `PluginBlockIo` encodes VM requests into the `(vm slot -> SLOT_BLK_IO)`
  shared-memory ring and polls responses from the `(SLOT_BLK_IO -> vm slot)`
  shared-memory ring. `BlockRequest` and `BlockResponse` use block wire version
  1, fixed little-endian field order, exact fixed header sizes, and
  `MAX_FRAME_DATA` bounds before `FrameEntry` construction; reserved bytes are zero on emit and rejected on decode; unknown operation/status values,
  unsupported versions, short frames, count-over-payload frames, and trailing
  payload bytes all fail as typed `BlockWireError` values without parsing past
  bounds. Response frames are accepted only from the reserved block slot, and
  `FrameEntry.delivery_icount` is the computed completion icount controlling
  visibility by `delivery_icount <= consumer.current_icount`.
  Summary: block request/response frames use the versioned ABI exclusively over
  `SLOT_BLK_IO` shared-memory rings; no separate per-request IPC channel is used.
- [x] **T-IO-4** Implement the block deterministic completion model
  (`completion_vt = vt(request_icount) + latency(op, count, params)`, no host
  timing) and total-order delivery of coincident responses. — satisfies [IO-10],
  [IO-22]; spec §15.2.3.
  Completed by `checks.crucible.phase3.blockCompletionModel`.
  `BlockLatencyParameters` computes modeled latency as a deterministic function of operation, byte count, and configured latency parameters; no host measured I/O time or wall-clock input participates. `BlockCompletionRequest::plan`
  implements `completion_vt = vt(request_icount) + latency(op, count, params)`
  with the fixed `Shift` and [TIME-4] ceil map to produce `delivery_icount`, then
  bridges the planned completion into the uniform `IoSubNodeRequest` path.
  Coincident block responses are sorted in `(delivery_icount, src_node, seq)` order, and overflow, invalid shifts, non-disk producers, and non-VM requesters
  fail loudly before a completion can be enqueued.
- [x] **T-IO-5** Implement block snapshot/restore as a CoW overlay delta over the
  parent plus device RNG position plus in-flight responses (never the base
  image), and the materialize-to-image hand-off for real-time QEMU. — satisfies
  [IO-11], [IO-12], [IO-23]; spec §15.2.4; cross-ref 07, 22.
  Completed by `checks.crucible.phase3.blockSnapshotRestore`.
  `BlockSubNodeSnapshot` captures a `BlockOverlayDelta` of dirty pages over the parent overlay, `DeviceRngState` stream positions, sorted in-flight
  `IoSubNodeCompletion` responses, `clock_icount`, and device `length`; it
  references the content-addressed base but never embeds base image bytes.
  `BlockSubNodeOverlay::restore_snapshot` validates the base reference, length, page alignment, strict page order, page size, and bounds before stacking the
  delta over the parent overlay and returning the RNG/in-flight/clock runtime
  state with in-flight responses normalized to deterministic order.
  `materialize_image` writes base bytes and then every live overlay page into a
  standalone raw image without mutating the immutable base.
- [x] **T-IO-6** Implement the read-only 9P2000.L server with path-hashed QIDs
  (not host inodes), fixed QID version, sorted directory enumeration, and fixed/
  content-derived getattr/statfs attributes; negotiate fixed version +
  deterministic msize. — satisfies [IO-13], [IO-14], [IO-15], [IO-16]; spec
  §15.3.1.
  Completed by `checks.crucible.phase3.ninePSubnodeServer`.
  `NinePServedTree` is an in-memory read-only 9P2000.L served-tree model with
  QID `path` values derived from a stable hash of the path within the served
  tree, fixed `NINEP_FIXED_QID_VERSION`, and no host inode, filesystem metadata, timestamp, uid/gid, or directory iteration input. `readdir` sorts child names lexicographically and assigns offsets after sorting; repeated enumeration is
  byte-identical. `getattr` and `statfs` return fixed or content-derived
  attributes, including fixed epoch/root uid/root gid/block size, no advertised
  write permission bits, and 512-byte size-derived block counts. `statfs.fsid` is
  the fixed synthetic zero value and ignores negotiation msize. Version
  negotiation accepts only `9P2000.L` and deterministically
  chooses `msize = min(client_msize, server_maximum_msize)`.
- [x] **T-IO-7** Implement the 9p read/traverse message set, the EROFS boundary
  for all mutating messages, ENOSYS/EINVAL handling, msize enforcement, and
  deterministic fid-state management with snapshot/restore. — satisfies [IO-17],
  [IO-19]; spec §15.3.2.
  Completed by `checks.crucible.phase3.ninePSessionLifecycle`.
  `NinePSession` handles the high-level Tversion/Tattach/Twalk/Tlopen/Tread/Treaddir/Tgetattr/Treadlink/Tclunk/Tstatfs/Tflush/Txattrwalk request set over `NinePServedTree`, derives modeled request sizes including minimum 9P2000.L fixed fields before the negotiated `msize` guard, rejects undersized negotiated/restored msize values, enforces negotiated `msize` before mutating fid state, clamps `Tread` payloads and `Treaddir` byte-budgeted entries to the negotiated message budget, rejects every `NinePMutatingMessage` with `NINEP_EROFS`, maps unknown requests to `NINEP_ENOSYS`, and maps malformed request bodies to `NINEP_EINVAL` or `NINEP_EIO`.
  `Tversion` deterministically resets the fid table. The fid table stores fid-to-path bindings plus open kind, keeps xattr fids as distinct empty file-like targets, caches sorted directory entries on `Tlopen`, and `NinePSessionSnapshot` persists negotiated msize plus fid snapshots while restore reconstructs file handles and directory caches from the read-only tree.
- [x] **T-IO-8** Add 9p wire-format golden vectors and a fuzzer (arbitrary bytes
  in: never panic, never OOB, always well-formed response or 9p error) feeding
  `gate:abi-conformance`. — satisfies [IO-18]; spec §15.3.2; forward-ref 24.
  Completed by `checks.crucible.phase3.ninePWireAbi` and wired into canonical `gate:abi-conformance` through `checks.crucible.phase2.gates.abiConformance`.
  `NinePSession::handle_wire_request` decodes raw 9P2000.L headers and bodies, rejects size mismatches or messages larger than the negotiated msize before dispatch, maps unknown message types to `Rlerror(ENOSYS)`, maps malformed supported messages to `Rlerror(EINVAL)`, and serializes every high-level response back into a well-formed 9p message.
  The focused ABI test carries exact 9P2000.L wire golden vectors for version negotiation, unknown/mutating/malformed errors, and read data, plus deterministic arbitrary-byte fuzz coverage that catches panics and checks every output frame's declared size.
- [x] **T-IO-9** Implement the network-link sub-node model: base latency sets
  delivery icount; latency/jitter/reorder/bandwidth shift it; loss drops;
  duplicate emits a second frame; corrupt flips seeded payload bits — all over
  `SLOT_NET_ROUTER`, applied at RESOLVE per the effective fault table. —
  satisfies [IO-20]; spec §15.4.1; cross-ref 08, 17.
  Completed by `checks.crucible.phase3.networkLinkSubnode` and wired into
  canonical `gate:layer1-injection` through the `network_link_subnode` test
  target.
  `NetworkLinkSubNode` models directed inter-VM frames over the reserved
  `SLOT_NET_ROUTER` network producer: source and target endpoints must be VM
  scheduler nodes backed by the declared `LinkDef`, base latency is computed
  from the source emit icount, bandwidth serialization delay, seeded link
  jitter, effective extra latency, and seeded reorder delay shift the delivery
  icount, and loss suppresses all output before duplicate/corruption are
  applied.  Duplicate emits a second deterministic delivery with a distinct
  event sequence, corruption flips a seeded payload bit, and the resulting
  deliveries bridge to scheduler `BackendInput` events that preserve the source
  VM as producer while passing through the modeled router slot.
  Summary: latency, jitter, reorder, bandwidth, loss, duplicate, and corruption
  are pure modeled perturbations of delivery icount and payload, with no host
  timing, filesystem, or scheduling input.
- [x] **T-IO-10** Implement per-device seeded RNG forked by name-hash, with every
  probabilistic device choice drawn from it in deterministic order and recorded
  as a `Decision`; route through `gate:harness-lint` (no unordered iteration /
  default hasher on response paths). — satisfies [IO-21], [IO-24]; spec §15.5;
  cross-ref 04, 08.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible --lib
  device`, `cargo test --manifest-path crates/Cargo.toml -p crucible-device`,
  `cargo test --manifest-path crates/Cargo.toml -p crucible`, and
  the focused `crucible-harness` `harness_lint`
  `reduction_path_sources_have_no_banned_nondeterminism` subtest.
  `device_rng` forks the per-device stream through the same name-hashed
  `RngStreamId::for_device` and SplitMix64 cursor convention as the engine
  decision RNG, `DeviceSchedulingSubNode` records block/9p raw draws followed by
  loss/duplicate/corrupt `FaultFires` decisions, and
  `emit_link_frame_with_recorded_faults` records the network-link jitter,
  reorder, loss, duplicate, corrupt, and corrupt-bit draws consumed by the real
  `NetLink` emission path. The link regression proves first emit and resumed
  cursor behavior against independently restored device-stream values. Future
  live link integration must use the recording helper, not the draw-discarding
  convenience API.
  Summary: all modeled probabilistic device choices are drawn from deterministic
  device streams and have an engine-side decision-recording path; the relevant
  reduction-path lint bans unordered/default-hasher response nondeterminism.
- [x] **T-IO-11** Wire device RNG state and active I/O faults into the device half
  of `MaterializedState`, proving a snapshot that omits RNG position or active
  faults fails the replay oracle. — satisfies [IO-23], [IO-26]; spec §15.5,
  §15.6; cross-ref 07 §3, §6.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible --lib
  device` and `cargo test --manifest-path crates/Cargo.toml -p crucible-device`.
  `DeviceOverlayDelta` carries a `DeviceRngState` keyed by the canonical device
  RNG stream, and `with_active_io_faults` folds the active I/O fault table into
  `SchedulerState.active_faults`; both feed the canonical `MaterializedState`
  hash. The replay-oracle test builds a faithful fat checkpoint with a non-zero
  device RNG cursor plus active jitter/loss faults, proves it replays, then proves
  checkpoints omitting either the cursor or active faults are rejected. A stripped
  hash-mode negative control proves the test would go red if the device cursor or
  active faults stopped affecting the state id. Block, 9p, and link snapshots
  also carry their concrete fault tables and RNG cursors.
  Summary: device RNG cursors and active I/O faults are materialized state, not
  hidden process state; omitting either is replay-oracle visible.
- [x] **T-IO-12** Implement uniform I/O fault injection (latency/jitter/failure/
  reorder/duplicate/corrupt/bandwidth) on block and 9p as perturbations of the
  modeled completion/response, sharing the fault taxonomy and activation
  mechanism with network faults. — satisfies [IO-25], [IO-26]; spec §15.6;
  cross-ref 17.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible-device`
  and `cargo test --manifest-path crates/Cargo.toml -p crucible --lib
  device_subnode`.
  `IoFaults` is the shared block/9p completion fault table using the same
  integer-only taxonomy as `LinkFaults`: latency and bandwidth add deterministic
  virtual-time shifts; jitter and reorder consume seeded shifts; loss maps a
  completion to an error-status response; duplicate emits a second response; and
  corruption flips seeded payload bits. `BlockDevice` and `NinepDevice` snapshot
  both the active fault table and RNG cursor. `DeviceSchedulingSubNode` resolves
  block requests and raw 9p frames through the same sorted modeled-completion
  path, updates the concrete device cursor from the same RNG stream, and exposes
  the final post-fault `delivery_icount` to the scheduler. Active I/O faults fold
  into scheduler state with the same device-scoped `FaultId` namespace used for
  network-link faults.
  Summary: block and 9p faults perturb modeled completions/responses, not host
  I/O, and use the same taxonomy and activation-state shape as network faults.
- [x] **T-IO-13** Build the in-process device test harness (construct node,
  enqueue requests, advance clock, assert responses + delivery icounts + overlay/
  fid state) and the per-device run-twice determinism + divergence-localization
  tests. — satisfies [IO-27], [IO-28]; spec §15.7; cross-ref 24.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible-device
  --test device_harness`.
  The `HarnessDevice` adapters project block, 9p, and network-link sub-nodes onto
  one in-process script surface: request/emit at chosen icounts, advance the
  device clock, and drain normalized delivery records keyed by
  `(delivery_icount, src_node, seq)`. The tests assert block overlay/dirty-page
  state, 9p fid/negotiated-msize state, link delivery streams, per-device
  run-twice byte identity, and deterministic first-difference localization for
  block payload drift, 9p fid/content drift, and link payload corruption drift.
  Summary: every I/O sub-node has a no-QEMU harness that can assert visible state,
  delivery icounts, run-twice determinism, and localized divergence.
- [x] **T-IO-14** Prove correctness is independent of guest idle-vs-busy-poll
  (completion lands at its exact icount either way) and record the busy-poll
  prevalence/mitigation spike; any mitigation preserves exactness. — satisfies
  [IO-29], [IO-30]; spec §15.8; forward-ref 30.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible-device
  --test device_harness`.
  `idle_busy_poll_equivalence` runs the same device script through both one-shot
  idle fast-forward and one-icount-at-a-time busy-poll advancement, then compares
  byte-identical delivery logs. Block, 9p, and link tests all assert nonempty
  idle/busy equivalence, and a bounded-outbox block regression proves the idle
  path drains all coincident completions instead of truncating at outbox capacity.
  `BUSY_POLL_SPIKE` records the §15.8 result: correctness is independent of poll
  mode, busy-poll is a performance concern only, and any mitigation must preserve
  exact delivery.
  Summary: exact completion visibility is independent of whether the consumer
  idles or polls; busy-poll remains a performance issue, not a correctness input.
- [x] **T-IO-15** Implement the request/response lifecycle: COMPUTE-then-DELIVER
  split (host access decoupled from virtual-time visibility), an in-flight
  response queue ordered by `delivery_icount` exposed as the sub-node's
  `next_exact_local_event`, and deterministic full-ring backpressure (block-and-
  wake, never drop/reorder). — satisfies [IO-31], [IO-32]; spec §15.1.1;
  cross-ref 08, 13.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible-device
  --test io_subnode_lifecycle`, `cargo test --manifest-path crates/Cargo.toml
  -p crucible-device`, and `cargo test --manifest-path crates/Cargo.toml -p
  crucible`.
  `IoCore::process_shmem_inbox` drains real VM-to-device `RingHeader`/
  `FrameEntry` rings, wakes the freed producer slots, and computes block/9p
  responses into the existing in-flight queue without making them visible early.
  `IoCore::advance_to_shmem` publishes only due responses to the device-to-VM
  ring, wakes the consumer slot on delivery, and requeues unpublished due
  responses at their original `delivery_icount`s when the response ring is full.
  `IoCore::dequeue_shmem_frame_and_wake_producer` covers the slot-free wake path
  for device-to-VM rings. The block and 9p lifecycle tests exercise real shmem
  rings, request-ring full/retry, response-ring full/retry with preserved order,
  and slot wakes on both sides.
  Summary: block and 9p request/response lifecycles now use real shmem rings
  while preserving COMPUTE-then-DELIVER visibility, exact next-event ordering,
  deterministic full-ring backpressure, and producer/consumer wakes.
  `checks.crucible.phase2.qemuLiveBlockIo` supplies the final real-backend
  discharge: a Linux guest's explicit sector write is computed by the host
  servicer, remains invisible until its future delivery icount, then crosses
  `SLOT_BLK_IO` and releases the guest. Delaying response publication by 100 ms
  under host CPU load changes neither the modeled completion horizon nor the
  normalized request/delivery stream.
- [x] **T-IO-16** Wire the link into the scheduler's lookahead: enforce the
  positive latency floor at the link, clamp sub-floor latency faults, trigger the
  lookahead/horizon recompute on any conservative effective-latency-bound change
  at the quantum boundary, and clamp/fail-loud reorder shifts that would land in
  the consumer's past. — satisfies [IO-33], [IO-34]; spec §15.4.2; cross-ref 08
  §8.7, §8.11, 13 §13.9.
  Completed by `cargo test --manifest-path crates/Cargo.toml -p crucible-device`
  and `cargo test --manifest-path crates/Cargo.toml -p crucible --test
  scheduler_topology_change`.
  `NetLink` rejects zero/sub-floor base latency, clamps effective latency to its
  strictly-positive floor, raises a one-shot recompute flag when the conservative
  minimum latency bound changes, and guards reorder/jitter deliveries with either
  fail-loud or future-clamp policy. `SingleScheduler::schedule_link_latency_recompute`
  validates the flagged edge before consuming the flag, incrementally updates the
  existing directed effective lookahead edge with the link's current
  `effective_latency_ns`, freezes cross-node sends while the change is pending,
  and lets the existing topology-change pipeline recompute node lookahead before
  the next PICK. Incremental edge updates preserve unrelated pending recomputes
  and do not restore edges removed by a partition.
  Summary: live link latency changes now flow into scheduler lookahead at the
  quantum boundary; stale sends are frozen until the recompute applies.
