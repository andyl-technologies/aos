# 14 — IPC control protocol (host ↔ plugin)

This file specifies the **out-of-band control protocol** between the host
executor (`crucible-qemu`) and the in-VM plugin (`crucible-qemu-plugin`,
[`12-qemu-plugin.md`](12-qemu-plugin.md)). It is a small, framed, request/reply
channel over a Unix socket pair, used for exactly three jobs: the **handshake**,
the **setup** (handing the plugin its shared-memory region, its node slot, and
its wake fd), and **shutdown**. It is deliberately *not* a data channel — every
per-frame, per-quantum synchronization happens in the shared-memory region
([`13-shmem-abi.md`](13-shmem-abi.md)) over the hot path. The control channel is
quiescent for the entire run between setup and teardown.

Requirement IDs in this file use the `PROTO` prefix (see
[`00-conventions.md`](00-conventions.md)). The protocol is one of the three
versioned boundary ABIs of [G-8] and is guarded by `gate:abi-conformance`; its
inertness when sim mode is off is guarded by `gate:qemu-inert`; its
responsiveness to control operations is guarded by `gate:control-responsive`
(gates defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)).
Like the shared-memory data plane, this is a public process protocol that either
side can implement without the other's private code; see
[`37-licensing-process-boundary.md`](37-licensing-process-boundary.md).

## 1. Scope and the control/data split

The protocol carries **control**, never **data**. Concretely:

- **Control (this file):** the version handshake, the one-time delivery of the
  shmem file descriptor and the wake file descriptor, the assignment of the
  node's slot index, and the shutdown command. These messages happen once at
  connection setup and once at teardown; the channel is otherwise silent.
- **Data (not this file):** virtual-time advancement, idle/resume signalling,
  per-frame queue delivery, status, and the per-node clock cell. All of it lives
  in the shmem region ([`13-shmem-abi.md`](13-shmem-abi.md)) and is exchanged via
  lock-free atomics and SPSC ring queues, with a wake fd
  ([`13-shmem-abi.md`](13-shmem-abi.md) §wake) used only as an edge-triggered
  "look at shmem now" nudge.

- **[PROTO-1]** The control protocol MUST carry only handshake, fd/slot setup,
  and shutdown messages. It MUST NOT carry virtual time, frame payloads, idle
  state, status, or any per-quantum synchronization; all of those MUST flow
  through the shmem region of [`13-shmem-abi.md`](13-shmem-abi.md). *Gate:*
  `gate:abi-conformance`. *Spec:* §1, §3.

  *Rationale.* Splitting control from data keeps the hot path free of socket
  round trips, payload copies, and serialization: a quantum advances by writing
  a u64 to a shmem cell and issuing the current non-private futex wake, not by
  sending a socket message. The wake is currently unconditional, so this is not
  a zero-syscall claim; a future waiter-armed optimization may skip it when no
  peer is parked. The split also keeps the
  protocol tiny — a few message types with fixed-size payloads — which is what
  makes it cheaply fuzzable and golden-vector-checkable ([G-8]). And it isolates
  the determinism-critical machinery (time, ordering) into a single audited
  surface (shmem) rather than spreading it across two transports.

- **[PROTO-2]** The control channel MUST be a connected Unix **stream** socket
  pair (`AF_UNIX`, `SOCK_STREAM`), one pair per VM node, created by the host
  before launching QEMU and inherited by the plugin. Stream (not datagram) is
  REQUIRED because the setup messages pass file descriptors via `SCM_RIGHTS`
  ancillary data, and because length-prefixed framing assumes an ordered byte
  stream. *Gate:* `gate:abi-conformance`. *Spec:* §2, §3.4.

## 2. Transport and connection establishment

Each VM node gets its own control socket. The host creates a `socketpair`,
retains one end, and arranges for the other end to be the plugin's control fd
(passed to the plugin via its argument string on the QEMU `-plugin` command
line, or inherited at a well-known fd number — the exact mechanism is a
[`12-qemu-plugin.md`](12-qemu-plugin.md) concern). The plugin opens its end at
load time.

- **[PROTO-3]** The host MUST create one control socket pair per VM node and MUST
  assign each node a stable, zero-based **slot index** that matches the node's
  index in the shmem region's per-node array ([`13-shmem-abi.md`](13-shmem-abi.md)).
  The slot index is communicated to the plugin in `HelloAck` (§3.6) and is the
  sole key the plugin uses to locate its own cells in shmem. *Gate:*
  `gate:abi-conformance`. *Spec:* §3.6.

- **[PROTO-4]** The control socket MUST be a blocking, synchronous channel from
  the plugin's perspective: the plugin sends `Hello` and blocks for `HelloAck`
  before touching shmem. The host side MAY be driven asynchronously but MUST
  preserve message ordering on each per-node socket. *Gate:* `gate:abi-conformance`.
  *Spec:* §4.

## 3. Framing and wire format

### 3.1 Frame layout

Every message is a single length-prefixed frame:

```text
 offset  size  field
 ------  ----  ---------------------------------------------------------
   0      4    length  : u32, big-endian. Count of bytes that FOLLOW the
                         length field, i.e. 1 (tag) + payload_len.
   4      1    tag     : u8. Identifies the message type (§3.3).
   5      N    payload : N bytes, tag-specific (§3.5–§3.9). N == length - 1.
```

All multi-byte integers on the wire are **big-endian** (network byte order),
including integers inside payloads, so the golden vectors are unambiguous and
endianness-independent. File descriptors are **not** part of the payload bytes;
they travel out-of-band as `SCM_RIGHTS` ancillary data attached to the frame
that references them (§3.4).

- **[PROTO-5]** Every control message MUST be encoded as one frame
  `[u32 BE length][u8 tag][payload]`, where `length` equals `1 + payload.len()`
  and all in-payload integers are big-endian. The decoder MUST treat the byte
  stream as a sequence of such frames. *Gate:* `gate:abi-conformance`. *Spec:*
  §3.1, §6.

### 3.2 Maximum frame size

The protocol's payloads are tiny and fixed in shape; an oversized length field
is always either corruption or a hostile peer.

- **[PROTO-6]** The decoder MUST reject any frame whose `length` exceeds
  `MAX_FRAME_SIZE` = **64 bytes** (a hard, compile-time constant) before reading
  the payload, returning a clean decode error and never allocating a buffer sized
  by the attacker-controlled length. Producers MUST NOT emit a frame larger than
  `MAX_FRAME_SIZE`. *Gate:* `gate:abi-conformance` (codec fuzz, [HARN-34]).
  *Spec:* §3.2, §6.

### 3.3 Tag registry

Tags are partitioned by direction so a misrouted frame is detectable. Setup and
data-plane handover tags occupy the low range; handshake tags occupy the high
range (mirroring the conventional `0xF0`/`0xF1` handshake numbering).

```text
 tag    name          direction          payload (§)
 ----   -----------   ----------------    -----------
 0x01   Setup         host  -> plugin     §3.7  (+ SCM_RIGHTS fds, §3.4)
 0x02   SetupAck      plugin -> host      §3.8
 0x12   Quit          host  -> plugin     §3.9  (empty)
 0xF0   Hello         plugin -> host      §3.5  [u32 BE proto_version,
                                                  u32 BE abi_version]
 0xF1   HelloAck      host  -> plugin     §3.6  [u32 BE proto_version,
                                                  u32 BE abi_version,
                                                  u32 BE slot_index,
                                                  u32 BE node_count]
```

- **[PROTO-7]** The tag value space is a closed registry: `0x01` Setup, `0x02`
  SetupAck, `0x12` Quit, `0xF0` Hello, `0xF1` HelloAck. A decoder that reads any
  other tag MUST reject the frame with an `UnknownTag` error and MUST NOT crash,
  block, or read out of bounds. A new message type requires a new tag plus a
  protocol-version bump (§4) and regenerated golden vectors (§6). *Gate:*
  `gate:abi-conformance`. *Spec:* §3.3.

### 3.4 Descriptor passing (`SCM_RIGHTS`)

The shmem region and the wake fd are kernel objects, not bytes, so they are
passed as ancillary data on the control socket rather than serialized into a
payload.

- **[PROTO-8]** The host MUST hand the plugin exactly two file descriptors — the
  **shmem fd** (a `memfd` or equivalent mapping the region of
  [`13-shmem-abi.md`](13-shmem-abi.md)) and the node's **wake fd** (an `eventfd`
  used as the edge-triggered nudge) — as `SCM_RIGHTS` ancillary data attached to
  the `Setup` frame (§3.7). The fds MUST be attached in a fixed order: shmem fd
  first, wake fd second. The plugin MUST read exactly two fds from the `Setup`
  frame's ancillary data; receiving any other count MUST be a setup failure
  (§5.4). *Gate:* `gate:abi-conformance`. *Spec:* §3.4, §3.7.

- **[PROTO-9]** The descriptors MUST be passed once, on the `Setup` frame, and
  never again. After `Setup`/`SetupAck` the control channel carries no further
  ancillary data until `Quit`. The host MAY close its copies of the passed fds
  after `SetupAck` (the plugin holds its own). *Gate:* `gate:abi-conformance`.
  *Spec:* §3.4, §5.

### 3.5 `Hello` payload (plugin → host, tag `0xF0`)

```text
 offset  size  field
   0      4    proto_version : u32 BE. Highest control-protocol version the
                               plugin speaks (§4).
   4      4    abi_version   : u32 BE. Shmem ABI version the plugin was built
                               against (the version constant of
                               13-shmem-abi.md).
```

- **[PROTO-10]** `Hello` MUST be the first frame the plugin sends and MUST carry
  the plugin's `proto_version` and the shmem `abi_version` it was compiled
  against. The plugin MUST NOT map or read the shmem region before it has sent
  `Hello` and received a successful `HelloAck`. *Gate:* `gate:abi-conformance`.
  *Spec:* §3.5, §4.

### 3.6 `HelloAck` payload (host → plugin, tag `0xF1`)

```text
 offset  size  field
   0      4    proto_version : u32 BE. The single negotiated protocol version
                               the host has chosen (<= the plugin's; §4).
   4      4    abi_version   : u32 BE. The shmem ABI version the host built the
                               region with. MUST equal the plugin's abi_version.
   8      4    slot_index    : u32 BE. This node's zero-based index into the
                               shmem per-node array (PROTO-3).
  12      4    node_count    : u32 BE. Total number of nodes in the region, so
                               the plugin can bounds-check slot_index.
```

- **[PROTO-11]** `HelloAck` MUST carry the negotiated `proto_version`, the host's
  `abi_version`, the node's `slot_index`, and the `node_count`. The plugin MUST
  verify `slot_index < node_count` and MUST verify the `abi_version` cross-check
  of [PROTO-13] before proceeding to `Setup`. *Gate:* `gate:abi-conformance`.
  *Spec:* §3.6, §4.

### 3.7 `Setup` (host → plugin, tag `0x01`)

`Setup` carries the two descriptors as ancillary data (§3.4). Its byte payload
is the shmem region size, so the plugin can `mmap` exactly the right length and
reject a truncated region.

```text
 offset  size  field
   0      8    region_len : u64 BE. Total byte length of the shmem region to
                            map. MUST match the region length implied by
                            node_count and the layout of 13-shmem-abi.md.
 -- ancillary (SCM_RIGHTS): [shmem_fd, wake_fd] in that order (PROTO-8) --
```

- **[PROTO-12]** The host MUST send `Setup` after `HelloAck`, carrying
  `region_len` and the two descriptors (§3.4). The plugin MUST `mmap` the shmem
  fd for exactly `region_len` bytes, validate the region header/ABI marker per
  [`13-shmem-abi.md`](13-shmem-abi.md), arm the wake fd, and only then reply
  `SetupAck`. *Gate:* `gate:abi-conformance`. *Spec:* §3.7, §5.

### 3.8 `SetupAck` (plugin → host, tag `0x02`)

```text
 offset  size  field
   0      1    status : u8. 0x00 = ready; non-zero = setup failure code (§5.4).
```

- **[PROTO-13]** `SetupAck` with `status == 0` signals the plugin has mapped the
  region, validated the ABI, and is ready to run via shmem. A non-zero status
  MUST abort the run for that node (§5.4); the host MUST NOT proceed to schedule a
  node whose `SetupAck` was not `0`. *Gate:* `gate:abi-conformance`,
  `gate:control-responsive`. *Spec:* §3.8, §5.

### 3.9 `Quit` (host → plugin, tag `0x12`)

`Quit` has an empty payload (`length == 1`, tag only). It is the first rung of
the graceful-shutdown escalation (§5.3).

- **[PROTO-14]** `Quit` MUST be encoded as a tag-only frame with no payload and
  no ancillary data. On receiving `Quit`, the plugin MUST initiate orderly QEMU
  shutdown and MUST stop touching shmem. *Gate:* `gate:control-responsive`.
  *Spec:* §3.9, §5.3.

## 4. Handshake and versioning

There are **two** independent version numbers, and both are checked at the
handshake:

- `proto_version` — the version of *this* control protocol (framing, tag set,
  payload shapes). Owned by this file.
- `abi_version` — the version of the shmem layout. Owned by
  [`13-shmem-abi.md`](13-shmem-abi.md). The control protocol *transports* it for
  cross-checking but does not define it.

```text
 Plugin                                    Host
   │                                         │
   │── Hello(proto=P_p, abi=A_p) ───────────►│
   │                                         │  choose proto = min(P_p, P_h)
   │                                         │  require abi: A_p == A_h
   │◄─ HelloAck(proto, abi=A_h, slot, n) ────│
   │   (or close socket on mismatch, §5.4)   │
   │                                         │
   │── Setup-wait... ───────────────────────│
   │◄─ Setup(region_len) + [shmem_fd,wake_fd]│
   │── SetupAck(status=0) ──────────────────►│
   │                                         │
   │        ... run entirely via shmem ...    │
```

- **[PROTO-15]** Protocol-version negotiation MUST select a single version equal
  to the minimum of the plugin's offered `proto_version` and the host's supported
  maximum, and the host MUST echo the chosen version in `HelloAck`. Both sides
  MUST then speak exactly that version. If the host cannot satisfy any version the
  plugin can speak (no overlap), the host MUST refuse the connection per §5.4 and
  MUST NOT send `Setup`. *Gate:* `gate:abi-conformance`. *Spec:* §4.

- **[PROTO-16]** The shmem `abi_version` cross-check MUST be exact: the host MUST
  reject the connection if the plugin's `abi_version` does not equal the host's
  shmem-region `abi_version` ([`13-shmem-abi.md`](13-shmem-abi.md)), because the
  two sides share a byte-for-byte memory layout and a mismatch is unrecoverable.
  This check is independent of `proto_version` negotiation: a compatible control
  protocol with an incompatible shmem ABI MUST still be rejected. *Gate:*
  `gate:abi-conformance`. *Spec:* §4.

- **[PROTO-17]** Forward/backward-compatibility policy (per [G-8]): a change that
  adds a new tag, grows a payload, or alters field meaning MUST bump
  `proto_version` and regenerate the golden vectors (§6) in the same change. A
  decoder MUST reject unknown tags and over-long-or-short payloads rather than
  silently accept them; there is no "ignore unknown trailing bytes" leniency on
  this channel, so that two peers either agree on the exact wire shape or fail
  loudly at the handshake. A shmem layout change is governed separately by
  `abi_version` ([`13-shmem-abi.md`](13-shmem-abi.md)). *Gate:*
  `gate:abi-conformance`. *Spec:* §4.

## 5. Lifecycle

### 5.1 Normal lifecycle

```text
 1. connect      host creates socketpair; plugin opens its end at load.
 2. Hello        plugin -> host  (proto + abi versions)
 3. HelloAck     host -> plugin  (negotiated proto, abi, slot, node_count)
 4. Setup        host -> plugin  (region_len + [shmem_fd, wake_fd])
 5. SetupAck     plugin -> host  (status = ready)
 6. RUN          all sync via shmem cells + SPSC queues + wake fd;
                 the control socket is SILENT for the whole run.
 7. Quit         host -> plugin  (begin graceful shutdown, §5.3)
 8. teardown     plugin shuts QEMU down; host reaps the process.
```

- **[PROTO-18]** Between `SetupAck` (step 5) and `Quit` (step 7) the host and
  plugin MUST exchange **no** control frames; all run-time interaction MUST occur
  through shmem. A control frame observed during the run is a protocol error and
  MUST be treated as a node fault. This silence is what makes the channel inert on
  the hot path ([PROTO-22]). *Gate:* `gate:abi-conformance`,
  `gate:control-responsive`. *Spec:* §5.1, §7.

### 5.2 Setup ordering guarantee

- **[PROTO-19]** The plugin MUST NOT begin participating in scheduling (reading
  its clock cell, polling its frame queue, or arming the wake fd for run use)
  until `SetupAck` has been sent with `status == 0`. The host MUST NOT include a
  node in a quantum until it has received that `SetupAck`. This ordering makes the
  shmem region's initial state well-defined at the first quantum. *Gate:*
  `gate:abi-conformance`. *Spec:* §5.1, §5.2.

### 5.3 Graceful shutdown escalation

Shutdown is an escalation ladder with bounded waits so that no QEMU child is ever
leaked, regardless of how unresponsive the guest or plugin becomes. The ladder is
host-driven; each rung has a deadline, and crossing the deadline escalates.
Detailed timeout values are a host-policy concern owned by
[`10-qemu-integration.md`](10-qemu-integration.md) and the session control plane
([`20-session-control-plane.md`](20-session-control-plane.md)); this file fixes
the *order* and the *guarantee*.

```text
 rung  action                              on-timeout escalate to
 ----  ----------------------------------  ----------------------
  1    send Quit on control socket         rung 2
  2    issue QMP { "execute": "quit" }     rung 3
  3    send SIGTERM to the QEMU child      rung 4
  4    send SIGKILL to the QEMU child      rung 5
  5    waitpid()/reap the child            done (no leaked process)
```

- **[PROTO-20]** Graceful shutdown MUST follow the escalation order Quit → QMP
  quit → SIGTERM → SIGKILL → reap, with a bounded wait at each rung; if a rung's
  deadline elapses without the child exiting, the host MUST escalate to the next
  rung. The host MUST `waitpid` (reap) the child at the end so that **no QEMU
  process is ever leaked**, even when the plugin never received `Quit` and the
  guest never responded to QMP. *Gate:* `gate:control-responsive`. *Spec:* §5.3.
  *Forward-ref:* [`10-qemu-integration.md`](10-qemu-integration.md),
  [`20-session-control-plane.md`](20-session-control-plane.md).

### 5.4 Failure handling

- **[PROTO-21]** Any of the following MUST abort the node's setup cleanly and
  trigger the shutdown escalation (§5.3) rather than hang or panic:
  (a) `proto_version` has no overlap (§4); (b) `abi_version` mismatch ([PROTO-16]);
  (c) `slot_index >= node_count` ([PROTO-11]); (d) wrong ancillary fd count
  ([PROTO-8]); (e) `region_len` smaller than the layout requires, or a failed
  shmem-header/ABI-marker validation ([PROTO-12]); (f) a `SetupAck` status that is
  non-zero; (g) the control socket closing before `SetupAck`. On any of these the
  host MUST NOT schedule the node and MUST reap any spawned child. *Gate:*
  `gate:abi-conformance`, `gate:control-responsive`. *Spec:* §5.4.

## 6. Codec

The codec is a small, pure, dependency-free encoder/decoder (one per direction)
that lives in `crucible-protocol`. "Pure" here means: no global state, no
I/O inside encode/decode (frame read/write is a thin separate layer), and total
on all inputs — every byte string either decodes to a message or returns a typed
error.

- **[PROTO-22]** The codec MUST provide `encode`/`decode` functions that satisfy
  the round-trip property `decode(encode(m)) == m` for every well-formed message
  `m`, and MUST return a typed error (never panic, never read out of bounds,
  never block) for: an empty buffer, an unknown tag, a payload shorter than the
  tag requires, a payload longer than the tag requires, and a frame `length`
  exceeding `MAX_FRAME_SIZE` ([PROTO-6]). The frame read/write helpers MUST
  reject a truncated length prefix and a truncated payload as I/O errors. *Gate:*
  `gate:abi-conformance`. *Spec:* §6. *Forward-ref:*
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §8.

- **[PROTO-23]** The codec MUST be covered by `gate:abi-conformance` via (a) a
  frozen **golden-vector** corpus — canonical encodings of `Hello`, `HelloAck`,
  `Setup` (byte payload only; fd passing is verified separately), `SetupAck`, and
  `Quit` for the current `proto_version`, compared byte-for-byte ([HARN-32]) — and
  (b) **fuzzing** that feeds malformed and adversarial frames and asserts the
  decoder never panics and never reads out of bounds, with the round-trip property
  holding for all well-formed inputs ([HARN-34]). Fuzz findings MUST be added to
  the regression corpus. *Gate:* `gate:abi-conformance`. *Spec:* §6.
  *Forward-ref:* [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §8.1, §8.3.

A sketch of the message types (illustrative, per
[`00-conventions.md`](00-conventions.md) §"Code sketches"):

```rust
/// Plugin -> host control messages.
pub enum PluginMsg {
    Hello { proto_version: u32, abi_version: u32 },
    SetupAck { status: u8 },
}

/// Host -> plugin control messages. (Descriptors for `Setup` travel
/// out-of-band as SCM_RIGHTS ancillary data, not in this enum.)
pub enum HostMsg {
    HelloAck { proto_version: u32, abi_version: u32, slot_index: u32, node_count: u32 },
    Setup { region_len: u64 },
    Quit,
}
```

## 7. Determinism note

The control channel is determinism-neutral by construction.

- **[PROTO-24]** The control protocol MUST NOT carry any timing-significant data:
  no virtual time, no wall-clock value, no host-scheduling-derived ordering, and
  no per-quantum payload. Because all such data lives in shmem and the channel is
  silent during the run ([PROTO-18]), the protocol cannot be a source of
  nondeterminism. When sim mode is off, the plugin is not loaded, no control
  socket is created, and no frame is ever sent, so the channel is fully inert
  ([INV-7]); when sim mode is on, the channel's only effect on a run is the
  one-time setup it performs before the first quantum. *Gate:* `gate:qemu-inert`,
  `gate:abi-conformance`. *Spec:* §1, §7. *Enforces:* [INV-7], [INV-10].

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The tasks whose
> primary area is this file are tracked here by [PLAN-3]; the master plan
> is the source of truth for ordering.

- [x] **T-PROTO-1** Define the frame format (`[u32 BE length][u8 tag][payload]`),
  the `MAX_FRAME_SIZE = 64` bound, and the closed tag registry (Hello `0xF0`,
  HelloAck `0xF1`, Setup `0x01`, SetupAck `0x02`, Quit `0x12`) in
  `crucible-protocol`. — satisfies [PROTO-5], [PROTO-6], [PROTO-7]; spec §3.
- [x] **T-PROTO-2** Implement the pure `encode`/`decode` codec for `PluginMsg`
  and `HostMsg` with typed errors (empty, unknown tag, short/long payload,
  oversize length) and the frame read/write helpers (truncated prefix/payload
  rejected). — satisfies [PROTO-5], [PROTO-6], [PROTO-22]; spec §6.
- [x] **T-PROTO-3** Implement the `SCM_RIGHTS` descriptor handover on `Setup`:
  host attaches `[shmem_fd, wake_fd]` in fixed order; plugin reads exactly two
  fds and fails setup on any other count. — satisfies [PROTO-8], [PROTO-9],
  [PROTO-12]; spec §3.4, §3.7.
- [x] **T-PROTO-4** Implement the handshake: plugin sends `Hello(proto, abi)`,
  host negotiates `proto = min(...)`, cross-checks `abi` exactly against the
  shmem ABI version, and replies `HelloAck(proto, abi, slot_index, node_count)`;
  plugin bounds-checks `slot_index < node_count`. — satisfies [PROTO-3],
  [PROTO-10], [PROTO-11], [PROTO-15], [PROTO-16], [PROTO-17]; spec §3.5, §3.6, §4.
- [x] **T-PROTO-5** Implement the setup completion: plugin `mmap`s `region_len`,
  validates the shmem ABI marker ([`13-shmem-abi.md`](13-shmem-abi.md)), arms the
  wake fd, and replies `SetupAck(status)`; host refuses to schedule a node whose
  `SetupAck` is non-zero. — satisfies [PROTO-12], [PROTO-13], [PROTO-19]; spec
  §3.7, §3.8, §5.2.
- [x] **T-PROTO-6** Wire the lifecycle: connect → Hello/HelloAck → Setup/SetupAck
  → run-via-shmem (control channel silent) → Quit; assert no control frame is
  exchanged during the run. — satisfies [PROTO-1], [PROTO-2], [PROTO-4],
  [PROTO-18]; spec §2, §5.1.
  Completed by `checks.crucible.phase2.qemuLivePluginInstall`, which drives the
  full lifecycle live against real qemu-crucible — connect, `Hello`/`HelloAck`,
  `Setup`/`SetupAck`, run via shared memory, then `Quit` — and proves the control
  channel stays silent during the run with a non-blocking `MSG_PEEK` that must
  find no unsolicited frame before teardown.
- [x] **T-PROTO-7** Implement the graceful-shutdown escalation Quit → QMP quit →
  SIGTERM → SIGKILL → reap with bounded per-rung waits, and prove no QEMU child
  is leaked under an unresponsive guest/plugin. — satisfies [PROTO-14],
  [PROTO-20]; spec §3.9, §5.3.
- [x] **T-PROTO-8** Implement clean failure handling for all setup failure modes
  (no version overlap, ABI mismatch, bad slot, wrong fd count, short/invalid
  region, non-zero SetupAck, premature socket close): abort the node, escalate
  teardown, reap the child. — satisfies [PROTO-21]; spec §5.4.
- [x] **T-PROTO-9** Freeze the protocol golden-vector corpus (Hello, HelloAck,
  Setup payload, SetupAck, Quit at the current `proto_version`) and wire it into
  `gate:abi-conformance` with the version-bump-regenerates rule. — satisfies
  [PROTO-23]; spec §6, §24 §8.1.
- [x] **T-PROTO-10** Add the structure-aware codec fuzz target (malformed /
  adversarial frames; round-trip on well-formed inputs) to `gate:abi-conformance`
  and seed the regression corpus. — satisfies [PROTO-22], [PROTO-23]; spec §6,
  §24 §8.3.
- [x] **T-PROTO-11** Add the inertness assertion: with sim mode off, no control
  socket is created and no frame is sent; with sim mode on, no timing-significant
  data crosses the channel and the channel is silent during the run. — satisfies
  [PROTO-18], [PROTO-24]; spec §7, §24 (`gate:qemu-inert`).
