# Host/plugin control protocol

Each QEMU node has one Unix stream socket between the host
(`crucible-qemu-host`) and the Crucible plugin loaded into QEMU
(`crucible-qemu-plugin`). This page specifies the framed protocol on that
socket: the frame format, the closed tag registry, the version handshake, the
descriptor handover, setup completion, the lifecycle, shutdown escalation,
inertness, and the conformance corpus.

The control protocol is a public process protocol, like the shared-memory
region it bootstraps. Either side can be implemented from this specification
without the other's private code; see the
[Crucible/QEMU process boundary](../../legal/licensing.md#crucibleqemu-process-boundary).

| Artifact | Path |
| --- | --- |
| Codec, handshake, lifecycle, descriptor handover | `crates/crucible/crucible-qemu-protocol/src/lib.rs` |
| Protocol version include | `crates/crucible/crucible-qemu-protocol/src/control_protocol_version.in` |
| Golden vectors | `crates/crucible/crucible-qemu-protocol/src/golden_vectors.rs` |
| Fuzz target and regression corpus | `crates/crucible/crucible-qemu-protocol/src/codec_fuzz.rs` |
| Composite plugin setup plan | `crates/crucible/crucible-qemu-protocol/src/plugin_setup_plan.rs` |
| Host setup | `crates/crucible/crucible-qemu-host/src/host_setup.rs` |
| Host shutdown ladder | `crates/crucible/crucible-qemu-host/src/shutdown.rs` |
| Plugin handshake and setup | `crates/crucible/crucible-qemu-plugin/src/handshake.rs`, `setup.rs` |

## Control versus data

The protocol carries control, never data. Its frames perform the version
handshake, hand over the shared-memory, wake, and plugin-plan descriptors,
acknowledge setup, and request shutdown. Virtual time, frame payloads, idle
state, status, and every per-quantum decision flow through the shared-memory
region ([shmem-abi.md](shmem-abi.md)). The separate wake eventfd carries only
a counter that tells QEMU to re-read shared memory.

`RUNTIME_DATA_PLANE_CONTRACT` records the split as data:
`runtime_data_plane = RuntimeDataPlane::SharedMemory`,
`control_channel_carries_runtime_frames = false`,
`control_channel_carries_delivery_icounts = false`, and
`control_channel_silent_between_setup_ack_and_quit = true`.

Keeping the hot path off the socket avoids round trips, payload copies, and
serialization per quantum. It also keeps the protocol tiny (five fixed-shape
messages), which makes it cheap to fuzz and to pin with golden vectors, and it
confines all determinism-critical state to one audited surface.

## Transport

The host creates one `AF_UNIX`/`SOCK_STREAM` socket pair per VM node before
launching QEMU (`socket_pair` in `crates/crucible/crucible-qemu-host/src/spawn.rs`,
created `SOCK_CLOEXEC`). A stream socket is required because the setup frame
carries descriptors as `SCM_RIGHTS` ancillary data and because the
length-prefixed framing assumes an ordered byte stream.

In the child, before `exec`, the host's spawn path duplicates the plugin's end
to the fixed descriptor `QEMU_PLUGIN_CONTROL_FD` (3), sets
`PR_SET_PDEATHSIG = SIGKILL`, and clears the inherited environment. The plugin
learns its socket and slot from its QEMU `-plugin` arguments (`simfd=` and
`slot=`); see [qemu-plugin.md](qemu-plugin.md) and
[qemu-integration.md](qemu-integration.md).

The host assigns each node a stable, zero-based slot index equal to the node's
index in the region's `NodeSlot` array. `HelloAck` communicates it, and it is
the only key the plugin uses to locate its own cells in shared memory.

The channel is blocking and synchronous from the plugin's point of view: the
plugin sends `Hello` and blocks for `HelloAck` before touching shared memory.
The host preserves message order on each per-node socket.

## Frame format

Every message is one length-prefixed frame:

```text
offset  size  field
0       4     length   u32 big-endian; counts the bytes that follow (1 + N)
4       1     tag      u8 from the closed registry
5       N     payload  tag-specific; N == length - 1
```

All multi-byte integers, including those in payloads, are big-endian (network
byte order), so the golden vectors are unambiguous. Descriptors are never
payload bytes; they travel as ancillary data on the frame that needs them.

| Constant | Value |
| --- | --- |
| `FRAME_LENGTH_PREFIX_SIZE` | 4 |
| `FRAME_TAG_SIZE` | 1 |
| `MAX_FRAME_SIZE` | 64 (maximum `length` value) |
| `MAX_PAYLOAD_SIZE` | 63 |
| `FRAME_LENGTH_INCLUDES_TAG` | `true` |
| `FRAME_INTEGERS_ARE_BIG_ENDIAN` | `true` |

`MAX_FRAME_SIZE` is a hard compile-time bound. Payloads are tiny and fixed in
shape, so a larger `length` is always corruption or a hostile peer. Readers
check it before reading or allocating the payload, and producers never emit a
larger frame.

### Tag registry

The registry (`ControlTag`) is closed. Each tag has exactly one direction and
one fixed payload length:

| Tag | Name | Direction | Payload bytes |
| --- | --- | --- | --- |
| `0x01` | `Setup` | host -> plugin | 8, plus `SCM_RIGHTS` descriptors |
| `0x02` | `SetupAck` | plugin -> host | 1 |
| `0x12` | `Quit` | host -> plugin | 0 |
| `0xF0` | `Hello` | plugin -> host | 8 |
| `0xF1` | `HelloAck` | host -> plugin | 16 |

Setup tags occupy the low range and handshake tags the high range. The
constants are `TAG_SETUP`, `TAG_SETUP_ACK`, `TAG_QUIT`, `TAG_HELLO`,
`TAG_HELLO_ACK`, and `ALL_CONTROL_TAGS`. A new message type requires a new tag,
a `CONTROL_PROTOCOL_VERSION` bump, and regenerated golden vectors.

The Rust message types are:

```rust
pub enum PluginMsg {
    Hello { proto_version: u32, abi_version: u32 },
    SetupAck { status: u8 },
}

pub enum HostMsg {
    HelloAck { proto_version: u32, abi_version: u32, slot_index: u32, node_count: u32 },
    Setup { region_len: u64 },
    Quit,
}
```

### `Hello` payload

Plugin -> host, tag `0xF0`, the first frame the plugin sends:

```text
offset  size  field
0       4     proto_version   u32 BE: exact control-protocol version required
4       4     abi_version     u32 BE: shared-memory ABI version compiled in
```

The plugin must not map or read the region before it has sent `Hello` and
received a valid `HelloAck`.

### `HelloAck` payload

Host -> plugin, tag `0xF1`:

```text
offset  size  field
0       4     proto_version   u32 BE: the exact current protocol version
4       4     abi_version     u32 BE: ABI version the host built the region with
8       4     slot_index      u32 BE: this node's zero-based NodeSlot index
12      4     node_count      u32 BE: physical slots in the region (MAX_NODES)
```

The plugin verifies `slot_index < node_count` and the exact version checks
below before it proceeds to `Setup`. `node_count` is the region header's
physical slot count (currently always 32), not the number of VMs.

### `Setup`

Host -> plugin, tag `0x01`. The byte payload is the region length so the
plugin can map exactly that many bytes and reject a truncated region:

```text
offset  size  field
0       8     region_len   u64 BE: total byte length of the region to map
-- ancillary SCM_RIGHTS: [shmem_fd, wake_fd, plugin_setup_plan_fd] --
```

`region_len` must equal the header's `region_size` and the layout recomputed
from the header geometry.

### `SetupAck`

Plugin -> host, tag `0x02`:

```text
offset  size  field
0       1     status   u8: 0 = ready, nonzero = setup failed
```

`SETUP_ACK_STATUS_READY = 0`. The plugin sends
`SETUP_ACK_STATUS_SETUP_FAILED = 1` for every failure; finer failure stages
are plugin-local diagnostics and are not encoded on the wire.

### `Quit`

Host -> plugin, tag `0x12`. `Quit` MUST be encoded as a tag-only frame with no
payload and no ancillary data: the five bytes `00 00 00 01 12`. It is the first
rung of the shutdown ladder.

## Handshake and versioning

Two independent versions are checked:

- `proto_version`: this protocol (framing, tags, payload shapes).
  `CONTROL_PROTOCOL_VERSION = 3`, from `control_protocol_version.in`.
- `abi_version`: the shared-memory layout, owned by `crucible-qemu-shmem`
  (`ABI_VERSION = 30`). The protocol only transports it for cross-checking.

```text
Plugin                                       Host
  |-- Hello(proto, abi_plugin) -------------->|  require proto == current
  |                                           |  require abi_plugin == abi_host
  |                                           |  require slot < node_count
  |<-- HelloAck(proto, abi_host, slot, n) ----|
  |  require proto == current                 |
  |  require abi_host == abi_plugin           |
  |  require slot < n, slot == launch slot    |
  |<-- Setup(region_len) + [shmem, wake, plan]|
  |   map, validate, arm, register wake fd    |
  |-- SetupAck(0) --------------------------->|
  |        ... run entirely via shared memory ...
```

`host_negotiate_handshake` and `plugin_validate_handshake_ack` implement the
checks without I/O; `host_accept_handshake` and `plugin_start_handshake` wrap
them in frame I/O. Both peers require exactly `CONTROL_PROTOCOL_VERSION`
(`HandshakeError::ProtocolVersionMismatch`); there is no range negotiation. The
ABI cross-check is exact and independent of the protocol check
(`HandshakeError::AbiMismatch`), because the peers share a byte-for-byte memory
layout and a mismatch is unrecoverable. A slot outside the declared range is
`HandshakeError::InvalidSlot`. On any failure the host sends no `HelloAck` and
setup aborts.

The plugin binds the exchange to its launch arguments
(`crucible-qemu-plugin/src/handshake.rs`): it offers its compiled
`CONTROL_PROTOCOL_VERSION` and `ABI_VERSION`, and rejects a host-assigned slot
that differs from the `slot=N` argument QEMU loaded it with.

Versioning policy: adding a tag, growing a payload, or changing a field's
meaning bumps `CONTROL_PROTOCOL_VERSION` and regenerates the golden vectors in
the same change. Decoders reject unknown tags and short or long payloads; there
is no "ignore trailing bytes" leniency, so two peers either agree on the exact
wire shape or fail at the handshake. Shared-memory layout changes are governed
separately by `abi_version`.

## Descriptor handover

Control protocol v3 hands the plugin exactly three descriptors
(`SETUP_DESCRIPTOR_COUNT = 3`), attached to the `Setup` frame as `SCM_RIGHTS`
ancillary data, always as
`[shmem_fd, wake_fd, plugin_setup_plan_fd]` in fixed order:

| Position | Descriptor | Created by the host as |
| --- | --- | --- |
| 0 | shared-memory region | memfd `crucible-qemu-shmem`, `MFD_CLOEXEC \| MFD_ALLOW_SEALING`, sized to `region_len`, sealed `F_SEAL_SHRINK` |
| 1 | wake | `eventfd(0, EFD_CLOEXEC)` |
| 2 | plugin setup plan | memfd `crucible-plugin-setup-plan`, sealed `F_SEAL_SHRINK \| F_SEAL_GROW \| F_SEAL_WRITE \| F_SEAL_SEAL` |

`send_setup_with_descriptors(socket_fd, region_len, fds)` sends the complete
`Setup` frame and all three descriptors in one `sendmsg` (with `MSG_NOSIGNAL`
on Linux); a partial write is `DescriptorHandoverError::ShortWrite`.

`recv_setup_with_descriptors(socket_fd)` receives the 4-byte length prefix and
the ancillary data in one `recvmsg`, with room for one extra descriptor so an
oversupply is detectable. It rejects, closing every received descriptor:
truncated ancillary data (`MSG_CTRUNC`, `AncillaryTruncated`), malformed
control messages, any count other than three (`WrongDescriptorCount`), peer
close (`PeerClosed`), an oversized length, and any frame that does not decode
to `HostMsg::Setup`. Accepted descriptors are marked close-on-exec and
returned as owned `OwnedFd`s in a `ReceivedSetup`.

Descriptors are passed once, on `Setup`, and never again. No other frame
carries ancillary data.

### Plugin setup plan

The third descriptor carries the canonical composite plan defined in
`plugin_setup_plan.rs`:

```text
offset  size  field
0       8     magic = "CRUCSUP2"
8       4     schema version = 2, big-endian
12      4     header length = 28, big-endian
16      4     total byte length, big-endian
20      4     app-random plan byte length (A), big-endian
24      4     selectable catalog plan byte length (S), big-endian
28      A     canonical AppRandomBranchPlanV1 body
28+A    S     canonical SelectableCatalogPlanV4 body
```

The length fields must partition the body exactly. The maximum is
`PLUGIN_SETUP_PLAN_MAX_BYTES` = 28 + 4 MiB + 32 MiB (36 MiB plus 28 bytes).
No alternate or trailing encoding is accepted. The plugin requires all four
seals, a regular file, and a nonzero length within the maximum before reading
and decoding it (`read_plugin_setup_plan` in
`crates/crucible/crucible-qemu-plugin/src/setup.rs`).

## Setup completion

On the plugin, `prepare_setup_completion` runs after `Setup` is received:

1. Record the region descriptor's device and inode identity.
2. Authenticate and decode the sealed plugin plan.
3. `mmap_setup_region(shmem_fd, region_len)`: map exactly `region_len` bytes
   `MAP_SHARED` after checking the backing length and shrink seal.
4. Validate the region header (magic, ABI version, ticks per nanosecond,
   region size, recomputed geometry); see
   [shmem-abi.md](shmem-abi.md#setup-validation).
5. Cross-check the handshake against the header: `node_count` must match and
   `slot_index` must be below the header's node count.
6. Arm the wake fd.

Each failure first sends `SetupAck(1)` and then returns a typed
`PluginSetupError`. The plugin then proves ownership of its QEMU callbacks
and registers the wake eventfd with QEMU; `send_ready_setup_ack` refuses to
send `SetupAck(0)` until the wake fd is registered, so QEMU consumes the
host's eventfd nudges from the first quantum.

`SetupAck` with `status == 0` therefore means the plugin has mapped the
region, validated the ABI, registered its wake fd, and is ready to run via
shared memory. The host accepts it with `host_accept_setup_ack`, which returns
a `SchedulableNodeSetup` token only for status 0 and
`SetupCompletionError::NonZeroSetupAck` otherwise. The host never includes a
node in a quantum without that token, and the plugin does not read its clock
cell, poll its queues, or use the wake fd for run traffic before sending it.
This ordering makes the region's state well-defined at the first quantum.

The host side is `complete_qemu_host_plugin_setup_with_plugin_setup_plan` in
`host_setup.rs`. It allocates the typed region image, checks that the spawn
memfd length equals the computed `region_size`, writes the image into the
memfd, and validates the header. It also queues the fault-capability and
target-manifest admission queries in the region's fault-command ring; the
plugin answers them through shared memory, and the host checks the answers
after `SetupAck`. The host then runs the handshake with
`node_count = layout.node_count`, sends `Setup` with the three descriptors,
accepts `SetupAck`, and finally enters the run state. A mismatched spawn
length, a region failure, or any protocol error aborts before scheduling.

## Lifecycle

```text
 1. connect      host creates socketpair; plugin opens its end at load.
 2. Hello        plugin -> host  (proto + abi versions)
 3. HelloAck     host -> plugin  (exact proto, abi, slot, node_count)
 4. Setup        host -> plugin  (region_len + [shmem_fd, wake_fd, plugin_setup_plan_fd])
 5. SetupAck     plugin -> host  (status = ready)
 6. RUN          all synchronization via shared memory + wake fd;
                 the control socket is silent for the whole run.
 7. Quit         host -> plugin  (begin graceful shutdown)
 8. teardown     plugin shuts QEMU down; host reaps the process.
```

`ControlLifecycle` enforces this order as a state machine over
`ControlLifecycleState` (`Disconnected`, `Connected`, `HelloSent`,
`HelloAcknowledged`, `SetupSent`, `SetupAcknowledged`,
`RunningViaSharedMemory`, `QuitSent`) driven by `ControlLifecycleEvent`.
`NORMAL_CONTROL_LIFECYCLE` is the canonical seven-event trace, and
`validate_complete_control_lifecycle` checks a full trace. Out-of-order events
are `UnexpectedEvent`; a nonzero `SetupAck` cannot enter the run
(`NonReadySetupAck`).

`ControlLifecycleStream<S>` couples the socket to the state machine, so frame
I/O is possible only in the matching state. Between `SetupAck` and `Quit` the
peers exchange no control frames:

- `host_read_run_control_frame` treats any inbound frame during the run as a
  fault (`ControlFrameDuringRun`): the host initiates `Quit`, so the plugin has
  nothing legitimate to send.
- `plugin_read_run_control_frame` accepts only `Quit`; any other frame is
  `ControlFrameDuringRun` and tears the plugin down as a run-control fault.
- `QemuHostPluginSetup::assert_run_control_silent` performs a nonblocking
  `MSG_PEEK` on the host end and fails if any byte is pending or the plugin has
  closed the socket before `Quit`.

A hot-fork child does not replay setup. After its supervisor authenticates and
installs a fresh private control endpoint, it wraps it with
`ControlLifecycleStream::restored_run_via_shared_memory`, so the only frame
that endpoint will ever accept is the terminal `Quit`.

The plugin's teardown (`crates/crucible/crucible-qemu-plugin/src/teardown.rs`)
accepts exactly two shutdown proofs: the region's `shutdown_requested` flag or
a `Quit` read through the lifecycle stream. On either, it marks the node
`STATUS_DONE`, seals further shared-memory access, and invokes QEMU's shutdown
hook.

## Failure handling

Each of these aborts the node's setup without hanging or panicking: a protocol
version that is not current; an ABI mismatch; `slot_index >= node_count` or a
slot that differs from the launch argument; a wrong descriptor count or
malformed ancillary data; a `region_len` that does not match the region or a
failed header validation; a nonzero `SetupAck`; and the socket closing before
`SetupAck`. The host never schedules such a node, and the production launch
cleanup runs the shutdown ladder so the spawned child is reaped.

## Shutdown escalation

Shutdown is a host-driven ladder with a bounded wait at each rung, so no QEMU
child is ever leaked however unresponsive the guest or plugin becomes:

| Rung | `QemuShutdownRung` | Action |
| --- | --- | --- |
| 1 | `ControlQuit` | send `Quit` on the control socket |
| 2 | `QmpQuit` | issue QMP `{ "execute": "quit" }` |
| 3 | `Sigterm` | send `SIGTERM` to the QEMU child |
| 4 | `Sigkill` | send `SIGKILL` to the QEMU child |
| 5 | `Reap` | `waitpid` the child |

`QEMU_SHUTDOWN_ESCALATION_ORDER` fixes the order and `QemuShutdownPolicy`
holds one bounded wait per rung (`control_quit_wait`, `qmp_quit_wait`,
`sigterm_wait`, `sigkill_wait`, `reap_wait`); the timeout values are host
policy. `shutdown_qemu_child` runs rungs 1 to 4 in order and stops early when
the child has exited. A rung whose action fails is recorded in
`QemuShutdownReport::failures` and escalation continues; a failed wait counts
as still running. The reap rung always runs. If the child is still alive after
the reap deadline the result is `QemuShutdownError::LeakedChild`, carrying the
report. `UnixQemuChildShutdownTarget` is the production adapter. Independently,
`PR_SET_PDEATHSIG = SIGKILL` in the child ensures QEMU dies if the host does.

## Inertness

The channel is determinism-neutral by construction. No frame carries virtual
time, wall-clock time, host-scheduling-derived ordering, or per-quantum
payload, and the channel is silent during the run. With simulation mode on,
its only effect is the one-time setup before the first quantum.

With simulation mode off, the plugin is not loaded, no control socket is
created, and no frame is sent. `gate:qemu-inert` checks both halves:

- Host (`crates/crucible/crucible-qemu-host/src/inertness.rs`):
  `QemuControlPlaneObservation::sim_off` expects no control socket, zero
  frames, and a QEMU argument vector free of `-plugin` and every control or
  sim-mode fragment in `SIM_OFF_FORBIDDEN_ARG_FRAGMENTS`.
  `SIM_ON_CONTROL_FRAME_CLASSES` classifies all five tags as not
  timing-significant and not allowed during the run.
- Plugin (`crates/crucible/crucible-qemu-plugin/src/inertness.rs`): with
  simulation off there is no launch argument, no install call, no control or
  shared-memory setup, no callback registration, and no call into patched QEMU
  capabilities.

See [qemu-patch.md](qemu-patch.md) for the QEMU side of inertness.

## Codec

The codec is pure: no global state and no I/O inside encode or decode. Frame
reading and writing are a thin separate layer. Every byte string either
decodes to a message or returns a typed error.

| Function | Purpose |
| --- | --- |
| `control_encode_plugin_msg`, `control_decode_plugin_msg` | plugin -> host frames |
| `control_encode_host_msg`, `control_decode_host_msg` | host -> plugin frames |
| `control_frame_tag` | tag of a well-formed frame in either direction |
| `read_control_frame`, `write_control_frame` | stream I/O with flush |

`decode_frame` rejects, as `FrameDecodeError`: an empty buffer
(`EmptyFrame`), fewer than four prefix bytes (`TruncatedLengthPrefix`),
`length > MAX_FRAME_SIZE` (`LengthExceedsMax`), fewer bytes than declared
(`TruncatedPayload`), more bytes than declared (`TrailingBytes`), a zero
length (`MissingTag`), an unregistered tag (`UnknownTag`), a tag from the
other direction (`UnexpectedDirection`), and payloads shorter or longer than
the registry shape (`PayloadTooShort`, `PayloadTooLong`).

`read_control_frame` reports a stream that ends inside the prefix or payload
as `FrameIoError::TruncatedLengthPrefix` or `TruncatedPayload`, and checks
`LengthExceedsMax` before sizing the payload buffer, so an attacker-controlled
length never drives an allocation. Round-trip `decode(encode(m)) == m` holds
for every well-formed message.

## Golden vectors

`GOLDEN_CONTROL_VECTORS` freezes one literal frame per message for
`GOLDEN_VECTOR_PROTOCOL_VERSION = 3`, which a compile-time assertion requires
to equal `CONTROL_PROTOCOL_VERSION`. The vectors use ABI version 1, slot 7,
node count 32, and region length 450,560 as arbitrary field values:

| Name | Frame bytes (hex) |
| --- | --- |
| `hello` | `00 00 00 09 F0 00 00 00 03 00 00 00 01` |
| `hello-ack` | `00 00 00 11 F1 00 00 00 03 00 00 00 01 00 00 00 07 00 00 00 20` |
| `setup-payload` | `00 00 00 09 01 00 00 00 00 00 06 E0 00` |
| `setup-ack` | `00 00 00 02 02 00` |
| `quit` | `00 00 00 01 12` |

The vectors are literal byte arrays, not generated by the encoder, so a
protocol bump forces a conscious regeneration
(`GOLDEN_VECTOR_REGENERATION_RULE`: "Regenerate every protocol golden vector
whenever CONTROL_PROTOCOL_VERSION changes."). The `Setup` vector covers the
byte payload only; descriptor passing is tested separately over a real socket
(`tests/descriptor_handover.rs`).

`tests/gate_abi_conformance.rs` in the protocol crate runs under
`gate:abi-conformance`. It checks that the vectors cover every control frame,
match the live codec byte for byte in both directions, carry an explicit
version, and change when the version changes. The same target also pins the
`CRUCSUP2` plugin setup plan, the selectable catalog and transport schemas,
and the white-box doorbell frame and marker vectors.

## Codec fuzzing

`run_control_codec_fuzz_target(frame)` runs arbitrary bytes through the plugin
decoder, the host decoder, and `control_frame_tag`, and returns a
`ControlCodecFuzzOutcome` holding all three typed results. It performs no I/O.

`CODEC_FUZZ_REGRESSION_CORPUS` seeds 15 malformed and adversarial cases:
`empty`, `truncated-length-one-byte`, `truncated-length-three-bytes`,
`oversize-length`, `missing-tag`, `unknown-tag`, `zero-length-trailing-byte`,
`hello-short-payload`, `hello-long-payload`, `setup-ack-truncated-payload`,
`setup-ack-long-payload`, `quit-trailing-bytes`,
`max-sized-quit-long-payload`, `well-formed-host-frame-in-plugin-decoder`, and
`well-formed-plugin-frame-in-host-decoder`. New findings are added to this
corpus.

`tests/codec_fuzz.rs` adds structure-aware generation: every registered and
unregistered tag with structurally relevant payload lengths, directional
adversarial frames, generated truncations and trailing bytes, and round trips
of generated well-formed messages. It asserts that the target never panics,
that malformed input yields typed errors, and that a frame decodes
successfully only in its registered direction.

## Checks

| Nix check (`tests/crucible/`) | Covers |
| --- | --- |
| `phase2-protocol-frame-format.nix` | prefix, tag registry, size bound |
| `phase2-protocol-codec.nix` | pure codec and typed errors |
| `phase2-protocol-handshake.nix` | exact version and slot checks |
| `phase2-protocol-descriptor-handover.nix` | three-descriptor `SCM_RIGHTS` order and count |
| `phase2-protocol-setup-completion.nix` | `SetupAck` gating of scheduling |
| `phase2-protocol-lifecycle.nix` | lifecycle order and run-phase silence |
| `phase2-protocol-shutdown-escalation.nix` | shutdown ladder and reap |
| `phase2-protocol-golden-vectors.nix` | frozen frame corpus |
| `phase2-protocol-codec-fuzz.nix` | fuzz target and regression corpus |
| `phase2-protocol-inertness.nix` | sim-off absence and timing neutrality |

The live lifecycle against a real patched QEMU, including the `MSG_PEEK`
run-silence check, is exercised by `phase2-qemu-live-plugin-install.nix`.
Setup failures that reach a real child (a non-ready acknowledgement after
descriptor handoff and a corrupted mapped region) are exercised by
`phase2-qemu-production-setup-failure.nix`. See
[testing-and-gates.md](testing-and-gates.md).
