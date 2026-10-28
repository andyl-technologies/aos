# Guest-host channel

Crucible requires nothing from the guest. Deterministic execution, fault
injection, coverage, and property checking over observable I/O all rely on
black-box observation from outside the VM. The guest-host channel is an
opt-in white-box addition: a guest can ring a doorbell instruction to report a
marker, or to request an app-controlled random value. Enabling the channel
never changes determinism-relevant state.

The code is spread across these locations:

| Location                                                    | Owns                                  |
|-------------------------------------------------------------|---------------------------------------|
| `crates/crucible/crucible-qemu-protocol/src/doorbell_abi.rs`    | Per-architecture trap instruction ABI |
| `crates/crucible/crucible-qemu-protocol/src/doorbell_frame.rs`  | `CRBL` frame codec and golden vectors |
| `crates/crucible/crucible-qemu-protocol/src/doorbell_marker.rs` | Closed marker vocabulary and bodies   |
| `crates/crucible/crucible-qemu-protocol/src/app_random_transport.rs` | Plugin-to-host app-random record |
| `crates/crucible/crucible-qemu-plugin/src/whitebox_doorbell.rs` | Trap callback core, setup validation  |
| `crates/crucible/crucible-qemu-plugin/src/runtime/live_whitebox.rs` | Live QEMU adapter                 |
| `crates/crucible/crucible-qemu-host/src/launch/whitebox_setup.rs` | x86 port collision probe           |
| `crates/crucible/crucible-engine/src/trigger/`               | Black-box surface, readiness, markers |
| `crates/crucible/crucible-guest`, `pkgs/tools/crucible-guest.nix` | Optional static guest emitter    |

`crucible-qemu-protocol` is a permissive boundary crate with no QEMU
dependency. The plugin and the guest re-export its constants and never
duplicate them, so the trap encoding, frame, and marker vocabulary each have a
single source. Licensing boundaries are described in
[../../legal/licensing.md](../../legal/licensing.md).

## Black-box mode: the default and the floor

A guest never needs an in-guest agent, a kernel patch, or image content added
by Crucible. The rationale has three parts. Requiring guest changes would mean
the production image no longer runs unchanged under Crucible. It would tie
Crucible to particular guest operating systems. And it would let guest-side
state influence determinism. All entropy is sealed from outside the VM, so the
guest can remain an unmodified black box.

`BlackBoxObservationKind` (`crucible-engine/src/trigger/observability.rs`) is
the closed catalog of what the host observes. `BLACK_BOX_OBSERVATION_KINDS`
lists all seven categories:

| `BlackBoxObservationKind`  | Observed from                                     |
|----------------------------|---------------------------------------------------|
| `NetworkTraffic`           | Host-owned network device path                    |
| `DiskOrNinePIo`            | Block and 9p device sub-nodes                     |
| `ConsoleSerialOutput`      | Host-side console/serial sink (output only)       |
| `ArchitecturalStateSample` | Registers or memory read at scheduler points      |
| `RunOutcome`               | Guest lifecycle outcome (start, exit)             |
| `CrashOrHangDetection`     | Crash, reset, or no forward progress (`Hung`)     |
| `BasicBlockCoverage`       | Plugin TCG execution hooks, no instrumentation    |

Each category has a `BlackBoxObservationContract`
(`BLACK_BOX_OBSERVATION_CONTRACTS`). The contract names a host-side
`BlackBoxObservationSource` and declares that the category depends on no guest
OS, init system, filesystem layout, or in-guest ABI. Console and serial capture
is an output sink only. It is never a way to control the host or to inject
input into the guest. `ObservableEvent::black_box_observation_kind` classifies
events into the catalog. White-box markers (`GuestMarker` and related variants)
fall outside it. Condition evaluation requires every black-box observation to
carry an icount stamp (`InvalidBlackBoxObservationStamp`) and to arrive in
virtual-time order (`OutOfOrderEventLogEntry`).

### Readiness without a guest signal

Each world node's `ReadyPoint` (`crucible-engine/src/model/topology_faults.rs`)
says when the guest is ready. That value is part of the node's hashed
material (`ready_point_material`), so readiness is deterministic:

| `ReadyPoint`             | Resolution                                           |
|--------------------------|------------------------------------------------------|
| `ReadyPoint::FixedIcount`  | Exactly that icount                                |
| `ReadyPoint::NetworkIdle`  | First idle window on the node's links after activity |
| `ReadyPoint::ConsoleMarker`| Event that completes a match on the console stream |
| `ReadyPoint::AgentSignal`  | White-box only; not resolvable in black-box mode   |

`resolve_ready_point(world, node, observed_until, observations)` returns a
`ReadyPointResolution` that carries both the icount and the virtual time. Its
inputs are the checked event-log frontier and the ordered observations, never
wall-clock time. Network activity in the same tick does not count as idle.
Console chunks that share a time are put into a canonical order. Observations
after the frontier are ignored. World validation rejects degenerate
parameters: `ReadyPointNetworkIdleWindowZero`,
`ReadyPointNetworkIdleWithoutLinks`, and `ReadyPointConsoleMarkerEmpty`.
`AgentSignal` returns `AgentSignalRequiresWhiteBoxChannel`. The white-box
`setup_complete` lifecycle marker gives a more precise readiness point, but
only as an optional addition.

## White-box mode: the trapped-instruction doorbell

White-box mode is enabled per node (`WhiteBoxPolicy::Enabled`; the default is
`WhiteBoxPolicy::Disabled`). On the plugin command line it is the `whitebox`
switch together with a `whitebox_setup` attestation. In this mode the guest
executes one reserved instruction. The plugin services it synchronously at
the icount where the instruction retires, reads the payload from guest memory,
and turns it into an observational marker or an app-random reply.

### Why a trapped instruction and not a device

A trapped instruction is the only guest-to-host signal that is synchronous
with respect to icount. Consider instead a virtio-serial or other device data
channel. The device model sees a write only when it processes its queue,
several steps after the guest instruction that made it. The marker would be
coupled to device reset values, queue state, and interrupt timing. The host
would drain bytes as they arrived, which reintroduces arrival-driven timing.
The guest would also need a driver and a `/dev` node. The doorbell avoids all
of this. It is one instruction plus one plugin-side memory read, it touches no
device state, and it carries a small binary frame that is easy to fuzz.

Guest-introspection exchanges (`CRGX` buffers carrying `CRGI` records, see
`guest_introspection_doorbell.rs`) use the same doorbell. So do the typed
selectable messages that campaigns use. Each of these is a separately
versioned message family with its own codec, and none extends the marker
vocabulary below. Debugger forks have one activation-only virtio-serial
endpoint that carries no payload; see
[time-travel-debugging.md](time-travel-debugging.md).

### Instruction ABI (version 4)

`WHITEBOX_DOORBELL_ABIS` is the single source for the trap encoding. The
plugin builds its registration state from it through
`WhiteboxDoorbellTrap::from_abi`. The guest emitter rings the instruction it
names. `WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION = 4`.

```text
instruction_abi_version = 4

arch     trap                    payload registers  trap bytes
-------  ----------------------  -----------------  --------------------------
x86_64   out 0xe7,al              ptr=rax len=rcx    e6 e7
aarch64  hint #0x4c               ptr=x0  len=x1     9f 29 03 d5

aarch64 doorbell bytes are the little-endian encoding of instruction word
0xd503299f.
```

The x86_64 port is `WHITEBOX_DOORBELL_X86_64_RESERVED_PORT = 0x00e7`. The
encoding is the immediate-port, byte-width form. The complete two-byte
instruction identifies the doorbell at translation time, so ordinary
`out dx,...` instructions need no register read. The data byte in `al` is not
part of the payload. Linux `ioperm(2)` can grant that one port by itself,
whereas an `eax` write would cover four ports. On aarch64 the doorbell is
`hint #0x4c` (`WHITEBOX_DOORBELL_AARCH64_RESERVED_HINT`). That instruction is
architecturally inert: after the callback it retires normally at EL0 and the
guest continues. Exception-class instructions (`HLT`, `BRK`, `HVC`) are not
used, because a guest agent that rings the doorbell repeatedly has to come
back from every ring.

The `crucible-guest` package build info records
`doorbell_instruction_abi_version`, read from the constant in `doorbell_abi.rs`,
so a mismatched guest asset can be detected before launch.

### Exact icount at the trap

At translation time the live adapter matches the frozen instruction bytes and
installs an execution callback only on that instruction. It also installs a
translation-block entry callback. The marker coordinate is computed without
allocation:

```text
TB entry callback:  cache qemu_plugin_icount_at_tb_entry() per vCPU
insn callback:      userdata = (tb_insns << 32) | (index + 1)
                    marker_icount = tb_entry_icount + index
                    validate: tb_entry_icount + tb_insns == observed raw icount
```

Every callback runs the same derivation. An inert HINT can sit in the middle
of a larger translation block, so the instruction callback must not call
QEMU's committing raw-icount reader. TB metadata that is missing or stale
fails closed (`LiveWhiteboxError::IcountObservation`).

### Setup validation, collisions, and inertness

The trap must not collide with anything the guest really uses; a collision is
a setup error, never a trap that is silently shared:

- `PluginWhiteboxDoorbell::registration_plan(capabilities, setup_validation)`
  first checks `if !self.mode.is_on()` and returns
  `WhiteboxDoorbellRegistrationPlan::Disabled`. With white-box off it installs
  no trap and never reads the validation record. The disabled doorbell remains
  uninstalled and inert. On x86 an `out` to port `0xe7` then behaves like any
  unhandled port write, and on aarch64 the HINT is a no-op.
- With white-box on, the plan requires a `WhiteboxDoorbellSetupValidation` for
  the configured trap. The record is built by
  `WhiteboxDoorbellSetupValidation::validate` from
  `WhiteboxDoorbellSetupResources::from_observed_resources(x86_mapped_ports,
  aarch64_reserved_immediates_in_use)`. The result is
  `WhiteboxDoorbellSetupOutcome::Unchecked`, `CollisionFree`, or `Collision`
  with a `WhiteboxDoorbellCollision` (`X86PortMapped` or
  `Aarch64ReservedImmediateInUse`). An unchecked record, a collision, or a
  record for a different trap fails as `SetupCollisionUnchecked`,
  `SetupCollision`, or `SetupValidationTrapMismatch`.
- Registration also requires the QEMU trap capability
  (`qemu_plugin_register_vcpu_insn_exec_cb`) and the guest-memory read
  capability (`qemu_plugin_read_memory_vaddr`), plus a `max_payload_len` in
  `1..=MAX_FRAME_DATA`.

In the live x86 case the host produces the evidence. Before the enabled run,
`crucible-qemu-host` starts the exact configured machine stopped and without
plugins, runs `info mtree -f`, and accepts port `0x00e7` only if QEMU maps it
to the unassigned `io` fallback region. Only then does it pass
`whitebox_setup=x86-port-00e7-unclaimed-v1` to the plugin. On aarch64 the
attestation is `aarch64-hint-4c-inert-v1`. The plugin argument parser rejects
white-box on without an attestation, and also rejects an attestation with
white-box off.

## The doorbell frame

The guest passes a pointer and a length. The plugin reads that range from guest
memory at the trap icount and decodes one architecture-independent frame. The
codec is `WhiteboxDoorbellFrame` in `doorbell_frame.rs`:

```text
offset  size  field
0       4     magic       u32 LE, WHITEBOX_DOORBELL_FRAME_MAGIC = 0x4c425243 ("CRBL")
4       2     version     u16 LE, WHITEBOX_DOORBELL_PROTOCOL_VERSION = 3
6       2     kind        u16 LE, marker kind
8       4     payload_len u32 LE
12      N     payload     N == payload_len
```

`WHITEBOX_DOORBELL_FRAME_HEADER_LEN` is 12. All integers are fixed-width
little-endian regardless of host or guest byte order. The format is not JSON
or any other self-describing text. Emitter and decoder must agree byte for
byte, and a fixed binary header is cheap to fuzz.
`GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS` freezes byte-exact examples
(`marker-kind-1-empty`, `random-request-kind-5`).
`WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE` requires every vector to be
regenerated whenever the protocol version changes. Any change to the header
or to a kind's body layout must bump the version.

### Decoder hardening

The payload is untrusted guest input. `WhiteboxDoorbellFrame::decode_bounded`
checks in a fixed order and allocates nothing before the bound check:

```text
len < 12                       -> TruncatedFrame
magic != CRBL                  -> BadMagic
version != 3                   -> UnsupportedVersion
payload_len > max_payload_len  -> PayloadLengthExceedsBound   (before any copy)
payload_len != bytes - 12      -> PayloadLengthMismatch
```

The plugin calls it with its trap-time budget. The marker path uses
`self.max_payload_len()`, and the app-random path uses
`doorbell.max_payload_len()`. A range larger than that budget is rejected
before guest memory is read, never read piecemeal across icounts. Body
decoding rejects an unknown kind
(`WhiteboxMarkerPayloadDecodeError::UnknownKind`), bodies over
`WHITEBOX_MARKER_BODY_MAX_BYTES` (4608), short payloads, length prefixes that
run past the payload, trailing bytes, invalid UTF-8, invalid bool, flavor, or
lifecycle values, out-of-range random widths, and malformed identifiers or
measurement values. On the marker path, a malformed frame is recorded as a
`WhiteboxDoorbellDecodeDiagnostic` (`record_whitebox_decode_diagnostic`) and
dropped. On the app-random path it becomes an `AppRandomDecodeDiagnostic` and
is dropped without drawing a decision or writing a reply. Neither path trusts
the input, crashes the plugin, or changes guest state. The protocol tests
include a no-panic fuzz corpus that runs each case under `catch_unwind`. Its
cases cover bad magic, bad version, a bounded declared length, length
mismatch, and wrong-kind/unknown-kind cases.

## Marker vocabulary

`doorbell_marker.rs` (`crucible_qemu_protocol::doorbell_marker`) owns the
closed kind set `WhiteboxDoorbellMarkerKind`, the body codecs, and
`GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS` (one vector per kind). Adding a kind
requires a protocol version bump. A decoder never tolerates an unknown kind.

```text
Doorbell protocol version 3 kind table (closed, versioned set):

  kind  name              body
  ----  ----------------  -----------------------------------------------
   1    assert            flavor:u8, condition:u8, must_hit:u8, lp_str id,
                          lp_str msg, lp_str location, lp_kv[] details
   2    lifecycle         event:u16 (1=setup_complete | 2=test_done)
   3    event             lp_str name, lp_kv[] details
   4    coverage          lp_str point
   5    random_request    request_id:u32, width:u8 (<=8), lp_str stream_tag
   6    measurement_begin lp_id measurement, lp_id instance
   7    metric_sample     lp_id measurement, lp_id instance, lp_id metric,
                          typed_value
   8    measurement_end   lp_id measurement, lp_id instance
   9    semantic_marker   lp_id marker, lp_id instance, typed_detail[]

  flavor (kind=assert): 0=always  1=sometimes  2=reachable  3=unreachable
  must_hit (kind=assert): 0=not catalog-declared  1=declared
  bool fields: 0 or 1; any other byte is rejected
  lp_str: u16 LE length prefix + that many UTF-8 bytes
  lp_kv:  u16 LE count, then that many (lp_str key, lp_str value) pairs
  lp_id:  lp_str restricted to 1..=128 bytes of ASCII alphanumerics plus
          `.`, `_`, `-`, `/`, and `:`
  typed_value tag:
    0 signed i64 LE
    1 unsigned u64 LE
    2 reduced rational: negative:u8, numerator:u128 LE, denominator:u128 LE
    3 boolean:u8
    4 enumerated lp_id
    5 signed vector:   count:u16 LE, count * i64 LE
    6 unsigned vector: count:u16 LE, count * u64 LE
  typed vectors hold at most 512 elements. A rational has a positive
  denominator, is reduced, and encodes zero only as (false, 0, 1).
  typed_detail: u16 LE count (<=64), then strictly increasing
                (lp_id key, typed_value value) pairs
  every complete marker body is at most 4,608 bytes, matching the dedicated
  shared-memory marker entry
```

Every kind except 5 is observational.
`WhiteboxDoorbellMarkerKind::is_observational` returns false only for
`RandomRequest`. The assertion body carries everything the host finalizer
needs, including for assertions whose guest code never runs. `must_hit` marks
a catalog-declared `reachable` or `always` assertion, so that a never-reached
assertion is reported instead of silently dropped.

### How markers reach the event log

```text
guest: write frame, ring doorbell
plugin (trap icount): read [ptr, ptr+len) -> decode_bounded -> decode body
        -> reject kind 5 on this path -> WhiteboxMarker{marker_icount, ...}
        -> WhiteboxMarkerEntry on the dedicated plugin-to-host marker ring
host (quantum boundary): validate + canonical decode
        -> observable_event_from_whitebox_marker_payload(icount, node, payload)
        -> SchedulerEventLogEntry, class Observational
```

`WhiteboxMarkerEntry` (`crucible-qemu-shmem/src/shmem/ring_whitebox_marker.rs`)
carries `current_icount`, `vcpu_index`, `kind`, `payload_len`, and a
`MAX_FRAME_DATA` payload. It lives on a ring separate from causal frame traffic
and coverage. The callback path performs no allocation and no diagnostic I/O.
`observable_event_from_whitebox_marker_payload`
(`crucible-engine/src/trigger/conditions.rs`) maps each payload:

| Payload           | `ObservableEvent`                                       |
|-------------------|---------------------------------------------------------|
| Assertion         | `ObservableEvent::guest_assertion_marker`                 |
| Lifecycle         | `guest_marker` named `lifecycle.setup_complete` / `.test_done` |
| Event             | `guest_marker` named by the event                       |
| Coverage          | `ObservableEvent::coverage_marker`                        |
| Measurement 6-8   | `guest_measurement` (begin, sample, end)                |
| Semantic marker   | `guest_semantic_marker`                                 |
| Random request    | `None`: handled by the app-random path                  |

Lifecycle and event markers use guest-marker identities, so they never
masquerade as black-box node lifecycle observations. The host assertion
finalizer evaluates assertion markers with the same Always, Sometimes,
Reachable, and Unreachable semantics as host-side properties (see
[assertions.md](assertions.md)). The marker event-log entries are described in
[event-log.md](event-log.md).

## App-controlled randomness: the one reply-bearing kind

`random_request` (kind 5) lets an opted-in guest ask for a value from the
same seeded decision source that drives every other `Decision`. The value is
therefore reproducible and replayable, and exploration can branch on it. It is
the only kind that affects the run and the only use of the host-to-guest
direction. Serving it produces decisions, and the plugin writes a value back
into the guest.

```text
guest:  frame{kind=5, request_id:u32, width:u8 in 1..=8, stream_tag}
plugin (handle_whitebox_app_random_callback, at the trap icount):
  decode_bounded + decode body           malformed -> decode diagnostic and dropped
  stream = app_random_stream_name(node, stream_tag)
         = "app-random/node:<len>:<node>/stream:<len>:<tag>"
  enforce draw cap                       exceeded -> typed error (fail loud)
  value  = next u64 of that stream, masked to width*8 bits
  reply  = WhiteboxGuestInput::new(trap_icount, reply_range, value LE[..width])
  inject_guest_input(..., current_icount = trap_icount)
  publish record on marker ring as kind 0xff05
host:   derive the same value from the scenario seed independently, then admit
        BackendRngEvidence { node, stream, request_id, width, value }
        -> Decision::RngDraw (+ Decision::Selection for campaign branches)
```

Properties of this flow:

- **Stream isolation.** The stream name frames each component with its length.
  Two nodes using the same tag therefore get independent streams, and no node
  name can collide with another by prefix.
- **Injection contract.** `inject_guest_input` writes only at its delivery
  icount. It returns `NotReady` before that icount and
  `InputDeliveryAlreadyPassed` after it. The reply is written at the trap
  icount through `qemu_plugin_crucible_write_memory_vaddr`. That function
  requires a `WhiteboxGuestInputCapability` proof token obtained at
  registration time. The reply overwrites the first `width` bytes of the
  request buffer and changes nothing else.
- **Transport record.** `WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION = 0xff05` is
  outside the guest kind registry and cannot be mistaken for a guest marker.
  Its body is `request_id:u32, width:u8, value:u64, tag_len:u16, tag`, all
  little-endian. The selectable family uses internal kinds `0xff06` through
  `0xff09` on the same ring.
- **Cap.** `ScenarioDef` carries the app-random draw cap into the scenario
  definition hash (`app_random_draw_cap={app_random_draw_cap}`). The default
  is `DEFAULT_APP_RANDOM_DRAW_CAP = u64::MAX`. The cap also round-trips
  through scenario TOML and the binary form. `DecisionRecorder`, `try_step`,
  and `reduce` enforce it with a typed `AppRandomDrawCapExceeded` error. The
  check also counts draws already present in a resumed schedule. The cap never
  clamps a draw silently.
- **Zero requests.** A zero-request compiled-in-unused run has the same
  fingerprint as a run with white-box disabled.

## Guest memory addressing

The live adapter reads `(pointer, length)` from the payload registers and reads
guest virtual memory with `qemu_plugin_read_memory_vaddr`, translating through
the guest page tables at the trap. The callback core makes this choice
explicit and fail-closed. `WhiteboxGuestMemoryAddressingResolution` selects
the default payload source. Only a resolution whose `check` is
`checks.crucible.phase0.s5VirtualMemory` and whose evidence flags all pass
selects `VirtualPointerLength`. The flags cover resident, page-spanning, and
paged-mmap reads, reproducible icounts and hashes, and a side-effect-free
fingerprint. `WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED` is the default. It
keeps the physical / pinned identity-mapped shared-page fallback, which is
retained if that evidence is absent or invalidated. The app-random reply
write is a second client of the same addressing decision. The plugin reads the
whole payload once at the trap icount as a snapshot and never reads it again
later.

## Determinism and safety

The channel adds information about a run without adding nondeterminism:

- The guest code that rings the doorbell is deterministic, and servicing is
  synchronous. The marker stream is therefore a pure function of scenario,
  seed, and schedule. Ringing the doorbell does retire guest instructions, but
  that is the guest's own deterministic choice. The host's servicing must not
  change guest state, and the payload read has no side effects.
- Markers are `SchedulerEventLogClass::Observational`. They are ordered by
  their exact icount, but they are excluded from causal replay comparison and
  from the execution fingerprint. A run with markers on and the same run with
  markers off produce identical causal event-log projections and backend
  fingerprints. The only difference is the observational entries.
- The only host-to-guest write is the app-random reply, delivered at an
  explicit icount (the trap icount), never whenever the host happens to
  compute it. The write cannot become a producer-consumer race.
- With white-box disabled, no trap is installed. A guest that never opts in
  behaves identically whether the machinery is compiled in or not. Removing
  `crucible-guest` from the image changes no core capability.

## The optional guest emitter

`crucible-guest` (`crates/crucible/crucible-guest`) is a small static binary
with a thin library (`crucible_guest::GuestCommand`). It builds frames with
the shared codec and rings the instruction named by `WHITEBOX_DOORBELL_ABIS`
using inline assembly. `InstructionDoorbellTransport` handles Linux x86_64 and
aarch64. On x86_64 it first requests access to the single reserved port with
`ioperm(2)`, and returns `GuestEmitterError::IoPermission` if the guest image
did not grant that privilege, instead of letting the guest fault. Marker verbs
send and return immediately. `crucible-guest get-random <width> [tag]` reads
the first `width` bytes of its frame buffer after the doorbell returns.

```text
crucible-guest always      <id> <message> <0|1>
crucible-guest sometimes   <id> <message> <0|1>
crucible-guest reachable   <id> <message>
crucible-guest unreachable <id> <message>
crucible-guest setup-complete
crucible-guest test-done
crucible-guest event       <name> [k=v ...]
crucible-guest coverage    <point>
crucible-guest measurement-begin <measurement> <instance>
crucible-guest metric-sample <measurement> <instance> <metric> <type> <value>
crucible-guest measurement-end <measurement> <instance>
crucible-guest semantic-marker <marker> <instance> [key:type=value ...]
crucible-guest get-random <width> [tag]      # default tag "crucible-guest"
```

The binary also provides `selectable ...` verbs for campaign choices and an
`agent` mode for guest introspection. Those are documented with their own
features. For guest-author usage see
[../../users/crucible/properties-and-evidence.md](../../users/crucible/properties-and-evidence.md).

`pkgs/tools/crucible-guest.nix` builds the emitter hermetically from source
for the current guest system with `-C target-feature=+crt-static -C
relocation-model=static`. After installation it checks that the binary has
no ELF interpreter, and it records `doorbell_instruction_abi_version`, the
x86_64 and aarch64 instruction ABI coverage, and the protocol source modules
in `nix-support/crucible-guest-build-info`.

## Verification

| Check or test                                          | Covers                                  |
|--------------------------------------------------------|-----------------------------------------|
| `checks.crucible.phase4.guestHostBlackBoxSurface`       | Closed black-box catalog and stamps     |
| `checks.crucible.phase4.guestHostOsAgnostic`            | OS-agnostic contracts, non-Linux image  |
| `checks.crucible.phase4.guestHostReadiness`             | `resolve_ready_point`                   |
| `checks.crucible.phase4.guestHostDoorbell`              | Trap callback core                      |
| `checks.crucible.phase4.guestHostDoorbellAbi`           | `WHITEBOX_DOORBELL_ABIS` byte vectors   |
| `checks.crucible.phase4.guestHostDoorbellCollisionInertness` | Setup validation, disabled plan    |
| `checks.crucible.phase4.guestHostDoorbellFrame`         | Frame codec and golden vectors          |
| `checks.crucible.phase4.guestHostMarkerVocabulary`      | Marker kinds and body codecs            |
| `checks.crucible.phase4.guestHostMarkerObservability`   | Marker-to-event-log path                |
| `checks.crucible.phase4.guestHostDecoderHardening`      | Bounded decode and fuzz corpus          |
| `checks.crucible.phase4.guestHostChannelDeterminism`    | Markers on/off fingerprint equality     |
| `checks.crucible.phase4.guestHostChannelGateWiring`     | `gate:any-guest`, `gate:single-vm-fingerprint` |
| `checks.crucible.phase4.guestHostVirtualMemorySpike`    | Consumes `checks.crucible.phase0.s5VirtualMemory` |
| `checks.crucible.phase4.guestHostEmitter`               | `crucible-guest` CLI and package        |
| `checks.crucible.phase4.guestHostEmitterAbsence`        | No in-guest content changes nothing     |
| `checks.crucible.phase4.guestHostAppRandomDoorbell`     | Kind-5 serving and reply                |
| `checks.crucible.phase4.guestHostAppRandomCap`          | Draw cap and zero-request identity      |
| `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`       | Live x86 and aarch64 QEMU flights       |

The live gate `checks.crucible.phase2.qemuLiveWhiteboxDoorbell` runs one
standalone guest twice, with white-box off and on. The off run must record
zero callbacks, the two execution fingerprints must match, and the on run must
deliver exactly one named marker through the shared-memory ring. It also
covers live collision rejection and a real app-random request and reply. The
engine tests `guest_host_marker_observability` and
`guest_host_channel_determinism` cover the scheduler side. `gate:abi-conformance`
covers the instruction, frame, and marker golden vectors
(`crates/crucible/crucible-qemu-plugin/tests/gate_abi_conformance.rs`). See
[testing-and-gates.md](testing-and-gates.md).
