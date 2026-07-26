# 16 — The guest↔host channel

This file specifies how a guest and the host communicate under Crucible. Its
single most important statement is what it does **not** require: the guest does
not have to cooperate at all. Every core capability of Crucible — deterministic
execution, fault injection, coverage, and property checking against observable
I/O — is built on **black-box observation from outside the VM**, and the
guest↔host channel proper (a guest signalling the host in-band) is an
**optional, opt-in white-box enhancement** that is never required and never
allowed to perturb determinism.

This is the concrete realization, at the transport layer, of the project's
any-unmodified-guest principle ([G-2]) and its black-box-by-default posture
([G-3]). The determinism contract already mandates that all determinism be
achieved host-side with an unmodified guest ([DET-15]–[DET-17]); this file is
where that mandate becomes a wire-level design.

Requirement IDs in this file use the prefix `GHC` (see
[`00-conventions.md`](00-conventions.md)). Gate names referenced here —
`gate:any-guest`, `gate:single-vm-fingerprint`, `gate:abi-conformance`,
`gate:layer1-injection` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). The
white-box doorbell is trapped and serviced by the in-VM plugin
([`12-qemu-plugin.md`](12-qemu-plugin.md)); its payload is read through the
plugin's guest-memory API and stamped against icount per the determinism contract
([`04-determinism-contract.md`](04-determinism-contract.md) §4.4); markers it
carries are observational event-log entries
([`19-observability-event-log.md`](19-observability-event-log.md)) and feed the
assertion vocabulary ([`18-assertions-properties.md`](18-assertions-properties.md)).

The code blocks in this file are illustrative sketches per the conventions in
[`00-conventions.md`](00-conventions.md), not the implementation; the
authoritative statement is always the prose requirement.

## 16.1 The principle: zero guest cooperation is the default and the floor

Crucible's guest is a sealed box. Determinism is established by pinning the
entire entropy boundary from *outside* the VM (the QEMU patch series, the
launch configuration, and the in-VM plugin), so the *same* unmodified image
that runs in production runs deterministically here. Nothing inside the guest is
load-bearing for any core function. That is the floor below which the channel
design may not sink, and it is stated first because every other requirement in
this file is constrained by it.

- **[GHC-1]** Crucible's core capabilities — deterministic execution
  ([G-1]), fault injection ([`17-fault-injection.md`](17-fault-injection.md)),
  basic-block coverage ([`22-advanced-features.md`](22-advanced-features.md)),
  and property checking against observable I/O
  ([`18-assertions-properties.md`](18-assertions-properties.md)) — MUST function
  with **zero guest cooperation**: no in-guest agent, no guest kernel patch, no
  content placed inside the guest image by Crucible. A guest that has never heard
  of Crucible MUST be fully usable for all of these. *Gate:* `gate:any-guest`.
  *Spec:* §16.1.

- **[GHC-2]** The guest↔host channel defined in this file is **opt-in and
  additive**. Enabling it MUST be a launch-time choice; its absence MUST NOT
  degrade any capability listed in [GHC-1]; and its presence MUST NOT be a
  precondition of any determinism, fault, coverage, or observable-I/O property.
  A scenario that does not enable the channel MUST behave identically (to the
  fingerprint) whether or not the channel machinery is compiled in. *Gate:*
  `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §16.1, §16.7.

The system therefore operates in two modes, and the boundary between them is the
boundary of [GHC-1]: everything above the floor is black-box; the white-box
channel is the only thing that requires anything of the guest, and even then only
optionally.

### 16.1.1 Black-box mode (default, required)

In black-box mode the host learns everything it knows about the guest by
observation from outside the VM. There is no inbound guest→host signal beyond the
externally observable surface of the machine.

- **[GHC-3]** Black-box mode MUST be the default and MUST be sufficient on its
  own for [GHC-1]. The host's observation surface in black-box mode is exactly
  the externally visible behavior of the VM, enumerated normatively in §16.2:
  network traffic, disk/9p I/O, console/serial output, QMP-readable
  register/memory state, exit codes, and crash/hang detection — **plus**
  basic-block coverage harvested from the plugin's TCG-execution hook, which
  works on *any* binary with *no* guest instrumentation
  ([`12-qemu-plugin.md`](12-qemu-plugin.md),
  [`22-advanced-features.md`](22-advanced-features.md)). *Gate:* `gate:any-guest`.
  *Spec:* §16.2.

- **[GHC-4]** Black-box mode MUST be guest-OS-agnostic: it MUST NOT assume Linux,
  any particular init, any particular filesystem, or any particular ABI inside the
  guest. Observation is of the *machine*, not of a guest-software contract, so a
  BSD image, a microkernel, or a bare-metal binary is observable on the same
  terms as Linux. *Gate:* `gate:any-guest`. *Spec:* §16.2.

Black-box observation is enough for fuzzing (coverage is the feedback signal) and
for the majority of properties (which are stated over observable I/O), and it is
what makes OS-agnosticism real rather than aspirational.

### 16.1.2 Readiness detection without a guest signal

A recurring need — "the guest has finished booting / finished setup, begin the
workload or begin checking" — is normally answered by an in-guest signal. Because
[GHC-1] forbids requiring one, black-box mode MUST be able to answer it by
host-side heuristic.

- **[GHC-5]** Black-box mode MUST provide a **readiness heuristic** that detects a
  guest-ready point with no guest cooperation, configurable per scenario, drawn
  from: (a) a **fixed icount** offset from boot (deterministic by construction;
  [DET-8]); (b) **first network idle** — the first quiescent virtual-time window
  on a node's links after initial activity ([`08-scheduling.md`](08-scheduling.md));
  or (c) a **console marker** — a host-side match against console/serial output
  (e.g. a login prompt or a configured string). The chosen heuristic and its
  parameters MUST be part of the scenario's content hash so readiness is itself
  deterministic. *Gate:* `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:*
  §16.1.2.

- **[GHC-6]** A readiness heuristic MUST resolve to a definite **virtual-time /
  icount point**, identical across runs of a fixed `(scenario, seed, schedule)`,
  so that "ready" is a deterministic event and not a host-timing observation. A
  heuristic that cannot be reduced to a deterministic icount (for example, one
  keyed on host wall-clock) MUST be rejected at scenario validation. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §16.1.2.

The white-box `setup_complete` marker (§16.5) is a *more precise* answer to the
same question when the guest opts in, but it is strictly an enhancement of
[GHC-5], never a replacement for it.

## 16.2 The black-box observation surface (normative)

This section enumerates the externally observable surface that constitutes the
host's knowledge in black-box mode. Each item is observable from outside the VM
and is deterministic under the contract of
[`04-determinism-contract.md`](04-determinism-contract.md).

- **[GHC-7]** The black-box observation surface MUST consist of exactly:
  1. **Network traffic** — every frame on every link, observed by the network I/O
     sub-node ([`15-io-subnodes.md`](15-io-subnodes.md)); the frame stream is
     already deterministic by Contract B ([DET-6]).
  2. **Disk / 9p I/O** — every block and 9p request/response on the device
     sub-nodes ([`15-io-subnodes.md`](15-io-subnodes.md)), with deterministic
     completion icounts.
  3. **Console / serial output** — the byte stream the guest writes to its
     console/serial devices, captured host-side.
  4. **QMP-readable architectural state** — registers and guest memory read
     out-of-band through QMP / the plugin's guest-memory API at scheduler-defined
     points (the basis of the execution fingerprint, [DET-29]).
  5. **Exit codes** — the guest's shutdown/reset/triple-fault disposition,
     surfaced as a typed run outcome.
  6. **Crash / hang detection** — guest panics, resets, and the absence of forward
     progress (no instructions retired across a bounded virtual-time window),
     detected host-side.
  7. **Basic-block coverage** — the set of translation blocks executed, harvested
     from the plugin's TCG-execution hook with no guest instrumentation
     ([`12-qemu-plugin.md`](12-qemu-plugin.md)).

  No other inbound guest→host signal is required for any [GHC-1] capability.
  *Gate:* `gate:any-guest`. *Spec:* §16.2.

- **[GHC-8]** Every observation in [GHC-7] MUST be stamped with the icount at
  which it occurs (for outputs) or is taken (for state reads), so the observation
  stream is totally ordered in virtual time ([INV-3]) and reproducible across runs
  ([DET-1]). An observation whose ordering depends on host wall-clock or
  host-scheduling order is a contract violation. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §16.2, forward-ref [`19-observability-event-log.md`](19-observability-event-log.md).

- **[GHC-9]** Console/serial output captured for observation ([GHC-7] item 3) MUST
  NOT introduce a back-channel that the guest can use to *control* the host or that
  the host uses to *inject* into the guest outside the injection contract; it is a
  pure output sink in black-box mode. Any inbound use of a serial/console device is
  governed by §16.4 and the injection contract ([DET-11]). *Gate:* `gate:any-guest`.
  *Spec:* §16.2, §16.4.

## 16.3 White-box mode: an opt-in trapped-instruction channel

White-box mode adds one capability black-box mode cannot have: a *guest-originated*
signal that names something inside the guest — an assertion result, a lifecycle
transition, a coverage marker — at the exact instruction where it happened. This
is the guest↔host channel proper. It is optional, it requires a tiny guest-side
emitter (§16.6), and it is built so that it cannot affect determinism (§16.7).

The mechanism is a **doorbell**: the guest executes a single reserved instruction
that the in-VM plugin traps **synchronously at an exact icount**, carrying a small
binary payload. The plugin reads the payload out of guest memory at the trap
instant, stamps it with the current icount, and turns it into an observational
event-log entry. There is no device, no driver, no `/dev` node, and no
device-timing coupling.

- **[GHC-10]** When white-box mode is enabled, the guest↔host channel MUST be a
  **trapped-instruction doorbell**: a reserved instruction (§16.4) that the in-VM
  plugin intercepts **synchronously** during execution, at the exact icount at
  which the guest retires it. The doorbell MUST be serviced inline with execution,
  not deferred to a device callback or a host poll, so its position in the
  instruction stream is exact and deterministic. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §16.3, §16.4.

- **[GHC-11]** The doorbell payload MUST be delivered to the plugin by one of two
  arch-appropriate means: (a) a **shared page** whose guest address the guest
  writes the payload into before ringing the doorbell, read by the plugin via the
  plugin guest-memory API; or (b) a **pointer + length in registers** at the trap,
  the pointer naming guest memory the plugin then reads. Both forms place the
  payload in guest memory and have the plugin read it at the trap icount; neither
  uses a device queue. *Gate:* `gate:abi-conformance`. *Spec:* §16.4, §16.6.

- **[GHC-12]** The doorbell protocol MUST be a **binary, versioned,
  length-prefixed** wire format — **not** JSON or any other textual,
  self-describing format. It MUST begin with a fixed magic and a protocol version,
  carry an explicit payload length, and use fixed-width little-endian integer
  fields, so that a guest emitter and the plugin reader agree byte-for-byte and
  the format is cheaply fuzzable. The format is one of the project's versioned
  boundary ABIs ([G-8]) and is covered by `gate:abi-conformance` with golden
  vectors. *Gate:* `gate:abi-conformance`. *Spec:* §16.5.

- **[GHC-13]** Every doorbell event the plugin services MUST be stamped with the
  **exact icount** at which the doorbell instruction was retired, giving every
  marker a deterministic position in the single total order ([INV-3], [DET-1]).
  Two runs of a fixed `(scenario, seed, schedule)` that enable white-box mode MUST
  produce the identical sequence of marker icounts. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §16.3, forward-ref [`19-observability-event-log.md`](19-observability-event-log.md).

### 16.3.1 Why a trapped instruction beats a virtio-serial device channel

The obvious alternative — a virtio-serial (or any virtio) device the guest writes
to and the host drains — is rejected. It is worth stating *why* precisely, because
the reasoning is what makes the doorbell Crucible's design rather than an
arbitrary choice.

- **[GHC-14]** The guest↔host channel MUST be a trapped-instruction doorbell and
  MUST NOT be implemented as a virtio-serial (or other virtio/PCI/MMIO device)
  data channel, for the following reasons, each of which is a determinism or
  fidelity property the device approach cannot match:
  - **Exact icount positioning.** A trapped instruction is serviced *at the
    instruction*, so its icount is the icount of the marker. A device write is
    observed only when the device model processes the queue, which is several
    deterministic-but-indirect steps removed from the guest's actual write
    instruction; attributing a marker to a precise icount through a device queue
    requires reconstructing "the instant the guest finished writing the line" from
    the device's flush timing, which is fragile.
  - **No device-timing coupling.** A device channel couples the marker to the
    emulated device's reset values, queue state, and interrupt timing — all of
    which are part of `T` ([DET-1]) and all of which the marker path would now have
    to keep deterministic. The doorbell touches no device state.
  - **Lowest overhead.** The doorbell is one trapped instruction plus one
    plugin-side memory read; the device path is a driver write, a virtqueue
    descriptor, a notification, and a host drain.
  - **No `/dev` dependency in the guest.** The device path needs a guest driver
    and a `/dev` node (e.g. `/dev/virtio-ports/...`), which is exactly the kind of
    in-guest content [GHC-1] forbids requiring; the doorbell is a single
    instruction any tiny static binary can execute with no driver.
  - **Fuzzable binary protocol.** The length-prefixed binary doorbell format
    ([GHC-12]) is trivially fuzzable and golden-vector-checkable; a JSONL device
    stream is neither.
  *Gate:* `gate:single-vm-fingerprint`, `gate:abi-conformance`. *Spec:* §16.3.1.

The device approach also tends to leak a host-side draining race: bytes arrive on
a socket and are read "as they show up," which is precisely the arrival-driven
nondeterminism the injection contract bans ([DET-13]). The doorbell has no such
race because servicing is synchronous with the guest instruction; there is nothing
to drain.

Implementation caveat: on Linux x86_64, architectural port I/O is privileged.
The userspace `crucible-guest` emitter therefore requests permission for the
single reserved port with `ioperm(2)` before executing `out dx,eax`, and fails
loudly if the guest image has not granted the required I/O capability. This keeps
the emitter free of `/dev` nodes and kernel modules, but it makes the x86_64
userspace privilege requirement explicit instead of relying on an unexplained
guest fault.

## 16.4 The doorbell instruction, per architecture

The doorbell is defined per supported architecture from day one, because the
reserved instruction is necessarily architecture-specific while everything above
it (§16.5) is not. Each architecture's doorbell MUST be an instruction the plugin
can trap synchronously and that does not collide with instructions a normal guest
would execute for its own purposes.

The canonical instruction ABI is versioned and single-sourced in the
`WHITEBOX_DOORBELL_ABIS` table. The plugin registration path consumes the table's
trap values, and the guest-agent crate re-exports the same table for its emitter
to consume when the emitter implementation lands.

Trap installation is also gated by an explicit setup validation record. Setup code
builds `WhiteboxDoorbellSetupResources` from the guest's observed x86 device-port
map and aarch64 reserved-immediate ownership, then calls
`WhiteboxDoorbellSetupValidation::validate(...)` for the configured trap. When
white-box mode is enabled, `PluginWhiteboxDoorbell::registration_plan` requires
that validated record before it returns an install plan. An unchecked trap, a
mismatched validation record, or a detected x86 port / aarch64 immediate collision
is a setup error. When white-box mode is disabled, registration returns `Disabled`
before consuming that record, so the disabled doorbell remains uninstalled and
inert.
The disabled doorbell remains uninstalled and inert by construction.
In short, a collision is a setup error, not a silently installed shared trap.

```text
instruction_abi_version = 1

arch     trap                    payload registers  trap bytes
-------  ----------------------  -----------------  --------------------------
x86_64   out dx,eax, port 0x00e7 ptr=rax len=rcx    ef
aarch64  hlt #0x04c1             ptr=x0  len=x1     20 98 40 d4

aarch64 trap bytes are the little-endian encoding of instruction word 0xd4409820.
```

- **[GHC-15]** On **x86_64**, the doorbell MUST be a write to a **reserved port-I/O
  address** (`out` to a configured, otherwise-unused port). Port I/O is the
  portable x86 choice: it is a single instruction, it is trappable by the plugin
  synchronously at retirement, the written value and the `dx`/`eax` register state
  are available at the trap, and a reserved port does not collide with real device
  I/O. The reserved port number is part of the channel configuration and the
  scenario hash. *Gate:* `gate:abi-conformance`. *Spec:* §16.4.

- **[GHC-16]** On **aarch64**, where architectural port I/O does not exist, the
  doorbell MUST use an aarch64-appropriate trappable instruction — the default is a
  reserved-immediate `HLT`/`BRK`-class debug/exception instruction (or an `hvc`
  with a reserved immediate) that the plugin traps synchronously, with the payload
  pointer/length passed in a fixed register pair per [GHC-11](b). The exact
  encoding is fixed in the channel configuration and the scenario hash. The
  per-arch doorbell mechanism differs, but the protocol above it (§16.5) is
  identical. *Gate:* `gate:abi-conformance`. *Spec:* §16.4.

- **[GHC-17]** The reserved doorbell instruction/port for each architecture MUST
  be chosen so it **cannot collide** with instructions or I/O a real guest would
  legitimately execute: the x86 port MUST be one with no device behind it, and the
  aarch64 immediate MUST be one reserved for this use. The channel MUST define what
  happens if the doorbell fires when white-box mode is *disabled*: it MUST be inert
  (the instruction behaves as it normally would on the platform — e.g. an
  unhandled port write or an exception delivered to the guest) and MUST NOT be
  intercepted, so a guest that happens to use the encoding for something else is
  unaffected when the channel is off. *Gate:* `gate:any-guest`, `gate:abi-conformance`.
  *Spec:* §16.4, §16.7.

- **[GHC-18]** The doorbell encoding for each architecture MUST be documented in
  the channel ABI and covered by `gate:abi-conformance`, and the guest emitter
  (§16.6) and the plugin trap handler MUST derive from the same single-source
  definition (consistent with the single-source-of-truth discipline of
  [`13-shmem-abi.md`](13-shmem-abi.md) §13.2). *Gate:* `gate:abi-conformance`.
  *Spec:* §16.4.

```text
Doorbell, abstractly (per-arch instruction, arch-independent payload):

  x86_64 :  mov   dx, <reserved_port>     ; configured port, no device behind it
            mov   eax, <ptr-or-tag>       ; payload pointer or inline command
            out   dx, eax                 ; <-- plugin traps synchronously here,
                                          ;     at the exact retirement icount

  aarch64:  ; payload guest-address in x0, length in x1
            hlt   #<reserved_imm>         ; <-- plugin traps synchronously here

  Above the instruction, the bytes the plugin reads from guest memory are the
  same on every architecture: the binary, versioned, length-prefixed frame
  of §16.5.
```

## 16.5 The doorbell wire format and the marker payload

Above the per-arch doorbell sits one architecture-independent binary protocol.
This is the only format the host marker decoder understands, and it is the format
the guest emitter (§16.6) produces. It is deliberately small and rigid.

The shared ABI owner is `crucible-protocol::doorbell_frame`: the
`WhiteboxDoorbellFrame` codec encodes and decodes the canonical frame, the
`GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS` corpus freezes byte-exact examples,
and `WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE` requires regenerating every
frame vector whenever `WHITEBOX_DOORBELL_PROTOCOL_VERSION` changes. The QEMU
plugin re-exports that protocol surface and routes app-random doorbells through
the shared decoder, so the host-side trap path and protocol conformance gates
observe one frame definition.

- **[GHC-19]** The doorbell frame MUST be a fixed-layout binary record:
  ```text
   offset  size  field
   ------  ----  ----------------------------------------------------------
     0      4    magic       : u32 LE, a fixed channel magic
     4      2    version     : u16 LE, the doorbell protocol version
     6      2    kind        : u16 LE, the marker kind (§16.5.1)
     8      4    payload_len : u32 LE, byte count of the body that follows
    12      N    payload     : N == payload_len bytes, kind-specific body
  ```
  A frame whose magic or version the plugin does not recognize MUST be rejected as
  a decode error (recorded as an observational diagnostic), never silently
  reinterpreted. The fixed header makes the format trivially length-delimited and
  fuzzable ([GHC-12]). *Gate:* `gate:abi-conformance`. *Spec:* §16.5.

- **[GHC-20]** The frame and all multi-byte fields MUST be **little-endian** and
  fixed-width regardless of guest or host endianness, and the body of each `kind`
  MUST itself be a fixed or length-prefixed binary layout (no embedded
  self-describing text), so the host decoder is a pure byte parse with no
  allocation-shaped ambiguity. String fields inside a body (e.g. an assertion id)
  MUST be length-prefixed UTF-8, not NUL-terminated. *Gate:* `gate:abi-conformance`.
  *Spec:* §16.5.

- **[GHC-21]** The doorbell protocol `version` MUST be bumped on any change to the
  header or to any `kind` body layout, and the channel MUST ship golden test
  vectors (byte-exact encodings of representative frames) checked by
  `gate:abi-conformance`, so that the guest emitter and the host decoder cannot
  drift. *Gate:* `gate:abi-conformance`. *Spec:* §16.5.

### 16.5.1 Marker kinds (the vocabulary carried over the channel)

The channel carries a small, fixed vocabulary of **markers**. Markers are the
white-box analogue of assertions and lifecycle signals: they let in-guest code
say "this property held / this point was reached / setup is done." The vocabulary
is shared with the assertion semantics of
[`18-assertions-properties.md`](18-assertions-properties.md) and the event-log
schema of [`19-observability-event-log.md`](19-observability-event-log.md); this
section defines the *wire* kinds, while 18 defines what each *means* for property
evaluation.

- **[GHC-22]** The doorbell `kind` field MUST enumerate exactly the following
  marker families, and the host decoder MUST map each to the corresponding
  event-log entry and assertion semantics in 18/19:
  - **Assertion markers**, carrying an assertion `id` (length-prefixed UTF-8), a
    human-readable `message`, a boolean `condition`, a `flavor`, and the
    finalize-driving fields of [GHC-36] (a `must_hit`/catalog-declaration flag, a
    structured `details` body, and the source `location`) so a never-reached
    assertion can still be finalized (18 §18.8, [ASRT-32]). The `flavor`
    distinguishes at least:
    - **always** — the condition MUST hold on every evaluation (invariant);
    - **sometimes** — the condition MUST hold on at least one evaluation
      (liveness witness);
    - **reachable** — this point MUST be reached at least once (coverage of a
      guest path); and its dual, a never-reached marker.
  - **Lifecycle markers**, with at least **setup_complete** (the guest has
    finished initialization; the white-box, precise form of the readiness point of
    [GHC-5]) and **test_done** (the guest's workload is complete; the VM may be
    quiesced/torn down).
  - **Event markers**, a free-form named diagnostic with a small key/value body,
    for in-guest observability that is not a pass/fail assertion.
  - **Coverage markers**, an in-guest-named coverage point (distinct from, and
    additive to, the black-box basic-block coverage of [GHC-7] item 7), letting a
    guest name a semantic coverage target the block-coverage signal cannot express.
  - **Random-request markers** (`random_request`), the OPTIONAL app-controlled
    randomness request of [GHC-37] (body: `request_id:u32`, `width:u8` ≤8,
    `stream_tag:lp_str`), on the guest→host path only. This is the **one** marker
    kind whose servicing produces a `Decision` (in-band, part of `reduce`) and
    elicits a host→guest reply; all other kinds are purely observational (§16.5.3).
  *Gate:* `gate:abi-conformance`. *Spec:* §16.5.1, forward-ref
  [`18-assertions-properties.md`](18-assertions-properties.md),
  [`19-observability-event-log.md`](19-observability-event-log.md).

- **[GHC-36]** An **assertion marker** body MUST carry enough to drive the
  assertion-finalize semantics of [`18-assertions-properties.md`](18-assertions-properties.md)
  §18.8 ([ASRT-32]): the assertion **id** (length-prefixed UTF-8, the id space of
  [GHC-20], [ASRT-5]); the **kind** (always/sometimes/reachable/unreachable, the
  `flavor` of [GHC-22] mirroring §18.2); a `must_hit` / **catalog-declaration**
  flag, so a `reachable`/`always` assertion whose in-guest instruction is **never
  reached** can still be finalized as never-reached (warn/fail) rather than silently
  dropped ([ASRT-21], [ASRT-22]); a structured **details** body (length-prefixed
  key/value, feeding the violation record of [ASRT-27]); and the source
  **location** (length-prefixed UTF-8). These fields MUST be a fixed or
  length-prefixed binary layout ([GHC-20]) and a change to them MUST bump the
  protocol `version` ([GHC-21]). The marker remains **observational and OPTIONAL**
  ([GHC-24], [GHC-28]) — it never gates the black-box path — but when present its
  payload MUST let the host finalize Always/Sometimes/Reachable/unreachable
  identically online and offline ([ASRT-15], [ASRT-32]). *Gate:*
  `gate:abi-conformance`. *Spec:* §16.5.1; cross-ref 18 §18.8, [ASRT-32].

- **[GHC-23]** The marker `kind` enumeration MUST be a closed, versioned set: a
  decoder MUST treat an unknown `kind` (within a recognized header magic/version)
  as a decode diagnostic, and adding a `kind` MUST bump the protocol version
  ([GHC-21]). This keeps the host's marker handling total and forward-compatible by
  explicit versioning, not by silent tolerance. *Gate:* `gate:abi-conformance`.
  *Spec:* §16.5.1.

```text
Illustrative kind table (closed, versioned set; numbers are sketches):

  kind  name              body
  ----  ----------------  -----------------------------------------------
   1    assert            flavor:u8, condition:u8, must_hit:u8, lp_str id,
                          lp_str msg, lp_str location, lp_kv[] details
   2    lifecycle         event:u16 (setup_complete | test_done)
   3    event             lp_str name, lp_kv[] details
   4    coverage          lp_str point
   5    random_request    request_id:u32, width:u8 (<=8), lp_str stream_tag

  flavor (kind=assert): 0=always  1=sometimes  2=reachable  3=unreachable
  must_hit (kind=assert): 0=not catalog-declared  1=declared (finalize never-reached)
  lp_str: u16 LE length-prefix + that many UTF-8 bytes
  lp_kv: u16 LE count, then that many (lp_str key, lp_str value) pairs

  Adding random_request (kind=5) BUMPS the doorbell protocol version ([GHC-21])
  and is golden-vectored ([GHC-37]). Unlike kinds 1-4 it is guest->host only,
  produces a Decision::AppRandom (05), and elicits a host->guest reply (§16.5.3).
```

Implementation note: `crucible-protocol::doorbell_marker` owns the closed marker
vocabulary, body codec, typed decode diagnostics, and byte-exact marker golden
vectors. The QEMU plugin decodes every generic marker trap through that shared
codec before recording it, rejects `random_request` on the observational marker
path, and maps decoded assertion payloads into `GuestAssertionMarker` events so
the existing guest assertion event-log/finalize machinery in `crucible` consumes
the shared wire fields.

### 16.5.2 Markers are observational, not part of the determinism comparison

Markers describe the run; they are not an *input* to it. A marker is emitted by
guest code that is itself deterministic (it runs at a deterministic icount under
the contract), so the *sequence and icounts* of markers are deterministic — but a
marker's *content* is descriptive output, recorded in the event log as an
observational entry and **excluded from the determinism fingerprint comparison**.

- **[GHC-24]** Every marker the channel delivers MUST be recorded as an
  **observational** event-log entry (in the sense of
  [`19-observability-event-log.md`](19-observability-event-log.md)): it is part of
  the totally-ordered record and is keyed by its exact marker icount, but it is
  **excluded** from the bit-identical determinism comparison of `T` and the
  execution fingerprint ([DET-29]). Enabling markers therefore cannot change a
  fingerprint, which is the determinism-safety property of §16.7. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §16.5.2, forward-ref
  [`18-assertions-properties.md`](18-assertions-properties.md),
  [`19-observability-event-log.md`](19-observability-event-log.md).

Implementation note: `guest_host_marker_observability` exercises the
`WhiteboxMarkerPayload` to `ObservableEvent` to `SchedulerEventLogEntry` path and
asserts that every observational marker family appends with
`SchedulerEventLogClass::Observational`, the marker's exact retired icount, and a
guest source. The QEMU plugin test drives the real doorbell callback through an
engine-backed `WhiteboxMarkerSink`, proving the decoded `WhiteboxMarker` sink
path appends the same event-log entry. The run-material test compares schedule
decisions, causal event-log projections, and backend fingerprints with marker
content and interleaving changed.

- **[GHC-25]** Because markers are observational, the host MUST evaluate
  assertion-flavored markers using the same Always/Sometimes/Reachable semantics
  as 18 (an `always` marker fails the run if its condition is ever false; a
  `sometimes` marker fails if it is never true; a `reachable` marker fails if it is
  never seen; its never-reached dual fails if it is ever seen), folding the
  guest-originated markers into the same property-evaluation pass as the black-box
  observations. *Gate:* `gate:any-guest`. *Spec:* §16.5.2, forward-ref
  [`18-assertions-properties.md`](18-assertions-properties.md).

### 16.5.3 App-controlled randomness — the one in-band, reply-bearing kind

Every marker kind above is **observational**: it describes the run and never feeds
`reduce`. The `random_request` kind ([GHC-22]) is the single exception, and it is
also the **first sanctioned use of the host→guest direction** ([GHC-31]). It lets a
guest that opts into white-box mode ask the host for a value drawn from the *same
single seeded decision source* that drives every other `Decision`, so that
app-level randomness is reproducible on exactly the terms as scheduling, fault, and
delivery decisions — and is replayable from the schedule like any other `Decision`.
Unlike an observational marker, servicing a `random_request` produces a `Decision`
(it is part of `reduce`) and writes a value back into the guest; it is therefore the
one marker kind that is *in-band* rather than purely descriptive.

- **[GHC-37]** When a node opts into white-box mode, the guest MAY ring the
  doorbell with a `random_request` marker ([GHC-22], body `request_id:u32`,
  `width:u8` ≤8, `stream_tag:lp_str`). The plugin MUST serve the requested value
  from the **single seeded decision source** of the contract
  ([`04-determinism-contract.md`](04-determinism-contract.md)), **forked per
  `(node, stream)` by name-hash of `stream_tag`** so distinct streams are
  independent and reproducible, MUST record it as a `Decision::AppRandom` (decision
  kind 05) in the schedule, and MUST write the value back **at the doorbell trap
  icount** as a host→guest reply that obeys the injection contract ([GHC-31],
  [DET-11]): delivered at an explicit delivery icount, never "as soon as computed,"
  so the reply cannot become a producer→consumer race ([DET-13], [DET-34]). The
  reply read MUST be **side-effect-free with respect to `T` except for the requested
  value** (it perturbs only the bytes the guest asked for, exactly as the doorbell
  payload read is side-effect-free, [GHC-30], [GHC-32]); `width` MUST be
  **bounds-checked** (≤8) and a malformed or over-wide request MUST be recorded as a
  decode diagnostic and dropped ([GHC-35]). This is the first sanctioned host→guest
  channel use. *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`,
  `gate:abi-conformance`. *Spec:* §16.5.3, §16.7; cross-ref
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.4.

- **[GHC-38]** The number of app-random draws per run MUST be bounded by a
  **per-scenario configured cap** that is part of the scenario content hash
  ([GHC-5], [INV-6]); exceeding the cap MUST **fail loud** (a typed run error, not a
  silently-clamped draw). The engine MUST function with **zero** app-random requests
  ([G-3], [GHC-1], [GHC-28]): a scenario that never rings a `random_request` behaves
  identically (to the fingerprint) whether or not app-random is compiled in, exactly
  as for the rest of the white-box channel ([GHC-2]). *Gate:*
  `gate:single-vm-fingerprint`, `gate:any-guest`, `gate:content-address`. *Spec:*
  §16.5.3.

## 16.6 The optional guest emitter (`crucible-guest`)

When a scenario wants white-box markers, the guest needs something that can ring
the doorbell. Crucible provides a minimal one. Its defining property is that it is
*not required*: it is a convenience for guests that opt into white-box mode, and
its complete absence changes nothing about [GHC-1].

- **[GHC-26]** Crucible MUST provide `crucible-guest`, a **minimal static
  binary** (and a thin library it wraps) that emits doorbell markers: a guest
  copies it in, or links the library, and calls it to ring the doorbell with a
  §16.5 frame. It MUST be a tiny, dependency-light static executable (no dynamic
  linker requirement, no `/dev` node, no kernel module) so it runs on an arbitrary
  guest userspace. *Gate:* `gate:abi-conformance`. *Spec:* §16.6.

- **[GHC-27]** `crucible-guest` MUST expose a CLI marker vocabulary mirroring
  §16.5.1 — at least `always`, `sometimes`, `reachable` (and its never-reached
  dual), `setup-complete`, `test-done`, an `event` form, a `coverage` form, and a
  `get-random <width> [tag]` verb (the `random_request` kind of [GHC-37],
  generated from the single-source channel ABI like every other verb, [GHC-18],
  [GHC-29]) — each producing the corresponding §16.5 binary frame and ringing the
  doorbell. Unlike the observational verbs, `get-random` rings the doorbell and then
  **reads the host→guest reply** at the injected delivery icount and returns the
  drawn value to its caller. The CLI surface mirrors the wire kinds so a guest author
  has one obvious tool. *Gate:* `gate:abi-conformance`. *Spec:* §16.6, §16.5.1,
  §16.5.3.

- **[GHC-28]** The **absence** of `crucible-guest` (or of any white-box emitter)
  MUST NOT affect core function ([GHC-1], [G-3]): a scenario that does not place
  the emitter in the guest still has full determinism, faults, coverage, and
  observable-I/O properties. The emitter MUST be the *only* in-guest content the
  white-box channel needs, and even that is optional. *Gate:* `gate:any-guest`.
  *Spec:* §16.6.

- **[GHC-29]** `crucible-guest` MUST be built hermetically from source within AOS
  as a static binary for each supported guest architecture ([G-7]); it MUST NOT be
  pulled in as an upstream binary, and its doorbell encoding and frame format MUST
  be generated from the same single-source channel-ABI definition as the plugin's
  trap handler ([GHC-18]). *Gate:* `gate:abi-conformance`. *Spec:* §16.6,
  forward-ref [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md).

```text
crucible-guest CLI sketch (mirrors §16.5.1; emits §16.5 binary frames):

  crucible-guest always     <id> <message> <0|1>
  crucible-guest sometimes  <id> <message> <0|1>
  crucible-guest reachable  <id> <message>
  crucible-guest unreachable <id> <message>
  crucible-guest setup-complete
  crucible-guest test-done
  crucible-guest event      <name> [k=v ...]
  crucible-guest coverage   <point>
  crucible-guest get-random <width> [tag]   # rings doorbell, reads host reply

  Each invocation encodes one binary frame and executes the per-arch
  doorbell instruction (§16.4). No /dev node, no driver, no dynamic linker.
  get-random additionally reads the host->guest reply at the injected delivery
  icount (§16.5.3) and returns the drawn value; all other verbs are fire-and-forget.
```

## 16.7 Determinism and safety of the channel

The channel must add information about the run without adding nondeterminism to
it. This section is the safety contract that makes the white-box channel safe to
enable.

- **[GHC-30]** The guest↔host channel MUST NOT introduce nondeterminism. Because
  the doorbell is serviced synchronously at the guest's instruction
  ([GHC-10]) and the guest code that rings it is itself deterministic under the
  contract, the marker stream is a pure function of `(scenario, seed, schedule)`.
  Enabling the channel MUST NOT change `S` or `T` for the guest (markers are
  observational, [GHC-24]); the **fingerprints of a run with markers enabled and
  the same run with markers disabled MUST be identical** for the determinism-relevant
  state, differing only in the observational event log. *Gate:*
  `gate:single-vm-fingerprint`, `gate:any-guest`. *Spec:* §16.7.

  *Rationale and caveat.* Executing the doorbell instruction does retire guest
  instructions like any other guest code, so a guest that conditionally rings the
  doorbell changes its own instruction stream relative to one that does not — but
  that is the guest's own deterministic choice, identical across runs. What [GHC-30]
  forbids is the *host servicing* of the doorbell perturbing the guest: the plugin's
  read of guest memory at the trap MUST be side-effect-free with respect to `T`.

- **[GHC-31]** Any host→guest direction over the white-box channel (for example, a
  host reply read back by the guest) MUST obey the injection contract ([DET-11]):
  it MUST be delivered at an explicit delivery icount, never "as soon as the host
  computed it," so that white-box interaction cannot become a producer→consumer
  race ([DET-13], [DET-34]). The default channel is guest→host-only; any bidirectional
  use is gated on this. *Gate:* `gate:layer1-injection`. *Spec:* §16.7,
  forward-ref [`04-determinism-contract.md`](04-determinism-contract.md) §4.4.

- **[GHC-32]** The plugin MUST read the doorbell payload from guest memory **at the
  exact trap icount** and MUST treat it as a snapshot taken at that instant; it MUST
  NOT read it later (when guest memory may have changed) nor defer the read past the
  trap. A payload too large to read atomically at the trap MUST be rejected as a
  decode error rather than read piecemeal across icounts. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §16.7.

- **[GHC-33]** **Guest virtual vs. physical address (spike).** The plugin reads the
  payload from a guest address supplied by the guest ([GHC-11]). It MUST be
  determined whether the plugin's guest-memory API can read a guest **virtual**
  address (translating through the guest page tables at the trap) or whether the
  ABI must instead pass a guest **physical** address (or a pinned, identity-mapped
  shared page) to read safely. Until resolved, the channel MUST default to the
  conservative option (a pre-agreed physical/identity-mapped shared page) and the
  spike MUST establish whether virtual-address reads are sound and reproducible.
  The app-random host→guest reply write-back ([GHC-37]) is a **second client of
  this same guest-memory path** (it writes the drawn value where the doorbell read
  the request) and introduces no new spike. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §16.7, forward-ref [`30-risks-spikes.md`](30-risks-spikes.md).

- **[GHC-34]** The reserved doorbell port/instruction ([GHC-15], [GHC-16]) MUST be
  validated at channel setup to not collide with the guest's real device map or
  legitimate instruction use ([GHC-17]); a collision MUST be a setup error, not a
  silently-shared resource. When the channel is disabled the doorbell MUST be inert
  ([GHC-17]), so a guest that never opts in is byte-identical with the channel
  machinery compiled in or out ([GHC-2]). *Gate:* `gate:any-guest`,
  `gate:abi-conformance`. *Spec:* §16.7.

- **[GHC-35]** A malformed or unexpected doorbell (bad magic, unknown version,
  oversized `payload_len`, unknown `kind`) MUST be handled defensively by the
  plugin: recorded as an observational decode diagnostic and dropped, never
  trusted, and never able to crash the plugin or perturb `T`. The doorbell payload
  is **untrusted guest input** and the host decoder MUST be written to that
  standard (bounds-checked, allocation-bounded, fuzzed under `gate:abi-conformance`).
  *Gate:* `gate:abi-conformance`. *Spec:* §16.7.

## 16.8 Summary

```text
Black-box (default, required, zero guest cooperation):
  network · disk/9p · console/serial · QMP regs/memory · exit codes ·
  crash/hang · basic-block coverage (TCG-exec hook, any binary)
  + readiness heuristic (fixed icount | first-network-idle | console marker)
  => enough for determinism, faults, coverage, most properties, OS-agnosticism.

White-box (opt-in, optional, additive — NEVER required):
  doorbell = reserved trapped instruction (x86_64: port I/O; aarch64: HLT/BRK)
           serviced synchronously at the exact icount
  payload  = shared page or ptr+len in registers, read by the plugin memory API
  protocol = binary, versioned, length-prefixed (NOT JSON), arch-independent
  markers  = assert(always/sometimes/reachable) · lifecycle(setup_complete/
             test_done) · event · coverage
           = observational event-log entries, icount-stamped, excluded from the
             determinism comparison
  emitter  = crucible-guest, a tiny static binary; its absence changes nothing.

Safety: the channel adds information, never nondeterminism. The plugin reads the
payload side-effect-free at the trap icount; enabling markers leaves the
fingerprint unchanged; a disabled doorbell is inert; the payload is untrusted.
```

If black-box observation is the floor and the white-box doorbell is a strictly
additive enhancement that cannot move the fingerprint, then "any unmodified
guest" ([G-2]) and "black-box by default, white-box by opt-in" ([G-3]) hold at
the transport layer by construction.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the guest↔host channel, tracked by [PLAN-3].

- [x] **T-GHC-1** Specify and enforce the black-box observation surface (network,
  disk/9p, console/serial, QMP regs/memory, exit codes, crash/hang, basic-block
  coverage) as the required floor, each observation icount-stamped and ordered. —
  satisfies [GHC-1], [GHC-3], [GHC-7], [GHC-8]; spec §16.1, §16.2.
  Completed by `checks.crucible.phase4.guestHostBlackBoxSurface`: `crucible`
  now exposes a closed `BlackBoxObservationKind` catalog for the required
  black-box floor, classifies observable event payloads into that surface while
  excluding optional white-box markers, enforces the required surface and
  virtual-time order plus required icount stamps when constructing condition
  prefixes, records
  no-progress detection as the black-box `Hung` node lifecycle state, and
  regresses that every required surface category becomes an ordered,
  icount-stamped observational event-log entry.
- [x] **T-GHC-2** Implement the OS-agnostic guarantee of black-box observation:
  no Linux/init/filesystem/ABI assumptions; verify on a non-Linux image. —
  satisfies [GHC-4], [GHC-9]; spec §16.2.
  Completed by `checks.crucible.phase4.guestHostOsAgnostic`: `crucible` now
  exposes a closed OS-agnostic black-box observation contract catalog, projects
  every required black-box observable event into that contract, marks all
  surfaces as requiring no guest OS, init system, filesystem layout, or in-guest
  ABI, treats console/serial observation as an output-only sink, and regresses
  those guarantees against a content-addressed raw non-Linux AArch64 root image
  byte fixture with white-box guest software disabled.
- [x] **T-GHC-3** Implement the readiness heuristic (fixed icount /
  first-network-idle / console marker), resolving to a deterministic icount and
  hashed into the scenario; reject non-deterministic heuristics at validation. —
  satisfies [GHC-5], [GHC-6]; spec §16.1.2.
  Completed by `checks.crucible.phase4.guestHostReadiness`: `crucible` now
  exposes a deterministic black-box `resolve_ready_point` API that resolves
  fixed-icount, first-network-idle, and console-marker readiness to explicit
  coherent virtual-time plus icount coordinates, uses the scenario's hashed
  `ReadyPoint` material and per-node icount shift for conversion, treats
  same-tick network activity as not yet idle, canonicalizes same-time console
  chunks deterministically, rejects degenerate network-idle and console-marker
  parameters during world validation, rejects network-idle nodes with no
  incident links, and treats the optional `AgentSignal` policy as white-box-only
  rather than black-box resolvable.
- [ ] **T-GHC-4** Implement the synchronous trapped-instruction doorbell in the
  plugin, serviced inline at the exact retirement icount, with payload via shared
  page or register ptr+len; forbid a virtio-serial/device data channel for the
  reasons of §16.3.1. — satisfies [GHC-10], [GHC-11], [GHC-13], [GHC-14]; spec
  §16.3, §16.3.1, §16.4.
  Partial callback-core evidence is provided by
  `checks.crucible.phase4.guestHostDoorbell`: the QEMU plugin model now
  exposes a typed white-box doorbell callback core and registration plan that
  selects the reserved trapped-instruction callback in white-box mode, services
  each trap inline through QEMU guest-memory reads, stamps markers with the exact
  trap `current_icount`, accepts only shared-page or register pointer+length
  payload sources, rejects disabled or oversized traps before reading guest
  memory, and keeps device-queue channel markers out of the doorbell path.
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell` now adds the first real
  backend slice: a standalone x86 guest rings the frozen `out dx,eax` doorbell
  on port `0x00e7`, and the packaged production Rust plugin reads its
  `rax`/`rcx` virtual pointer+length payload, decodes the golden coverage marker,
  and reports the exact trap icount before the run reaches its exact scheduler
  ceiling. Its paired off/on runs also prove that disabling white-box installs
  no callback record and that servicing the observational marker leaves the
  production execution fingerprint unchanged. Live collision validation,
  decoded host event-log routing, and host-to-guest replies are now covered by
  the same gate. The item remains open only for the aarch64 live adapter.
- [x] **T-GHC-5** Define the per-arch doorbell: x86_64 reserved port I/O and
  aarch64 reserved-immediate HLT/BRK (or hvc), from a single-source ABI
  definition; document and golden-vector the encodings. — satisfies [GHC-15],
  [GHC-16], [GHC-18]; spec §16.4.
  Completed by `checks.crucible.phase4.guestHostDoorbellAbi`: `crucible-protocol`
  now exports `WHITEBOX_DOORBELL_ABIS` as the single-source instruction ABI, the
  QEMU plugin and guest-agent boundary re-export it, the x86_64 `out dx,eax` byte
  vector (`ef`) and aarch64 `hlt #0x04c1` byte vector (`20 98 40 d4`) are frozen,
  the payload register contract is recorded (`rax`/`rcx`, `x0`/`x1`), and plugin
  registration state is built from those ABI trap entries.
- [x] **T-GHC-6** Implement collision avoidance and inertness for the reserved
  doorbell port/instruction: validate non-collision at setup; inert when the
  channel is disabled. — satisfies [GHC-17], [GHC-34]; spec §16.4, §16.7.
  Completed by `checks.crucible.phase4.guestHostDoorbellCollisionInertness`
  together with `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`:
  `checks.crucible.phase4.guestHostDoorbellCollisionInertness`: the
  plugin now validates the configured trap against
  `WhiteboxDoorbellSetupResources`, requires the resulting
  `WhiteboxDoorbellSetupValidation` before installing the white-box trap, rejects
  unchecked, mismatched, x86 port collision, and aarch64 reserved-immediate
  collision records as setup errors, and preserves the disabled plan that installs
  no trap so the doorbell remains inert when the channel is off. The real x86
  backend gate now corroborates that model by executing the same doorbell guest
  with white-box off and on: off mode emits zero white-box callback records, and
  the production-plugin execution fingerprints are equal. Before the enabled
  run registers the callback, the host now launches the exact configured QEMU
  machine stopped and plugin-free, queries its flattened I/O map, and accepts
  port `0x00e7` only when QEMU reports the unassigned `io` fallback. A versioned
  `x86-port-00e7-unclaimed-v1` attestation is required by the plugin parser and
  consumed by live registration; omission is fail-closed. The real-backend
  negative maps `isa-debugcon` at `0x00e7` and proves the same production parser
  rejects the collision before the control plugin is launched.
- [x] **T-GHC-7** Implement the binary, versioned, length-prefixed doorbell frame
  format (magic/version/kind/len/payload, little-endian, length-prefixed strings),
  with golden vectors and a versioning rule. — satisfies [GHC-12], [GHC-19],
  [GHC-20], [GHC-21]; spec §16.5.
  Completed by `checks.crucible.phase4.guestHostDoorbellFrame`: `crucible-protocol`
  now owns the fixed little-endian `WhiteboxDoorbellFrame` header/body codec,
  exports byte-exact golden frame vectors plus a regeneration rule tied to the
  protocol version, and feeds those vectors through the ABI-conformance and
  golden-vector tests; the QEMU plugin re-exports the same frame ABI, decodes
  generic marker traps before recording their kind/body bytes, and maps shared
  decode failures into its observational app-random diagnostics.
- [x] **T-GHC-8** Implement the closed, versioned marker-kind vocabulary
  (assert always/sometimes/reachable + dual; lifecycle setup_complete/test_done;
  event; coverage) and its mapping to event-log/assertion semantics, including the
  assertion-marker payload fields (id/kind/`must_hit`/details/location) that drive
  finalize. — satisfies [GHC-22], [GHC-23], [GHC-25], [GHC-36]; spec §16.5.1.
  Completed by `checks.crucible.phase4.guestHostMarkerVocabulary`:
  `crucible-protocol` now owns the closed marker-kind vocabulary, assertion,
  lifecycle, event, coverage, and app-random body codecs, typed decode errors, and
  marker payload golden vectors; `crucible` maps decoded assertion payloads into
  `GuestAssertionMarker` events for the existing finalize machinery; the QEMU
  plugin validates generic white-box marker traps through that shared codec,
  records decoded observational marker payloads, and rejects `random_request` on
  the observational marker path while preserving the existing app-random servicing
  path.
- [x] **T-GHC-9** Record every marker as an observational, icount-stamped
  event-log entry excluded from the determinism comparison; prove markers do not
  move the fingerprint. — satisfies [GHC-24], [GHC-30]; spec §16.5.2, §16.7.
  Completed by `checks.crucible.phase4.guestHostMarkerObservability` and
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`: decoded white-box assertion,
  lifecycle, event, and coverage marker payloads append as observational
  scheduler event-log entries stamped with the exact marker icount and guest
  source. The live gate proves the production x86 guest → QEMU-plugin callback →
  ABI-v4 SPSC shmem ring → host quantum-boundary validation and canonical decode
  → unified `EventLog` path, with no callback allocation or diagnostic I/O.
  Model tests prove marker content and interleaving cannot change schedule
  decisions, causal event-log projections, or backend fingerprints, and the live
  white-box off/on executions produce identical fingerprints while admitting
  exactly one named marker in on mode.
- [x] **T-GHC-10** Build `crucible-guest`, a minimal static guest emitter (CLI +
  thin library) mirroring the marker vocabulary, hermetically from source for each
  guest arch from the single-source ABI. — satisfies [GHC-26], [GHC-27], [GHC-29];
  spec §16.6.
  Completed by `checks.crucible.phase4.guestHostEmitter`: `crucible-guest::GuestCommand`
  now constructs every §16.5.1 marker family through the shared
  `crucible-protocol` marker codec, the `crucible-guest` CLI mirrors the
  always/sometimes/reachable/unreachable/lifecycle/event/coverage/get-random
  vocabulary, `InstructionDoorbellTransport` rings the Linux x86_64 and aarch64
  trap instructions from `WHITEBOX_DOORBELL_ABIS` (with x86_64 `ioperm(2)`
  requested before `out dx,eax`), and the dedicated AOS `pkgs.crucible-guest`
  package builds the current-system `crucible-guest` binary from source with
  target-specific `target-feature=+crt-static` flags plus an ELF interpreter
  absence check while recording the shared x86_64/aarch64 instruction ABI
  coverage separately from the current packaged guest system.
- [x] **T-GHC-11** Prove the emitter's absence changes nothing: full determinism,
  faults, coverage, observable-I/O properties with no in-guest content. —
  satisfies [GHC-2], [GHC-28]; spec §16.6, §16.1.
  Completed by `checks.crucible.phase4.guestHostEmitterAbsence`: the
  `guest_host_emitter_absence` test drives both `WhiteBoxPolicy::Disabled` and
  enabled-but-unused worlds with empty guest command lines and no kernel/root/initrd
  content additions, then proves no-emitter repeatability and enabled-unused
  behavioral equivalence for event-log determinism, trigger fault activation/heal
  snapshots, real host assertion verdicts, coverage projection fingerprints,
  black-box observable-I/O condition firings, and backend fingerprints while
  rejecting any named or guest-marker leaf fallback and any guest-marker event-log
  entry.
- [x] **T-GHC-12** Enforce channel determinism/safety: side-effect-free payload
  read at the exact trap icount; host→guest direction (if any) obeys the injection
  contract; fingerprint-identical with markers on vs off. — satisfies [GHC-30],
  [GHC-31], [GHC-32]; spec §16.7.
  Callback-core and scheduler-model evidence is provided by
  `checks.crucible.phase4.guestHostChannelDeterminism`: the QEMU plugin model
  routes generic marker traps through the shared trap-icount payload
  reader, and `whitebox_channel_safety_reads_payload_snapshot_at_exact_trap_icount`
  pins the safe callback-core contract to a single `current_icount` snapshot whose
  decoded marker is unaffected by later guest-memory mutation in the reader
  backend; the host→guest path is pinned by
  `whitebox_channel_safety_injects_host_to_guest_only_at_delivery_icount`,
  `whitebox_channel_safety_ignores_producer_timing_before_delivery_icount`, and
  the app-random trap-icount reply test, which reject early and late writes and
  make eager producer attempts produce the same write as a just-in-time producer;
  `guest_host_channel_determinism` drives the engine scheduler event-log path
  under `WhiteBoxPolicy::Disabled` and `WhiteBoxPolicy::Enabled` and proves
  marker-enabled and marker-disabled witnesses keep identical causal event-log and
  backend fingerprint material while a changed causal boundary or backend workload
  still moves the witness. Canonical `gate:any-guest` and
  `gate:single-vm-fingerprint` wiring is bound by
  `checks.crucible.phase4.guestHostChannelGateWiring`.
  Live host-to-guest closure is provided by
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`: the reply write occurs
  synchronously through the current-vCPU guest-memory mapping at the trap
  icount, the guest validates it before acknowledging, the causal decision is
  independently reconstructed by the host, and off/on fingerprints remain
  equal.
- [x] **T-GHC-13** Run the guest virtual-vs-physical address spike for the payload
  read; default to the conservative physical/identity-mapped shared page until
  resolved. — satisfies [GHC-33]; spec §16.7.
  Completed by `checks.crucible.phase4.guestHostVirtualMemorySpike`: the
  phase gate now depends on the Phase 0
  `checks.crucible.phase0.s5VirtualMemory` result file and rejects missing S5
  evidence for the instruction-marker doorbell surface, register pointer+length
  payload source, `qemu_plugin_read_memory_vaddr`, resident/page-spanning/paged-mmap
  reads, reproducible marker icounts, byte hashes, side-effect-free final
  fingerprints, and `physical_pinned_fallback_adopted=false`. The white-box
  doorbell exposes `WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED` as the
  fail-closed default, and its virtual-address soundness predicate requires the
  S5 check identity before selecting a virtual register pointer+length payload
  source. The app-random reply path is covered as a second client of the same
  guest-memory addressing decision. The physical / pinned identity-mapped shared-page fallback
  remains retained if that evidence is absent or invalidated.
- [x] **T-GHC-14** Harden the host decoder against untrusted guest input
  (bad magic/version/len/kind): defensive decode diagnostic, bounded allocation,
  fuzzed under conformance. — satisfies [GHC-23], [GHC-35]; spec §16.5, §16.7.
  Completed by `checks.crucible.phase4.guestHostDecoderHardening`: the shared
  doorbell frame decoder now exposes `WhiteboxDoorbellFrame::decode_bounded`,
  which rejects a header-declared payload length above the caller's trap-time
  budget before copying payload bytes. The protocol codec and
  `gate:abi-conformance` tests cover bad magic, bad version, bounded declared
  length, length mismatch, and wrong-kind/unknown-kind cases with no-panic fuzz
  regression coverage. The plugin marker and app-random paths use the bounded
  decoder; malformed marker-path frames record
  `WhiteboxDoorbellDecodeDiagnostic` before being dropped, while malformed
  app-random frames are turned into typed decode diagnostics and dropped without
  drawing a decision or writing a reply.
- [x] **T-GHC-15** Wire `gate:any-guest` and `gate:single-vm-fingerprint` to cover
  the channel: black-box sufficiency, opt-in additivity, and fingerprint-equality
  with white-box on/off. — satisfies [GHC-1], [GHC-2], [GHC-30], [G-3]; spec
  §16.1, §16.7.
  Completed by
  `checks.crucible.phase4.guestHostChannelGateWiring`: the phase4
  binding gate carries the relevant gate definition files in lazy passthru,
  statically pins the phase2 canonical gate ordering in `tests/crucible/default.nix`
  including `qemuInert -> singleVmFingerprint -> anyGuest`, enforces their
  source/result contract text plus the phase4 channel determinism and
  emitter-absence result contracts, requires black-box no-agent/no-content
  sufficiency, records white-box as a host/plugin opt-in rather than guest content,
  and preserves the real QEMU icount/register/RAM fingerprint axis. It also
  depends on `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`, whose paired
  production-plugin runs execute the same standalone guest with white-box off
  and with a live kind-4 coverage marker enabled, require byte-identical
  execution fingerprints, and admit the enabled marker through the
  plugin-to-host shared-memory ring at a completed quantum boundary. Together
  with the scheduler marker-neutrality proof, this establishes black-box
  sufficiency, opt-in additivity, and live white-box on/off fingerprint equality.
- [x] **T-GHC-16** Implement the OPTIONAL app-controlled-randomness `random_request`
  doorbell kind (kind=5, bumps the protocol version, golden-vectored): serve from
  the single seeded decision source forked per `(node, stream_tag)` by name-hash,
  record a `Decision::AppRandom` (05), and write the value back at the trap icount
  as a host→guest reply obeying the injection contract; bounds-check `width` ≤8;
  malformed → decode diagnostic + drop. Reuse the spike-S5 guest-memory path (second
  client, no new spike). — satisfies [GHC-37]; spec §16.5.3, §16.7.
  Callback-core and engine-model evidence is provided by
  `checks.crucible.phase4.guestHostAppRandomDoorbell`: the phase4
  gate binds the existing golden-vectored kind-5 `random_request` protocol
  surface to the plugin's trap-time guest-memory read and host-to-guest injection
  path, with width `<=8`, bounded decode diagnostics, and malformed-frame drop
  behavior inherited from the phase2 app-random doorbell gate. Its focused
  engine-backed tests drive the full doorbell callback through a test-only
  `DecisionRecorder` adapter, using a node plus `stream_tag` composite
  `RngStreamId::from_name(...)` so requests are served from scenario-seed
  name-hashed decision streams that are isolated across nodes with the same tag,
  preserving the guest request id and recording `RngDraw` followed by
  `Decision::AppRandom` before writing the little-endian reply at the trap
  icount. The gate also consumes the T-GHC-13 S5 result, reruns the app-random
  reply-range client of that guest-memory path, and reruns the random-request
  doorbell-frame and marker-payload golden-vector tests.
  Live closure is provided by
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`: a real x86 guest submits
  request `0x01020304` for three bytes on tag `live-rng`, the production plugin
  returns the scenario-seeded value through patched QEMU at the trap icount,
  and the host consumes the typed shmem record as an authoritative
  `Decision::AppRandom` only after independently deriving the same value.
- [x] **T-GHC-17** Enforce the app-random per-scenario draw cap (part of the scenario
  hash; exceeding fails loud) and prove the engine functions with zero app-random
  requests (fingerprint-identical with app-random compiled in vs out); add the
  `get-random <width> [tag]` verb to `crucible-guest` from the single-source ABI. —
  satisfies [GHC-38], [GHC-27]; spec §16.5.3, §16.6.
  Completed by `checks.crucible.phase4.guestHostAppRandomCap`: `ScenarioDef`
  now carries the app-random draw cap into the scenario definition hash and DAG
  store material, and `ScenarioDefForm` round-trips it through TOML and compact
  binary artifacts. `DecisionRecorder`, checked `try_step`, and `reduce`
  enforce the cap through typed `AppRandomDrawCapExceeded` errors for live
  requests, explorer overrides, direct configuration stepping, and manually
  supplied schedules, including resumed schedules whose prior
  `Decision::AppRandom` entries already consume draw budget. The
  `guest_host_channel_determinism` test adds a zero-request compiled-in-unused
  run fingerprint-identical to the white-box-disabled run, while the gate keeps
  binding the phase2 no-decisions/no-replies byte identity proof. The guest ABI
  side is covered by the existing `crucible-guest get-random <width> [tag]`
  parser, single-source protocol payload encoding, reply readback, and
  malformed-width rejection tests.
