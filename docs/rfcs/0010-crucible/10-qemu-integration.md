# 10 — QEMU integration (host side)

This file specifies the **host-side** half of the QEMU layer (L2): the Rust
crate `crucible-qemu` that owns each VM's QEMU child process, drives it through
the determinism contract, and exposes it to the scheduler as a single
scheduling node. The *in-VM* half — the cdylib that holds time control and runs
the device/channel callbacks — is [`12-qemu-plugin.md`](12-qemu-plugin.md); the
source changes to QEMU itself are [`11-qemu-patches.md`](11-qemu-patches.md).
This file is about what the host process does: how it launches QEMU, how it
realizes a VM from a `Configuration` (boot / loadvm / replay, file 05), how it
talks to QMP, how it shuts a child down without ever leaking it, and how it
bridges the synchronous node-step interface the scheduler wants to the
asynchronous socket and QMP I/O QEMU needs.

Requirement IDs in this file use the prefix `QEMU`. Gate names referenced here
(`gate:single-vm-fingerprint`, `gate:any-guest`, `gate:qemu-inert`,
`gate:layer0-determinism`, `gate:control-responsive`, `gate:e2e-determinism`,
`gate:layer1-injection`, `gate:replay-oracle`) are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). The
launch configuration realizes the determinism contract of
[`04-determinism-contract.md`](04-determinism-contract.md) §4.6 and the time
model of [`09-virtual-time-icount.md`](09-virtual-time-icount.md); the
realization branches (boot/loadvm/replay) are the execution model of
[`05-execution-model.md`](05-execution-model.md) §5–§7; the three logical planes are
the protocol of [`14-protocol.md`](14-protocol.md), the shared-memory ABI of
[`13-shmem-abi.md`](13-shmem-abi.md), and QMP defined here.

`crucible-qemu` is Apache host-side code. It launches and supervises QEMU as a
separate process and MUST NOT link to QEMU, include its headers, or expose QEMU
callback entry points. All Crucible-specific communication crosses the public
process protocols defined in 13/14 and constrained by
[`37-licensing-process-boundary.md`](37-licensing-process-boundary.md).

## 10.1 Why QEMU TCG + `-icount`, not KVM

Crucible's contract ([DET-1]) is that a guest produces a bit-identical
instruction stream and architectural-state trajectory for fixed
`(image, cmdline, seed, I)`. That contract is only achievable on an execution
backend whose progress is a pure function of the instructions retired, not of
how fast the host CPU happened to run. KVM is exactly the wrong backend for
this: under hardware virtualization the guest runs *natively* on the host core,
so its timing — TSC reads, interrupt arrival relative to instructions, the
number of instructions executed before a timer deadline — is a function of the
host microarchitecture, host frequency scaling, and host scheduling. There is no
instruction counter the host can read and command, and `RDRAND`/`RDTSC` go
straight to the metal. KVM cannot satisfy [DET-1] even in principle.

QEMU's **TCG** (Tiny Code Generator) binary-translates guest instructions into
host instructions and *interprets the guest in software*. With `-icount`, TCG
maintains an exact count of retired guest instructions and derives the guest's
virtual clock from that count (`ns = icount << shift`, [TIME-3]). This is the
one mode in which "advance the guest to virtual time `T`" has a precise,
host-independent meaning: retire exactly the instructions that fit before `T`.
Every entropy source in [`04-determinism-contract.md`](04-determinism-contract.md)
§4.6 is either eliminated by configuration or made a pure function of the icount
clock — but *only* because TCG emulates rather than delegates. Floating point
(E15) is deterministic across hosts because TCG soft-float computes it, not the
host FPU; the TSC (E4) is icount-derived because TCG owns the cycle counter; the
CPU model (E10) is whatever `-cpu` says, not the host's.

- **[QEMU-1]** Every simulation VM node MUST run under QEMU's TCG-derived
  `sim` accelerator with `-accel sim,thread=single` and `-icount shift=N` for a
  fixed integer `N`. Crucible MUST
  NOT run a VM node under KVM or any hardware-accelerated backend for a
  simulation run, because hardware virtualization makes guest progress a function
  of host timing and defeats [DET-1] in principle. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §10.1, §10.2;
  satisfies [DET-1], [TIME-1], references [DET-8].

- **[QEMU-2]** The host launcher MUST reject — at scenario-validation /
  launch-configuration time, before spawning any child — a Crucible runtime
  configuration that selects stock `tcg`, KVM, any accelerator other than the
  TCG-derived `sim` accelerator, `thread=multi`, `-icount shift=auto`, or omits `-icount`.
  The rejection MUST be a loud, early error, never a silent fall-through to a
  non-deterministic run. *Gate:* `gate:layer0-determinism`. *Spec:* §10.1, §10.2;
  satisfies [DET-9], [TIME-5].

## 10.2 The launch configuration (enumerated)

The host constructs each VM's QEMU command line from the node's `World` entry
(06) plus the scenario's global determinism pins (shift, seed, CPU model). The
command line is the *only* knob by which the host configures intra-VM
hermeticity ([DET-15]: the guest image is untouched), so it is enumerated here
exhaustively and is part of the scenario content hash ([TIME-6], [DET-35]). The
launch flags below are the host-side realization of the §4.6 entropy
elimination; the patch-class mechanisms (warp suppression, deterministic
getrandom, etc.) are activated by sim mode and specified in 11.

- **[QEMU-3]** The host MUST construct each VM's QEMU launch configuration
  deterministically from the node's `World` entry and the scenario's global pins,
  and the full launch configuration (every flag that can affect `S` or `T`) MUST
  be incorporated into the scenario content hash so two builds launch
  byte-identical command lines. A flag that affects determinism but is not in the
  content hash is a defect. *Gate:* `gate:single-vm-fingerprint`,
  `gate:content-address`. *Spec:* §10.2; satisfies [DET-35], [TIME-6].

The enumerated, REQUIRED launch elements (illustrative command sketch follows
the requirements):

- **[QEMU-4]** **Execution backend.** `-accel sim,thread=single` and `-icount
  shift=N` with the fixed scenario shift; `sim` is the patch series'
  TCG-derived accelerator and the icount mode MUST be the precise (fixed-shift) mode,
  never `auto` ([QEMU-2]). Idle warp MUST be suppressed when the plugin holds
  time control (the patch-series mechanism E2/[TIME-21]); the host requests the
  no-warp behavior via the icount/plugin configuration so the virtual clock
  advances only by retired instructions and scheduler-authorized jumps. *Gate:*
  `gate:layer0-determinism`. *Spec:* §10.2; satisfies [DET-8], [DET-10],
  [TIME-21], references [DET-9].

- **[QEMU-5]** **vCPUs under single-threaded round-robin TCG.** `-smp N` is
  permitted (N ≥ 1); the accelerator MUST be single-threaded round-robin TCG
  (`-accel sim,thread=single`). Stock `-accel tcg` MUST also be rejected for a
  Crucible run because it leaves the sim-gated RR, IPI, shmem-dispatch, and
  preemption mechanisms inactive. Multi-threaded TCG (`thread=multi`, MTTCG)
  MUST be rejected at launch-configuration time, because parallel host threads make
  instruction interleaving a function of host scheduling and defeat [DET-1].
  Under single-threaded round-robin all N vCPUs are driven serially on one host
  thread, so guest progress and the vCPU-switch interleaving remain a pure
  function of icount. The round-robin switch boundary MUST be pinned to a fixed,
  content-addressed `rr_switch_quantum` expressed in node-icount and MUST NOT use
  QEMU's adaptive / realtime round-robin default ([QEMU-43]); the host MUST refuse
  a configuration that selects `thread=multi` or leaves `rr_switch_quantum`
  unpinned. *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`.
  *Spec:* §10.2; satisfies [DET-1], references [NG-1], [DET-23], [QEMU-43].

- **[QEMU-43]** **Round-robin single-thread launch validation.** The host MUST
  validate, at launch-configuration time before spawning any child, that the
  accelerator is the single-threaded TCG-derived sim accelerator: it MUST reject
  stock `tcg` and `thread=multi` (MTTCG) loudly and MUST accept `-smp N` only in
  conjunction with `-accel sim,thread=single`. The host MUST set the round-robin switch boundary
  to the scenario's content-addressed `rr_switch_quantum` (in node-icount) via
  the patch-series flag (`crucible-rr-quantum-icount`, 11/[PATCH-44]), MUST
  reject a configuration that leaves the quantum at QEMU's adaptive/realtime
  default, and MUST fold N and the pinned `rr_switch_quantum` into the scenario
  content hash so two builds launch byte-identical vCPU/round-robin
  configurations ([DET-35], [TIME-6]). *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §10.2; satisfies [DET-1], [DET-23],
  [DET-35], [TIME-6], references [NG-1], [PATCH-44].

- **[QEMU-6]** **Fixed CPU model.** `-cpu <model>` naming a concrete model that
  does **not** advertise `RDRAND`/`RDSEED` (or, equivalently, the patch series
  emulates those from the seeded stream, E1). `-cpu host` MUST NOT be used. The
  model is part of the scenario hash and makes floating point (E15) deterministic
  under TCG soft-float. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §10.2; satisfies [DET-19], [DET-20].

- **[QEMU-7]** **Fixed machine and reset state.** A fixed `-machine` type, with
  deterministic machine reset (RAM zeroed or fixed-pattern, device reset values
  fixed — E16, the genesis bake, 05). Guest memory size and device topology are
  fixed by the `World` entry. *Gate:* `gate:layer0-determinism`. *Spec:* §10.2;
  satisfies [DET-18] (E16), references [EXEC-18].

- **[QEMU-8]** **Fixed clock base, no host time.** A fixed RTC epoch tied to the
  virtual (icount) clock (e.g. `-rtc base=<fixed-epoch>,clock=vm`), so the guest
  reads icount-derived time, never host wall-clock (E5/[TIME-20]). No
  guest-visible time source may resolve to host real time. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §10.2;
  satisfies [DET-18] (E5), [TIME-20].

- **[QEMU-9]** **Seeded firmware entropy.** Guest boot entropy MUST be seeded as
  a pure function of the scenario seed via firmware configuration (an `fw_cfg`
  random-seed entry, E8/[DET-22]) and a deterministic virtio-rng source whose
  draws come from QEMU's seeded internal PRNG (E9/[DET-21]), so the guest CSPRNG
  is never seeded from host entropy. The per-node entropy is derived from the
  decision RNG by name-hash ([DET-25]) so adding a node does not perturb another
  node's seed. *Gate:* `gate:layer0-determinism`. *Spec:* §10.2; satisfies
  [DET-22], [DET-21], references [DET-25].

- **[QEMU-10]** **Internal-PRNG seed.** QEMU's own entropy (device MACs/IDs, glib
  PRNG, `qemu_guest_getrandom`) MUST be seeded deterministically from the run
  seed (the `-seed` launch value plus the patch-series getrandom/glib hooks,
  E9/[DET-21]), so device state in `T` is reproducible, not just guest memory.
  *Gate:* `gate:layer0-determinism`. *Spec:* §10.2; satisfies [DET-21].

- **[QEMU-11]** **No external input.** No interactive input device, no host
  user-mode networking, no host time/clock device, no random source outside the
  seeded path. All cross-node input arrives via the injection contract (4.4)
  through the shared-memory transport (13), never "as it arrives" on a host
  socket (E17/E18). Networking is the shmem frame transport, not QEMU
  user-networking; block and 9p I/O are the shmem-backed sub-node devices (15),
  not host files read at host timing. *Gate:* `gate:layer1-injection`,
  `gate:layer0-determinism`. *Spec:* §10.2; satisfies [DET-11], [DET-18]
  (E17, E18), references 15.

- **[QEMU-12]** **CoW disks.** Every guest disk MUST be presented as a
  copy-on-write overlay over a read-only base image so a run never mutates the
  backing image (E16/[DET-16], [INV-5]); two runs from the same genesis start
  from byte-identical backing state. The overlay is the block I/O sub-node (15),
  driven from shmem. *Gate:* `gate:any-guest`, `gate:replay-oracle`. *Spec:*
  §10.2; satisfies [DET-16], [INV-5], references 15.

- **[QEMU-13]** **Stock guest cmdline; host-side entropy sealing.** The kernel
  cmdline MUST be the guest's own **stock** cmdline: Crucible MUST NOT add
  `nokaslr`/`norandmaps` or any other guest entropy-suppression flag, and MUST
  NOT require the guest to carry them. KASLR/ASLR (E11/E12) stay enabled and are
  reproducible because all boot entropy is seeded deterministically host-side
  (E8/E9: `fw_cfg` random-seed, controlled RDRAND, no host-entropy passthrough),
  as verified by S6/T-RISK-6 ([DET-33]). The cmdline (whatever the guest sets) is
  part of the content hash. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §10.2;
  satisfies [DET-18] (E11, E12), [DET-33].

- **[QEMU-14]** **Plugin + sim activation.** The host MUST load the in-VM plugin
  (`-plugin <crucible-qemu-plugin>,...`, 12) and activate sim mode so the
  patch-class determinism mechanisms (11) take effect; with the plugin absent and
  sim flags off, the same QEMU binary MUST behave as upstream ([INV-7],
  `gate:qemu-inert`). The plugin argument string carries the per-node setup hints
  (slot index, fd numbers) needed before the control handshake (14). *Gate:*
  `gate:qemu-inert`, `gate:layer0-determinism`. *Spec:* §10.2; satisfies
  [DET-36], references [INV-7].

```text
# Illustrative launch sketch (CONV-1; the prose requirements are authoritative).
# The host builds this command line from the node's World entry + scenario pins.
qemu-system-x86_64 \
  -accel sim,thread=single -icount shift=N  # QEMU-4/5 fixed shift, precise mode, no warp,
                                            #          single-threaded RR-TCG (NOT thread=multi)
  -smp N                               # QEMU-5  N vCPUs under single-threaded RR
  # rr_switch_quantum pinned to node-icount via the patch-series flag (QEMU-43,
  # crucible-rr-quantum-icount, 11), NEVER QEMU's adaptive/realtime rr_quantum
  -cpu <model-no-rdrand>               # QEMU-6  fixed model, no host entropy
  -machine <fixed>  -m <fixed>         # QEMU-7  fixed machine/reset/memory
  -rtc base=<fixed-epoch>,clock=vm     # QEMU-8  icount-derived RTC, no host time
  -fw_cfg name=etc/seed,file=<seed>    # QEMU-9  seeded guest entropy (E8)
  -object rng-builtin -device virtio-rng,...   # QEMU-9  deterministic virtio-rng
  -seed <scenario-seed>                # QEMU-10 seeded QEMU-internal PRNG (E9)
  -drive driver=<cow-overlay>,...      # QEMU-12 CoW disk (block sub-node, 15)
  -netdev <shmem-frame-transport>,...  # QEMU-11 frames via shmem, not host net
  -kernel <kernel> -append "<stock-guest-cmdline>"  # QEMU-13 stock cmdline; entropy sealed host-side (E8/E9)
  -plugin <crucible-qemu-plugin>,slot=<i>,...  # QEMU-14 plugin + sim activation
  -qmp unix:<path>,server=on,wait=off  # QMP control socket (§10.4)
  # plugin IPC + shmem + wake fds passed by fd-mapping (§10.5, 14)
```

- **[QEMU-15]** The host MUST NOT pass any flag, device, or environment value
  that introduces a host-timing or host-entropy dependence into `S` or `T`
  (e.g. host user networking, a host RNG-backed device, a wall-clock RTC, a
  realtime-clock-driven timer). Any such flag is a determinism defect caught by
  `gate:single-vm-fingerprint`. The host process's *own* nondeterminism
  (e.g. QEMU-internal hash-table seeding) MUST also be pinned where it can affect
  TCG translation-block ordering and thus `T`. *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer0-determinism`. *Spec:* §10.2;
  satisfies [DET-1], [DET-21].

## 10.3 A VM as a scheduling node (the host wrapper)

The host represents each VM as a `SimNode` — an actor-like object that owns one
QEMU child process and presents the scheduler ([INV-8], 08) a small synchronous
interface: report current icount, advance to a ceiling, deliver/emit frames, go
idle, report next deadline, snapshot/restore, shut down. The node owns three
channels to its child and nothing else owns the child.

- **[QEMU-16]** A VM node MUST be modeled host-side as a single owner of exactly
  one QEMU child process, exposing the scheduler a synchronous node interface
  (current icount, advance-to-ceiling, frame deliver/emit, idle/next-deadline,
  snapshot/restore, shutdown). The node is the *only* owner of its child; no
  other component may signal, wait on, or reap the child. *Gate:*
  `gate:scheduler-liveness`, `gate:control-responsive`. *Spec:* §10.3; satisfies
  [INV-8], references 05 §10.

### The three logical communication planes

A VM node communicates with its QEMU child through three logical planes, each
with a distinct, non-overlapping role. The shared-memory plane uses both the
mapped memfd and kernel wake objects; counting file descriptors would therefore
misdescribe this as only three kernel objects.

1. **The plugin IPC channel** (14) — a per-node `AF_UNIX` `SOCK_STREAM` pair for
   the *control* handshake only: version negotiation, the one-time handover of
   the shmem fd / wake fd / slot index, and `Quit`. It is silent for the entire
   run between setup and teardown ([PROTO-18]).
2. **The shared-memory data plane** (13) — the *hot path*: per-node icount/status,
   the scheduler's advance ceiling, idle-wake icount, the cross-process futex
   word, and the SPSC frame rings. Every per-quantum timing decision and every
   cross-node frame payload flows here, never over a socket ([SHM-2]). The host
   writes the separately handed-over plugin eventfd at least once per quantum
   only to rouse QEMU to re-read this state; retry and serviced-I/O paths may add
   counter writes.
3. **The QMP socket** (§10.4) — out-of-band machine control: capability
   negotiation, `savevm`/`loadvm` for the VM-state half of a checkpoint, and
   `quit` as a shutdown rung. The separate fixed debugger activation stream is
   established at launch but remains inert until an explicit non-canonical fork
   boundary (36 [DBG-45A]).

- **[QEMU-17]** A VM node MUST preserve exactly three logical channel roles — the
  plugin IPC control channel (14), the shared-memory region (13), and the QMP
  socket (§10.4) — with the strict role split: control handshake/teardown on
  plugin IPC, *all* per-quantum timing state and frame payloads on shmem with
  futex/eventfd kernel wakes, machine
  control (snapshot/quit) on QMP. No per-quantum timing or per-frame data may
  cross the plugin IPC or QMP channels ([SHM-2], [PROTO-1]). *Gate:*
  `gate:abi-conformance`, `gate:layer1-injection`. *Spec:* §10.3; satisfies
  [SHM-2], [PROTO-1].

- **[QEMU-18]** The node's hot path (advance to a ceiling, deliver/emit a frame,
  observe idle) MUST be expressed as shared-memory atomics, the current
  unconditional non-private futex wake, a host plugin-eventfd write at least once
  per quantum, explicit service-release/frame-delivery futex wakes, and explicit
  retry/service eventfd writes; parked plugin paths MAY issue repeated actual
  futex waits after non-actionable returns ([SHM-1]); it MUST NOT
  perform a QMP round-trip or plugin-IPC message on the advance path. QMP and plugin-IPC traffic
  occur only at instantiate/save/teardown or explicit non-canonical debugger-fork
  boundaries, never as ordinary per-quantum traffic. *Gate:*
  `gate:control-responsive`, `gate:layer1-injection`. *Spec:* §10.3; satisfies
  [SHM-1], [SHM-2].

```rust,illustrative
// Illustrative sketch (CONV-1, 00). The host wrapper owns one QEMU child and
// its three logical planes; the scheduler sees only the synchronous node interface.
pub struct QemuNode {
    slot: SlotIndex,                 // index into the shmem per-node array (13, 14)
    child: Option<Child>,            // the one QEMU process this node owns
    control: PluginIpcChannel,       // AF_UNIX control: handshake + Quit only (14)
    shmem: NodeSlotView,             // hot-path: ceiling/clock/futex/rings (13)
    qmp: QmpConnection,              // machine control: savevm/loadvm/quit (§10.4)
    config: LaunchConfig,            // the content-addressed launch config (§10.2)
    status: NodeRunStatus,           // running / idle / done / crashed
}
```

## 10.4 QMP (a typed, minimal client)

QMP is QEMU's JSON-line machine-control protocol. Crucible uses a **minimal,
typed** client — not a general QMP binding — covering exactly the commands the
execution model needs: capability negotiation, `savevm`/`loadvm` (the VM-state
half of a `Checkpoint`, 07), and `quit` (a shutdown rung, §10.6). Debugger
activation does not use QMP commands: QEMU connects its fixed activation-only
chardev to a Crucible-owned Unix stream during launch, and Crucible writes the
fixed token only after an explicit non-canonical fork (36 [DBG-45A]). It is an
out-of-band control channel: it carries no per-quantum timing and no frames
([QEMU-17]).

A QMP session is: connect to the per-node Unix socket; read the `{"QMP": {...}}`
greeting; send `qmp_capabilities` to enter command mode; thereafter send
`{"execute": <cmd>, "arguments": {...}}` and read JSON-line responses,
discarding asynchronous `{"event": ...}` lines until a `{"return": ...}` or
`{"error": ...}` arrives. Crucible models commands and responses as Rust types,
not free-form JSON, so an unexpected shape is a typed error, never a silent
mis-parse.

- **[QEMU-19]** The host MUST provide a typed QMP client over the per-node QMP
  Unix socket that (a) reads the greeting and completes `qmp_capabilities`
  capability negotiation before any command, (b) models each supported command
  and its response as a Rust type, and (c) skips asynchronous QMP events while
  awaiting a command's `return`/`error`, surfacing an `error` response as a typed
  `Result::Err`. The client MUST cover, at minimum: capability negotiation,
  `savevm`, `loadvm`, and `quit`. The fixed activation-only debugger stream
  MUST NOT accept caller-selected devices or bytes and MUST
  carry no guest-introspection payload. It MUST NOT expose a stringly-typed
  execute-arbitrary-JSON path on the determinism-critical control flow. *Gate:*
  `gate:control-responsive`. *Spec:* §10.4; references 07.

- **[QEMU-20]** `savevm` MUST capture, and `loadvm` MUST restore, the VM-state
  half of a `Checkpoint` (07): the complete machine state QEMU owns (guest RAM,
  device/timer state, and — critically — the icount, the icount bias, and the
  TCG/plugin time-control state). The host pairs the QMP VM snapshot with the
  Crucible-owned state (CoW device overlays (15), the SPSC ring contents
  ([SHM-21]/[SHM-22]), and the scheduler/RNG state, all of which are functions of
  the `Configuration`, 05) to form a complete, content-addressed checkpoint. The
  QMP snapshot tag MUST be derived from the checkpoint's content address so a
  `loadvm` targets exactly the right VM state. *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §10.4; satisfies [EXEC-23], references 07, 13,
  15.

### The savevm-completeness spike, and the thin-checkpoint fallback

The execution model's fast-resume and fork (05 §5) and the replay oracle (05 §8,
[INV-2]) rely on `loadvm` reproducing a state **bit-identical** to a fresh
replay to the same icount. Whether QEMU's `savevm`/`loadvm` actually preserves
*all* of the icount, icount bias, TCG state, timer state, and the plugin's
time-control state — completely enough that the restored fat checkpoint hashes
equal to its thin (replay) derivation — is a known open question ([DET-32],
E20). It MUST be verified, not assumed.

- **[QEMU-21]** The completeness of QMP `savevm`/`loadvm` for the determinism
  contract — that a restored fat checkpoint is bit-identical to a fresh replay to
  the same icount (icount, bias, TCG/device/timer state, and plugin time-control
  state all preserved) — MUST be treated as a SPIKE ([DET-32], forward-ref 30)
  and verified by the replay oracle before snapshot-based resume is relied upon.
  Until the spike is green, the host MUST default to the **thin-checkpoint
  fallback**: realize a configuration by replaying from genesis (or a verified
  ancestor) rather than by `loadvm` of an unverified fat snapshot (07). *Gate:*
  `gate:replay-oracle`. *Spec:* §10.4; satisfies [DET-32], [EXEC-15],
  forward-ref 30, 07.

- **[QEMU-22]** When `loadvm` is used as the realization branch, the host MUST
  validate the restored runtime against the replay oracle (re-reduce from an
  ancestor and compare execution fingerprints, [INV-2]) at least on the gated
  paths; a fat checkpoint that fails to hash-equal its thin derivation MUST be
  treated as a determinism defect (divergence-bisected, never silently
  re-snapshotted). *Gate:* `gate:replay-oracle`, `gate:divergence-bisect`.
  *Spec:* §10.4; satisfies [EXEC-17], [EXEC-23], [EXEC-24].

## 10.5 instantiate realization for a VM (boot / loadvm / replay)

`instantiate(config)` (05 §5) is the single function that turns a configuration
into a live runtime, with three branches resolved in priority order: an exact
cached snapshot → `loadvm`; the nearest cached ancestor → recurse + replay the
suffix; else recurse to genesis, whose base case is the **baked** genesis
snapshot (05 §6), itself a `loadvm`. The single true *cold boot* in the entire
system lives inside `bake`. This section is the QEMU-level realization of those
three branches and of `bake`.

### Cold boot (only inside `bake`)

A cold boot launches a fresh QEMU child with the §10.2 launch configuration,
performs the plugin-IPC handshake (14) to hand over the shmem region and unblock
plugin initialization, connects QMP (§10.4), and runs the guest to the node's
deterministic *ready point* (05 §6: fixed icount / network-idle / console marker
/ agent signal). `bake` then `savevm`s the result and content-addresses it as the
genesis checkpoint.

- **[QEMU-23]** A VM cold boot MUST occur **only** inside `bake` (05 §6,
  [EXEC-16]): launch a fresh child with the §10.2 launch config, complete the
  plugin-IPC handshake (14), connect and negotiate QMP (§10.4), run to the node's
  deterministic ready point ([EXEC-20]), and `savevm` the genesis VM state. The
  hot loop (start/resume/fork/replay) MUST NOT cold-boot a VM. *Gate:*
  `gate:replay-oracle`, `gate:content-address`. *Spec:* §10.5; satisfies
  [EXEC-16], [EXEC-18], references [EXEC-23].

- **[QEMU-24]** The genesis `savevm` produced by `bake` MUST be content-addressed
  by the node's `World` entry plus the determinism pins, cached, and shared across
  every scenario and fork with the same `World` ([EXEC-18], [INV-6]); `bake` MUST
  reach a content-identical genesis snapshot across runs for a fixed `World`
  ([EXEC-20]). *Gate:* `gate:content-address`. *Spec:* §10.5; satisfies
  [EXEC-18], [EXEC-20].

### loadvm-from-snapshot (warm resume / fork target)

The warm branch maps the genesis (or a descendant) snapshot back into a live
runtime: launch a child in the launch configuration with the plugin loaded,
hand over the shmem region (14), connect QMP, and `loadvm` the content-addressed
VM snapshot. The host then restores the Crucible-owned half (CoW overlays (15),
ring contents ([SHM-22]), scheduler/RNG state) so the runtime denotes exactly the
configuration ([EXEC-22]).

- **[QEMU-25]** The `loadvm` realization branch MUST launch a plugin-loaded child
  in the launch configuration, hand over the shmem region via the control
  handshake (14), connect QMP, `loadvm` the content-addressed VM snapshot, and
  restore the Crucible-owned state half (CoW overlays, ring contents,
  scheduler/RNG state) so the resulting runtime is content-equal to the
  configuration ([EXEC-22]). This branch is gated on the savevm-completeness
  spike ([QEMU-21]); until green, the host prefers replay ([QEMU-26]). *Gate:*
  `gate:replay-oracle`. *Spec:* §10.5; satisfies [EXEC-15], [EXEC-22], references
  [QEMU-21].

### replay (partial advance from an ancestor)

The replay branch instantiates the nearest cached ancestor (recursively) and
advances it forward over the missing schedule suffix — running the scheduler
quanta that lie between the ancestor and the target configuration, applying each
suffix `Decision` (05 §3) in order. Replay reaches a runtime by the same
quantum-step machinery (§10.8) the live loop uses, so a replayed runtime and a
live one are produced by identical code, which is what makes the replay oracle
meaningful.

- **[QEMU-26]** The replay realization branch MUST instantiate the nearest
  cached ancestor and advance it forward over the missing schedule suffix by the
  *same* quantum-step machinery (§10.8) used in the live loop — applying each
  suffix `Decision` in schedule order — so a replayed runtime is produced by
  identical code to a live one. Replay MUST be the default realization for any
  configuration without a spike-verified fat snapshot ([QEMU-21]). *Gate:*
  `gate:replay-oracle`. *Spec:* §10.5; satisfies [EXEC-15], [EXEC-16],
  [EXEC-17].

- **[QEMU-27]** All three realization branches (loadvm of an exact snapshot,
  ancestor-replay, baked-genesis load) MUST yield a runtime whose state is
  content-equal for the same configuration ([INV-2], [EXEC-17]); the branch
  chosen is a performance decision and MUST NOT be observable in the resulting
  `S`/`T`. `start`, `resume`, and `fork` MUST be the same `instantiate` call
  differing only in the configuration argument (genesis / tip / prefix,
  [EXEC-14]); there MUST be no separate boot/resume/fork code path in the QEMU
  layer. *Gate:* `gate:replay-oracle`. *Spec:* §10.5; satisfies [EXEC-14],
  [EXEC-17].

```text
# Illustrative — the QEMU-level realization of instantiate(config) (05 §5).
instantiate_vm(config):
    if fat_snapshot(config.id) and spike_verified:        # QEMU-25 warm branch
        launch(plugin, launch_config); handshake(14); qmp_connect()
        qmp.loadvm(content_tag(config.id))
        restore_crucible_state(overlays, rings, sched/rng) # 13, 15, 05
    elif anc := nearest_cached_ancestor(config):           # QEMU-26 replay branch
        rt = instantiate_vm(anc)
        for decision in schedule[anc.len .. config.len]:
            rt.advance_one_quantum(decision)               # same machinery, §10.8
    else:                                                   # QEMU-23 genesis base
        rt = loadvm(bake(world).genesis_for(node))         # baked once; not a boot
    return rt
```

## 10.6 Process lifecycle and the no-leak requirement

A QEMU child is a heavyweight OS process; leaking one is not a cosmetic bug. A
prior internal exploration suffered a real, severe failure mode in which crashed
or timed-out runs left orphaned QEMU processes that reparented to PID 1 and spun
forever in a synchronization check, accumulating until they saturated the build
host's CPU and *distorted the very determinism measurements the system existed
to make*. The lifecycle here is designed so that **no QEMU child is ever
leaked**, under any termination path — clean shutdown, control-plane stop, guest
crash, plugin hang, host panic, or host SIGKILL.

### Spawn with fd passing

The host creates the per-node control socket pair, the shmem `memfd`, and the
wake `eventfd` *before* `exec`, and passes their child ends to QEMU by fd
mapping at fixed, well-known fd numbers (so the plugin can locate them, 14). The
shmem and wake fds are duplicated so the host retains its own copies. The child
is configured to die with the host: `kill_on_drop` for the clean path, plus a
kernel-delivered parent-death signal (`PR_SET_PDEATHSIG = SIGKILL`) for the
unclean path where the host is SIGKILLed or panics without unwinding.

- **[QEMU-28]** The host MUST create the per-node control socket pair, the shmem
  region fd, and the wake fd before `exec`, and MUST pass the child ends to QEMU
  by fd mapping at fixed fd numbers known to the plugin (14, [PROTO-8]). The
  shmem/wake fds passed to the child MUST be duplicates so the host keeps its own
  copies. *Gate:* `gate:abi-conformance`. *Spec:* §10.6; satisfies [PROTO-8],
  references 13, 14.

- **[QEMU-29]** Every spawned child MUST be configured to die with the host on
  *every* host-exit path: drop-time kill for the clean path, **and** a
  kernel-delivered parent-death signal (`PR_SET_PDEATHSIG = SIGKILL` on Linux,
  the host target) so that a host SIGKILL or a panic-without-unwind cannot leave
  an orphaned child reparented to PID 1. Relying on drop-time kill alone is
  insufficient and MUST NOT be the only mechanism. *Gate:*
  `gate:control-responsive`. *Spec:* §10.6.

### Graceful shutdown escalation

Shutdown is the host-driven escalation ladder fixed by [PROTO-20]: plugin `Quit`
→ QMP `quit` → `SIGTERM` → `SIGKILL` → reap. Each rung has a **bounded** wait;
crossing the deadline escalates to the next rung. The final `waitpid` reap is
unconditional, so the child is reaped even if the plugin never received `Quit`
and the guest never answered QMP. This file owns the *timeout policy*; the
*order and the no-leak guarantee* are fixed by [PROTO-20].

- **[QEMU-30]** Graceful shutdown MUST follow the escalation order plugin `Quit`
  → QMP `quit` → `SIGTERM` → `SIGKILL` → reap ([PROTO-20]), with a bounded,
  configured wait at each rung; on a rung's deadline elapsing without exit, the
  host MUST escalate. The host owns the per-rung timeout policy; the order and
  the guarantee are [PROTO-20]'s. *Gate:* `gate:control-responsive`. *Spec:*
  §10.6; satisfies [PROTO-20].

- **[QEMU-31]** The host MUST `waitpid`/reap every QEMU child it spawns, on every
  termination path (clean stop, control-plane stop, guest crash, plugin hang,
  setup failure, host panic). **No QEMU process may ever be leaked.** A reap MUST
  occur even when the plugin never received `Quit`, the guest never responded to
  QMP, and signals were required to terminate it. This is a hard requirement
  motivated by a real prior failure mode; the no-leak property MUST be covered by
  a test that induces each termination path and asserts the child count returns
  to zero. *Gate:* `gate:control-responsive`. *Spec:* §10.6; satisfies
  [PROTO-20].

### Crash detection

A VM node detects an unexpected child exit, a closed plugin-IPC channel, or a
QMP disconnect, and surfaces it as a typed crashed-node status to the scheduler —
distinct from an *intended* crash fault (17). A crash on the determinism-gated
paths is a defect to localize ([INV-10]), not a transient to retry.

- **[QEMU-32]** The host MUST detect an unexpected child exit, a plugin-IPC
  channel close, or a QMP disconnect, and surface it to the scheduler as a typed
  crashed-node status carrying the cause (exit status / channel error), distinct
  from an intended crash fault (17). On a determinism-gated path a crash MUST be
  reported and localized ([INV-10]), never swallowed or retried-until-it-passes.
  *Gate:* `gate:control-responsive`, `gate:divergence-bisect`. *Spec:* §10.6;
  satisfies [INV-10], references 17.

## 10.7 Determinism wiring and the single-VM fingerprint hook

The host is where the per-VM hermetic boundary (§4.6) is *configured* and
*verified*. Configuration is §10.2: every entropy source the host controls is
pinned by a launch flag or activated as a patch mechanism via sim mode.
Verification is the execution fingerprint ([DET-29]): the host computes, at a
fixed periodic icount cadence and at every cross-node interaction point, a
deterministic digest combining the node's icount with a hash of its
architectural registers, guest memory, and device state — **black-box**, with no
guest cooperation ([DET-17]).

- **[QEMU-33]** The host MUST configure the per-VM hermetic boundary entirely
  through the §10.2 launch configuration and sim-mode activation ([DET-15]: no
  guest modification), and MUST verify it via the execution fingerprint
  ([DET-29]): a periodic-icount + register/memory/device digest computed
  black-box from the host through the plugin's introspection hooks (12), with no
  guest cooperation. *Gate:* `gate:single-vm-fingerprint`, `gate:any-guest`.
  *Spec:* §10.7; satisfies [DET-15], [DET-17], [DET-29].

- **[QEMU-34]** The host MUST expose the single-VM fingerprint hook that
  `gate:single-vm-fingerprint` consumes: run one VM twice for fixed
  `(image, cmdline, seed, I)` under adversarial host conditions ([DET-38]) and
  assert identical fingerprint sequences; a mismatch MUST localize to the first
  differing icount window for bisection ([DET-30], [INV-10]), never be tolerated.
  The fingerprint cadence and the included state set MUST be fixed and
  content-addressed with the scenario ([DET-31]). For an `-smp N` node the
  black-box fingerprint MUST read **all N vCPUs' register files** plus the
  round-robin cursor (which vCPU is current and the position within the pinned
  `rr_switch_quantum`) via the plugin's per-vCPU introspection capability
  (12/[PLUG-50]) and QMP, so the interleaving state is part of the digest;
  reading only `first_cpu` is a defect. *Gate:* `gate:single-vm-fingerprint`,
  `gate:divergence-bisect`. *Spec:* §10.7; satisfies [DET-29], [DET-30],
  [DET-31], references 24, [PLUG-50].

- **[QEMU-35]** Each host-controlled entropy elimination in §10.2 MUST have a
  micro-test that fails if the elimination is removed (e.g. dropping the `-cpu`
  pin, omitting the seed `fw_cfg`, or unsuppressing warp MUST turn a determinism
  gate red), and the QEMU-side sim mechanisms MUST be inert with sim mode off
  ([INV-7], `gate:qemu-inert`). *Gate:* `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §10.7; satisfies [DET-18], [DET-36].

## 10.8 Host ↔ plugin ↔ guest data flow for one quantum

This section traces the per-quantum data flow at the QEMU level, the host-side
view of one scheduler quantum (08) realized through the plugin (12) and the
shmem ABI (13). The guest is unmodified; everything below is host + plugin
mechanism.

The cycle, for one running VM in one quantum:

1. **Idle / report.** The guest executes until it either reaches its advance
   ceiling or goes idle (executes `HLT` with no runnable work). On idle, the
   plugin reads the node's next armed `QEMU_CLOCK_VIRTUAL` timer deadline
   ([TIME-24]) and publishes it as `idle_wake_icount` in the node slot (13),
   sets `status = STATUS_IDLE`, and the node publishes its `current_icount`
   ([SHM-24]).
2. **Scheduler sets the ceiling.** The scheduler reads every node's icount and
   idle/next-deadline, picks the minimum-horizon node, computes that node's
   horizon (`min(next exact local event, conservative network lookahead)`, 08),
   converts it to a target icount via the `ceil` map ([TIME-4]), and stores it
   into the node's `max_advance_icount` with release ordering ([SHM-24],
   [TIME-27]).
3. **Advance.** The futex wake ([SHM-26]/[SHM-27]) publishes the race-free shared
   wake, and the host's per-quantum eventfd write rouses QEMU's between-quantum
   idle wait. The plugin reads the raised ceiling and lets the guest retire instructions under
   `-icount` until `current_icount` reaches the ceiling, then stops and reports
   ([TIME-27], [SHM-25]).
4. **Frame inject / emit.** A frame destined for this node is delivered when
   `delivery_icount <= current_icount` ([SHM-33]); the plugin injects it into the
   guest's emulated NIC at exactly that icount, in the deterministic total order
   `(delivery_icount, src_node, seq)` ([SHM-34], [INV-3]). A frame the guest
   emits is enqueued by the plugin into the outbound ring toward the network
   router slot (13 §13.5), stamped with the emitter's icount; the router
   re-stamps the consumer-side `delivery_icount` per the link model (15).
5. **I/O.** Block and 9p completions are produced by the I/O sub-nodes (15) as
   first-class scheduling nodes with deterministic completion icounts, delivered
   to the requesting VM by the same injection contract (the `device_io_active`
   flag in the slot freezes virtual time across a device-I/O burst so HZ ticks
   cannot slip between round trips, [SHM-9]).

- **[QEMU-36]** The host MUST realize one scheduler quantum at the QEMU level as
  the cycle: guest runs to ceiling-or-idle → plugin reports `current_icount`,
  `status`, and (on idle) the exact next-timer `idle_wake_icount` ([TIME-24]) →
  scheduler computes the horizon and stores `max_advance_icount` ([TIME-27]) →
  unconditional futex wake + plugin eventfd write → guest advances under
  `-icount` to the ceiling → due frames/I/O
  injected at their `delivery_icount` ([SHM-33]) and emitted frames enqueued
  toward the router. Every per-quantum step MUST flow through the shmem region
  ([SHM-2]); no per-quantum QMP or plugin-IPC traffic. *Gate:*
  `gate:layer1-injection`, `gate:control-responsive`. *Spec:* §10.8; satisfies
  [SHM-2], [TIME-24], [TIME-27], [SHM-33].

- **[QEMU-37]** Frame injection and emission at the QEMU level MUST obey the
  injection contract (4.4): an inbound frame becomes architecturally visible to
  the guest at exactly its `delivery_icount`, never "as it arrives" on the ring
  ([DET-11], [DET-13], [SHM-33]), and simultaneously-deliverable frames are
  injected in the `(delivery_icount, src_node, seq)` total order ([SHM-34],
  [INV-3]). A node found to have advanced past an inbound frame's
  `delivery_icount` is a contract violation and MUST fail loudly ([DET-12],
  [SHM-25]), never be delivered late. *Gate:* `gate:layer1-injection`,
  `gate:divergence-bisect`. *Spec:* §10.8; satisfies [DET-11], [DET-12],
  [DET-13], [SHM-33], [SHM-34].

- **[QEMU-38]** A device-I/O burst (block/9p round trips, 15) MUST freeze the
  node's virtual time for the duration of the burst (via the slot's
  `device_io_active` flag, [SHM-9]) so guest HZ ticks cannot slip between the
  round trips of a single logical I/O, keeping completion timing a pure function
  of the I/O sub-node's deterministic model rather than of how many idle callbacks
  the host happened to interleave. *Gate:* `gate:layer0-determinism`,
  `gate:layer1-injection`. *Spec:* §10.8; satisfies [DET-18] (E19), references 15.

## 10.9 The async driver (sync node-step ↔ async socket/QMP I/O)

The scheduler drives nodes through a **synchronous** node interface (advance to
a ceiling, deliver a frame, report idle — §10.3) because the scheduler is the
single authoritative actor whose total order must be exact ([INV-8]). But the
host's I/O to a QEMU child — the plugin-IPC handshake, QMP commands, child-exit
detection — is **asynchronous** socket and process I/O on real wall-clock time.
The async driver bridges the two: it presents the scheduler a synchronous
node-step, and internally runs the necessary async I/O to completion on a
host-I/O runtime that is *not* part of virtual time.

The key separation: the host-I/O runtime moves *bytes and lifecycle events* in
real time, while *virtual time* is owned entirely by the scheduler through the
shmem ceiling and the plugin's time control ([TIME-23], [INV-8]). The async
runtime's scheduling, latency, and ordering are host-timing artifacts and
therefore MUST NOT influence `S`, `T`, or the schedule — which is exactly why all
per-quantum timing lives in shmem (decided by virtual time, [SHM-33]) and not on
the async sockets. The async driver is allowed to be nondeterministic precisely
because nothing determinism-relevant depends on its timing.

- **[QEMU-39]** The host MUST bridge the synchronous scheduler-facing node-step
  interface (§10.3) to the asynchronous socket/QMP/process I/O of a QEMU child
  via a host-I/O runtime that operates in real wall-clock time and is **not** part
  of virtual time. The async runtime moves bytes and detects lifecycle events;
  virtual time is owned solely by the scheduler through the shmem ceiling and the
  plugin's time control ([TIME-23]). The async runtime's scheduling/ordering MUST
  NOT influence `S`, `T`, or the `Schedule` — which holds because all per-quantum
  timing is decided in shmem by virtual time ([SHM-33]), not on the async
  channels. *Gate:* `gate:layer1-injection`, `gate:control-responsive`. *Spec:*
  §10.9; satisfies [INV-8], [TIME-23], [SHM-33].

- **[QEMU-40]** Each node-step MUST be **bounded** and the driver MUST **yield**
  between quanta so the control plane (20) is serviced at well-defined points with
  no long-held lock ([INV-8], [EXEC-28]). A node-step MUST advance the node by at
  most one scheduler quantum and return; it MUST NOT block the engine for an
  unbounded time on an unresponsive child. Every blocking await on a child
  (handshake, QMP command, advance-completion) MUST carry a bounded timeout that,
  on expiry, surfaces a crashed-node status ([QEMU-32]) and triggers shutdown
  escalation ([QEMU-30]) rather than hanging. *Gate:* `gate:control-responsive`,
  `gate:scheduler-liveness`. *Spec:* §10.9; satisfies [EXEC-28], [INV-8],
  references [QEMU-30], [QEMU-32].

- **[QEMU-41]** The async driver MUST treat the hot advance path as shmem-only
  ([QEMU-18]): a quantum's advance is a ceiling store, an unconditional futex
  wake, at least one plugin-eventfd write, and a bounded poll for the node to
  publish its reached icount. Unchanged-icount retries and serviced host I/O may
  add eventfd writes, with no
  per-quantum socket message or QMP round-trip. Async socket/QMP traffic MUST be
  confined to instantiate (handshake, loadvm), save (savevm), and teardown
  (Quit/quit) boundaries. *Gate:* `gate:control-responsive`,
  `gate:layer1-injection`. *Spec:* §10.9; satisfies [SHM-1], [QEMU-18].

```rust,illustrative
// Illustrative sketch (CONV-1, 00). The synchronous node-step the scheduler
// calls; inside, the driver runs bounded async I/O on a real-time host runtime.
// Per-quantum timing is shmem-only; the async path only carries lifecycle bytes.
impl SimNode for QemuNode {
    fn advance_to(&mut self, ceiling: Icount) -> NodeStepResult {
        // Hot path: publish the ceiling, wake the parked node, wait (bounded)
        // for it to reach the ceiling — shmem state plus futex/eventfd wakes,
        // with no socket round trip or payload copy.
        self.shmem.set_max_advance(ceiling);              // release store (13)
        self.shmem.wake();                                // futex wake (13)
        self.plugin_eventfd.signal();                     // eventfd counter write
        match self.shmem.wait_reached(self.config.advance_timeout) {
            Ok(reached) => self.report(reached),          // current_icount, status
            Err(Timeout) => self.crashed("advance timed out"), // QEMU-40 / QEMU-32
        }
    }
    // deliver()/emit() enqueue/dequeue shmem rings at delivery_icount (SHM-33);
    // snapshot()/restore() bridge to async QMP savevm/loadvm (§10.4) at
    // checkpoint boundaries only, never per quantum.
}
```

- **[QEMU-42]** The async driver MUST itself be free of host-timing influence on
  any *ordering-significant* decision ([INV-9]): no host wall-clock read, no
  thread RNG, and no nondeterministic `select` may feed the schedule or the
  fingerprint. Timeouts and retries on the async path are permitted only on
  lifecycle/crash handling (which is determinism-neutral, surfacing a typed crash
  rather than altering `S`/`T`), never on the per-quantum advance/delivery
  decision. *Gate:* `gate:harness-lint`, `gate:layer1-injection`. *Spec:* §10.9;
  satisfies [INV-9], [INV-10].

## 10.10 Summary

The host side of the QEMU layer is: launch a TCG `-icount` child with the fully
enumerated determinism configuration (§10.2); own it as a single scheduling node
with exactly three logical planes — plugin-IPC control, shmem plus futex/eventfd
wakes on the hot path, and QMP machine
control (§10.3, §10.4); realize any `Configuration` through the one `instantiate`
function whose branches are loadvm / replay / baked-genesis-load, the only true
boot living in `bake` (§10.5); never leak a child, on any termination path
(§10.6); configure and fingerprint-verify the hermetic boundary black-box
(§10.7); flow every per-quantum timing and frame through shmem in virtual time
(§10.8); and bridge the synchronous scheduler interface to async child I/O with
a bounded, yields-between driver whose host timing can never reach `S`, `T`, or
the schedule (§10.9). With those in place, a VM node is a deterministic,
controllable, leak-free realization of the execution model (05) over the
determinism contract (04).

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is host-side QEMU integration, tracked by [PLAN-3]. They
> populate Phase 1–2 (the determinism/transport foundation and
> the QEMU layer built on it).

- [x] **T-QEMU-1** Implement the launch-config builder: the TCG-derived `sim`
  accelerator + fixed `-icount shift=N`, `-accel sim,thread=single` with `-smp N`, fixed `-cpu` (no
  RDRAND/RDSEED, never `host`), fixed `-machine`/`-m`/reset, icount-derived RTC,
  seeded `fw_cfg`/virtio-rng, seeded internal PRNG, CoW disks,
  the guest's stock cmdline (no `nokaslr`/`norandmaps` added or required),
  plugin load + sim activation; fold the whole command
  line into the scenario content hash. — satisfies [QEMU-3], [QEMU-4], [QEMU-5],
  [QEMU-6], [QEMU-7], [QEMU-8], [QEMU-9], [QEMU-10], [QEMU-12], [QEMU-13],
  [QEMU-14]; spec §10.2.
  Completed as the typed `crucible-qemu` launch-command builder: it validates the
  deterministic profile, requires content-addressed VM launch artifacts resolved
  to AOS store paths (QEMU binary, plugin, kernel, root image, optional initrd),
  emits the CoW root-disk argv, appends the plugin activation argument with fixed
  child fd numbers (`simfd=3`, `shmemfd=4`, `wakefd=5`, `slot`,
  white-box/coverage switches), re-runs the pre-spawn determinism validator over
  the final argv, and exposes world-derived VM material plus executable+argv
  material for scenario identity. Child ownership/fd-passing remains tracked by
  [T-QEMU-3] and [T-QEMU-7]; the N-vCPU launch extension remains tracked by
  [T-QEMU-15].
- [x] **T-QEMU-2** Implement launch-config validation that rejects stock TCG,
  KVM, and every non-`sim` accelerator / `shift=auto` / missing-`-icount` /
  `thread=multi` (MTTCG) /
  unpinned `rr_switch_quantum` / `-cpu host` / host-timing-or-entropy flags,
  loudly and before spawning. — satisfies [QEMU-1], [QEMU-2], [QEMU-5],
  [QEMU-43], [QEMU-11], [QEMU-15]; spec §10.1, §10.2.
  Completed as a pre-spawn argv validator layered over the deterministic launch
  profile; the full launch builder/spawn path remains tracked by [T-QEMU-1],
  [T-QEMU-3], and [T-QEMU-7].
- [x] **T-QEMU-3** Implement the `QemuNode` host wrapper owning one child and its
  three logical planes (plugin-IPC control, shmem plus futex/eventfd hot path,
  QMP), exposing the
  synchronous scheduler node interface with the strict control/data split. —
  satisfies [QEMU-16], [QEMU-17], [QEMU-18]; spec §10.3.
  Completed as the `QemuNode` one-child/three-plane wrapper in
  `crucible-qemu`: it owns a private `std::process::Child` handle through
  `QemuNodeChild` plus a `QemuNodeChannels` bundle, exposes the synchronous
  `crucible::Backend` boundary, routes current icount/advance/frame/idle/
  fingerprint operations only through the shmem hot path, rejects generic
  backend snapshot/restore, routes the paired exact-checkpoint API through QMP,
  and runs scheduler shutdown through the existing
  plugin-Quit → QMP-quit → signal → reap ladder using the owned child. Spawn,
  fd passing, and die-with-host behavior remain tracked by [T-QEMU-7]; the
  concrete per-quantum shmem implementation remains tracked by [T-QEMU-12] and
  [T-QEMU-13]; async socket/QMP/process bridging remains tracked by [T-QEMU-14].
- [x] **T-QEMU-4** Implement the typed minimal QMP client (greeting +
  `qmp_capabilities`, typed `savevm`/`loadvm`/`quit`, event-skipping,
  error-as-typed-Result), with snapshot tags derived from checkpoint content
  addresses. — satisfies [QEMU-19], [QEMU-20]; spec §10.4.
- [x] **T-QEMU-5** Implement exact snapshot capture and restore with icount,
  bias, TCG, timer, plugin time-control, QEMU device state, and Apache-side
  host-I/O continuations preserved under one content identity; oracle-validate
  every `loadvm`-realized runtime. — satisfies [QEMU-21], [QEMU-22], [SHM-49];
  spec §10.4, 13 §13.3.2, forward-ref §30.
  Completed by `QemuNode::capture_exact_snapshot`, `QemuVmSnapshot`,
  `QemuHostIoCheckpoint`, `QemuExactSnapshotPolicy`, and
  `checks.crucible.phase2.qemuExactSnapshotRestore`. Capture writes the host
  continuation before QEMU VMState while a shared-memory coordinated pause is
  active. The plugin acknowledges that specific pause with a new slot publish
  generation at the unchanged icount; busy guests clamp at their current raw
  icount without blocking QMP, halted guests park on the non-private futex, and
  capture/restore release both the futex and doorbell only after the paired
  host/QEMU transaction finishes. Later transaction failures remove only
  artifacts known to have been created by that transaction, while ambiguous or
  duplicate saves preserve pre-existing state. The mandatory live gate covers
  diskless and pending-block snapshots, force-kills the captured QEMU, restores
  in a fresh process, continues execution, and compares the complete pair and
  suffix against independent replay. There is no incomplete-snapshot fallback.
- [x] **T-QEMU-6** Implement the VM `instantiate` realization with three branches
  (loadvm / ancestor-replay / baked-genesis load) plus `bake`'s single cold boot
  to the ready point; wire `start`/`resume`/`fork` as the same call differing
  only in the configuration. — satisfies [QEMU-23], [QEMU-24], [QEMU-25],
  [QEMU-26], [QEMU-27]; spec §10.5.
  Completed as the `crucible-qemu` QEMU VM realization coordinator: it exposes
  `instantiate_qemu_vm` plus `start`, `resume`, and `fork` wrappers that all
  delegate to the same instantiate path, selects exact-snapshot `loadvm`,
  nearest-ancestor replay, or baked-genesis load in priority order, keeps runtime
  `loadvm` gated by replay-oracle admission through the exact-snapshot
  policy, validates checkpoint/configuration and baked-World identity, rejects
  invalid ancestors and out-of-range fork prefixes, dispatches replay one recorded
  decision at a time to the quantum executor, and exposes `bake_qemu_genesis_vm`
  as the only cold-boot-to-ready-point entry. The concrete shmem/QEMU quantum
  machinery remains tracked by [T-QEMU-12] and frame/device replay details remain
  tracked by [T-QEMU-13].
- [x] **T-QEMU-7** Implement spawn with fd passing (control socket pair + shmem
  memfd + wake eventfd at fixed fd numbers, dup'd for the child) and die-with-host
  on every exit path (`kill_on_drop` + `PR_SET_PDEATHSIG=SIGKILL`). — satisfies
  [QEMU-28], [QEMU-29]; spec §10.6.
  Completed as the Linux-only `crucible-qemu` spawn adapter: it consumes a
  validated `QemuLaunchCommand`, creates the per-node plugin control
  `socketpair`, shmem `memfd`, and wake `eventfd`, keeps host copies, duplicates
  child copies, maps the child side to fd 3/4/5 in `pre_exec`, sets
  `PR_SET_PDEATHSIG=SIGKILL`, verifies the parent did not change before `exec`,
  and wraps the child in `QemuNodeChild`, whose drop path kills and reaps any
  unreaped process. The protocol setup handshake remains tracked by [T-PROTO-3]
  and setup-completion tasks; realization-level `start`/`resume`/`fork` assembly
  remains tracked by [T-QEMU-6].
- [x] **T-QEMU-8** Implement the graceful-shutdown escalation (Quit → QMP quit →
  SIGTERM → SIGKILL → reap) with bounded per-rung timeouts and an unconditional
  reap; add the no-leak test that induces each termination path and asserts zero
  surviving children. — satisfies [QEMU-30], [QEMU-31]; spec §10.6.
- [x] **T-QEMU-9** Implement crash detection (unexpected child exit, plugin-IPC
  close, QMP disconnect) surfaced as a typed crashed-node status distinct from an
  intended crash fault, localized rather than retried on gated paths. —
  satisfies [QEMU-32]; spec §10.6.
- [x] **T-QEMU-10** Wire the determinism boundary: configure hermeticity entirely
  via launch config + sim mode, expose the black-box execution-fingerprint hook
  (periodic icount + register/memory/device digest via the plugin), and add the
  per-elimination micro-tests + inertness checks. — satisfies [QEMU-33],
  [QEMU-35]; spec §10.7.
  Completed as the `crucible-qemu` determinism-boundary validator: it accepts
  only a deterministic launch profile plus sim-mode inertness evidence, defines
  a content-addressed black-box plugin fingerprint definition with periodic
  icount, architectural-register, guest-memory, and device-state components,
  builds the digest consumed by the single-VM fingerprint hook, and requires a
  per-elimination executable negative microtest matrix for the sim accelerator,
  stock-TCG/MTTCG rejection, icount, CPU
  entropy, RTC, guest entropy, run seed, kernel randomization, input, CoW
  backing, idle-warp, and sim-mode inertness. The full real-QEMU
  `gate:qemu-inert` corpus is implemented by
  `checks.crucible.phase2.gates.qemuInert`; the N-vCPU fingerprint expansion is
  covered by `checks.crucible.phase2.qemuNvcpuFingerprint`.
- [x] **T-QEMU-11** Implement the single-VM fingerprint hook for
  `gate:single-vm-fingerprint`: run-twice-and-diff under adversarial host
  conditions with first-mismatch icount-window localization and a fixed,
  content-addressed fingerprint definition. — satisfies [QEMU-34]; spec §10.7,
  §24.
  Completed by `checks.crucible.phase2.qemuLivePluginFingerprint`. The
  production Rust runner performs fresh exact-input launches, applies
  adversarial host load to the second run, and compares a content-addressed
  five-boundary stream containing periodic, real frame-delivery, and real
  signal-effect-boundary samples. Its negative control proves the complete diagnostic
  path: ordinal-aware fresh-run probes localize a real launch divergence to one
  instruction, and the plugin's terminal paused callback exports complete
  per-vCPU registers, writable RAM, and serialized non-RAM VMState from both
  QEMU processes for a validated, content-addressed dump.
- [x] **T-QEMU-12** Implement the per-quantum data flow at the QEMU level (run to
  ceiling-or-idle → report icount/idle-deadline → scheduler ceiling store →
  unconditional futex wake + plugin eventfd write → advance → frame inject/emit
  / I/O), with state and payloads entirely in shmem and no per-quantum
  QMP/plugin-IPC traffic. — satisfies [QEMU-36]; spec §10.8.
  Completed as the `crucible-qemu` shared-memory hot path: the
  `QemuQuantumShmemHotPath` adapter observes plugin-published node reports,
  authorizes and stores scheduler ceilings through the node slot, wakes the
  plugin via the futex word and eventfd counter, finishes after a later shared-memory completion
  report is visible, moves inbound and outbound frame records through SPSC
  rings, and asserts the per-quantum operation log is shared-memory-only with
  QMP and plugin IPC rejected from the hot path. The exact frame visibility and
  device-I/O freeze semantics are completed by [T-QEMU-13], and the bounded
  real-time async wait remains tracked by [T-QEMU-14].
- [x] **T-QEMU-13** Implement injection-contract frame inject/emit at the QEMU
  level: visibility at exactly `delivery_icount`, `(delivery_icount, src_node,
  seq)` total order, fail-loud on a past-delivery node; and the
  `device_io_active` virtual-time freeze across device-I/O bursts. — satisfies
  [QEMU-37], [QEMU-38]; spec §10.8.
  Completed as QEMU-level injection-contract enforcement: the
  `QemuQuantumShmemHotPath` authorizes a ceiling exactly at the next
  `delivery_icount` while still rejecting overshoot, previews inbound SPSC
  entries before committing them, rejects frames behind the passed-delivery
  floor without consuming the ring, and reports due frames in
  `(delivery_icount, src_node, seq)` order. The scheduler-facing `deliver_frame`
  path assigns monotonic router-source sequence numbers and fails loudly if that
  sequence space is exhausted. Emitted frames now preserve the guest-side
  `emit_icount` stamp for the router, and each quantum carries device-I/O
  freeze observations from the node slot so `device_io_active`
  transitions are part of the QEMU-level report and fingerprint boundary. The
  plugin RX path remains the QEMU-facing architectural injection mechanism:
  it queues due frames through the lossless QEMU RX API, flushes after the
  ordered batch, and uses the existing `PluginDeviceIoFreeze` submit/complete
  state machine to hold HZ ticks across device-I/O bursts. The bounded
  real-time async wait remains tracked by [T-QEMU-14].
- [x] **T-QEMU-14** Implement the async driver bridging the synchronous node-step
  to bounded async socket/QMP/process I/O on a real-time host runtime decoupled
  from virtual time, with shmem-only hot path, inter-quantum yields, bounded
  per-await timeouts → crash/escalate, and no host-timing influence on any
  ordering-significant decision. — satisfies [QEMU-39], [QEMU-40], [QEMU-41],
  [QEMU-42]; spec §10.9.
  Completed as the `crucible-qemu` bounded async driver boundary: the
  `QemuHostIoRuntime` trait owns real-time child awaits and explicit
  control-plane yields, `QemuAsyncDriverPolicy` requires nonzero timeouts for
  handshake, QMP command, process-event, and advance-completion waits, and
  `run_bounded_qemu_node_step` starts exactly one split shared-memory quantum,
  awaits the plugin completion with the configured budget, finishes the quantum
  from shmem, and yields before returning. `QemuNode::advance_to_ceiling` is
  wired through that driver using the concrete `QemuQuantumShmemHotPath`
  start/finish adapter, so the scheduler-facing path cannot bypass the bounded
  wait. Advance and lifecycle timeouts are converted into typed crashed-node
  status (`BoundedAwaitTimeout`) and shutdown escalation instead of a retry or
  hang, including QMP timeout channel errors observed through the node wrapper.
  `QmpClient` requires a timeout-capable stream, applies one total deadline to
  each greeting or command exchange, caps JSON-line bytes and skipped async
  events, and installs read/write timeouts before stream operations. The driver
  asserts that quantum operations are shared-memory-only, rejects per-quantum QMP
  or plugin-IPC operations, and the gate forbids wall-clock reads, randomness,
  sleeps, and nondeterministic select APIs in the ordering-significant driver
  path.
- [x] **T-QEMU-15** Extend the launch-config builder and validator for
  multi-vCPU single-threaded round-robin: emit `-accel sim,thread=single` with
  `-smp N`, set the round-robin switch boundary to the scenario's
  content-addressed `rr_switch_quantum` (node-icount) via the patch-series flag
  (`crucible-rr-quantum-icount`, 11), reject `thread=multi` and an unpinned
  quantum loudly, and fold N + the pinned `rr_switch_quantum` into the scenario
  content hash. — satisfies [QEMU-5], [QEMU-43]; spec §10.2.
  **Completed:** `DeterministicLaunchProfile` now accepts `smp_vcpus >= 1`,
  emits `-accel sim,thread=single` with `-smp N`, pins the
  `rr_switch_quantum` node-icount boundary in `-icount`, and folds both
  `smp_vcpus=N` and `rr_switch_quantum` plus the ascending vCPU rotation into
  scenario material. The pre-spawn validator rejects MTTCG and unpinned or zero
  RR quantum before QEMU is spawned, while accepting the RFC alias
  `crucible-rr-quantum-icount` for patched QEMU command lines.
- [x] **T-QEMU-16** Extend the single-VM fingerprint hook to N-vCPU nodes: read
  all N vCPUs' register files plus the round-robin cursor (current vCPU +
  position within `rr_switch_quantum`) via the plugin's per-vCPU introspection
  capability (12) and QMP, include them in the digest, and localize a mismatch
  to the first differing icount window. — satisfies [QEMU-34]; spec §10.7.
  **Implemented but not closed:** the `crucible-qemu` single-VM fingerprint stream now carries
  canonical N-vCPU sample material: sorted register-file digests for exactly
  vCPUs `0..N`, the RR cursor (`current_vcpu`, position inside the pinned
  `rr_switch_quantum`, and the quantum), guest-memory digest, and device-state
  digest. The scenario carries the launch-derived `-smp N` and pinned
  `rr_switch_quantum`, and gate admission rejects streams that omit launched
  vCPUs or report cursor state from a different quantum. Stream validation
  recomputes each rolling fingerprint from that material, the definition digest,
  and the previous rolling fingerprint, so all-vCPU registers and the RR cursor
  are part of the compared digest rather than advisory metadata. Sample mismatch
  diagnostics localize the first differing icount window and name the first
  differing component, including per-vCPU register digests and RR cursor
  position. The task check realizes the plugin per-vCPU introspection check and
  the typed QMP control-boundary check, runs the same bounded real-QEMU `-smp 4`
  sim/RR-TCG workload twice with second-run bounded scheduler preemption, checks exact sorted QMP
  CPU indexes on both runs, binds register schemas/bytes and retired-count sums,
  uses a definition-only QEMU preflight to pin the observation shape before
  importing both plugin traces through the Rust path, and executes
  register/RR/retired post-processing mismatch-localization plus structural red controls. It
  binds current serialized non-RAM VMState in addition to keeping MMIO history
  as a diagnostic.
  **Closed live by `checks.crucible.phase2.qemuLivePluginFingerprintSmp`** at the
  frozen `-smp 4` pin (corroborated at `-smp 2`). Two paths satisfy disjoint
  clauses: the C-trace path (`checks.crucible.phase2.qemuNvcpuFingerprint`) stays
  the independent differential oracle over the same real `-smp 4` S11 workload;
  the Rust control plugin is now the live fingerprint AUTHORITY. Reading all N
  register files plus the RR cursor via the plugin's per-vCPU introspection
  capability (12) is live: `PluginFingerprintSampling::sample` reads exactly the
  `0..N` register files and the authoritative RR cursor (`current_vcpu`, position
  inside the pinned `rr_switch_quantum`) at every boundary — the gate emits
  `vcpu_register_count=N` and the deterministic `rr_current_vcpu` /
  `rr_position_in_quantum` per sample. Those components are in the compared digest
  (`per_vcpu_registers_match_run_twice`, `rr_cursor_matches_run_twice`, plus
  guest-RAM and device-state digests, all byte-identical over two runs, the second
  under host load, plus a restart probe). The definition mints under the new
  `crucible.qemu.rust-plugin-fingerprint.v2` domain. Mismatch localization to the
  first differing icount window is realized by the run-twice stream comparison and
  its bisection report (`SingleVmFingerprintGateError::Mismatch` names the first
  differing component and icount window). The per-vCPU retired-count clause is a
  deterministic constant stamp: under single-threaded RR icount QEMU keeps one
  global counter (patch 0029 sets the per-vCPU stamp to zero by construction), so
  the per-vCPU accounting exercised live is the RR cursor, not a per-vCPU retired
  sum. Frame/fault boundary sampling triggers remain M4/M5 scope (this gate uses
  the periodic aggregate-icount cadence in busy windows).
