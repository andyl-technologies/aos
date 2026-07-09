# 04 — The Determinism Contract

This file is the spine of the RFC. Everything else — the execution model, the
temporal graph, the scheduler, the QEMU patch series, the test harness — exists
to *establish*, *exploit*, or *defend* the contract stated here. The headline
goal [G-1] and the invariants [INV-1], [INV-4], [INV-10] are made precise in
this file; the rest of the spec satisfies them.

The contract is unusually strong on purpose. Most "deterministic simulation"
systems guarantee that the *delivered sequence of cross-node messages* is
reproducible — they put the determinism boundary at the network edge and treat
each node's interior as a black box that happens to behave the same way "in
practice." Crucible instead guarantees that the *interior is bit-identical too*:
every guest produces the same instruction stream and the same architectural
state at every instruction count. This file defines what that means formally,
enumerates every source of nondeterminism that could break it, states the
elimination mechanism for each, and specifies how the contract is verified.

Requirement IDs in this file use the prefix `DET`. Gate names referenced here
are defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md);
the QEMU-side mechanisms are specified in [`11-qemu-patches.md`](11-qemu-patches.md)
and [`12-qemu-plugin.md`](12-qemu-plugin.md); virtual time in
[`09-virtual-time-icount.md`](09-virtual-time-icount.md).

## 4.1 What "hermetic instruction-level determinism" means

Two systems that merely agree on which messages were delivered, in what order,
are *behaviorally equivalent at the network boundary* but may have taken wildly
different interior paths to get there — different interrupt-handler entry points,
different scheduler decisions inside the guest, different memory contents at a
crash point. That is not enough to (a) reproduce an interior bug, (b) fork a run
and have both branches agree on shared history, or (c) bisect a divergence to a
single instruction. Crucible therefore raises the bar to the interior.

### The formal statement

Fix, for a single VM:

- `image` — the kernel, the read-only root image, the firmware (06, 26),
- `cmdline` — the kernel command line including all determinism-relevant flags
  (4.6),
- `seed` — the root entropy from which all *intended* randomness is derived
  (4.7),
- an **ordered injected-input sequence** `I = [(icount_0, input_0), (icount_1,
  input_1), ...]` where each `input_k` (a delivered network frame, an I/O
  completion, a fault activation, a white-box channel write) is stamped with the
  *exact instruction count* `icount_k` at which it becomes architecturally
  visible to the guest (4.4, Contract B).

Define the VM's execution as the function

```text
run(image, cmdline, seed, I) = (S, T)
```

where:

- `S` — the **instruction stream**: the ordered sequence of guest instructions
  retired, identified by guest program counter and decoded operation; and
- `T : icount -> ArchState` — the **architectural state trajectory**: the
  general-purpose and system registers, the full guest physical memory, and the
  architectural state of every emulated device, as a function of instruction
  count.

- **[DET-1]** For a fixed `(image, cmdline, seed, I)`, Crucible MUST produce a
  bit-identical `S` and a bit-identical `T` across any number of runs, on any
  conforming host, regardless of host CPU model, host load, host scheduler
  decisions, wall-clock time, or number of host cores. *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer0-determinism`. *Spec:* §4.1, §4.4.

"Bit-identical `T`" is the strong clause: not just the same observable outputs,
but the same *bytes in guest memory at the same instruction count*. Because
device state and memory are included, every downstream artifact — a snapshot, an
execution fingerprint (4.8), a panic backtrace — is also bit-identical.

### Distinguished from weaker contracts

- **[DET-2]** Crucible's per-VM determinism MUST be *instruction-level*
  (bit-identical `S` and `T`), not merely *same-delivered-message-sequence*.
  Message-sequence determinism is a strictly weaker property that this contract
  implies but is not implied by; the harness MUST verify the interior, not only
  the network boundary. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §4.1,
  §4.8.

- **[DET-3]** Per-VM determinism MUST be achieved by *eliminating nondeterminism
  at its source*, not by recording the outcomes of nondeterministic operations
  and replaying them (NG-6). Every entropy source enumerated in §4.6 MUST be
  removed, fixed, or routed through the seeded decision source (4.7); no entropy
  source may be left live with a replay log compensating for it on subsequent
  runs. *Gate:* `gate:layer0-determinism`, `gate:replay-oracle`. *Spec:* §4.3,
  §4.6.

The distinction in [DET-3] is the load-bearing one. A record/replay log is an
*input* that must itself be produced by a first, nondeterministic run, and is
only valid for that exact build, that exact host quirk, that exact path. Source
elimination has no such "golden first run": the *first* run is already
deterministic, so any run reproduces any other run, forks are trivially
consistent with their parents, and a divergence is a real defect rather than a
stale log. QEMU's own record/replay subsystem MAY be used as a *diagnostic* to
*find* a residual entropy source (it will diverge precisely where one leaks), but
it MUST NOT be the mechanism by which the shipped contract holds (see
[`30-risks-spikes.md`](30-risks-spikes.md)).

### Why the stronger bar is worth it

Eliminating entropy at the source is *most* of the work either way: to get even
message-sequence determinism you must already pin the CPU model, suppress
`RDRAND`/`RDTSC` leakage, seed guest entropy, and drive virtual time from
instruction count. Once those are done, the interior is *already*
deterministic — the stronger contract is very nearly free. What it buys is large
and disproportionate:

- **Trivial fork/resume.** A fork (22) is consistent with its parent because both
  branches share a bit-identical prefix `T`. No reconciliation, no "replay
  divergence tolerance."
- **Trivial replay oracle.** [INV-2] (a materialized snapshot must hash-equal its
  replay-from-ancestor) is only meaningful if the replay is bit-identical;
  weaker determinism makes the oracle untestable.
- **Trivial divergence bisection.** A divergence (4.8, [INV-10]) localizes to a
  *single instruction count* by comparing fingerprints, which only exists because
  `T` is a function of icount.
- **Trivial debugging.** A failure reproduces to the byte; a watchpoint set in a
  second run fires at the same instruction as the first.

- **[DET-4]** The system MUST be designed so that the marginal mechanisms
  required to lift message-sequence determinism to instruction-level determinism
  (deterministic memory/device state, the icount-stamped injection contract of
  §4.4, and the execution fingerprint of §4.8) are first-class, not optional
  add-ons. *Gate:* `gate:single-vm-fingerprint`, `gate:layer1-injection`. *Spec:*
  §4.1, §4.4, §4.8.

## 4.2 The two sub-contracts

The contract decomposes into two independently testable halves. Keeping them
separate is what makes the foundation gateable layer by layer (G-5): Contract A
is provable on a *single* VM with no scheduler, no transport, and no peers;
Contract B is provable on a *pair* of VMs and is the only part that depends on
the cross-node machinery.

### Contract A — intra-VM hermeticity

- **[DET-5]** **Contract A.** For one VM with `N >= 1` vCPUs, fixed
  `(image, cmdline, seed, N, rr_switch_quantum)`, and a fixed icount-stamped
  injected-input sequence `I`, the VM MUST produce a bit-identical
  *aggregate-icount* stream and architectural-state trajectory `T` (i.e. `run`
  from [DET-1] is a pure function for a single node). For `N > 1`, `T` INCLUDES
  every one of the `N` vCPUs' register files and the round-robin (RR) scheduler
  cursor; the interleaving — which vCPU retires each instruction, and the point
  at which each vCPU is preempted — MUST be a pure function of
  `(image, cmdline, seed, I, rr_switch_quantum, N)` and of the `Schedule`'s
  preemption decisions, not of host thread scheduling. The multi-vCPU node runs
  under QEMU single-threaded round-robin TCG with `-icount` (NOT MTTCG; §4.6
  E13), so the whole interleaving is a pure function of the inputs above. This
  MUST be testable in isolation, with `I` supplied from a recorded list rather
  than from live peers. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §4.2.1.

Contract A is entirely about *removing entropy from inside one VM*: it is the
union of every elimination in §4.6. It says nothing about *when* inputs arrive —
it takes their arrival icounts as given. It is the L0/L2 + patch-series property.

### Contract B — injection determinism

- **[DET-6]** **Contract B.** The instruction count at which an external input
  becomes architecturally visible to a receiving VM MUST be a pure function of
  virtual time and the scheduler's total order, NOT a function of when the
  producer happened to compute it in host wall-clock time. There MUST be no
  producer→consumer race: a frame computed "early" by a fast host peer and a
  frame computed "late" by a slow one MUST be delivered at the identical
  consumer icount. *Gate:* `gate:layer1-injection`, `gate:e2e-determinism`.
  *Spec:* §4.2.2, §4.4.

Contract B is the cross-node property. It is satisfied by (a) deriving each
node's clock from its icount (4.3), (b) the single authoritative scheduler that
assigns a delivery virtual-time to every cross-node event and converts it to a
consumer icount ([INV-3], [INV-8], 08), and (c) the conservative PDES lookahead
discipline that guarantees no input can arrive "in the past" of a node that has
already advanced (08). The transport (13) carries the *delivery icount* with
every payload so the receiving plugin makes the input visible at exactly that
count, never "as soon as it shows up on the socket."

- **[DET-7]** A and B MUST be tested by *separate* gates and the system MUST NOT
  build any L3+ feature on a VM image until Contract A is green for that image,
  nor any multi-VM feature until Contract B is green for a representative pair.
  *Gate:* `gate:layer0-determinism` (A), `gate:layer1-injection` (B). *Spec:*
  §4.2, [`32-implementation-plan.md`](32-implementation-plan.md) Phase 1.

```text
Contract A (single VM)              Contract B (VM pair)
------------------------            -------------------------------
fix image,cmdline,seed,I            fix scenario,seed,schedule
   |                                   |
   v                                   v
run twice under adversarial         run twice under adversarial
host conditions                     host conditions (esp. uneven
   |                                core counts / host load skew)
   v                                   |
fingerprints must match             v
(gate:single-vm-fingerprint)        consumer icount of each delivery
                                    must match across runs
                                    (gate:layer1-injection)
```

## 4.3 icount is the canonical clock

- **[DET-8]** A VM's notion of time MUST be its executed guest instruction count
  (icount). Virtual nanoseconds MUST be derived from icount by the fixed mapping
  `ns = icount << shift` for a configured integer `shift` (TIME). No other clock
  — not host monotonic, not host wall-clock — may influence guest-visible time.
  *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §4.3,
  forward-ref 09.

- **[DET-9]** The icount shift MUST be a fixed integer (`-icount shift=N`).
  Crucible MUST NOT use `-icount shift=auto`. The `auto` mode adapts the
  instructions-per-nanosecond ratio to *host execution speed* at runtime, which
  makes the number of instructions executed before a virtual-timer deadline a
  function of how fast the host is — directly destroying [DET-1]. The shift is
  part of the scenario's content hash. *Gate:* `gate:layer0-determinism`. *Spec:*
  §4.3, forward-ref 09.

- **[DET-10]** Virtual time MUST advance *only* by retiring instructions and by
  explicit, scheduler-authorized jumps across idle gaps; it MUST NOT advance by
  host wall-clock while the guest is idle ("warp"). The plugin owns the virtual
  clock and the warp path is suppressed whenever a plugin holds time control
  (4.6, source E2). *Gate:* `gate:layer0-determinism`. *Spec:* §4.3, §4.6,
  forward-ref 09, 11, 12.

The consequence of [DET-8]–[DET-10] is that "time" inside a VM is a *pure
counter the host can read and command*, not a quantity the host races against.
Every other entropy elimination in §4.6 either feeds this clock (so the guest's
own time-reads are deterministic) or is downstream of it (so device timers fire
at deterministic icounts).

## 4.4 The injection contract (icount-stamped inputs)

Contract B reduces to one precise requirement about *how an input is timed*.

- **[DET-11]** Every external input delivered to a VM MUST carry an explicit
  **delivery icount** (equivalently, a delivery virtual time the plugin converts
  to an icount via the fixed shift), and the plugin MUST make that input
  architecturally visible to the guest at *exactly* that icount — neither earlier
  (the guest has not reached it) nor later (the guest has run past it). *Gate:*
  `gate:layer1-injection`. *Spec:* §4.4, forward-ref 08, 13.

- **[DET-12]** A VM MUST NOT advance past the earliest icount at which an input
  *could* become visible to it without the scheduler's authorization. The
  conservative lookahead bound (minimum inbound link latency; 08) MUST gate how
  far a node runs, so that an input's delivery icount is always in the node's
  future at the moment it is computed. A node that has run past a delivery icount
  is a contract violation and MUST fail loudly, never be papered over by
  delivering late. *Gate:* `gate:layer1-injection`, `gate:divergence-bisect`.
  *Spec:* §4.4, forward-ref 08.

- **[DET-13]** The visibility icount of an input MUST NOT depend on transport
  timing: the moment a payload becomes readable on the shared-memory queue or a
  socket is irrelevant to *when the guest sees it*. The shared-memory ABI MUST
  carry the delivery icount in-band so the consumer is time-driven, not
  arrival-driven. *Gate:* `gate:layer1-injection`. *Spec:* §4.4, forward-ref 13.

- **[DET-14]** When multiple inputs target the same VM at the same delivery
  icount, their visibility order MUST be the deterministic total order
  `(virtual_time, consumer node_id, producer node_id, sequence)` of [INV-3] (see [`08-scheduling.md`](08-scheduling.md)
  §8.6 for the full key; `node_id` here is the consumer, with producer and sequence
  as further tiebreaks), resolved by the single
  authoritative scheduler, identical across runs. *Gate:* `gate:layer1-injection`.
  *Spec:* §4.4, forward-ref 08.

This is the whole of Contract B: inputs are *timestamped in virtual time*, and
the guest's perception of "now" is *also* virtual time (4.3), so delivery is a
join of two pure quantities. The host wall-clock — when QEMU process A finished
computing a frame versus when process B is ready to receive it — never enters.

## 4.5 Determinism is a host-side property; the guest is unmodified

- **[DET-15]** Determinism MUST be achieved entirely host-side. Crucible MUST
  NOT require modifications to the guest kernel, the guest userspace, or the
  on-disk image to obtain [DET-1] (this is [INV-5] / [G-2]). All elimination
  mechanisms in §4.6 MUST act through launch-time configuration, the QEMU patch
  series, the in-VM plugin, or seeded firmware/cmdline values — never through
  content placed inside the guest. *Gate:* `gate:any-guest`. *Spec:* §4.5,
  forward-ref 16.

- **[DET-16]** Booting and running a guest MUST NOT mutate the guest's on-disk
  image; all guest writes MUST land in copy-on-write overlays (15). Two runs from
  the same genesis MUST start from byte-identical backing state. *Gate:*
  `gate:any-guest`, `gate:replay-oracle`. *Spec:* §4.5, forward-ref 15.

- **[DET-17]** Black-box observation MUST be sufficient for the determinism
  contract: the execution fingerprint (4.8) MUST be computable without any
  guest cooperation. The optional white-box channel (16) MAY add finer markers
  but MUST NOT be required for [DET-1], and any white-box input MUST itself obey
  the injection contract (4.4) so enabling it cannot perturb determinism. *Gate:*
  `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §4.5, forward-ref 16.

The practical force of [DET-15]–[DET-17] is that the *same* unmodified Linux (or
BSD) image used in production runs deterministically under Crucible with only
QEMU flags and a kernel cmdline. The determinism work is the host's; the guest is
a sealed black box that happens to behave identically because its entire entropy
boundary has been pinned from outside.

## 4.6 The entropy-source enumeration and its elimination

This is the exhaustive list. Each row names a source, says how it leaks into `S`
or `T`, states the elimination mechanism, and classifies it as **launch** (a
QEMU flag or cmdline value), **plugin** (logic in `crucible-qemu-plugin`), or
**patch** (a change in the AOS QEMU patch series, 11). A source is *eliminated*
when it can no longer cause two runs of fixed `(image, cmdline, seed, I)` to
differ.

| ID | Source | How it leaks | Elimination | Class |
| --- | --- | --- | --- | --- |
| E1 | Hardware RNG (`RDRAND`/`RDSEED`) | Guest reads true entropy into memory/registers | Fixed `-cpu` model without RDRAND/RDSEED feature bits, OR plugin/patch emulates the instruction from the seeded stream; never the host's hardware RNG | launch + patch |
| E2 | Wall-clock warp while idle | QEMU advances the virtual clock by host real time during guest idle | Plugin holds time control; warp path suppressed when a plugin owns the clock (`qemu-no-warp-with-plugin`) | plugin + patch |
| E3 | Real-time deadlines in the icount budget | Mixing `QEMU_CLOCK_REALTIME` deadlines into the instruction limit makes instructions-per-TB host-speed-dependent | In fixed-shift (precise) mode, compute the icount budget from `QEMU_CLOCK_VIRTUAL` deadlines only (`qemu-icount-no-realtime`) | patch |
| E4 | Timestamp counter (`RDTSC`/`RDTSCP`) | Guest reads a host-correlated cycle counter | Under TCG `-icount`, TSC is derived from the instruction counter; the fixed `-cpu` plus icount makes it a pure function of icount | launch |
| E5 | `gettimeofday`/`clock_gettime`/RTC reads | Guest reads wall-clock-derived time | RTC/wall-clock base is a fixed, configured epoch; the clock advances only via icount (4.3); no host time enters | launch + patch |
| E6 | Emulated timer devices (LAPIC, PIT, RTC, HPET) | Timer fire ordering/timing relative to instructions | All are virtual-clock-driven; the virtual clock is icount-derived, so deadlines map to deterministic icounts | launch |
| E7 | CPU/timer interrupt delivery timing | An interrupt taken one instruction earlier/later forks the path | TCG delivers CPU/timer interrupts at deterministic translation-block boundaries under icount; the virtual clock that schedules them is icount-derived | launch |
| E7a | Asynchronous device-completion delivery timing | A virtio-rng entropy completion is serviced from a host-scheduled main-loop bottom half, so its completion interrupt lands at a host-timing-dependent instruction and forks the path — even when the completion payload (seeded entropy) is byte-pure. Inherent to upstream icount, which pins virtual *time* but not the *icount* of an async completion. (virtio-blk/9p completions do not share this hazard: their delivery icount is already pinned by the crucible blk/9p shmem substrate, patches 0015-0019.) | Deliver the virtio-rng completion synchronously on the requesting vCPU thread at the request icount: `crucible-det-virtio-ioeventfd` disables ioeventfd under icount for the virtio-rng device so its virtqueue kick dispatches synchronously (block/9p keep the stock async kick their shmem substrate assumes), and `crucible-det-rng-delivery` completes builtin-RNG entropy inline instead of via a bottom half. No QEMU record/replay (NG-6); modeled completion latency, if ever wanted, belongs in the IO sub-node (15), not here. Verified by S6/T-RISK-6 and guest-entropy-launch. | patch |
| E8 | Guest entropy pool seeding (`getrandom`, `/dev/urandom`, `random.trust_cpu`) | Guest CSPRNG seeded from true entropy diverges | Seed the guest deterministically via firmware (`fw_cfg`) random-seed and/or controlled RDRAND; the seed is a pure function of the scenario seed (4.7) | launch |
| E9 | QEMU-internal use of host RNG (`qemu_guest_getrandom`, glib `GRand`) | QEMU device models / MACs / IDs draw from host entropy, perturbing device state in `T` | Seed QEMU's guest-random and glib PRNG deterministically from the run seed (`qemu-deterministic-getrandom`, `qemu-deterministic-glib-prng`) | patch |
| E10 | CPU model variation | Different host CPUs expose different feature bits / instruction semantics | Fixed `-cpu <model>` (never `-cpu host`); the model is part of the scenario hash | launch |
| E11 | Kernel address-space randomization (KASLR) | Randomized kernel base changes addresses throughout `T` | KASLR stays **enabled** (stock guest cmdline). Its randomization is a pure function of the boot entropy, which is itself seeded deterministically host-side (E8/E9: `fw_cfg` random-seed, controlled RDRAND, no host-entropy passthrough), so the kernel base is reproducible across replays. S6/T-RISK-6 verified this bit-stability under fully seeded boot entropy. Crucible neither adds nor requires `nokaslr`. | launch |
| E12 | Userspace ASLR (`norandmaps`) | Randomized mmap/stack/brk bases change `T` | ASLR stays **enabled** (stock guest cmdline). Userspace randomization derives from the same deterministically seeded boot entropy (E8/E9), so mmap/stack/brk bases are reproducible across replays. S6/T-RISK-6 verified this bit-stability under fully seeded boot entropy. Crucible neither adds nor requires `norandmaps`. | launch |
| E13 | Multi-vCPU instruction interleaving (MTTCG excluded; multi-vCPU = single-threaded RR-TCG) | Concurrent vCPUs would interleave nondeterministically under MTTCG (`thread=multi`) | MTTCG is excluded; all `N` vCPUs time-share ONE host thread under single-threaded round-robin TCG with `-icount`, switching at a fixed content-addressed `rr_switch_quantum` in node-icount (never QEMU's adaptive `rr_quantum`, never realtime). The interleaving is then a pure function of `(image, cmdline, seed, I, rr_switch_quantum, N)` | launch + patch |
| E14 | Host thread scheduling of QEMU threads | Order of QEMU's own threads (vCPU, iothread, main loop) affects timing | Single vCPU plus icount makes guest progress independent of host thread order; the plugin's synchronous time-control handshake forces a defined order at idle/advance points | plugin + patch |
| E15 | Floating-point nondeterminism | FP results vary by rounding mode / FMA contraction / library | Under a fixed `-cpu` and TCG soft-float, FP is a deterministic function of inputs; cross-host reproducibility holds because TCG emulates, not delegates to host FPU. No action beyond E10 | (covered by E10) |
| E16 | Uninitialized memory / device reset values | Power-on memory and device registers differ run to run | Deterministic machine reset: RAM zeroed (or fixed-pattern), device reset values fixed; part of the genesis bake (05) | launch + patch |
| E17 | Input devices (keyboard, mouse, serial) | Asynchronous human/host input perturbs the guest | No interactive input during a run; all input arrives via the injection contract (4.4) with a delivery icount | launch |
| E18 | Network arrival timing | Frames delivered "as they arrive" race producer vs consumer | Contract B (4.4): every frame carries a delivery icount; the scheduler assigns it; transport timing is irrelevant | plugin + patch |
| E19 | Block / 9p I/O completion timing | Disk/filesystem completions land at host-timing-dependent points | I/O sub-nodes (15) are first-class scheduling nodes with deterministic completion icounts; completions obey the injection contract | plugin + patch |
| E20 | Snapshot/restore state loss | `loadvm` that drops icount or TCG state diverges from a fresh boot | Snapshot must preserve icount, bias, and TCG/device state completely; verified by the replay oracle. Completeness is a SPIKE (4.9) | patch |
| E21 | RR vCPU-switch quantum | The granularity and order in which vCPUs are switched on the single host thread determines the interleaving | Fixed content-addressed `rr_switch_quantum` in node-icount units, with a fixed ascending vCPU rotation; never QEMU's adaptive `rr_quantum`, never realtime | launch + patch |
| E22 | Inter-vCPU IPI / cross-CPU interrupt timing | A vCPU-to-vCPU IPI taken one instruction earlier/later on the target forks the path | The IPI becomes visible to the target at a deterministic node-icount = sender's icount + a fixed modeled IPI latency, delivered at the next RR switch boundary; never at a host-timing-dependent point | patch |
| E23 | Per-vCPU TSC / RNG | Each vCPU's timestamp counter or entropy reads could diverge per vCPU | Every per-vCPU TSC/RNG value is derived from the node icount, and a uniform `-cpu` model is pinned across ALL vCPUs (no per-vCPU feature variation), so per-vCPU reads are pure functions of node icount | launch |
| E24 | vCPU bringup / hotplug | Secondary-vCPU SIPI/INIT timing or runtime topology change perturbs `T` | Topology is fixed at the genesis bake (no runtime hotplug); secondary-vCPU SIPI/INIT sequencing is deterministic under RR-TCG + icount | launch + patch |

- **[DET-18]** Each entropy source E1–E20 MUST be eliminated by its stated
  mechanism, and each mechanism MUST have a micro-test that fails if the source
  is reintroduced (e.g. removing the `-cpu` pin, or unsuppressing warp, MUST turn
  a determinism gate red). *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`.
  *Spec:* §4.6, forward-ref 11, 24.

- **[DET-19]** Hardware entropy instructions (E1) MUST NOT reach the host: either
  the configured `-cpu` model MUST NOT advertise `RDRAND`/`RDSEED`, or the patch
  series MUST emulate them from the seeded stream. A run in which the guest
  obtains true hardware entropy is a contract violation. *Gate:*
  `gate:layer0-determinism`. *Spec:* §4.6 (E1), forward-ref 11.

- **[DET-20]** The CPU model MUST be fixed (`-cpu <model>`, never `-cpu host`)
  and recorded in the scenario hash; a run MUST NOT depend on the host CPU's
  feature set (E10), which also makes floating-point (E15) deterministic under
  TCG soft-float. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §4.6 (E10, E15).

- **[DET-21]** All entropy consumed by *QEMU itself* (device MACs, IDs, internal
  PRNG draws — E9) MUST be seeded deterministically from the run seed via the
  patch series, so that device state in `T` is reproducible, not only guest
  memory. *Gate:* `gate:layer0-determinism`. *Spec:* §4.6 (E9), forward-ref 11.

- **[DET-22]** Guest entropy (E8) MUST be seeded as a pure function of the
  scenario seed through launch-time configuration (e.g. `fw_cfg` random-seed),
  with no path by which the guest's CSPRNG is seeded from host entropy. *Gate:*
  `gate:layer0-determinism`. *Spec:* §4.6 (E8).

- **[DET-23]** Multi-vCPU determinism MUST be achieved via QEMU single-threaded
  round-robin TCG plus `-icount`, with all `N` vCPUs time-sharing one host thread
  and switching at a fixed content-addressed `rr_switch_quantum` (E13, E21).
  MTTCG (`thread=multi`) MUST be rejected by the harness, and the adaptive
  `rr_quantum` / any realtime-based switching MUST NOT be used. The harness MUST
  reject a launch configuration that requests MTTCG or an unpinned switch
  quantum. *Gate:* `gate:layer0-determinism`. *Spec:* §4.6 (E13, E21).

The patch-series mechanisms (E2, E3, E9, E14, E18, E19, E20) are specified in
[`11-qemu-patches.md`](11-qemu-patches.md); each patch MUST be inert unless
simulation mode is active ([INV-7], 4.10).

## 4.7 The single seeded decision source for *intended* randomness

Eliminating accidental nondeterminism (4.6) is distinct from making *intended*
randomness reproducible. A scenario legitimately wants randomness: a 1%-loss
link, a probabilistic fault, a randomized workload. That randomness must exist,
must be controllable, and must be reproducible — but it is the *only* randomness
in the entire system.

- **[DET-24]** All *intended* nondeterminism in a run (probabilistic fault
  firing, link loss/jitter draws, randomized workloads, tie-breaking that the
  scenario chooses to randomize) MUST be derived from a single seeded decision
  RNG rooted at the scenario `seed`. There MUST be no other source of randomness
  in the engine: no host thread RNG, no wall-clock-seeded RNG, no unordered-map
  iteration on an ordering-significant path ([INV-9]). *Gate:*
  `gate:harness-lint`, `gate:replay-oracle`. *Spec:* §4.7.

- **[DET-25]** Per-entity randomness MUST be drawn from a stream forked by
  name-hash: `entity_seed = seed XOR stable_hash(entity_name)`. Forking by
  name-hash (rather than by sequential draw from the root) ensures that adding or
  removing an entity does NOT perturb any other entity's stream, and that the
  same entity name yields the same stream regardless of construction order.
  *Gate:* `gate:replay-oracle`. *Spec:* §4.7.

- **[DET-26]** The decision RNG and its forks MUST be consumed in a deterministic
  order — the order is the scheduler's total order ([INV-3], [INV-8]) — and the
  hash used for forking MUST be a fixed, stable, cross-platform hash (not the
  language's default randomized hasher). *Gate:* `gate:harness-lint`. *Spec:*
  §4.7.

```rust
// Illustrative sketch (CONV-1, 00): the only randomness in the system.
// Forking by name-hash makes streams order- and topology-stable.
struct DecisionRng {
    seed: u64,
    root: ChaCha20Rng, // a fixed, cross-platform PRNG, not a host RNG
}

impl DecisionRng {
    fn fork(&self, entity_name: &str) -> ChaCha20Rng {
        // stable_hash: a fixed algorithm, NOT the default randomized hasher.
        let s = self.seed ^ stable_hash(entity_name);
        ChaCha20Rng::seed_from_u64(s)
    }
}
```

- **[DET-27]** The boundary between "eliminate accidental nondeterminism" (4.6)
  and "make intended randomness reproducible" (4.7) MUST be explicit in the code:
  every probabilistic decision MUST flow through a [DET-24] stream and be
  recorded as a `Decision` in the `Schedule` (05, 08); a `Decision` is therefore
  both reproducible (same seed ⇒ same draw) and forkable (a different draw is a
  different branch of the temporal graph). *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §4.7, forward-ref 05, 08.

### Ambient vs app-requested intended randomness

Two distinct things both touch "guest randomness," and they MUST NOT be
conflated:

- **Ambient guest entropy** is the entropy the guest's CSPRNG is *seeded* with at
  boot (E8): a `fw_cfg` random-seed that is a pure function of the scenario seed.
  This requires **zero guest changes**, is opaque to Crucible (the host neither
  sees nor explores individual guest draws), and is an *elimination* mechanism
  (4.6), not a capability.
- **App-requested randomness** is an *optional* capability in which a cooperating
  guest application explicitly opts in — via the white-box channel (16) — to
  request named random draws from Crucible. Each such draw is **white-box** and
  becomes an explorable `Decision`, unlike the opaque ambient seeding.

- **[DET-44]** Optional app-requested randomness MUST be served from the SINGLE
  seeded decision source of §4.7 (it MUST NOT introduce a new entropy source).
  Each app-requested stream MUST be forked per `(node, stream-name)` by name-hash
  ([DET-25]), each draw MUST be recorded as a `Decision` in the `Schedule`
  ([DET-27]), and each draw MUST be delivered to the guest under the injection
  contract (4.4) at a deterministic delivery icount. The guest opts in through
  the white-box channel (16); the capability MUST be distinguishable from ambient
  `fw_cfg` guest entropy (which entails zero guest changes and is opaque). The
  full determinism contract MUST hold *identically* in a run that makes zero
  app-random requests (enabling the capability with no draws is byte-identical to
  not enabling it). *Gate:* `gate:layer1-injection`, `gate:any-guest`,
  `gate:single-vm-fingerprint`. *Spec:* §4.7, forward-ref 16.

## 4.8 The reduction identity and the execution fingerprint

### The reduction identity

- **[DET-28]** Whole-system execution state MUST be a pure function of the
  scenario and the schedule: `State(t) = reduce(ScenarioDef, Schedule[0..t])`
  ([INV-1]). No wall-clock value, host-scheduling order, host entropy, or
  uncontrolled external input may appear as a free variable of `reduce`. The
  determinism contract of this file is exactly the statement that `reduce` is a
  pure function. *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:*
  §4.8, forward-ref 05.

`reduce` is total over `(ScenarioDef, Schedule)`: the `ScenarioDef` pins
`(image, cmdline, seed)` and the per-node injection (via the World and Plan), and
the `Schedule` is the totally-ordered sequence of `Decisions` (4.7) the scheduler
made. Given both, `S` and `T` for every VM follow from Contracts A and B. This is
why "start, resume, fork, replay, search" are operations on one object (G-4): all
of them are evaluations of the same pure `reduce`.

### The execution fingerprint

A full bit-for-bit comparison of `T` at every instruction is too expensive to run
continuously. The fingerprint is the cheap divergence detector that approximates
it.

- **[DET-29]** Each VM MUST expose an **execution fingerprint**: at a fixed
  periodic icount cadence (and at every cross-node interaction point), a digest
  combining the current icount with a hash of architectural registers and a hash
  (or rolling hash) of guest memory and device state. For a multi-vCPU node, the
  fingerprint MUST include *every* vCPU's register file and the RR scheduler
  cursor (the current vCPU, the quantum-remaining, and the per-vCPU retired
  instruction counts), all keyed by the node's aggregate icount. Per-vCPU state
  is plugin-internal and surfaces only here, in the fingerprint (it does not
  cross the shmem ABI; 13). The fingerprint MUST be computed black-box from the
  host side (4.5) with no guest cooperation. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §4.8, forward-ref 12, 24.

- **[DET-30]** Two runs of a fixed `(image, cmdline, seed, I)` MUST produce
  identical fingerprint sequences; the *first* differing fingerprint MUST
  localize a divergence to a bounded icount window, which the bisection procedure
  (4.8, [INV-10]) then narrows to the first differing instruction. A fingerprint
  mismatch is always a defect — never an accepted tolerance. *Gate:*
  `gate:single-vm-fingerprint`, `gate:divergence-bisect`. *Spec:* §4.8,
  forward-ref 24.

- **[DET-31]** The fingerprint cadence and the set of state included MUST be
  fixed and content-addressed alongside the scenario, so that two builds compare
  the *same* digest over the *same* state; changing the fingerprint definition is
  a versioned change. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §4.8.

The fingerprint is the operational form of [DET-1]: [DET-1] says `T` is
bit-identical; the fingerprint is a deterministic, cheap-to-compare *witness* of
`T` that the harness checks every run. Because it is keyed by icount, a mismatch
points at *when* divergence began, which is the input to bisection (24).

## 4.9 Subtle threats and open questions

Some threats to the contract are not "an entropy source we forgot" but
structural risks in the mechanisms themselves. Each is called out, assigned a
disposition, and (where unresolved) flagged as a spike forward-referencing
[`30-risks-spikes.md`](30-risks-spikes.md).

- **[DET-32]** **Snapshot/restore completeness (spike).** Fork and fast-resume
  rely on `loadvm` reproducing a state bit-identical to a fresh replay to the
  same icount. It MUST be verified that the snapshot captures and restores the
  icount, the icount bias, the full TCG/device/timer state, and the plugin's
  time-control state, such that the replay oracle ([INV-2]) holds for a restored
  fat checkpoint. Until verified, snapshot-based resume is gated behind a spike.
  *Gate:* `gate:replay-oracle`. *Spec:* §4.9 (E20), forward-ref 30.

- **[DET-33]** **KASLR/ASLR reproducibility (spike, resolved).** S6/T-RISK-6
  determined that kernel/userspace randomization is bit-stable when all boot
  entropy (E8/E9) is seeded deterministically host-side. Crucible therefore
  ships **stock guest cmdlines with KASLR/ASLR enabled** (E11, E12) and delivers
  determinism entirely host-side; it neither adds nor requires `nokaslr`/
  `norandmaps`. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §4.9 (E11, E12),
  forward-ref 30.

- **[DET-34]** **Producer→consumer visibility is icount-not-wallclock.** The
  shared-memory transport MUST be designed so that a payload's *presence* on a
  queue never determines its *visibility* to the guest (4.4, [DET-13]); the
  consumer is driven by the in-band delivery icount. This is the single most
  important correctness property of the transport and MUST be conformance-tested
  by delivering identical inputs under artificially skewed producer timing.
  *Gate:* `gate:layer1-injection`. *Spec:* §4.9, forward-ref 08, 13.

- **[DET-35]** **QEMU version/build drift.** Determinism is only stable for a
  *fixed* QEMU build: TCG codegen, device models, and the patch series all affect
  `T`. The patched QEMU MUST ship as a pinned, from-source AOS package (G-7); the
  build identity MUST be part of the reproduction artifact so a run reproduces
  only against the build that produced it, and a build change is a versioned,
  re-gated change. *Gate:* `gate:e2e-determinism`, `gate:qemu-inert`. *Spec:*
  §4.9, forward-ref 11, 26.

## 4.10 Patch inertness: determinism is opt-in, production QEMU is untouched

- **[DET-36]** Every patch-class mechanism in §4.6 MUST be *inert* unless
  simulation mode is explicitly activated (plugin loaded + sim flags). The same
  AOS QEMU source built without sim mode active MUST be behaviorally identical to
  upstream ([INV-7]); a determinism mechanism MUST NOT change non-sim behavior.
  *Gate:* `gate:qemu-inert`. *Spec:* §4.10, forward-ref 11.

- **[DET-37]** Each patch MUST carry a micro-test demonstrating both that it
  *takes effect* in sim mode (some entropy source is eliminated) and that it is
  *inert* out of sim mode (upstream behavior unchanged). *Gate:* `gate:qemu-inert`.
  *Spec:* §4.10, forward-ref 11.

## 4.11 Verification: run-twice-and-diff under adversarial conditions

Determinism that only holds on a quiet host is not determinism. The contract is
verified by running the *same* `(scenario, seed, schedule)` twice (or N times)
while *deliberately perturbing the host* and asserting the runs are
fingerprint-identical.

- **[DET-38]** The determinism gates MUST verify the contract under *adversarial
  host conditions*: randomized host thread scheduling/affinity, injected host
  scheduling jitter and load, varying numbers of host cores, and skewed
  producer/consumer timing across VMs. A contract that holds on a quiet host but
  fails under perturbation is a failed contract. *Gate:* `gate:layer0-determinism`,
  `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §4.11, forward-ref 24.

- **[DET-39]** When two runs diverge, the harness MUST localize the divergence to
  the *first* differing decision (Schedule level) and the *first* differing
  instruction/fingerprint (execution level), and report it; divergence MUST NEVER
  be smoothed over, tolerated, or retried until it "passes" ([INV-10]). *Gate:*
  `gate:divergence-bisect`. *Spec:* §4.11, forward-ref 24.

- **[DET-40]** A representative multi-VM, fault-injected scenario MUST run
  bit-identically across adversarial host conditions and MUST reproduce from its
  self-contained artifact `(seed, scenario, schedule, build identity)` — this is
  the end-to-end determinism gate that gates acceptance of the whole RFC
  ([G-6], acceptance criterion 2). *Gate:* `gate:e2e-determinism`. *Spec:*
  §4.11, forward-ref 24, 22.

- **[DET-41]** The replay oracle MUST be enforced continuously: for any
  checkpoint, materializing from a stored snapshot MUST hash-equal re-reducing
  from an ancestor along the same schedule ([INV-2]); a fat checkpoint and its
  thin derivation MUST hash equal. This is the structural form of "the contract
  holds": if `reduce` is pure (4.8), the oracle passes by construction, so an
  oracle failure is a determinism defect. *Gate:* `gate:replay-oracle`. *Spec:*
  §4.11, forward-ref 05, 07, 24.

### Multi-vCPU scenario identity and the A/B boundary

- **[DET-42]** The `rr_switch_quantum`, the vCPU count `N`, and the vCPU rotation
  order MUST be part of the scenario content hash, exactly as the icount shift is
  ([DET-9]). A run MUST refuse to replay against a different `rr_switch_quantum`,
  `N`, or rotation order, because each changes the multi-vCPU interleaving and
  therefore `T`. *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:*
  §4.6 (E13, E21), §4.2.1.

- **[DET-43]** Delivery under Contract B (4.4) is to the NODE's aggregate icount:
  an external input carries a single delivery icount on the node's aggregate
  timeline, and Contract B fixes only *when* the input becomes visible to the
  node. The intra-node routing of a delivered input to a particular vCPU (and the
  exact RR boundary at which that vCPU observes it) is part of Contract A, not
  Contract B — it is a pure function of the node's aggregate state and the RR
  cursor, established by §4.2.1, not by the cross-node scheduler. *Gate:*
  `gate:layer1-injection`. *Spec:* §4.4, §4.2.1.

## 4.12 Summary of the contract

```text
DET-1   run(image,cmdline,seed,I) -> (S,T) is bit-identical across runs/hosts
  = Contract A (DET-5: intra-VM hermeticity, source-eliminated, §4.6)
  + Contract B (DET-6: injection determinism, icount-stamped, §4.4)
  on  icount-as-clock (DET-8..10, fixed shift, no warp, no realtime)
  with intended randomness = one seeded decision source (DET-24..27)
  host-side only, guest unmodified (DET-15..17)
  witnessed by the execution fingerprint (DET-29..31)
  stated as purity of reduce (DET-28) and enforced by the replay oracle (DET-41)
  verified run-twice-and-diff under adversarial host conditions (DET-38..40)
  with QEMU mechanisms inert unless sim mode is on (DET-36..37)
```

If `reduce` is a pure function of `(ScenarioDef, Schedule)`, then reproduction is
free, fork/resume are the same operation as start, divergence bisects to one
instruction, and the failure space is a graph you can search. Every other file in
this RFC is an elaboration of how `reduce` is *made* pure and *kept* pure.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the determinism contract, tracked by [PLAN-3].
> They populate Phase 1 (the determinism / harness / transport / API
> foundation).

- [x] **T-DET-1** Pin the launch configuration for intra-VM hermeticity: fixed
  `-cpu <model>` (no RDRAND/RDSEED, never `-cpu host`), `-smp 1`, `-accel tcg`,
  fixed `-icount shift=N` (never `auto`), deterministic machine reset, fixed RTC
  epoch; record all of it in the scenario hash; make a VM's notion of time its
  guest icount with virtual ns derived by the fixed `ns = icount << shift` mapping
  and no host clock influencing guest-visible time. — satisfies [DET-8], [DET-9],
  [DET-10], [DET-19], [DET-20], [DET-23], [DET-16]; spec §4.3, §4.6.
- [x] **T-DET-2** Port the QEMU patch that drops `QEMU_CLOCK_REALTIME` deadlines
  from the icount budget in fixed-shift mode, with a micro-test that the
  instruction-per-TB count is host-speed-independent. — satisfies [DET-9],
  [DET-18] (E3); spec §4.6 (E3).
- [x] **T-DET-3** Port the QEMU patch suppressing wall-clock warp when a plugin
  holds time control, preserving the clock-notify wakeup path; micro-test that
  the virtual clock advances only by icount and plugin-authorized jumps. —
  satisfies [DET-10], [DET-18] (E2); spec §4.6 (E2).
- [x] **T-DET-4** Seed QEMU-internal entropy deterministically (guest-random and
  glib PRNG) from the run seed so device MACs/IDs and internal draws are
  reproducible in `T`. — satisfies [DET-21], [DET-18] (E9); spec §4.6 (E9).
- [x] **T-DET-5** Seed guest entropy deterministically via firmware
  (`fw_cfg` random-seed) / controlled RDRAND as a pure function of the scenario
  seed; verify no path seeds the guest CSPRNG from host entropy. — satisfies
  [DET-22], [DET-18] (E8); spec §4.6 (E8).
- [x] **T-DET-6** Ship **stock guest cmdlines** with KASLR/ASLR enabled and
  deliver their reproducibility host-side via fully-seeded boot entropy (E8/E9);
  Crucible neither adds nor requires `nokaslr`/`norandmaps`, and guest
  entropy-suppression flags are not part of the launch contract (a guest may
  still set them itself). Phase 0 retired [RISK-13] with `T-RISK-6`, which proved
  KASLR/ASLR bit-stability under seeded boot entropy. — satisfies [DET-18] (E11,
  E12), [DET-33]; spec §4.6 (E11, E12), §4.9.
- [x] **T-DET-7** Implement Contract A in isolation: a single-VM driver that
  feeds an icount-stamped recorded input list `I` and runs `run` with no
  scheduler/transport. — satisfies [DET-5], [DET-1]; spec §4.2.1.
- [x] **T-DET-8** Implement the execution fingerprint (periodic icount +
  register/memory/device digest), computed black-box from the host, with a fixed
  content-addressed definition. — satisfies [DET-29], [DET-31], [DET-17]; spec
  §4.8.
- [x] **T-DET-9** Implement `gate:single-vm-fingerprint`: run-twice-and-diff a
  single VM, asserting identical fingerprint sequences. — satisfies [DET-1],
  [DET-2], [DET-30]; spec §4.8, §4.11.
- [x] **T-DET-10** Implement `gate:layer0-determinism`: the aggregate single-VM
  determinism gate across the elimination set, with per-source micro-tests that
  fail if any of E1–E10, E13–E17 is reintroduced. — satisfies [DET-18],
  [DET-3], [NG-6]; spec §4.6.
- [x] **T-DET-11** Specify and implement the icount-stamped injection contract in
  the shared-memory ABI: every input carries an in-band delivery icount; the
  consumer is time-driven, not arrival-driven. — satisfies [DET-11], [DET-13],
  [DET-34]; spec §4.4, §4.9.
- [x] **T-DET-12** Enforce the lookahead gate so a node cannot advance past an
  input's possible delivery icount; a node that ran past a delivery icount fails
  loudly. — satisfies [DET-12]; spec §4.4.
- [x] **T-DET-13** Implement the deterministic tie-break for same-icount inputs
  using `(virtual_time, consumer node_id, producer node_id, sequence)`. — satisfies [DET-14], routes
  [INV-3]; spec §4.4.
- [x] **T-DET-14** Implement `gate:layer1-injection`: two-VM run-twice-and-diff
  asserting each delivery's consumer icount is identical under artificially
  skewed producer timing. — satisfies [DET-6], [DET-7], [DET-34]; spec §4.2.2,
  §4.4, §4.11.
- [x] **T-DET-15** Implement the single seeded decision RNG with name-hash
  forking (`seed XOR stable_hash(name)`) using a fixed cross-platform PRNG and a
  fixed stable hash. — satisfies [DET-24], [DET-25], [DET-26]; spec §4.7.
- [x] **T-DET-16** Route every probabilistic decision through a decision stream
  and record it as a `Decision` in the `Schedule`; assert no other randomness
  exists in the engine. — satisfies [DET-24], [DET-27]; spec §4.7.
- [x] **T-DET-17** Implement `gate:harness-lint`: ban host wall-clock, thread
  RNG, default-hasher maps on ordering-significant paths, and nondeterministic
  `select` in the engine. — satisfies [DET-24], [DET-26], routes [INV-9]; spec
  §4.7.
- [x] **T-DET-18** Establish purity of `reduce` as the determinism statement and
  wire `gate:replay-oracle` to enforce [INV-2] continuously (fat ≡ thin;
  materialize ≡ re-reduce). — satisfies [DET-28], [DET-41], [INV-2]; spec §4.8,
  §4.11.
- [x] **T-DET-19** Run the snapshot/restore-completeness spike: the S3 rerun
  verifies QMP `snapshot-save`/`snapshot-load` for diskless and CPU-timer
  windows under plugin time control, and it exercises a marked block pending-I/O
  negative control whose restored suffix diverges from replay. The recorded
  outcome keeps `full_fat_checkpoint_complete=false` and the thin/replay
  realization as the default until a future S3 rerun proves fat snapshots across
  the full surface. — satisfies [DET-32], [DET-18] (E20); spec §4.9.
- [x] **T-DET-20** Implement `gate:divergence-bisect`: on any fingerprint or
  Schedule mismatch, localize to the first differing decision and the first
  differing instruction; never tolerate or retry. — satisfies [DET-30],
  [DET-39], routes [INV-10]; spec §4.8, §4.11.
- [x] **T-DET-21** Enforce guest non-modification: CoW-only guest writes,
  byte-identical genesis backing state across runs, no Crucible content placed
  inside the guest for core operation. — satisfies [DET-15], [DET-16], [INV-5];
  spec §4.5.
- [x] **T-DET-22** Implement the first enforced `gate:any-guest` slice: black-box
  determinism evidence holds on an unmodified generic AOS Linux fixture with
  white-box disabled, no in-guest Crucible content is required, and optional
  white-box behavior is consumed only through a separate host/plugin contract,
  not live any-guest boot fingerprint evidence. — satisfies [DET-15], [DET-17];
  spec §4.5.
  Completed by `checks.crucible.phase2.gates.anyGuest`: the gate boots a generic
  AOS Linux kernel/initramfs fixture under diskless and guest-visible CoW-block
  launch profiles twice with the black-box QEMU trace plugin, compares the
  diskless cadence fingerprint streams byte-for-byte through the host QMP-quit
  window after a generic serial completion marker, structurally validates both
  CoW traces while writing a deterministic marker through `/dev/vda`, verifies
  the copied base image hash is unchanged after overlay-backed runs, rejects any
  required in-guest Crucible agent, and consumes the separate white-box doorbell
  off/on contract proving black-box operation remains functional when that
  optional host/plugin channel is enabled but unused. This completion does not
  claim live any-guest white-box-on QEMU fingerprint equivalence.
- [x] **T-DET-23** Implement `gate:qemu-inert`: prove every patch is inert out of
  sim mode (production QEMU behaviorally identical to upstream) and effective in
  sim mode, with a per-patch micro-test. — satisfies [DET-36], [DET-37], routes
  [INV-7]; spec §4.10.
  - Completed by `checks.crucible.phase2.gates.qemuInert` plus
    `checks.crucible.phase2.gates.patchMicrotests`: the former compares
    unpatched pinned QEMU against patched sim-off QEMU over the real-QEMU corpus,
    and the latter requires each carried patch's focused micro-test.
- [x] **T-DET-24** Pin the QEMU build identity into the reproduction artifact and
  re-gate on any QEMU/patch change; document the version-drift contract. —
  satisfies [DET-35]; spec §4.9.
  - Completed by `checks.crucible.phase2.qemuPatchRegeneration`: the patched QEMU
    package now emits a manifest-derived `qemu_build_id` with the QEMU version,
    source hash, qemu.nix hash, configure flag hash, patch count,
    patch-series hash, tracked-branch bundle/material hashes, and sim capability
    flags. The gate embeds that identity in a reproduction-artifact-shaped fixture
    and verifies both a matching artifact and a changed-build negative control, so
    replay is tied to the exact QEMU build that produced the run.
- [x] **T-DET-25** Stand up the adversarial-host test fixture (randomized
  scheduling/affinity, injected jitter/load, varied core counts, skewed
  producer/consumer timing) shared by all determinism gates. — satisfies
  [DET-38]; spec §4.11.
  - Completed by `checks.crucible.phase1.adversarialHostFixture`: the shared
    `crucible_harness::adversarial` fixture now publishes the canonical
    host-adversary profile matrix, seeded task-order and logical-affinity
    planning that drives worker partitioning, deterministic jitter/load
    injection, varied worker counts, and a role-aware producer/consumer skew
    runner. The check runs the focused harness regression tests and the
    model-side single-VM fingerprint adversarial matrix through the shared
    runner while leaving the later `gate:adversarial-determinism` placeholder
    untouched.
- [x] **T-DET-26** Implement `gate:e2e-determinism`: a representative multi-VM
  fault-injected scenario runs bit-identically under adversarial conditions and
  reproduces from its self-contained artifact. — satisfies [DET-40], [DET-4],
  [G-1]; spec §4.11.
  - Completed by `checks.crucible.phase4.gates.e2eDeterminism`: the harness-level
    mock backend now runs a representative multi-node partition-recovery artifact
    containing `(seed, scenario, schedule, build identity)` across the canonical
    adversarial host profile matrix, compares canonical logs and final
    fingerprints, verifies reproduction from the artifact, and rejects build
    identity, fault-corpus, and schedule-drift regressions. The phase7 CLI-owned
    target is completed by `checks.crucible.phase7.gates.e2eDeterminism` over
    the same shared mock artifact route; the real artifact format, real-host
    reproduction check, and AOS VM/fleet wiring remain later tasks.
- [x] **T-DET-27** Add the `gate:replay-oracle` reproduction-artifact round-trip:
  re-run from `(seed, scenario, schedule, build identity)` and assert
  fingerprint and oracle equality. — satisfies [DET-28], [DET-41], [DET-40];
  spec §4.8, §4.11.
  - Completed by `checks.crucible.phase1.gates.replayOracle`: the replay-oracle
    gate now builds a model-backed reproduction artifact carrying `(seed,
    ScenarioDef, Schedule, build identity)`, replays it through the same
    SimDouble fat-checkpoint/thin-reconstruction path, and requires both the
    deterministic fingerprint and materialized oracle case to match exactly.
    Negative controls reject build-identity drift, schedule drift, and
    internally valid but non-identical oracle-case drift.
- [x] **T-DET-28** Implement the multi-vCPU Contract A driver: run a single
  `N > 1` vCPU node under single-threaded RR-TCG + icount with a recorded
  icount-stamped input list and a per-vCPU execution fingerprint (every vCPU's
  register file + the RR cursor, keyed by node aggregate icount); assert
  bit-identical aggregate-icount trajectory across runs. — satisfies [DET-5],
  [DET-29]; spec §4.2.1, §4.8.
  - Completed by `checks.crucible.phase1.contractAIsolation`: the isolated
    `crucible-sim::contract_a::ContractADriver` now models `N > 1` vCPU runs on
    a single aggregate icount axis, samples every vCPU register file plus the RR
    cursor at each aggregate-icount boundary, folds that material into the run
    fingerprint, and proves replayed aggregate-icount trajectories are
    bit-identical. The later launch rejection, content-hash quantum pinning, and
    IPI/entropy details remain covered by the following tasks.
- [x] **T-DET-29** Pin the RR switch quantum: fix `rr_switch_quantum` (node-icount
  units) and the ascending vCPU rotation, fold `rr_switch_quantum`/`N`/rotation
  into the scenario content hash, and reject MTTCG (`thread=multi`), the adaptive
  `rr_quantum`, and any realtime-based switching in the launch config. —
  satisfies [DET-23], [DET-42]; spec §4.6 (E13, E21), §4.2.1.
  - Completed by `checks.crucible.phase2.qemuMultiVcpuLaunch`, consumed by
    `checks.crucible.phase1.gates.layer0Determinism`: the deterministic QEMU
    launch profile emits `-accel tcg,thread=single`, fixed `-smp N`, fixed
    `rr_switch_quantum` in node-icount units, and records ascending vCPU rotation
    plus `N`/quantum/rotation in scenario hash material. The pre-spawn validator
    rejects MTTCG, missing/duplicate RR quantum declarations, adaptive icount
    mode, realtime icount switching, and QEMU realtime launch flags before spawn.
- [x] **T-DET-30** Verify per-vCPU entropy uniformity and IPI determinism: a
  uniform `-cpu` pin across all vCPUs, per-vCPU TSC/RNG derived from node icount
  (E23), inter-vCPU IPI delivered at a deterministic node-icount via a fixed
  modeled latency at the next RR switch (E22), and deterministic secondary-vCPU
  SIPI/INIT bringup with no runtime hotplug (E24). — satisfies [DET-18] (E22, E23,
  E24), [DET-43]; spec §4.6 (E22, E23, E24), §4.4.
  - Completed by `checks.crucible.phase2.qemuMultiVcpuLaunch` and
    `checks.crucible.phase2.qemuPluginPreemption`, consumed by
    `checks.crucible.phase1.gates.layer0Determinism`: the launch profile hashes
    the uniform `-cpu` model, node-icount TSC source, scenario/run-seed-backed
    per-vCPU RNG source with node-icount-timed delivery, fixed-at-genesis topology,
    no runtime hotplug, and deterministic RR-TCG/icount secondary-vCPU bringup. The
    plugin preemption gate plans inter-vCPU IPI delivery as sender
    icount plus fixed modeled IPI latency, rounded to the next fixed RR switch
    boundary, and emits the resulting interrupt through the commanded-icount
    preemption path rather than a realtime callback.
- [x] **T-DET-31** Implement app-requested randomness served from the single
  seeded decision source: white-box opt-in (16), per-`(node, stream-name)`
  name-hash fork, each draw a recorded `Decision` delivered under the injection
  contract; assert the contract holds byte-identically with zero app-random
  requests and distinguish it from opaque ambient `fw_cfg` entropy. — satisfies
  [DET-44]; spec §4.7.
  - Completed by `checks.crucible.phase1.decisionRecording` and
    `checks.crucible.phase2.qemuPluginAppRandomDoorbell`, consumed by
    `checks.crucible.phase1.gates.layer0Determinism`: `DecisionRecorder` owns
    the single seeded `DecisionRng`, forks streams by the canonical
    `(node, stream-name)` tag, records the raw `RngDraw` plus
    `Decision::AppRandom`, and rejects ambient engine entropy APIs. The optional
    white-box `random_request` doorbell requires white-box opt-in, replies at the
    trap icount through the host-to-guest injection gate, and its zero-request
    path records no decisions and writes no replies, preserving byte identity.
    App-requested randomness is reported separately from ambient `fw_cfg` entropy,
    which remains launch-time guest CSPRNG seeding rather than an app-random
    source.
