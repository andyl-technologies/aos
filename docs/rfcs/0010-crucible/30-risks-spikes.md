# 30 — Risks and validation spikes

This file is the **foundation-first discipline** ([G-5]) made operational. The
whole RFC is a bet that a small set of physical facts about QEMU TCG, `-icount`,
shared memory, and snapshotting are true; if any of the load-bearing ones are
false, the design above it does not work as written. Rather than discover that
after building three layers on a false premise, this file enumerates the
assumptions, turns each into a **spike** — a small, cheap, throwaway experiment
that proves or disproves the assumption with a concrete fingerprint or metric —
and gates the phased plan ([`32-implementation-plan.md`](32-implementation-plan.md))
on the result. A spike is not a feature; it is a measurement that retires a risk.

Requirement IDs in this file use the prefix `RISK` (see
[`00-conventions.md`](00-conventions.md)). Gate names referenced here are defined
in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). Each
spike forward- or back-references the requirement it validates: the determinism
contract ([`04-determinism-contract.md`](04-determinism-contract.md)), the QEMU
integration ([`10-qemu-integration.md`](10-qemu-integration.md)) and patch series
([`11-qemu-patches.md`](11-qemu-patches.md)), the shared-memory ABI
([`13-shmem-abi.md`](13-shmem-abi.md)), the I/O sub-nodes
([`15-io-subnodes.md`](15-io-subnodes.md)), the guest↔host channel
([`16-guest-host-channel.md`](16-guest-host-channel.md)), the scheduler
([`08-scheduling.md`](08-scheduling.md)), and the temporal graph
([`07-temporal-graph.md`](07-temporal-graph.md)).

## 30.1 How a spike is specified and what "Phase 0" means

Every spike in this file is specified with the same five fields, so that a result
is unambiguous and reviewable:

1. **Assumption under test** — the precise physical or behavioral claim the rest
   of the RFC relies on.
2. **What to build/measure** — the minimal experiment, named down to the QEMU
   flags and the artifact compared. A spike is throwaway code; it does not need
   the engine, the scheduler, or the control plane.
3. **Pass/fail criterion** — a *concrete fingerprint or metric*, not a vibe. A
   spike passes only when a named digest matches (or a named number lands inside
   a stated budget) under the stated conditions, including adversarial host
   perturbation where the assumption is about determinism.
4. **What it could invalidate** — the requirements, layers, or features that
   collapse or change shape if the spike fails.
5. **Fallback** — the concrete alternative design taken if the spike fails, so a
   failed spike degrades the system rather than blocking it (with the one
   exception of S1, whose failure is fatal to the project).

- **[RISK-1]** Every spike in this file MUST be specified with all five fields
  (assumption, build/measure, pass/fail criterion as a concrete fingerprint or
  metric, what-it-invalidates, fallback) before it is run, and its result MUST be
  recorded in [`31-decision-register.md`](31-decision-register.md) as
  pass/fail-with-fallback-taken. A spike with no concrete pass/fail criterion is
  not a spike and MUST NOT be used to retire a risk. *Gate:* `gate:harness-lint`.
  *Spec:* §30.1.

- **[RISK-2]** The spikes designated **Phase-0 blockers** ([RISK-3] below) MUST be
  run and MUST pass (or have their fallback adopted and re-validated) **before any
  Phase-1 foundation code is built on the assumption they test**. Foundation-first
  ([G-5]) means the determinism bet is measured before it is built upon, not after.
  *Gate:* `gate:layer0-determinism`, `gate:layer1-injection`. *Spec:* §30.1,
  [`32-implementation-plan.md`](32-implementation-plan.md) Phase 0.

- **[RISK-3]** The Phase-0 blocker set, in priority order, is **S1**
  (single-VM bit-identical determinism), **S2** (guest HLT during blocking I/O),
  **S4** (producer→consumer visibility is icount-not-wallclock), and **S3**
  (snapshot/restore completeness). S1 is the highest priority because its failure
  invalidates the entire RFC; S2 and S4 gate the I/O and injection models that
  Phase 1's transport and scheduler depend on; S3 gates fast-resume and fork but
  has a clean fallback (thin/replay checkpoints), so it is a blocker for the
  *snapshot* path only, not for the determinism foundation. *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer1-injection`, `gate:replay-oracle`.
  *Spec:* §30.1, §30.13 (risk register).

## 30.2 S1 — `-icount` + entropy elimination yields bit-identical single-VM execution

This is the foundational bet. If two runs of one unmodified guest under fixed
`(image, cmdline, seed, I)` are not bit-identical, [DET-1] is false, Contract A
([DET-5]) is false, and *every other file in this RFC* describes a system that
cannot be built. Nothing is constructed on top of the single-VM determinism
foundation until this spike is green. It is the first thing measured.

### Assumption under test

A guest run under QEMU TCG with `-icount shift=N` (fixed integer, never `auto`),
a fixed `-cpu` model without hardware-RNG features, `-smp 1`, fixed machine/reset,
an icount-derived RTC, and seeded firmware/internal entropy, with idle warp and
realtime-clock deadlines suppressed (the §4.6 elimination set E1–E17 applied),
produces a **bit-identical instruction stream `S` and architectural-state
trajectory `T`** across runs, regardless of host CPU model, host load, host core
count, or wall-clock — [DET-1], [DET-8]–[DET-10].

### What to build / measure

Boot one stock guest image (a stripped Linux kernel + minimal root, the same
image AOS already builds for VM tests) twice, with the §10.2 launch configuration
and the §4.6 patch-class mechanisms active, to a fixed icount horizon (e.g. boot
to a fixed instruction count past kernel entry, no injected inputs: `I = []`). At
a fixed periodic icount cadence and at the horizon, capture the **execution
fingerprint** ([DET-29]): the icount, a hash of the architectural registers, and
a hash of full guest physical memory plus emulated-device state, read black-box
from the host (QMP / the plugin's introspection hook). Diff the two fingerprint
sequences. Then repeat under adversarial host conditions ([DET-38]): pin the two
runs to different core counts, inject host scheduling jitter/load, and run on a
second host model if available.

```text
S1 procedure (throwaway; no engine, no scheduler):
  build launch config: -accel sim,thread=single -icount shift=N -smp 1 -cpu <no-rdrand>
                       -machine <fixed> -m <fixed> -rtc base=<epoch>,clock=vm
                       seeded fw_cfg + virtio-rng, seeded internal PRNG,
                       nokaslr norandmaps, plugin loaded + sim active
  run A: boot to icount horizon H; fingerprint at cadence C and at H -> FP_A[]
  run B: identical config, adversarial host (different cores, injected jitter)
         boot to H; fingerprint at C and at H -> FP_B[]
  compare: FP_A == FP_B  (element-by-element)
```

### Pass / fail criterion

**Pass:** `FP_A[i] == FP_B[i]` for every cadence point `i` and at the horizon,
across all adversarial conditions, where each `FP[i]` is the full
`(icount, reg_hash, mem+device_hash)` digest of [DET-29]. The first differing
element, if any, is the bisection target ([DET-30]).

**Fail:** any fingerprint element differs. The harness MUST localize the first
differing icount window and the specific state component (registers vs a memory
region vs a device) so the leaking entropy source is identified.

- **[RISK-4]** Spike **S1** MUST demonstrate that a single unmodified guest, run
  twice under fixed `(image, cmdline, seed, I=[])` with the §4.6 elimination set
  active, produces a **bit-identical execution-fingerprint sequence** ([DET-29])
  across runs and across adversarial host conditions ([DET-38]). S1 MUST pass
  before any Phase-1 foundation code is built. A fingerprint mismatch MUST be
  treated as a leaking entropy source to eliminate ([DET-3], [INV-10]), never a
  tolerance to accept. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §30.2; satisfies [DET-1], [DET-5];
  back-ref §4.1, §4.6.

### What it could invalidate

Everything. [DET-1], Contracts A and B, the execution model ([INV-1]), the
temporal graph, the replay oracle, fork, and search all assume `T` is a pure
function of icount. If S1 fails irrecoverably, the project's premise is wrong.

### Fallback

There is no fallback that preserves the headline contract. The *response to a
failure* is to bisect to the leaking source and eliminate it (extend §4.6) — S1
failing on the first attempt is expected and is *the work of Phase 0*, not a
project-ending result. The project-ending case is a residual source that *cannot*
be eliminated host-side under TCG (a TCG codegen nondeterminism, a device model
that reads host state with no seam to seed). The diagnostic-only use of QEMU's own
record/replay ([NG-6]) is permitted here to *find* such a source: record/replay
diverges precisely where entropy leaks, so it is the bisection instrument, never
the shipped mechanism.

- **[RISK-5]** If S1 cannot be made green by extending the §4.6 elimination set,
  QEMU's record/replay subsystem MAY be used **as a diagnostic only** to localize
  the residual entropy source ([NG-6]); it MUST NOT become the determinism
  mechanism. A residual source that cannot be eliminated host-side under TCG is a
  fatal finding that MUST be recorded and escalated, not papered over with a replay
  log. *Gate:* `gate:layer0-determinism`. *Spec:* §30.2; references [NG-6],
  [DET-3].

## 30.3 S2 — the guest HLTs during a blocking disk/9p read (vs busy-poll)

The I/O-as-scheduled-event model ([IO-2], [IO-3]) is *correct* whether the guest
idles or spins (§15.8, [IO-29]), but the **fast-forward** that makes it fast
depends on the guest issuing `HLT` (or the architectural equivalent) while a
blocking I/O is outstanding, so the scheduler can collapse the wait to a single
jump to the completion icount ([SCHED-28]). This spike measures how often the
target guests actually idle. It is a **performance** spike, not a correctness one.

### Assumption under test

For the guest configurations Crucible targets (a Linux guest issuing synchronous
block and 9p reads through the standard virtio/9p drivers), the requesting vCPU
goes idle (`HLT`, no runnable work) for the duration of the wait, rather than
busy-polling a status register — so the scheduler's idle fast-forward
([SCHED-28]) collapses the wait at zero wall-clock cost. (§15.8, [IO-29],
[IO-30].)

### What to build / measure

Boot the target guest under TCG `-icount` with the plugin loaded. Drive a
sequence of synchronous block reads and 9p reads (e.g. `cat` a large file off the
9p mount; `dd` from the block device with direct, synchronous I/O). Using the
plugin's idle/`HLT` callback and the instruction-execution hook, measure, per
outstanding I/O: (a) whether the vCPU executed `HLT` and parked, and (b) the
number of guest instructions retired between request emission and completion
delivery — the "wait cost." Bucket I/O operations into *idled* (≈0 instructions
retired during the wait beyond the request/interrupt path) vs *busy-polled*
(thousands+ retired in a tight loop on an I/O-status address).

```text
S2 procedure:
  for each synchronous read in a representative workload:
    t0 = icount at request emit
    observe: did vCPU HLT before completion?   (plugin idle hook)
    t1 = icount at completion delivery
    wait_instructions = retired between t0 and t1 (minus the irq path)
  report: fraction idled, distribution of wait_instructions for busy-polled ops
```

### Pass / fail criterion

**Pass:** at least the great majority of synchronous block/9p reads in the
representative workload idle (HLT), so idle fast-forward applies; the *busy-polled
fraction* and its instruction cost are small enough that overall fuzzing/interactive
throughput stays within the [`25-performance-targets.md`](25-performance-targets.md)
budget. The concrete metric is: **fraction-idled ≥ a stated threshold** (target:
the common synchronous-read path idles) **and** the wall-clock spent on
busy-polled waits is within the performance budget.

**Fail:** a large fraction of target-workload I/O busy-polls, so idle
fast-forward rarely fires and waits cost real wall-clock proportional to the spin
— the run stays *correct* but slow.

- **[RISK-6]** Spike **S2** MUST characterize, for the target guest
  configurations, the fraction of synchronous block/9p reads during which the
  requesting vCPU **idles (HLT)** versus **busy-polls**, and the instruction cost
  of busy-polled waits. Crucible's correctness MUST NOT depend on the result
  ([IO-29]); S2 measures only whether idle fast-forward ([SCHED-28]) applies often
  enough to meet the performance budget. *Gate:* `gate:single-vm-fingerprint`,
  `gate:e2e-determinism`. *Spec:* §30.3; satisfies [IO-30]; back-ref §15.8.

### What it could invalidate

Nothing about correctness ([IO-29] holds either way). It could invalidate the
*performance* assumptions of [`25-performance-targets.md`](25-performance-targets.md)
("idle time fast-forwarded to zero wall-clock") for I/O-heavy workloads, and
motivate the busy-poll mitigation.

### Fallback

If busy-polling is common, implement the exactness-preserving busy-poll
fast-forward of [IO-30]: detect a tight poll loop on a known I/O-status address
whose only exit is the pending completion, and collapse the span the guest *would*
have spun through to its deterministically-identical outcome. The mitigation MUST
NOT change which instruction observes the completion ([IO-30]); it only elides a
provably-identical span. A weaker fallback is to prefer guest configurations and
drivers that idle (an interrupt-driven rather than polled virtio config), recorded
as a target-environment recommendation.

- **[RISK-7]** If S2 finds busy-polling common in the target workloads, the
  busy-poll fast-forward mitigation of [IO-30] MUST be implemented as an
  **exactness-preserving** optimization (collapse only a span whose deterministic
  outcome is provably identical to instruction-by-instruction execution; never
  change the completion-observing instruction). Until any such mitigation exists,
  the run MUST remain bit-correct and merely slower. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §30.3; satisfies [IO-29], [IO-30].

## 30.4 S3 — savevm/loadvm preserves complete icount/TCG state

Fork and fast-resume ([`07-temporal-graph.md`](07-temporal-graph.md),
[`22-advanced-features.md`](22-advanced-features.md)) and the replay oracle
([INV-2]) rely on `loadvm` reproducing a state **bit-identical** to a fresh
replay to the same icount. QEMU's `savevm`/`loadvm` were designed for live
migration and user-facing snapshots, not for instruction-level reproduction; this
spike verifies they preserve *everything* that affects `S`/`T` going forward.
([DET-32], [QEMU-20], [QEMU-21], E20.)

### Assumption under test

A QMP `savevm` at icount `K` followed by `loadvm` reproduces a runtime that, when
advanced forward, yields a fingerprint sequence **identical** to a single
uninterrupted run advanced to the same icounts — i.e. `savevm`/`loadvm` preserve
the icount, the icount bias, the full TCG translation/execution state, all
device/timer state, and the plugin's time-control state, completely enough that a
restored *fat* checkpoint hashes equal to its *thin* (replay) derivation
([INV-2]).

### What to build / measure

Take one guest, run to icount `K`, `savevm` (tag = content address), continue to a
later horizon `H`, capturing the fingerprint sequence `FP_cont[K..H]`. Separately,
`loadvm` the snapshot at `K` into a fresh plugin-loaded child and advance to `H`,
capturing `FP_load[K..H]`. Compare. Repeat across several `K` (early boot, post-boot
idle, mid-I/O burst) and verify the §13.6 ring `snapshot`/`restore` ([SHM-21],
[SHM-22]) and the device-overlay/RNG state ([IO-11], [IO-23]) round-trip too, since
the checkpoint is the QMP VM-state half plus the Crucible-owned half ([QEMU-20]).

```text
S3 procedure:
  run U: 0 -> K -> H ; fingerprints FP_cont[K..H]
  run R: 0 -> K ; savevm(tag_K) ; fresh child ; loadvm(tag_K) ; K -> H
         fingerprints FP_load[K..H]
  pass iff FP_cont[i] == FP_load[i] for all i in [K..H], for every chosen K
  also: ring snapshot/restore byte-identical; overlay delta + RNG position exact
```

### Pass / fail criterion

**Pass:** `FP_cont[i] == FP_load[i]` for all `i in [K..H]` at every tested `K`,
including a `K` inside a device-I/O burst, **and** the ring/overlay/RNG
round-trip is byte-identical — i.e. the restored fat checkpoint passes the replay
oracle ([INV-2], [QEMU-22]).

**Fail:** any post-restore fingerprint diverges from the uninterrupted run —
`loadvm` dropped or perturbed icount, bias, TCG, timer, or time-control state.

- **[RISK-8]** Spike **S3** MUST verify that QMP `savevm`/`loadvm` (paired with
  the Crucible-owned ring/overlay/RNG round-trip) reproduces a runtime whose
  forward fingerprint sequence is **bit-identical** to an uninterrupted run to the
  same icounts, at several snapshot points including one inside a device-I/O burst
  — i.e. a restored fat checkpoint passes the replay oracle ([INV-2]). Until S3 is
  green, the host MUST default to the **thin-checkpoint (replay) fallback**
  ([QEMU-21], [QEMU-26]): realize a configuration by replaying from genesis or a
  verified ancestor rather than by `loadvm` of an unverified fat snapshot. *Gate:*
  `gate:replay-oracle`. *Spec:* §30.4; satisfies [DET-32], [QEMU-21]; back-ref
  §4.9, §10.4.

### What it could invalidate

The *fat-checkpoint* path: `loadvm`-based fast-resume and fork-by-snapshot. It
does **not** invalidate the determinism contract or the execution model, because
those are defined over `reduce` (replay), and replay is the always-correct base
case ([QEMU-26]).

### Fallback

The thin-checkpoint fallback ([QEMU-21], [QEMU-26],
[`07-temporal-graph.md`](07-temporal-graph.md)): every checkpoint is stored as
`(parent, schedule_delta)` and realized by replay from a verified ancestor (whose
base case is the baked genesis snapshot). Fast-resume becomes "replay from the
nearest verified ancestor" instead of "load a snapshot." This is slower but always
correct; the savevm path is purely a performance optimization layered on top once
S3 (or a per-state-component subset of it) is green. If S3 fails for a *specific*
state component, an intermediate fallback is to patch QEMU's snapshot path to
serialize that component (recorded as a patch-series item, 11) and re-run S3.

- **[RISK-9]** The temporal graph and `instantiate` MUST be designed so that the
  thin-checkpoint (replay) realization is the **default and always-correct** path
  and the fat-snapshot (`loadvm`) realization is an *optimization gated on S3*;
  the two MUST yield content-equal runtimes ([QEMU-27], [INV-2]), so adopting the
  fallback changes only performance, never `S`/`T`. *Gate:* `gate:replay-oracle`.
  *Spec:* §30.4; satisfies [QEMU-27], references [EXEC-15].

## 30.5 S4 — producer→consumer shmem visibility is icount-not-wallclock

This is the single most important correctness property of the transport
([DET-34], [SHM-33]) and the crux of Contract B ([DET-6]). A frame's *visibility*
to a consumer must be decided by virtual time (`delivery_icount <= current_icount`),
not by when the producer's store landed in shared memory. If a fast host peer
computing a frame "early" and a slow peer computing it "late" deliver it at
*different* consumer icounts, Contract B is false and multi-VM determinism is
impossible.

### Assumption under test

Two VMs sharing the §13 region, with the scheduler assigning each cross-node frame
a `delivery_icount`, deliver every frame at the **identical consumer icount**
across runs, **independent of the wall-clock instant** at which the producer's
release-store published the entry or the consumer happened to poll the ring
([SHM-33], [SHM-34], [DET-13], [DET-34]).

### What to build / measure

Run a fixed two-VM scenario (VM A sends a known sequence of frames to VM B on a
fixed-latency link, B echoes or records each at the icount it became visible)
under a fixed seed and schedule, twice, while **artificially skewing producer
timing** ([DET-38]): inject host sleeps/jitter into A's frame-production path on
one run and into B's poll path on the other, and vary host core counts. For each
delivered frame, record the consumer icount at which it became architecturally
visible (the plugin's frame-injection hook), and the `(delivery_icount, src_node,
seq)` order in which coincident frames were injected ([SHM-34]). Diff the
per-frame consumer-icount vectors and the injection orders across the two runs.

```text
S4 procedure (two VMs, fixed schedule, skewed producer timing):
  run X: A produces frames with injected production jitter; B records
         (frame_id -> consumer_icount_visible, injection_order)
  run Y: identical scenario/seed/schedule; jitter moved to B's poll path;
         different host core count
  pass iff for every frame: consumer_icount_visible_X == consumer_icount_visible_Y
       and the (delivery_icount, src_node, seq) injection order is identical
```

### Pass / fail criterion

**Pass:** every frame's consumer-visibility icount is identical across runs X and
Y despite the skewed producer timing, and coincident frames are injected in the
identical `(delivery_icount, src_node, seq)` total order — the two-VM
run-twice-and-diff of `gate:layer1-injection`.

**Fail:** any frame becomes visible at a different consumer icount in X vs Y, or
the injection order differs — visibility leaked transport (wall-clock) timing.

- **[RISK-10]** Spike **S4** MUST demonstrate that for a fixed two-VM
  `(scenario, seed, schedule)`, every cross-node frame becomes architecturally
  visible at the **identical consumer icount** across runs under **artificially
  skewed producer/consumer timing** ([DET-38]), and that coincident frames are
  delivered in the `(delivery_icount, src_node, seq)` total order ([SHM-34],
  [INV-3]). S4 MUST pass before any multi-VM feature is built ([DET-7]); a node
  found to have advanced past an inbound frame's `delivery_icount` MUST fail loudly
  ([SHM-35], [DET-12]), never deliver late. *Gate:* `gate:layer1-injection`. *Spec:*
  §30.5; satisfies [DET-6], [DET-34], references §13.9, §8.

### What it could invalidate

Contract B ([DET-6]), the entire multi-VM story, the injection contract ([DET-11]),
and the conservative-PDES lookahead discipline (08). If visibility cannot be made
icount-driven, no multi-VM run is reproducible.

### Fallback

The §13.9 design is constructed *precisely* to make S4 pass by construction
(visibility = `delivery_icount <= current_icount`, the producer's store moment is
irrelevant). If S4 fails, the failure is a **bug in the implementation** of that
discipline, not a need for a different design — the fix is to find where transport
timing leaked into a visibility decision (e.g. a consumer delivering in
ring-arrival order rather than icount order, [SHM-34]) and remove it. The only
genuine design fallback, if the SPSC-ring visibility model proved unworkable, is to
route all cross-node frames through the single scheduler as explicit events it
injects at resolved icounts (slower, more central) rather than via the lock-free
rings — but this trades performance, not correctness, and §13 is the optimization
of exactly that model.

- **[RISK-11]** The shared-memory transport MUST be designed so that S4 passes by
  construction: a frame's *presence* on a ring MUST NOT determine its *visibility*
  ([SHM-33]); only `delivery_icount <= consumer.current_icount` does. An S4 failure
  MUST be localized as a transport-timing leak in the visibility decision and
  removed ([INV-10]); the central-scheduler-injection design is a performance
  fallback only, never a correctness necessity. *Gate:* `gate:layer1-injection`.
  *Spec:* §30.5; satisfies [SHM-33], [SHM-34].

## 30.6 S5 — the plugin can read guest VIRTUAL memory at the trap icount

The white-box doorbell ([GHC-10], [GHC-11], [GHC-33]) reads its payload from a
guest address the guest supplies. The convenient form passes a guest *virtual*
address; reading it requires the plugin's guest-memory API to translate through
the guest page tables at the trap instant. This spike verifies that virtual-address
reads are sound and reproducible; if not, the channel falls back to a physical or
pinned identity-mapped page.

### Assumption under test

At the synchronous doorbell trap ([GHC-10]), the in-VM plugin's guest-memory API
can read a guest **virtual** address — translating through the guest's page tables
as they stand at the trap icount — and the bytes read are exactly the bytes the
guest wrote, reproducibly across runs ([GHC-32], [GHC-33]).

### What to build / measure

With white-box mode enabled, have a tiny guest emitter write a known payload to a
buffer at a known virtual address and ring the doorbell with that virtual address
in the register pair ([GHC-11](b)). In the plugin trap handler, read the payload
via the virtual-address path of the guest-memory API and compare the bytes to the
known payload. Repeat with the buffer placed so it (a) is fully resident, (b)
spans a page boundary, and (c) is in a region subject to the guest's normal paging.
Run twice and confirm the read bytes and the marker icount are identical ([GHC-13],
[GHC-30]).

```text
S5 procedure:
  guest: write PAYLOAD at vaddr V; doorbell(ptr=V, len=L)
  plugin trap: bytes = read_guest_virtual(V, L) at trap icount
  pass iff bytes == PAYLOAD for resident / page-spanning / paged buffers,
       and (bytes, marker_icount) identical across two runs
  also confirm: the read is side-effect-free w.r.t. T (GHC-30 fingerprint-equal)
```

### Pass / fail criterion

**Pass:** the virtual-address read returns the exact payload in all three buffer
placements, reproducibly across runs, and the read leaves the determinism
fingerprint unchanged ([GHC-30]).

**Fail:** the virtual read returns wrong/partial bytes, faults, or is not
reproducible (e.g. a not-present page at the trap).

- **[RISK-12]** Spike **S5** MUST determine whether the plugin's guest-memory API
  can read a guest **virtual** address at the doorbell trap icount soundly and
  reproducibly ([GHC-33]), including page-spanning and paged buffers, with the read
  side-effect-free with respect to `T` ([GHC-30], [GHC-32]). Until S5 is green, the
  channel MUST default to the conservative **physical / identity-mapped pinned
  shared page** ([GHC-11](a), [GHC-33]). S5 gates only the white-box channel, which
  is itself opt-in ([GHC-2]); it MUST NOT block the black-box foundation. *Gate:*
  `gate:single-vm-fingerprint`, `gate:abi-conformance`. *Spec:* §30.6; satisfies
  [GHC-33]; back-ref §16.7.

### What it could invalidate

The virtual-address payload form of the doorbell ([GHC-11](b)) only. The white-box
channel itself is opt-in ([GHC-2]) and the physical/pinned-page form is always
available, so no core capability is at risk.

### Fallback

The conservative physical / identity-mapped pinned shared page ([GHC-11](a),
[GHC-33]): the host and guest agree on a fixed shared page at setup, the guest
writes the payload there, and the plugin reads a known physical address — no page
walk, always resident, trivially reproducible. The emitter's API hides which form
is in use, so the fallback is invisible to a guest author.

## 30.7 S6 — deterministic boot WITH KASLR/ASLR enabled, given full entropy seeding

The conservative default disables kernel and userspace randomization (`nokaslr`,
`norandmaps`, E11/E12, [QEMU-13]). This spike asks whether they are *required* or
merely conservative: if all boot entropy (E8) is seeded deterministically, the
randomization draws from a deterministic pool and may already be bit-stable —
which would broaden "any unmodified guest" fidelity ([G-2]) by letting Crucible run
images exactly as they run in production. ([DET-33], [QEMU-13].)

### Assumption under test

With boot entropy fully seeded as a pure function of the scenario seed (E8,
[DET-22]) and QEMU-internal entropy seeded (E9, [DET-21]), a guest booted **with
KASLR and userspace ASLR enabled** produces a bit-identical `T` across runs — the
randomized kernel/mmap/stack bases are drawn from the deterministic pool and are
therefore reproducible.

### What to build / measure

Run S1's single-VM fingerprint procedure twice, once with `nokaslr norandmaps` on
the cmdline (the control, known green from S1) and once with them **removed** and
the boot-entropy seeding (E8/E9) confirmed active. Compare the with-randomization
run against itself across two runs (and adversarial host conditions). Inspect the
chosen kernel base / mmap bases (via the fingerprint's register/memory hash or a
targeted read of a known symbol's resolved address) to confirm they are identical
across runs.

```text
S6 procedure:
  control: nokaslr norandmaps -> FP_ctrl_A == FP_ctrl_B   (S1, already green)
  test:    randomization ENABLED, E8/E9 seeding active
           FP_kaslr_A vs FP_kaslr_B  (two runs, adversarial host)
  pass iff FP_kaslr_A == FP_kaslr_B  (and kernel/mmap bases identical across runs)
```

### Pass / fail criterion

**Pass:** the randomization-enabled run is fingerprint-identical across two runs
under adversarial host conditions, and the kernel/mmap/stack bases are confirmed
identical across runs — randomization is deterministic given seeding.

**Fail:** the randomization-enabled runs diverge — some randomization draw escapes
the seeded pool (or is seeded from a source E8/E9 do not cover).

- **[RISK-13]** Spike **S6** determined that a guest with KASLR/ASLR **enabled**
  boots bit-identically across runs given fully-seeded boot entropy (E8/E9,
  [DET-22], [DET-21]) — i.e. `nokaslr`/`norandmaps` are **not required**, only
  formerly conservative ([DET-33]). Per **D-31**, the shipped default is now a
  **stock guest cmdline** with randomization enabled and determinism sealed
  host-side; Crucible neither adds nor requires the suppression flags. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §30.7; satisfies [DET-33]; back-ref
  §4.9 (E11, E12), §10.2.

### What it could invalidate

Nothing load-bearing — the conservative defaults are always available. S6 is an
*opportunity* spike: passing it improves fidelity; failing it costs nothing beyond
keeping the defaults.

### Fallback

None needed: S6 passed, so per **D-31** the shipped default is a **stock guest
cmdline** with randomization enabled and determinism sealed host-side. (Had S6
failed, the fallback would have been to keep `nokaslr norandmaps` — a minor
fidelity reduction that does not affect determinism. That fallback was not
adopted.)

## 30.8 S7 — exact next-deadline plugin capability works and is exact

The scheduler's fast-forward ([SCHED-28]) and exact-local-event horizon
([SCHED-9], [SCHED-10], [IO-3]) depend on the plugin being able to report a node's
**exact** next virtual-clock deadline when it idles (the next armed
`QEMU_CLOCK_VIRTUAL` timer, [TIME-24], published as `idle_wake_icount`, [SHM-9])
and to advance the guest to *exactly* a target icount, not overshoot it. This spike
verifies both the reporting and the stopping are exact.

### Assumption under test

When a guest idles, the plugin can read the **exact** next armed virtual-clock
timer deadline and convert it to an exact `idle_wake_icount`; and when the
scheduler raises the ceiling, the plugin can run the guest to **exactly**
`max_advance_icount` and stop there — not one translation block past it ([TIME-27],
[SHM-25]).

### What to build / measure

Boot a guest to an idle point with a known next timer (e.g. the kernel tick).
Read the plugin-reported `idle_wake_icount` and compare it to the actual icount at
which the timer fires when the guest is allowed to run. Then set a ceiling at a
chosen icount `C` and confirm the guest stops with `current_icount == C` exactly
(not `C + k` for the remainder of a translation block). Repeat across several
ceilings, including ceilings that fall *inside* a translation block, to confirm the
plugin can stop mid-block or that the TB is split at the boundary.

```text
S7 procedure:
  idle the guest with a known next virtual timer at icount D_true
  measure: idle_wake_icount reported by plugin == D_true ?
  set ceiling C (incl. C inside a TB); release; let guest run
  measure: current_icount at stop == C exactly ?  (no overshoot)
  pass iff reported deadline == actual AND stop icount == ceiling, for all C
```

### Pass / fail criterion

**Pass:** the plugin-reported `idle_wake_icount` equals the actual timer-fire
icount, and the guest stops at exactly the ceiling for every tested `C`, including
mid-TB ceilings (zero overshoot).

**Fail:** the reported deadline is approximate, or the guest overshoots the
ceiling by a TB remainder — either breaks the exact-local-event horizon and the
no-advance-past-delivery guarantee ([DET-12], [SHM-25]).

- **[RISK-14]** Spike **S7** MUST verify that the plugin reports a node's
  **exact** next virtual-clock deadline at idle ([TIME-24], `idle_wake_icount`,
  [SHM-9]) and advances the guest to **exactly** `max_advance_icount` with **zero
  overshoot** ([TIME-27], [SHM-25]), including ceilings interior to a translation
  block. An overshoot or an approximate deadline MUST be resolved (e.g. via
  `-icount` precise mode and TB-splitting at the ceiling) before the scheduler's
  fast-forward and lookahead gating are relied upon. *Gate:* `gate:layer1-injection`,
  `gate:scheduler-liveness`. *Spec:* §30.8; satisfies [DET-12]; back-ref §8, §9.

### What it could invalidate

The exactness of [DET-11]–[DET-12] (delivery at exactly the delivery icount), the
fast-forward ([SCHED-28]), and the conservative lookahead gate ([SHM-25]). An
overshoot means a node could run *past* a delivery icount, which the design
requires to be impossible.

### Fallback

`-icount` precise mode already stops at instruction boundaries; if whole-TB
overshoot is observed, the fallback is the patch-series mechanism that splits the
translation block at the ceiling so execution stops exactly (recorded as an 11
patch item). If the *deadline report* is approximate, the fallback is for the
plugin to set the ceiling conservatively below the approximate deadline and
re-evaluate at the next idle — slower (more quanta) but still exact, since the
guest never advances past an unauthorized icount.

## 30.9 S8 — TCG-exec coverage extraction is cheap enough for fuzzing throughput

Coverage-guided fuzzing ([G-6], [`22-advanced-features.md`](22-advanced-features.md))
harvests basic-block coverage from the plugin's TCG-execution hook ([GHC-7] item 7)
with no guest instrumentation. This spike verifies the hook is cheap enough that
collecting coverage every run does not crater fuzzing throughput.

### Assumption under test

Harvesting basic-block coverage via the plugin's TCG-execution callback adds
**acceptable overhead** to a run — small enough that coverage-guided fuzzing meets
the throughput target in [`25-performance-targets.md`](25-performance-targets.md)
([G-9]).

### What to build / measure

Run a representative short scenario (a boot-and-workload of a few hundred million
instructions) in three configurations: (a) no plugin, (b) plugin loaded with the
TCG-exec hook **registered but coverage collection disabled**, and (c) plugin with
coverage collection **enabled** (recording the set of executed translation
blocks). Measure wall-clock per run and instructions-per-second for each. Compute
the coverage overhead as `(c) / (a)` and the hook-registration overhead as
`(b) / (a)`.

```text
S8 procedure:
  run the same scenario three ways; report instructions/sec:
    (a) no plugin                    -> baseline ips_a
    (b) plugin, hook registered, off -> ips_b
    (c) plugin, coverage on          -> ips_c
  overhead_coverage = ips_a / ips_c ; overhead_hook = ips_a / ips_b
  pass iff overhead_coverage within the perf budget for fuzzing throughput (25)
```

### Pass / fail criterion

**Pass:** coverage-enabled instructions-per-second stay within the
[`25-performance-targets.md`](25-performance-targets.md) fuzzing-throughput budget
(a stated maximum slowdown factor relative to the no-plugin baseline).

**Fail:** coverage collection slows execution beyond the budget, so fuzzing
throughput is inadequate.

- **[RISK-15]** Spike **S8** MUST measure the per-run overhead of basic-block
  coverage extraction via the plugin's TCG-execution hook ([GHC-7] item 7) and
  confirm coverage-enabled throughput stays within the fuzzing-throughput budget of
  [`25-performance-targets.md`](25-performance-targets.md) ([G-9]). If overhead
  exceeds budget, a cheaper coverage representation MUST be adopted (edge-set
  bitmap, sampled or once-per-block-first-execution recording) before
  coverage-guided fuzzing ([`22-advanced-features.md`](22-advanced-features.md)) is
  relied upon. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §30.9; back-ref §22,
  §25.

### What it could invalidate

The fuzzing-throughput target ([G-9]) and the practicality of always-on coverage.
It does not affect determinism — coverage is observational.

### Fallback

Cheaper coverage: record only the *first* execution of each translation block
(once-per-block, then disable the hook for that block), or use an edge-bitmap
keyed by `(prev_tb, cur_tb)` updated with a single store, or sample coverage on a
subset of fuzzing runs. Each preserves the feedback signal at lower cost; the
choice is a performance tuning recorded in 22/25.

## 30.10 S9 — determinism survives the AOS QEMU build and version bumps

Determinism is only stable for a *fixed* QEMU build: TCG codegen, device models,
and the patch series all affect `T` ([DET-35]). This spike verifies that the
patched QEMU AOS ships reproduces the determinism contract, that the patches are
inert when sim mode is off ([INV-7]), and that the build identity travels with the
reproduction artifact so a version bump is a controlled, re-gated event.

### Assumption under test

The AOS-built, patched QEMU ([G-7], [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md))
(a) reproduces S1's bit-identical single-VM fingerprint, (b) is behaviorally
identical to upstream when sim mode is off ([INV-7], [DET-36]), and (c) produces a
build identity that, recorded in the reproduction artifact, lets a run reproduce
*only* against the build that produced it — so a QEMU/patch change is detectable
and re-gated, never a silent determinism drift ([DET-35]).

### What to build / measure

Build the patched QEMU hermetically in AOS. (a) Re-run S1 against the AOS build and
confirm the fingerprint matches the S1 baseline build. (b) For each patch in the
series, run its inertness micro-test ([DET-37]): the same source built without sim
mode active behaves identically to upstream on a representative non-sim workload
(`gate:qemu-inert`). (c) Capture the build identity (a content hash of the QEMU
derivation + patch series) into the reproduction artifact; then rebuild with a
deliberate trivial QEMU change and confirm the artifact's recorded build identity
no longer matches, so the run is flagged as needing re-gating rather than silently
producing a different `T`.

```text
S9 procedure:
  (a) S1 on AOS-built patched QEMU -> fingerprint == S1 baseline
  (b) per patch: sim-off behavior == upstream on a non-sim workload (qemu-inert)
  (c) artifact records build_id = hash(qemu drv + patches);
      rebuild with a trivial change -> build_id changes -> run flagged "re-gate"
```

### Pass / fail criterion

**Pass:** (a) the AOS build reproduces the S1 fingerprint; (b) every patch is
inert sim-off (production QEMU behaviorally identical to upstream); (c) the build
identity is in the artifact and a build change is detected as a re-gate, not a
silent drift.

**Fail:** the AOS build diverges from the baseline, a patch changes non-sim
behavior, or a build change is not reflected in the artifact's build identity.

- **[RISK-16]** Spike **S9** MUST confirm the AOS-built patched QEMU reproduces
  the single-VM fingerprint ([DET-1]), that every patch is **inert when sim mode is
  off** ([INV-7], [DET-36], [DET-37], `gate:qemu-inert`), and that the QEMU **build
  identity** is recorded in the reproduction artifact so a run reproduces only
  against its producing build and a build/patch change is a re-gated, never silent,
  event ([DET-35]). A QEMU or patch change MUST re-run S1 and S9 before it ships.
  *Gate:* `gate:qemu-inert`, `gate:e2e-determinism`. *Spec:* §30.10; satisfies
  [DET-35], [INV-7]; back-ref §4.9, §11, §26.

### What it could invalidate

Cross-build reproducibility and the inertness guarantee ([INV-7], [G-7]). A failure
means runs do not reproduce across AOS QEMU rebuilds, or the production QEMU is
perturbed by the patches.

### Fallback

Pin the QEMU build hard: the reproduction artifact already records the build
identity ([DET-35]), so the minimal fallback is to *refuse* to reproduce a run
against a non-matching build (a loud mismatch, not a best-effort run). If a patch
is found to perturb non-sim behavior, the patch MUST be reworked to gate strictly
on sim activation ([DET-36]) before it ships; until then sim mode for that
mechanism is disabled and the corresponding §4.6 source is handled by a launch
flag rather than the patch.

## 30.11 S10 — multi-arch doorbell works on aarch64

The doorbell is defined per architecture ([GHC-15] x86_64 port I/O, [GHC-16]
aarch64 reserved-immediate `HLT`/`BRK`/`hvc`). The x86 form is the well-trodden
path; this spike verifies the aarch64 form traps synchronously and carries its
payload, so multi-arch support is real from day one rather than aspirational.

### Assumption under test

On aarch64, the chosen reserved-immediate trap instruction ([GHC-16]) is
intercepted by the plugin **synchronously at the exact retirement icount**, the
payload pointer/length in the fixed register pair ([GHC-11](b)) is readable at the
trap, and the doorbell is **inert** when white-box mode is disabled ([GHC-17],
[GHC-34]) — identical channel semantics to x86_64 above the instruction.

### What to build / measure

Build the `crucible-guest` emitter for aarch64 ([GHC-29]) and run an aarch64 guest
under TCG `-icount` with the plugin loaded. Have the emitter ring the aarch64
doorbell with a known payload; confirm the plugin traps it synchronously, reads the
payload at the trap icount, and produces the §16.5 frame with the correct marker
icount ([GHC-13]). Run twice to confirm the marker icount is reproducible. Then
disable white-box mode and confirm the same instruction is inert (delivered to the
guest as a normal exception, not intercepted, [GHC-17]).

```text
S10 procedure (aarch64):
  white-box ON:  emitter rings doorbell(payload P) ->
                 plugin traps synchronously; reads P at trap icount;
                 emits §16.5 frame; marker_icount reproducible across 2 runs
  white-box OFF: same instruction is inert (normal guest exception, not trapped)
  pass iff payload read == P, marker icount reproducible, and inert when disabled
```

### Pass / fail criterion

**Pass:** the aarch64 doorbell traps synchronously, the payload reads correctly at
the trap icount, the marker icount is reproducible across runs, and the doorbell is
inert when disabled.

**Fail:** the trap is asynchronous/imprecise, the payload is unreadable at the
trap, the marker icount is not reproducible, or the instruction is not inert when
disabled.

- **[RISK-17]** Spike **S10** MUST verify the aarch64 doorbell ([GHC-16]) traps
  **synchronously at the exact retirement icount**, carries its payload via the
  fixed register pair ([GHC-11](b)), produces a reproducible marker icount
  ([GHC-13]), and is **inert when white-box mode is disabled** ([GHC-17], [GHC-34])
  — matching the x86_64 channel semantics above the instruction. S10 gates aarch64
  white-box support only; aarch64 black-box determinism is covered by S1 run on an
  aarch64 image. *Gate:* `gate:abi-conformance`, `gate:single-vm-fingerprint`.
  *Spec:* §30.11; satisfies [GHC-16]; back-ref §16.4.

### What it could invalidate

aarch64 *white-box* support only. aarch64 black-box determinism is an S1 concern
(S1 SHOULD be run on at least one aarch64 image to confirm the contract is not
x86-specific).

### Fallback

If the chosen reserved-immediate instruction does not trap precisely, select a
different aarch64 trappable instruction (the candidate set in [GHC-16]: a different
`BRK`/`HLT` immediate, or an `hvc` with a reserved immediate). If no aarch64
instruction traps synchronously with a readable payload, aarch64 ships **black-box
only** (full determinism, faults, coverage, observable-I/O properties via S1) with
white-box deferred — a fidelity reduction confined to one optional channel on one
architecture.

## 30.11a S11 — deterministic multi-vCPU under single-threaded RR-TCG + icount

This is the Phase-0 blocker that gates the multi-vCPU goal ([G-10]). The bet is
that the single-threaded TCG-derived sim accelerator (`-accel sim,thread=single`), where the
vCPU-switch boundary is itself an icount-commandable quantum, makes an SMP guest
as deterministic as a single-vCPU one — the same source-elimination contract,
extended over N vCPUs and the round-robin cursor. If it does not, the multi-vCPU
restatement of Contract A is false and [G-10]/[G-11] cannot be built.

### Assumption under test

An SMP guest under `-accel sim,thread=single`, `-smp N`, `-icount shift=K`, a
fixed content-addressed `rr_switch_quantum` in node-icount, the S11-relevant
§4.6 launch eliminations (`-cpu` pin, fixed RTC epoch, deterministic seed,
`nokaslr`/`norandmaps`, no interactive input), and plugin-visible fingerprint
capture, produces a **bit-identical aggregate-icount instruction stream AND
extended fingerprint** — the existing [DET-29] RAM fingerprint extended to cover
all N vCPUs' register files plus the round-robin cursor — across a clean run and
a host-jitter run. Because round-robin TCG pins every vCPU onto a single host
thread, host CPU load is irrelevant to the interleaving *by construction*; the
switch boundary is decided by virtual time, not by host scheduling. S11 retires
the RR-TCG interleaving risk (E13/E21); unrelated entropy sources such as
QEMU-internal RNG seeding, plugin time control, block-device completion timing,
and full device-model state hashing remain owned by their later §4.6 patch/gate
work.

### What to build / measure

Boot a stock Linux `-smp 4` guest twice to a fixed icount horizon under the
launch configuration above, capturing the **extended fingerprint** (all N vCPUs'
register hashes + the RR cursor + the [DET-29] RAM hash) at a fixed
icount cadence and at the horizon. The Phase-0 proof MAY use a diskless
initramfs and MUST then assert `block_devices=0`, so S11 isolates the RR-TCG
multi-vCPU interleaving from unrelated asynchronous block-device completion
paths. Drive an SMP-contended microworkload (shared counter / spinlock ping-pong
across vCPUs). Diff the two extended-fingerprint sequences. Then repeat with
injected host scheduling jitter/load ([DET-38]) — which, because RR pins all
vCPUs to one host thread, should be irrelevant by construction.

```text
S11 procedure (throwaway; no engine, no scheduler):
  launch: -accel sim,thread=single -smp 4 -icount shift=K
          rr_switch_quantum=Q (fixed, content-addressed), S11 launch eliminations,
          plugin-visible all-vCPU fingerprint capture active
  run A: boot diskless to horizon H; extended fingerprint at cadence C and at H -> EFP_A[]
         (extended FP = per-vCPU reg hashes + RR cursor + RAM hash; block_devices=0)
  run B: identical config, adversarial host jitter/load
         boot to H; extended fingerprint -> EFP_B[]
  compare: EFP_A == EFP_B  (element-by-element, all vCPUs + RR cursor)
```

### Pass / fail criterion

**Pass:** `EFP_A[i] == EFP_B[i]` for every cadence point `i` and at the horizon
across the clean and host-jitter runs, where each extended fingerprint covers all
N vCPUs' register files, the RR cursor, and the [DET-29] RAM hash; the Phase-0
diskless proof additionally asserts from the launch argv that no block-device
state is present.

**Fail:** any extended-fingerprint element differs. The harness MUST localize the
first differing node-icount **and the component** — which vCPU's registers, or the
RR cursor — so the leaking source is identified.

- **[RISK-25]** Spike **S11** (Phase-0 blocker ★ for [G-10]) MUST demonstrate
  that an SMP guest under `-accel sim,thread=single`, `-smp N`, `-icount`, a fixed
  content-addressed `rr_switch_quantum`, diskless launch, the S11-relevant §4.6
  launch eliminations, and plugin-visible all-vCPU fingerprint capture produces a
  **bit-identical aggregate-icount stream and extended fingerprint** (all N vCPUs'
  register files + the RR cursor) across clean and host-jitter runs ([DET-38]).
  S11 MUST pass before any multi-vCPU foundation code is built; a mismatch MUST
  be localized to the first differing node-icount and component (which vCPU /
  the RR cursor) and treated as a leaking source to eliminate, never a tolerance
  to accept. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §30.11a; satisfies [G-10], [DET-23],
  [SCHED-45], [PLUG-3]; back-ref §4.6, §8.

### What it could invalidate

[G-10], the multi-vCPU restatement of Contract A, and `Decision::Preemption`
interleaving exploration ([G-11]). If a specific path leaks irrecoverably, the
multi-vCPU story collapses.

### Fallback

If a specific path leaks, patch it (pin the RR quantum / make IPI delivery
deterministic) and re-run. If the leak is irrecoverable, revert to `-smp 1`
([NG-1] behavior): the rest of the RFC was designed single-vCPU, so [G-10] and
[G-11] withdraw cleanly without disturbing the single-vCPU foundation.

## 30.11b S12 — `Decision::Preemption` is reproducible and discriminating

The vCPU-switch / interrupt-timing choice is a first-class `Decision::Preemption`
([G-11], D-24): forced at a commanded node-icount, it must yield a
*different-but-bit-reproducible* trajectory, so the explorer can branch on
interleavings. The single-vCPU case (`N=1`) still matters: varying the timer
interrupt's delivery icount explores intra-thread races even without a second
vCPU.

### Assumption under test

Forcing a preemption — a vCPU switch (for `N>1`), or a timer interrupt delivered
at a commanded node-icount in `[deadline, horizon]` — yields a trajectory that is
**different** from the default but **bit-reproducible** across runs of that same
choice. For `N=1`, varying the timer-interrupt delivery icount produces
**distinct** reproducible trajectories (intra-thread race exploration).

### What to build / measure

Take a scenario with a known intra-VM race (two paths whose outcome depends on
when a preemption lands). For each of several commanded preemption icounts in
`[deadline, horizon]`, run the configuration **twice** and capture the horizon
fingerprint. Compare each choice against its own second run (reproducibility) and
across choices (discrimination). Confirm the known race manifests under one
choice and is absent under another.

```text
S12 procedure:
  for each commanded preemption icount p in [deadline, horizon]:
    run twice with the same p -> FP_p_A, FP_p_B
    reproducible(p) := (FP_p_A == FP_p_B)
  discriminating := exists p1,p2 : FP_p1 != FP_p2
  race-sensitive := race manifests under some p, absent under another
  pass iff every p reproducible AND discriminating AND race-sensitive
```

### Pass / fail criterion

**Pass:** each commanded choice is reproducible across its own two runs, **and**
at least two choices yield different horizon fingerprints, **and** a known race
manifests under one choice and is absent under another.

**Fail:** a choice is not reproducible, no two choices differ (preemption has no
effect), or no choice surfaces the known race.

- **[RISK-26]** Spike **S12** MUST either demonstrate that a forced
  `Decision::Preemption` (vCPU switch for `N>1`, or timer-interrupt timing for any
  `N`) at a commanded node-icount in `[deadline, horizon]` yields a
  **different-but-bit-reproducible** trajectory, that at least two choices produce
  different horizon fingerprints, and that a known race manifests under one choice
  and not another, or it MUST adopt the default-deterministic-interleaving fallback
  and keep `Decision::Preemption` exploration disabled until the commanded
  preemption-injection surface is paired with a non-fallback S12 race-yield
  proof. For `N=1`, a successful S12 MUST produce distinct reproducible
  trajectories by varying the timer-interrupt delivery icount. *Gate:* `gate:layer1-injection`,
  `gate:single-vm-fingerprint`. *Spec:* §30.11b. A successful non-fallback S12
  satisfies [G-11], [SCHED-46], and [DET-12]; the fallback branch satisfies only
  this risk-resolution requirement and keeps those capabilities disabled.
  Back-ref §8, §22.

### What it could invalidate

The `Decision::Preemption` exploration dimension ([G-11], D-24): if preemption is
not reproducible it cannot be a Decision; if it is not discriminating it explores
nothing.

### Fallback

If vCPU-switch injection is unreliable but interrupt-timing is reproducible and
discriminating, ship **interrupt-timing exploration only** — which still covers
the single-vCPU intra-thread race dimension. If neither is reliable, withdraw
`Decision::Preemption` and keep the default deterministic interleaving only.

## 30.11c S13 — `rr_switch_quantum` granularity vs throughput

The round-robin switch quantum is correctness-neutral — *any* fixed quantum is
deterministic ([RISK-25]) — but it trades race-surfacing power against throughput,
so its default value is a tuning question (open decision D-25), not a determinism
question. This spike measures the trade and resolves D-25.

### Assumption under test

There exists an `rr_switch_quantum` value (in node-icount) small enough to surface
realistic intra-VM races yet large enough not to crater multi-vCPU throughput
below the [`25-performance-targets.md`](25-performance-targets.md) budget. The
choice is **correctness-neutral**: every fixed quantum is deterministic, so this
is a perf/sensitivity sweep, not a determinism gate.

### What to build / measure

Sweep `rr_switch_quantum` across a range. For each value, on a race-bearing
SMP microworkload, measure (a) instructions-per-second (throughput) and (b)
whether/how often the known race is surfaced by the `Decision::Preemption`
explorer (S12). Plot race-surfacing yield against throughput cost and pick the
knee.

```text
S13 procedure:
  for each candidate quantum Q in sweep:
    throughput(Q)   = ips on SMP race microworkload
    race_yield(Q)   = fraction of known races surfaced by S12 explorer at Q
  pass iff exists Q : race_yield(Q) adequate AND throughput(Q) within 25 budget
  resolved default := the knee Q (records D-25)
```

### Pass / fail criterion

**Pass (perf):** a quantum exists whose race-surfacing yield is adequate while
multi-vCPU throughput stays within the [`25-performance-targets.md`](25-performance-targets.md)
budget; that value is recorded as the resolved default for D-25.

**Fail:** no quantum simultaneously surfaces realistic races and meets the
throughput budget — the explorer must override per-branch (see fallback).

- **[RISK-27]** Spike **S13** MUST sweep `rr_switch_quantum` and report, per value,
  multi-vCPU throughput against the [`25-performance-targets.md`](25-performance-targets.md)
  budget and race-surfacing yield via the S12 explorer, then record the resolved
  default value (closing open decision **D-25**), or it MUST adopt the
  modeled-throughput default-only fallback and leave D-25 open until S12 passes
  without fallback and the full race-yield sweep can run. The result is
  **correctness-neutral** — any fixed quantum is deterministic per [RISK-25] — so
  S13 gates only the default value, never the contract. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §30.11c. A successful non-fallback S13
  resolves [D-25] and satisfies [SCHED-45] and [PLUG-3]; the fallback branch
  satisfies only this risk-resolution requirement and leaves D-25 open. Back-ref
  §22, §25.

### What it could invalidate

The chosen *default* quantum only (open decision D-25), and the practicality of a
single global quantum. It does not affect determinism — any fixed quantum is
deterministic.

### Fallback

A coarser default quantum (favoring throughput), with the explorer **overriding
the quantum per-branch** for targeted race-hunting — fine-grained where a race is
suspected, coarse elsewhere. Each fixed per-branch quantum remains deterministic.

## 30.11d S14 — gdbstub attach/step does not disturb icount or plugin time control

Time-travel and gdb debugging (D-30, file 36) attach QEMU's gdbstub to a running
node. The bet is that *read-only* gdbstub use leaves icount and the plugin's time
control untouched, and that any gdbstub-initiated stepping is routed through (or
refused in favor of) the scheduler's deterministic step machinery — so debugging
cannot silently perturb the determinism contract.

### Assumption under test

A read-only gdbstub attach (register/memory reads, breakpoint set without
continue) leaves the node's icount and the plugin's time-control state **exactly**
as they were — fingerprint-unchanged — and any gdbstub-initiated single-step is
either routed through the scheduler's deterministic `step` or refused, never
executed as a raw QEMU step that advances icount outside the scheduler's control.

### What to build / measure

Attach the gdbstub to a node at a known icount. (a) Perform read-only operations
(read registers, read memory, set/clear a breakpoint without continuing) and
confirm the [DET-29] fingerprint and the reported icount are unchanged. (b)
Attempt a gdb single-step and confirm it is either serviced by the scheduler's
deterministic step machinery (icount advances exactly as a scheduler step would)
or refused — never a raw QEMU step that advances icount out of band.

```text
S14 procedure:
  attach gdbstub at icount X
  (a) read-only ops (regs, mem, breakpoint set/clear, no continue)
      pass iff fingerprint unchanged AND reported icount == X
  (b) gdb single-step attempt
      pass iff routed through scheduler step (icount advances == scheduler step)
           OR refused (icount still X); NEVER a raw out-of-band advance
```

### Pass / fail criterion

**Pass:** read-only gdbstub use is fingerprint- and icount-neutral, and any
gdbstub step is routed through the deterministic scheduler step or refused.

**Fail:** a read-only operation perturbs icount/fingerprint, or a gdb step
advances icount outside the scheduler's control (a raw QEMU step).

- **[RISK-28]** Spike **S14** MUST verify that read-only gdbstub use (register /
  memory reads, breakpoint set without continue) leaves a node's icount and the
  plugin's time-control state **fingerprint-unchanged** ([DET-29]), and that any
  gdbstub-initiated stepping is routed through (or refused in favor of) the
  scheduler's deterministic step machinery — never a raw QEMU step that advances
  icount out of band, or it MUST adopt the read-only attach +
  Crucible-driven-step fallback until the debug surface lands and S14 can run.
  Until S14 is green, debugging MUST default to **read-only attach +
  Crucible-driven step/reverse-step**, with gdb single-step **disabled**. *Gate:*
  `gate:single-vm-fingerprint`, `gate:replay-oracle`. *Spec:* §30.11d. A
  successful non-fallback S14 satisfies [DBG-1] and [SCHED-46]; the fallback
  branch satisfies only this risk-resolution requirement and keeps live debugging
  constrained. Back-ref file 36.

### What it could invalidate

Safe interactive gdb debugging on a live node (file 36, [DBG-*]). It does not
affect the determinism contract, which is defined over the scheduler's `step`, not
over gdbstub operations.

### Fallback

Default to **read-only gdbstub attach** plus **Crucible-driven step / reverse-step**
through the deterministic scheduler, with gdb single-step disabled — the debugger
observes but never advances time itself. This is the conservative posture until
S14 confirms gdbstub stepping can be safely routed.

> **App-controlled randomness (file 16) reuses the existing S5 guest-memory-read
> spike.** The `Decision::AppRandom` reply write-back (D-26) is simply a *second
> client* of the same plugin guest-memory path S5 validates (the doorbell reads a
> request, the reply writes a value back); it introduces **no new physical
> assumption and therefore no new spike** — S5's virtual-read soundness and the
> existing injection contract cover it.

## 30.12 Secondary spikes and standing risks

Beyond the ten headline spikes, the following are smaller validations or standing
risks tracked here and in the register (§30.13). They are not Phase-0 blockers but
each is gated before the dependent feature.

- **[RISK-18]** The **shmem ABI single-source-of-truth** mechanism (the generated
  C header from the Rust `#[repr(C)]` definitions, the bilateral static assertions,
  and the golden-vector round-trip, [SHM-3]–[SHM-5], [SHM-31]) MUST be validated by
  a spike that deliberately drifts a field offset on one side and confirms the
  build fails on at least one side and the golden vector mismatches — proving ABI
  drift cannot pass silently. *Gate:* `gate:abi-conformance`. *Spec:* §30.12;
  satisfies [SHM-31]; back-ref §13.2, §13.8.

- **[RISK-19]** The **cross-process non-private futex** wake/wait idiom ([SHM-26],
  [SHM-27]) MUST be validated by a spike that exercises the publish-precondition /
  read-counter / re-check / wait race under host scheduling jitter and confirms
  **no lost wake** and **no spurious advance** across millions of park/wake
  cycles, before the scheduler hot path relies on it. *Gate:*
  `gate:layer1-injection`. *Spec:* §30.12; satisfies [SHM-26]; back-ref §13.7.

- **[RISK-20]** The **no-leak process lifecycle** ([QEMU-29], [QEMU-31]) MUST be
  validated by a spike that induces every termination path (clean stop,
  control-plane stop, guest crash, plugin hang, setup failure, host SIGKILL, host
  panic-without-unwind) and asserts the surviving-QEMU-child count returns to
  zero — confirming `kill_on_drop` plus `PR_SET_PDEATHSIG=SIGKILL` plus the
  unconditional reap leave no orphan that could spin and distort determinism
  measurements. *Gate:* `gate:control-responsive`. *Spec:* §30.12; satisfies
  [QEMU-29], [QEMU-31]; back-ref §10.6.

- **[RISK-21]** The **search-tree explosion** risk in state-space search
  ([`22-advanced-features.md`](22-advanced-features.md)) — the temporal graph
  growing super-polynomially in decisions — MUST be bounded by design before search
  is built: content-addressed checkpoint deduplication ([INV-6]), bounded frontier
  expansion, and coverage-guided prioritization. A spike MUST measure graph growth
  on a representative scenario and confirm the bounding keeps memory and frontier
  size within budget. *Gate:* `gate:content-address`. *Spec:* §30.12; back-ref §07,
  §22.

- **[RISK-22]** The **multi-VM parallelism vs lookahead** performance risk
  (conservative PDES only parallelizes nodes up to the minimum-link-latency
  lookahead, so a tight-latency topology collapses toward lockstep, [SCHED-6],
  [IO-33]) MUST be measured by a spike that varies link latency and reports
  achieved host-core parallelism, confirming the latency floor ([SCHED-20]) and the
  lookahead budget meet the multi-VM-parallelism target of
  [`25-performance-targets.md`](25-performance-targets.md). *Gate:*
  `gate:scheduler-liveness`. *Spec:* §30.12; back-ref §08, §15.4.2, §25.

## 30.13 The risk register

The register collects every risk above plus the standing design risks, with
likelihood, impact, mitigation, and the owning spike. **Likelihood** and
**impact** are L/M/H. The **owning spike** is the experiment that retires (or
re-classifies) the risk. Phase-0 blockers ([RISK-3]) are marked ★.

```text
RISK                                            LIKE  IMPACT  MITIGATION                                  OWNING SPIKE
--------------------------------------------    ----  ------  ------------------------------------------  ------------
★ icount+elimination NOT bit-identical          M     FATAL   extend §4.6; bisect with rr-as-diagnostic   S1  (RISK-4)
  (single-VM determinism false) [DET-1]
★ guest busy-polls (no HLT) during I/O          M     M(perf) exactness-preserving busy-poll FF (IO-30)   S2  (RISK-6)
  (defeats fast-forward, not correctness)
★ savevm/loadvm loses icount/TCG state          M     M       thin/replay checkpoints default (QEMU-21)   S3  (RISK-8)
  (fat checkpoint != replay) [DET-32]
★ producer→consumer visibility wall-clock       L     H       §13.9 by construction; localize leak        S4  (RISK-10)
  (Contract B false) [DET-34]
  plugin can't read guest VIRTUAL mem           M     L       physical/pinned identity page (GHC-33)       S5  (RISK-12)
  KASLR/ASLR not deterministic w/ seeding       M     L       S6 PASS: stock cmdline, host-side seal (D-31) S6 (RISK-13)
  next-deadline approx / ceiling overshoot      L     H       TB-split at ceiling; conservative ceiling   S7  (RISK-14)
  TCG-exec coverage too expensive               M     M(perf) edge bitmap / once-per-block / sampling     S8  (RISK-15)
  determinism breaks on QEMU rebuild/bump       M     H       pin build id in artifact; re-gate (DET-35)  S9  (RISK-16)
  aarch64 doorbell can't trap synchronously     L     L       black-box-only aarch64; defer white-box     S10 (RISK-17)
★ multi-vCPU RR-TCG NOT bit-identical            M     H       patch leak / IPI; else revert to -smp 1     S11 (RISK-25)
  (Phase-0 blocker for G-10) [G-10]
  Decision::Preemption unavailable/not discrim   L     M       default-only until injection API lands      S12 (RISK-26)
  rr_switch_quantum default (perf vs races)      M     M(perf) modeled default until S12 green            S13 (RISK-27)
  gdbstub attach/step disturbs icount            L     M       read-only + Crucible step until green        S14 (RISK-28)
  shmem ABI drift passes silently               L     H       gen header + bilateral asserts + golden     RISK-18
  cross-process futex lost/spurious wake        L     H       race-free idiom; jitter stress spike        RISK-19
  leaked QEMU child distorts determinism         M     H       pdeathsig+kill_on_drop+unconditional reap   RISK-20
  search-tree explosion                         H     M       CAS dedup + bounded frontier + cov-guided   RISK-21
  multi-VM parallelism < target (lookahead)     M     M(perf) latency floor + lookahead budget tuning     RISK-22
```

Recorded retirements: **RISK-15** is retired by `T-RISK-8`:
`checks.crucible.phase0.coverageOverhead` ran the same deterministic
boot-and-workload scenario in three interleaved repetitions across no-plugin
baseline, plugin-loaded/no-callback disabled mode, hook-registered count mode,
and coverage-on translated-TB-id set mode. Because the no-plugin run deliberately
has no instruction counter, its IPS is normalized with the paired hook-count
retired-instruction count after identical workload output and tight
hook-vs-coverage equal-work assertions. The run reported
`coverage_unique_entries_min=113515`, `coverage_on_vs_baseline_min=1.0211`,
`coverage_on_vs_hook_off_min=0.9136`,
`max_retired_instruction_delta=0.000044`, and `max_tb_exec_delta=0.000023`,
clearing the `0.7000` budget floor. No cheaper coverage representation is
adopted for Phase 0; the row remains listed as a regression risk for future
production coverage work and the full `gate:perf-bench` baseline.

**RISK-18** is retired by `T-RISK-11`: `checks.crucible.phase0.abiDrift`
generated a C header from Rust `#[repr(C)]` layout facts, compiled the matching
good C and Rust views, then deliberately drifted `RegionHeader.node_count` from
offset `12` to offset `16`. The run reported
`generated_header_diff_detected=1`, `c_static_assert_drift_failed=1`,
`c_static_assert_specific_offset_failed=1`,
`rust_static_assert_specific_offset_failed=1`,
`golden_vector_good_c_roundtrip=1`, `golden_vector_good_rust_roundtrip=1`,
`golden_vector_drifted_c_matches_generated=1`, and `drifted_header_size=256`.
This is a throwaway Phase-0 proof of the fail-closed ABI-drift defenses; the row
remains listed as a regression risk until the production `crucible-shmem` crate
and full `gate:abi-conformance` wiring land.

**RISK-19** is retired by `T-RISK-12`:
`checks.crucible.phase0.futexStress` completed 2,000,000 actionable
cross-process non-private futex wake cycles and 2,000,000 wake-without-action
cycles under yield-based host jitter. The run required at least 1,000,000
successful futex returns in each phase and reported `lost_wakes=0`,
`timed_out_after_wake=0`, and `spurious_advances=0`. The row remains listed as a
regression risk; future shmem work must keep the same publish-precondition /
read-counter / re-check / wait idiom and non-private futex operation.

**RISK-20** is retired by `T-RISK-13`: `checks.crucible.phase0.lifecycle`
induced clean QMP quit, control-plane SIGTERM, guest kernel panic, plugin hang,
setup failure, host SIGKILL, and parent death without unwind against real
AOS-built QEMU children. The run reported each path exactly once, `survivors=0`,
and `reaped=7`. The row remains listed as a regression risk; the production
`QemuNode` implementation must preserve `kill_on_drop`, `PR_SET_PDEATHSIG`, and
unconditional reap behavior.

**RISK-21** is retired by `T-RISK-14`:
`checks.crucible.phase0.searchTreeGrowth` measured a deterministic synthetic
pending-message/fault temporal-graph search model with four symmetric replicas,
14 pending-message slots, source/destination/payload messages, append/ack/heartbeat
deliveries, crash/drop/partition/heal/timer decisions, event-log/RNG coordinates,
and materialized-state reference counts. A deterministic raw branching proxy at
depth 5 was `raw_branching_proxy=46812255`; the bounded search at depth 4 stored
`bounded_seen_nodes=351`, expanded `bounded_expanded_nodes=102`, reported
`symmetry_skipped_edges=186`, `dedup_hits=35`, `frontier_pruned=687`,
`frontier_dropped=438`, `frontier_replaced=249`, `bounded_max_frontier=64`,
`uncapped_seen_nodes=66349`, `uncapped_max_frontier=12512`,
`uncapped_frontier_pruned=0`, and `estimated_store_bytes=67392` against a
`196608` byte budget. This retires the
Phase-0 pre-build bounding risk for the modeled representative search family; the
row remains listed as a regression risk until the production temporal graph,
replay oracle, search engine, and scenario corpus land.

**RISK-22** is retired by `T-RISK-15`:
`checks.crucible.phase0.multiVmParallelism` measured a deterministic
conservative-lookahead cost model for a uniform full-mesh four-VM scenario on four
modeled host cores. The spike rejects declared zero/sub-floor base latencies,
clamps a sub-floor latency fault from `128` to the `512` virtual-time floor, and
honors a raised latency fault at `2048`. Sweeping link latencies
`512,1024,2048,4096` produced `sample_0_parallelism_x1000=3605`,
`sample_1_parallelism_x1000=3792`, `sample_2_parallelism_x1000=3893`, and
`sample_3_parallelism_x1000=3946` against a `3500` target, with
`monotonic_parallelism=1` and `halving_sync_frequency=1`. The floor avoided the
modeled sub-floor collapse from `unfloored_latency_64_parallelism_x1000=2133`
(`floor_vs_unfloored_subfloor_ratio_x1000=1690`). This retires the Phase-0
pre-production lookahead-budget risk for the modeled scheduler cost surface; the
row remains listed as a regression risk until production scheduler liveness,
real host-core perf measurement, and `gate:perf-bench` land.

**RISK-4 / RISK-5** are retired by `T-RISK-1`:
`checks.crucible.phase0.s1Fingerprint` booted the same stock Linux kernel plus
diskless initramfs twice with no block devices, `-smp 1`,
`-accel sim,thread=single`, `-icount shift=0,sleep=off,align=off`, a fixed RTC,
fixed seed material through `fw_cfg`, `virtio-rng`, and the conservative
`nokaslr norandmaps random.trust_cpu=off` kernel arguments. The second run
injected host scheduling jitter with CPU load. The plugin sampled the extended
fingerprint every `100000000` retired guest instructions, requested a stop at
the fixed `3200000000`-instruction horizon, and compared both the exact horizon
cadence sample and the plugin-exit sample. The QMP-visible pause took effect
deterministically at `3200000005` retired instructions in both runs. The run
reported `extended_fingerprint_match=true`,
`aggregate_icount_stream_match=true`, `cadence_fingerprint_match=true`,
`horizon_fingerprint_match=true`, `plugin_exit_fingerprint_compared=true`,
`paused_migration_state_match=not_asserted`, `horizon_retired=3200000000`,
`pause_retired=3200000005`, `pause_overshoot=5`,
`horizon_extended_hash=9d1e61606ac54920`,
`horizon_register_hash=a732f3acdae34c85`,
`horizon_ram_hash=110f5442638e18ba`, `horizon_ram_bytes=268967936`,
`horizon_device_event_hash=1ba88ef5d7831ee0`,
`device_state_scope=io_event_multiset`,
`migration_state_comparison=diagnostic_not_gated`,
`register_read_failures=0`, `register_count_assertion=nonempty_single_vcpu`,
`block_device_assertion=launch_argv_scan`,
`mismatch_localization=component`, `first_differing_line=none`,
`first_differing_component=none`, `s1_complete=true`, and
`open_gap=paused_qemu_migration_state_timer_icount_hpet`. Raw QEMU migration
streams are logged only as diagnostics for this spike: repeated runs exposed a
narrow paused-state serialization split around `timer/icount` bias and HPET/local
timer state even when the execution-fingerprint sequence, RAM, registers, and
IO-event multiset match. The proof path required the plugin `stop_at` pause hook
and a QEMU RR-TCG fix that accounts icount idle warps at the deterministic RR
idle boundary before waiting. This retires the fatal single-VM
execution-fingerprint risk for the stock Linux diskless proof path; full
production DET-29 device-state hashing at every cadence, byte-identical paused
QEMU device migration state, block-device determinism, fat snapshot restore,
broader DET-38 host coverage, and QEMU-version gating remain owned by later
gates/spikes.

**RISK-6 / RISK-7** are retired by `T-RISK-2`:
`checks.crucible.phase0.s2HltBusyPoll` booted the target stock Linux kernel plus
initramfs under `-accel sim,thread=single` and
`-icount shift=0,sleep=off,align=off`, attached a synchronous virtio block read
device with `throttling.iops-read=20`, attached a virtio-9p tree with
`throttling.iops-read=20`, and bracketed 32 reads from each path with
observation-only guest markers. The plugin counted retired instructions, `HLT`
opcodes, and MMIO events inside each bracket, and the gate requires every
bracketed operation to include device I/O events. The run reported
`block_outstanding_wait_source=qemu_block_read_throttle_iops_20`,
`ninep_outstanding_wait_source=qemu_9p_read_throttle_iops_20`,
`idle_threshold_ppm=900000`, `block_idle_fraction_requirement=ge_900000`,
`block_busy_poll_fraction_requirement=le_100000`,
`block_idled_operations=32`, `block_busy_polled_operations=0`,
`block_idle_fraction_ppm=1000000`,
`block_operations_with_io_events=32`, `block_operations_without_io_events=0`,
`block_busy_poll_instruction_distribution=empty`, `block_hlt_observed=true`,
`block_io_events_observed_per_operation=true`,
`block_idle_threshold_met=true`, `ninep_idle_fraction_requirement=ge_900000`,
`ninep_busy_poll_fraction_requirement=le_100000`,
`ninep_idled_operations=32`, `ninep_busy_polled_operations=0`,
`ninep_idle_fraction_ppm=1000000`,
`ninep_operations_with_io_events=32`, `ninep_operations_without_io_events=0`,
`ninep_busy_poll_instruction_distribution=empty`, `ninep_hlt_observed=true`,
`ninep_io_events_observed_per_operation=true`,
`ninep_idle_threshold_met=true`, `fallback_adopted=false`, and
`busy_poll_mitigation_decision=not_needed_for_measured_delayed_sync_read_path`.
The guest workload completed all 64 synchronous reads and printed
`TEST_RESULT:PASS`. This retires the S2 performance risk for delayed synchronous
virtio-block and virtio-9p reads on the target Linux guest: idle fast-forward is
valid for the measured blocking-read path, and the exactness-preserving busy-poll
fallback remains specified by [IO-30] but is not adopted for this path.

**RISK-10 / RISK-11** are retired by `T-RISK-3`:
`checks.crucible.phase0.s4ShmemVisibility` runs a throwaway shared-memory
scheduler/node double over a real `MAP_SHARED` region. It forks two producer
processes and one consumer process, uses §13-style SPSC rings with release/acquire
publication, assigns a fixed frame script with 32 frames across 8 delivery-icount
groups, and runs the same script twice: once with producer publish-path wall-clock
skew and once with consumer poll-path wall-clock skew. The consumer holds its
published `current_icount` at `delivery_icount - 1` until every frame in the due
group is present, then records visibility at exactly `delivery_icount` in the
deterministic `(delivery_icount, src_node, seq)` order. The run reported
`model=shmem_scheduler_node_double`, `shared_memory=MAP_SHARED`,
`ring_ordering=release_acquire_spsc`, `source_nodes=2`, `consumer_nodes=1`,
`rings=2`, `frames_per_source=16`, `total_frames=32`, `delivery_groups=8`,
`run_x_skew=producer_publish_path`, `run_y_skew=consumer_poll_path`,
`delivery_rule=delivery_icount_lte_current_icount`,
`tie_break_key=delivery_icount_src_node_seq`,
`consumer_ceiling=delivery_icount_minus_1_until_group_present`,
`producer_skew_ceiling_wait_observed=true`,
`consumer_skew_early_peek_observed=true`, `arrival_order_differs=true`,
`publish_order_unique_nonzero=true`, `visibility_vectors_match=true`,
`visibility_icounts_equal_delivery_icount=true`, `injection_order_match=true`,
`arrival_order_negative_control_failed=true`,
`late_enqueue_negative_control_failed=true`, `late_delivery_failures=0`,
`early_delivery_failures=0`, `late_enqueue_failures=0`,
`fallback_adopted=false`, and
`scope=phase0_shmem_visibility_discipline_not_qemu_device_injection`. This
retires the S4 risk for the §13.9 visibility discipline: queue presence and
host-poll timing do not decide architectural visibility in the measured
discipline, and delivery order ignores arrival order. Production QEMU/plugin
device injection remains owned by the later `gate:layer1-injection` and QEMU
integration gates.

**RISK-8 / RISK-9** are resolved by `T-RISK-4` with the thin/replay fallback
adopted: `checks.crucible.phase0.s3SavevmLoadvm` verified the currently
available QMP snapshot transport and the Crucible-owned checkpoint half without
enabling fat snapshots as the default. The check found typed
`snapshot-save`/`snapshot-load`, `migrate`, `migrate-incoming`, and
`human-monitor-command` in QMP, confirmed typed legacy `savevm`/`loadvm` are not
available, and used `snapshot-save`/`snapshot-load` against a qcow2 `vmstate`
node rather than HMP. It tested three snapshot points:
`snapshot_point_0=diskless_boot_window`,
`snapshot_point_1=cpu_timer_window`, and
`snapshot_point_2=block_pending_io`. The diskless and CPU-timer restored suffixes
matched replay, while the marked block pending-I/O negative control reached
`mid_io_active_medium=block`, `mid_io_pause_io_events=1`,
`mid_io_pause_hlt_events=1`, and `mid_io_guest_block_direct=true`, then diverged
after restore with `mid_io_suffix_fingerprint_match=false`. The run reported
`snapshot_icount=100000008`, `cpu_timer_snapshot_icount=150000010`,
`mid_io_snapshot_icount=6211647588`,
`all_suffix_fingerprints_match=false`,
`boot_window_suffix_fingerprint_match=true`,
`cpu_timer_suffix_fingerprint_match=true`,
`suffix_fingerprint_match=true`, `register_hash_match=true`,
`ram_hash_match=true`, `suffix_stream_hash=bdb7658e9d86101e`,
`suffix_register_hash=75b96364eff3a764`,
`suffix_ram_hash=78d57d4a3984e159`, `suffix_ram_bytes=1074274304`,
`current_vmstate_snapshot_scope=diskless_and_cpu_timer_single_vcpu_qemu_vmstate_plus_block_pending_negative_control`,
`mid_io_burst_snapshot_exercised=true`,
`mid_io_burst_snapshot_covered=false`,
`plugin_time_control_snapshot_covered=true`,
`device_timer_snapshot_covered=true`,
`device_event_hash_match=false`,
`replay_oracle_fat_thin_match=false`,
`full_fat_checkpoint_complete=false`,
`crucible_owned_state_roundtrip=true`,
`ring_snapshot_restore=pass`, `overlay_delta_roundtrip=pass`,
`rng_position_roundtrip=pass`, `thin_checkpoint_default=true`,
`fat_snapshot_default=false`, `loadvm_branch_enabled=false`,
`fallback_adopted=thin_replay_until_full_s3`,
`risk8_status=mitigated_by_fallback_not_retired_for_fat_snapshot`, and
`risk9_status=retired_thin_replay_default`. This adopts the [QEMU-21] /
[QEMU-26] fallback for Phase 0: checkpoint realization defaults to thin replay
from genesis or a verified ancestor, and the `loadvm` branch remains disabled
until a later S3 rerun proves fat snapshots across the full required surface.
RISK-9 is retired for the default realization discipline; RISK-8 is mitigated by
non-use of unverified fat snapshots, not retired for the fat-snapshot
optimization.

**RISK-12** is retired by `T-RISK-5`:
`checks.crucible.phase0.s5VirtualMemory` booted a diskless stock Linux guest and
used a throwaway instruction-marker doorbell double whose register triplet carried
`(kind, ptr, len)` at the marker instruction. The plugin read those registers at
the marker, called QEMU's `qemu_plugin_read_memory_vaddr`, and verified the bytes
against deterministic payload formulas before the guest poisoned the buffers after
the marker. The run covered three virtual-address placements:
resident static storage, a payload spanning two guest pages, and an anonymous
`mmap` region subject to the guest's normal page tables. Two read-enabled runs
matched exactly, and a read-disabled control matched the final fingerprint. The
run reported `qemu_plugin_read_memory_vaddr_available=true`,
`doorbell_surface=phase0_instruction_marker_double`,
`payload_source=register_triplet_kind_ptr_len`,
`virtual_address_read_result=pass`, `placements=3`,
`resident_read=pass`, `page_spanning_read=pass`, `paged_mmap_read=pass`,
`marker_icounts=3002401208,3002411158,3002477481`,
`marker_icounts_reproducible=true`, `read_bytes_match_expected=true`,
`read_hashes_reproducible=true`, `side_effect_free_fingerprint_match=true`,
`production_whitebox_channel_implemented=false`, and
`physical_pinned_fallback_adopted=false`. This retires the S5 virtual-vs-physical
payload-address risk for the measured plugin memory-read path: the convenient
virtual pointer+length form is sound enough to remain the default for the future
white-box channel. The production doorbell, binary frame decoder, inertness, and
white-box on/off fingerprint gates remain owned by the later `T-GHC-*` and
`T-PLUG-*` implementation tasks.

**RISK-13** is retired by `T-RISK-6`:
`checks.crucible.phase0.s6KaslrAslr` booted the same stock Linux kernel plus a
diskless initramfs under the S1 deterministic launch controls, first with the
conservative `nokaslr norandmaps` command-line control and then with those flags
removed. Each mode ran twice; the second run injected host scheduling jitter. The
guest probe mounted `/proc`, confirmed `randomize_va_space=0` for the control and
`randomize_va_space=2` for the randomized mode, read the resolved kernel text
symbol from `/proc/kallsyms`, and sampled stack, heap, brk, anonymous-`mmap`, and
VDSO bases. The plugin used the extended fingerprint without memory-event
callbacks, sampled every `200000000` retired instructions, and paused through QMP
at `3400000000` retired instructions after the guest printed `TEST_RESULT:PASS`.
The run reported `control_fingerprint_match=true`,
`control_bases_identical=true`, `randomized_fingerprint_match=true`,
`randomized_sample_count_match=true`, `randomized_bases_identical=true`,
`control_randomize_va_space=0`, `randomized_randomize_va_space=2`,
`kernel_text_nonzero=true`, `kernel_base_identical=true`,
`stack_base_identical=true`, `heap_base_identical=true`,
`brk_base_identical=true`, `mmap_base_identical=true`,
`vdso_base_identical=true`, `kernel_base_differs_from_control=true`,
`stack_base_differs_from_control=true`, `heap_base_differs_from_control=true`,
`brk_base_differs_from_control=true`, `mmap_base_differs_from_control=true`,
`vdso_base_differs_from_control=true`, `register_read_failures=0`,
`first_differing_line=none`, `first_differing_component=none`,
`randomization_reenabled_capability=true`,
`default_decision=randomization_may_be_enabled_per_image`, and
`fallback_adopted=none`. This retires the Phase-0 KASLR/ASLR necessity risk for
the measured diskless stock-Linux proof path: with deterministic E8/E9 seeding,
the randomized bases are reproducible across runs and genuinely differ from the
control. On this evidence, **D-31** made the stock guest cmdline (randomization
enabled, determinism sealed host-side) the shipped default and removed guest
entropy-suppression flags from the launch contract entirely.

Host-side sealing here includes the *delivery icount* of the seeded entropy, not
only its bytes. The seeded virtio-rng payload was always a pure function of the
scenario seed (E8/E9), but on the stock guest its completion interrupt was
delivered from a host-scheduled main-loop bottom half, so its icount — and thus
the instruction at which the guest observed the entropy — was host-timing
dependent and forked the fingerprint across otherwise-identical runs (an inherent
upstream-icount property for asynchronous device completions, present in pristine
QEMU, not a Crucible regression). This is now sealed by construction (E7a): the
`crucible-det-virtio-ioeventfd` patch disables ioeventfd under sim-mode icount for the
virtio-rng device so its virtqueue kick dispatches synchronously on the requesting
vCPU thread, and the `crucible-det-rng-delivery` patch completes builtin-RNG
entropy inline instead of via a bottom half, so the completion interrupt lands at
the exact request icount. The ioeventfd seal is scoped to virtio-rng specifically:
virtio-blk/9p completions are already pinned by the crucible blk/9p shmem substrate
(patches 0015-0019), which assumes the stock async kick, so those devices keep it —
this is why the `s2HltBusyPoll` throttled-IO idle counts are unchanged. No QEMU
record/replay is used ([NG-6]). `checks.crucible.phase0.s6KaslrAslr` and
`checks.crucible.phase1.guestEntropyLaunch` are the executing witnesses.

**RISK-14** is resolved by `T-RISK-7` with the exact-deadline/TB-split fallback:
`checks.crucible.phase0.s7DeadlineCeiling` booted a diskless stock Linux guest
under the deterministic S1 launch controls and loaded a throwaway ceiling probe
plugin. The plugin checked for the `qemu_plugin_clock_deadline_ns` symbol; the
original spike run found it missing, and the patch series has since landed the
export, so the rerun records `deadline_api_available=true`. The throwaway probe
still does not consume the export, so no exact `idle_wake_icount` is
reported or compared against a timer-fire icount. The same run commanded two
fixed instruction ceilings plus one dynamically chosen ceiling inside a
translation block. The probe requested the pause exactly at each commanded
ceiling (`request_exact_all=true`) but QEMU stopped after the request point
(`zero_overshoot_all=false`). The run reported
`idle_wake_icount_reported=unavailable`,
`actual_timer_fire_icount=not_measured_spike_probe_predates_export_use`,
`exact_deadline_match=false`, `max_pause_overshoot=9`,
`fixed_a_pause_overshoot=1`, `fixed_b_pause_overshoot=9`,
`interior_pause_overshoot=9`, `interior_target_tb_index=2`,
`interior_target_tb_insns=12`, `interior_target_inside_tb=true`,
`exact_next_deadline_capability=false`, `max_advance_exact_capability=false`,
`layer1_scheduler_fast_forward_enabled=false`, and
`fallback_adopted=tb_split_exact_pause_deadline_export_landed`. Phase 0
therefore does not rely on fast-forward/lookahead scheduling through this
surface. The deadline export has landed in the patch series; the production
path remains gated on a ceiling mechanism that stops at `max_advance_icount`
exactly, including interior-TB ceilings.

**RISK-16** is resolved by `T-RISK-9` and the Phase-2 regeneration/build-identity
gate. `checks.crucible.phase2.qemuPatchRegeneration` now verifies the checked-in
`crucible/qemu-10.0.0` branch bundle, proves the bundle base/head and each
per-patch commit/tree entry match the manifest, regenerates all 27 committed patch
files byte-for-byte with `--unified=3`, applies the regenerated stack with fuzz
disabled, and emits a manifest-derived QEMU build identity. The run reported
`qemu_version=10.0.0`,
`patch_series_hash=0e9a335295d577f51cf93395f7d8c7ba6a0b3d54083e06a7357f558f115e8566`,
`patch_branch_bundle_hash=1d969b51af280458fe3fc5405d1a49eb302afdeac2d3cb88382d3aa2f734efd2`,
`patch_branch_head_commit=1b2b6240a2e0887244f7c4c5aef0653754503365`,
`patch_branch_material_hash=5167675402324af5e1e5010451bfa1e19c41d34dfa40e5e5c68e0d9ed10ffb8e`,
`qemu_build_id=ca7044e84a68ebaf9df0c55b52e291803d95f062ff8bfc8d1ee70d44e3fde318`,
`qemu_nix_hash=35aad46df419155f4ce336d66dd4eac329348b333b1d202937ad05a0d94add09`,
`qemu_configure_flags_hash=716c3de64e42d5fee65c1b0ebb4dc213f282aba1d916820e1896ee36bc0db5f8`,
`artifact_build_id_match=true`, `artifact_validator_rejects_mismatch=true`,
`artifact_mismatch_regates=true`, and
`qemu_version_bump_regate_enforced=true`. `gate:patch-microtests` consumes that
result, and `gate:qemu-inert` owns the separate upstream-vs-patched sim-off
inertness proof.

**RISK-17** is retired by `T-RISK-10`.
`checks.crucible.phase0.s10Aarch64Doorbell` consumes the real-backend
`checks.crucible.phase2.qemuLiveWhiteboxDoorbell` result. The active
`qemu-crucible` package records
`qemu_target_list=x86_64-softmmu,aarch64-softmmu`,
`qemu_aarch64_softmmu_target=true`, `qemu_system_aarch64_available=true`, and
`production_aarch64_doorbell_trap_implemented=true`. A raw AArch64 `virt` guest
executes the frozen `hlt #0x04c1` instruction, the production Rust plugin reads
the `x0`/`x1` virtual pointer and length synchronously, admits `hot-path` at the
observed trap icount, reaches the exact scheduler ceiling, and exits normally.
The spike records `whitebox_on_trap_tested=true`,
`whitebox_off_inertness_tested=true`, a numeric
`marker_icount_reproducible`, `payload_read_result=pass`,
`aarch64_whitebox_supported=true`, `aarch64_blackbox_only_fallback=false`, and
`fallback_adopted=none`.

**RISK-25** is retired by `T-RISK-17`.
`checks.crucible.phase0.s11MultiVcpuFingerprint` booted the stock Linux diskless
initramfs twice under the normative `-accel sim,thread=single` path, including a
host-jitter run, with `vcpus=4`, `rr_switch_quantum=4096`,
`cadence=100000000`, and an exact `horizon_icount=3300000000`. The sustained
pthread spinlock workload reported affinity on vCPUs `0,1,2,3`; both runs
produced 33 periodic samples plus a sole final teardown record,
`rr_switch_events=389751`, identical aggregate/per-vCPU/RR traces through the
exact horizon, four nonempty
3868-byte register files with 66 descriptors each, and a nonzero 256 MiB RAM
digest. The sample at `observed_icount=3300000000` is authoritative. The two
plugin-exit observations occurred 11 and 4 instructions after that boundary
while processing QMP teardown. They are retained as non-authoritative
diagnostics and each is bounded by the 4096-instruction RR quantum, rather than
being treated as execution past the requested horizon. The run reported
`extended_fingerprint_match=true`,
`plugin_exit_fingerprint_compared=diagnostic-only`,
`register_read_failures=0`, and `fallback=smp1_not_needed`.

**RISK-26** uses the `T-RISK-18` default-only fallback while live preemption
exploration remains pending:
`checks.crucible.phase0.s12PreemptionDecision` scanned the current QEMU Nix
wiring, every local QEMU patch, the production trace plugin, and the Rust crates,
and found the commanded preemption-injection surface. This is capability and
model evidence, not the live S12 experiment. The S11 sim-mode prerequisite is
green, so the fallback records
`preemption_surface_scan_scope=qemu_nix_all_qemu_patches_trace_plugin_crates`,
`known_preemption_injection_surface_found=true`,
`preemption_injection_api_available=qemu_plugin_inject_preemption`,
`preemption_patch_present=0030-crucible-preemption-inject.patch`,
`plugin_preemption_surface_present=true`,
`vcpu_switch_injection_tested=checks.crucible.phase2.qemuPreemptionInject`,
`interrupt_timing_injection_tested=checks.crucible.phase2.qemuPreemptionInject`,
`commanded_preemption_choices_tested=2`,
`commanded_preemption_reproducible=patch_microtest`,
`commanded_preemption_discriminating=modeled`,
`known_race_manifested_under_one_choice=modeled`,
`known_race_absent_under_another_choice=modeled`,
`single_vcpu_interrupt_variation_distinct=modeled`,
`default_determinism_prereqs_green=true`,
`default_determinism_prereqs_source=decision_register_s1_s11`,
`s1_decision_entry_consumed=true`, `s11_decision_entry_consumed=true`,
`s11_result_status=PASS`, `s11_rr_switch_quantum=4096`,
`s11_horizon_icount=3300000000`, `s11_extended_fingerprint_match=true`,
`decision_preemption_exploration_enabled=false`, and
`fallback_adopted=preemption_injection_patch_landed_explorer_enablement_pending`.
The four discrimination fields advanced from `not_tested` to `modeled` once the
deterministic model discrimination proof landed: a known two-vCPU
last-writer-wins race resolves to different observable outcomes under different
commanded `Decision::Preemption` values (the race manifests under one choice,
is absent under another), and a single-vCPU interrupt-timing variation yields
distinct replayable schedules. The model witness is
`crates/crucible/tests/preemption_discrimination.rs::commanded_preemption_discriminates_a_known_two_vcpu_race`
and the injection-surface witness is `checks.crucible.phase2.qemuPreemptionInject`.
Phase 0 therefore has demonstrated commanded-preemption discrimination at the
model layer but still does **not** enable the **live** `Decision::Preemption`
campaign explorer: that remains gated on a live race-yield proof under a running
guest. Until then it keeps the default deterministic interleaving whose S1/S11
prerequisites are now recorded green.

**RISK-27** is resolved by `T-RISK-19` with the S11-validated default-only
fallback:
`checks.crucible.phase0.s13RrSwitchQuantumFallback` consumed the S12 fallback
result, swept candidate `rr_switch_quantum` values in a deterministic default-only
RR switch-overhead model, and selected `4096` as the smallest modeled quantum
above the throughput floor. It then consumed the green sim-mode S11 result with
the same quantum before reporting completion. The run reported
`candidate_quantums=1024,2048,4096,8192,16384`,
`throughput_metric=modeled_retired_instruction_efficiency_x1000`,
`throughput_measurement_scope=modeled_rr_switch_overhead_default_only`,
`target_efficiency_x1000=980`, `sample_0_efficiency_x1000=941`,
`sample_2_rr_switch_quantum=4096`, `sample_2_efficiency_x1000=984`,
`coarse_baseline_rr_switch_quantum=16384`,
`coarse_baseline_efficiency_x1000=996`,
`selected_vs_coarse_efficiency_x1000=987`,
`selected_phase0_default_rr_switch_quantum=4096`,
`selected_default_basis=s11_validated_modeled_smallest_quantum_above_throughput_floor`,
`race_yield_tested=false`,
`race_yield_source=preemption_patch_surface_available_explorer_disabled`,
`s11_result_consumed=true`, `s11_sim_rerun_green=true`,
`s11_rr_switch_quantum=4096`, `s11_workload_affinity_active=true`,
`s11_extended_fingerprint_match=true`,
`d25_status=open_until_preemption_explorer_enabled`, and
`fallback_adopted=s11_validated_modeled_throughput_default_only_quantum_until_preemption_explorer`,
with `s13_complete=true`. Phase 0 may therefore use
`rr_switch_quantum=4096` for the default-only deterministic interleaving. This
accepted fallback does not claim empirical throughput against the §25 budget and
does not close D-25's race-yield half; the full default-selection spike must still
be rerun after S12 enables commanded-preemption exploration.

**RISK-28** is resolved by `T-RISK-20` with the read-only/Crucible-driven-step fallback:
`checks.crucible.phase0.s14GdbstubFallback` scanned the current implementation
surface and the debug/session/CLI specifications for the Phase-0 gdbstub gate.
The check found no hermetic gdb client package and no known gdbstub single-step
mediation or continuation hook in the scanned AOS QEMU patch/plugin integration
surface; the session/backend `open_gdbstub` path is now implemented by
`checks.crucible.phase5.sessionDebugTimeTravel` but is not yet a live S14
neutrality measurement. It also required the recorded green
`checks.crucible.phase0.s1Fingerprint` decision entry as the baseline single-VM
determinism prerequisite. The run reported
`hermetic_gdb_client_available=false`,
`qemu_gdbstub_mediation_scan_scope=aos_qemu_nix_patches_plugin`,
`known_aos_qemu_gdbstub_step_hook_detected=false`,
`aos_qemu_gdbstub_mediation_patch_implemented=false`,
`session_open_gdbstub_implemented=true`,
`cli_debug_command_implemented=false`,
`read_only_gdbstub_ops_tested=false`,
`read_only_fingerprint_neutral=not_tested`,
`read_only_icount_neutral=not_tested`, `gdb_single_step_tested=false`,
`gdb_single_step_routed_through_scheduler=not_tested`,
`gdb_single_step_policy=disabled_until_s14_green`,
`raw_gdb_single_step_allowed_by_crucible_policy=false`,
`policy_enforcement_runtime=not_implemented`,
`default_debug_policy=read_only_attach_crucible_driven_step_reverse_step`,
`live_gdbstub_attach_gate_status=fallback_pending_hermetic_gdb_client_and_mediation_gate`, and
`fallback_adopted=read_only_attach_crucible_driven_step_until_gdbstub_gate`.
Phase 0 therefore does not claim live gdbstub attach neutrality or
scheduler-routed gdb single-step. Until a hermetic debug client, CLI live attach
command, and mediation gate land, raw gdb single-step remains disabled by
Crucible policy. The permitted advancement model
for the future debug surface remains Crucible-driven deterministic
step/reverse-step, but runtime enforcement is not implemented yet.

- **[RISK-23]** The risk register MUST be kept current: every spike result
  ([RISK-1]) updates its row (retired / re-classified / fallback-adopted), and a
  new load-bearing assumption discovered during implementation MUST be added as a
  new `RISK-n` row with an owning spike before it is built upon. A row whose owning
  spike has not run MUST NOT have its risk treated as retired. *Gate:*
  `gate:harness-lint`. *Spec:* §30.13.

- **[RISK-24]** The five ★ Phase-0 blockers (S1, S2, S4, S3 per the priority of
  [RISK-3]) MUST be green-or-fallback-adopted before their dependent Phase-1 work
  begins: S1 before any single-VM foundation, S4 before any multi-VM/transport
  feature ([DET-7]), S2 before relying on I/O fast-forward performance, and S3
  before relying on fat-snapshot resume/fork (thin/replay is the default until
  then), and S11 before multi-vCPU foundation work. No later-phase work may
  proceed on an unmeasured ★ assumption ([G-5],
  [PLAN-4]). *Gate:* `gate:layer0-determinism`, `gate:layer1-injection`,
  `gate:replay-oracle`. *Spec:* §30.13, §30.1.

**RISK-23 / RISK-24** are enforced as a Phase-0 checklist guard by `T-RISK-16`:
`checks.crucible.phase0.riskRegisterGate` verifies that every completed Phase-0
risk spike has a decision-register entry and a concrete check name, that the
foundational Phase-0 blockers are either passed or fallback-adopted before
dependent work proceeds. The current audited state reports
`checked_risk_tasks=20`, `checked_task_scope=T-RISK-only`,
`retired_decision_entries=20`, and `phase0_foundational_blockers_open=0`. S11 is
green under sim mode, and S13 has adopted the validated default-only fallback;
D-25 remains separately open for live preemption-explorer race-yield telemetry.

## 30.14 Summary

```text
Foundation-first (G-5): measure the load-bearing bets BEFORE building on them.

Phase-0 blockers (run/pass first, in priority order):
  S1  ★  icount + entropy elimination => bit-identical single-VM (FATAL if false)
  S2  ★  guest HLTs during blocking I/O (idle fast-forward applies to measured path)
  S4  ★  producer→consumer shmem visibility is icount-not-wallclock
  S3  ★  savevm/loadvm scoped smoke; thin/replay fallback adopted for fat snapshots
  S11 ★  deterministic multi-vCPU under RR-TCG + icount (G-10; else revert -smp 1)

Gated-but-not-blocking spikes:
  S5   plugin reads guest VIRTUAL memory via marker double (physical fallback unused)
  S6   deterministic boot WITH KASLR/ASLR (per-image re-enable capability)
  S7   exact next-deadline + zero ceiling overshoot (else TB-split / conservative)
  S8   TCG-exec coverage cheap enough for fuzzing (else cheaper representation)
  S9   determinism survives AOS QEMU build / version bumps (pin build id; re-gate)
  S10  multi-arch doorbell on aarch64 (else aarch64 black-box only)
  S12  Decision::Preemption reproducible + discriminating (else default-only)
  S13  rr_switch_quantum default: perf vs races (D-25 stays open until S12 green)
  S14  gdbstub attach/step fallback (read-only + Crucible step until green)

Secondary validations / standing risks:
  ABI drift can't pass silently · cross-process futex no lost-wake · no leaked
  QEMU child · search-tree explosion bounded · multi-VM parallelism meets target.

Every spike has a concrete fingerprint/metric pass-fail and a fallback; a failed
spike degrades the system (S1 excepted: its failure is fatal and is bisected,
never tolerated). Results live in the decision register (31).
```

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is risks/spikes, tracked by [PLAN-3]. They are
> **Phase 0**: the spikes run before, or at the very start of, the foundation work
> they validate ([G-5], [RISK-2], [RISK-3]). Each task is a throwaway measurement
> that retires a risk and is recorded in [`31-decision-register.md`](31-decision-register.md).

- [x] **T-RISK-1** Run **S1** (Phase-0 blocker ★, highest priority): boot one
  unmodified guest twice under the §10.2 launch config with §4.6 elimination
  active, capture the execution-fingerprint sequence ([DET-29]) under adversarial
  host conditions, and diff; bisect any mismatch to the leaking entropy source
  (rr-as-diagnostic only). — satisfies [RISK-4], [RISK-5], [DET-1], [DET-5]; spec
  §30.2.
- [x] **T-RISK-2** Run **S2** (Phase-0 blocker ★): characterize the HLT-vs-busy-poll
  fraction and busy-poll instruction cost for synchronous block/9p reads on the
  target guests; determine whether idle fast-forward ([SCHED-28]) applies often
  enough for the perf budget; record the busy-poll mitigation decision. —
  satisfies [RISK-6], [RISK-7], [IO-29], [IO-30]; spec §30.3.
- [x] **T-RISK-3** Run **S4** (Phase-0 blocker ★): two-VM fixed-schedule
  run-twice-and-diff under artificially skewed producer/consumer timing, asserting
  identical per-frame consumer-visibility icounts and `(delivery_icount, src_node,
  seq)` injection order ([SHM-33], [SHM-34]); localize any transport-timing leak.
  — satisfies [RISK-10], [RISK-11], [DET-6], [DET-34]; spec §30.5.
- [x] **T-RISK-4** Run **S3** (Phase-0 blocker ★): savevm/loadvm +
  ring/overlay/RNG round-trip vs uninterrupted replay at several snapshot points
  (incl. mid-I/O burst) under the replay oracle; keep thin/replay checkpoints
  the default until green. Phase 0 verified a scoped QMP `snapshot-save` /
  `snapshot-load` diskless VMState suffix match plus Crucible-owned
  ring/overlay/RNG round-trip and adopted the thin/replay fallback; fat snapshots
  stay disabled until full mid-I/O and plugin time-control coverage is green. —
  satisfies [RISK-8] via fallback adoption, [RISK-9], and [QEMU-21]; keeps full
  [DET-32] / [QEMU-27] fat-snapshot content equality gated on a later complete S3
  run; spec §30.4.
- [x] **T-RISK-5** Run **S5**: plugin reads guest **virtual** memory at the
  doorbell trap icount (resident / page-spanning / paged buffers), reproducibly
  and side-effect-free; default to the physical/pinned identity page until green.
  Phase 0 verified QEMU's `qemu_plugin_read_memory_vaddr` using a synchronous
  instruction-marker doorbell double carrying `(kind, ptr, len)` in registers;
  the production white-box channel remains a later implementation task. —
  satisfies [RISK-12], [GHC-33]; spec §30.6.
- [x] **T-RISK-6** Run **S6**: KASLR/ASLR-enabled boot fingerprint-identical across
  runs given fully-seeded E8/E9; decide whether `nokaslr`/`norandmaps` are required
  or merely conservative. Phase 0 verified the randomized command-line mode with
  QMP-stop extended fingerprints and explicit kernel/user base probes and found
  them not required; on that evidence **D-31** made the stock guest cmdline the
  shipped default (randomization enabled, sealed host-side), with no fallback
  adopted. — satisfies [RISK-13], [DET-33]; spec §30.7.
- [x] **T-RISK-7** Run **S7**: plugin reports the exact next virtual-clock deadline
  at idle and advances to exactly `max_advance_icount` with zero overshoot (incl.
  mid-TB ceilings); adopt TB-split-at-ceiling or conservative-ceiling fallback if
  not. Phase 0 found the exact deadline export absent and the current pause
  surface overshoots after exact pause requests, so fast-forward/lookahead remain
  disabled until the exact-deadline export and TB-split/max-advance patch land. —
  satisfies [RISK-14], [DET-12]; spec §30.8.
- [x] **T-RISK-8** Run **S8**: measure TCG-exec coverage overhead (no-plugin /
  hook-registered / coverage-on) and confirm coverage-enabled throughput meets the
  fuzzing budget; adopt a cheaper coverage representation if over budget. —
  satisfies [RISK-15]; spec §30.9.
- [x] **T-RISK-9** Run **S9**: AOS-built patched QEMU reproduces the S1
  fingerprint, every patch is inert sim-off (`gate:qemu-inert`), and the QEMU build
  identity is recorded in the reproduction artifact so a build change is re-gated,
  never silent. Phase 0 recorded the active AOS QEMU derivation and patch-series
  identity, consumed the green S1 fingerprint, and proved a mutated build id
  forces re-gating; full upstream-vs-patched inertness remains a later
  `gate:qemu-inert` obligation because the current patch series intentionally
  changes icount behavior. — satisfies [RISK-16], [DET-35], [INV-7]; spec §30.10.
- [x] **T-RISK-10** Run **S10**: aarch64 doorbell traps synchronously at the exact
  retirement icount, carries its register payload, yields a reproducible marker
  icount, and is inert when disabled; fall back to aarch64-black-box-only if no
  instruction traps precisely. The AOS-built `qemu-system-aarch64` target now
  boots a raw `virt` guest through the production plugin; the live gate observes
  the frozen `hlt #0x04c1` marker through `x0`/`x1`, enforces the exact ceiling,
  and completes normal teardown. No fallback is active. — satisfies [RISK-17],
  [GHC-16]; spec §30.11.
- [x] **T-RISK-11** Run the **ABI-drift** spike: deliberately drift a field offset
  and confirm the generated-header diff, bilateral static asserts, and golden
  vector catch it on at least one side. — satisfies [RISK-18], [SHM-31]; spec
  §30.12.
- [x] **T-RISK-12** Run the **cross-process futex** stress spike: millions of
  park/wake cycles under host jitter with no lost wake and no spurious advance. —
  satisfies [RISK-19], [SHM-26]; spec §30.12.
- [x] **T-RISK-13** Run the **no-leak lifecycle** spike: induce every termination
  path and assert the surviving-child count returns to zero. — satisfies [RISK-20],
  [QEMU-29], [QEMU-31]; spec §30.12.
- [x] **T-RISK-14** Run the **search-tree-growth** spike: measure temporal-graph
  growth on a representative scenario and confirm CAS dedup + bounded frontier +
  coverage-guided prioritization keep memory/frontier within budget. — satisfies
  [RISK-21]; spec §30.12.
- [x] **T-RISK-15** Run the **multi-VM-parallelism** spike: vary link latency,
  report modeled host-core parallelism, and confirm the latency floor + lookahead
  budget meet the multi-VM-parallelism target. — satisfies [RISK-22]; spec §30.12.
- [x] **T-RISK-16** Maintain the **risk register** ([RISK-23]) and enforce the
  Phase-0 gate ([RISK-24]): record each spike result in the decision register,
  block dependent Phase-1 work on the five ★ blockers, and add a new `RISK-n` row
  with an owning spike for any newly-discovered load-bearing assumption. —
  satisfies [RISK-1], [RISK-2], [RISK-3], [RISK-23], [RISK-24]; spec §30.1, §30.13.
- [x] **T-RISK-17** Run **S11** (Phase-0 blocker ★ for [G-10]): boot a stock
  Linux `-smp 4` diskless initramfs twice under `-accel sim,thread=single` with a
  fixed `rr_switch_quantum`, S11-relevant §4.6 launch eliminations, and an
  asserted no-block-device launch; capture the **extended fingerprint** (all N
  vCPUs' nonempty register descriptor sets + RR cursor + RAM hash) at a cadence
  and at the horizon under an SMP-contended microworkload and host jitter/load,
  and diff; localize any
  mismatch to the first differing node-icount + component. Block multi-vCPU
  foundation work until green; fall back to `-smp 1` if irrecoverable. Phase 0
  completed the two sim-mode runs through 3.3 billion aggregate instructions,
  observed all four affinity-pinned workload vCPUs and 389163 RR switches, and
  matched the complete horizon fingerprint under host jitter; no `-smp 1`
  fallback was needed. —
  satisfies [RISK-25], [G-10], [DET-23], [SCHED-45], [PLUG-3]; spec §30.11a.
- [x] **T-RISK-18** Run **S12**: force a `Decision::Preemption` (vCPU switch for
  `N>1`, timer-interrupt timing for any `N`) at several commanded node-icounts in
  `[deadline, horizon]`, run each twice, and confirm each choice is reproducible,
  that ≥2 choices yield different horizon fingerprints, and that a known race
  manifests under one choice and not another; for `N=1` confirm interrupt-timing
  variation gives distinct reproducible trajectories. Fall back to
  interrupt-timing-only exploration if that surface is reliable, or default-only
  deterministic interleaving if no commanded surface is reliable. Phase 0 now
  finds the `qemu_plugin_inject_preemption` patch/API surface and the phase2
  patch microtest exercises deterministic vCPU-switch and interrupt landing, but
  S12 has not yet run the full known-race/yield proof; `Decision::Preemption`
  exploration remains disabled and the system keeps the default deterministic
  interleaving until that non-fallback proof lands. — resolves [RISK-26] by
  disabling the [G-11] exploration surface for now; satisfies [RISK-26] via the
  accepted fallback; does not yet satisfy [SCHED-46] or [DET-12] for full
  commanded-preemption exploration; spec §30.11b.
- [x] **T-RISK-19** Run **S13** fallback: consume the S12 fallback, model the
  default-only `rr_switch_quantum` throughput side, then validate the provisional
  `rr_switch_quantum=4096` against a green sim-mode S11 result and record
  `race_yield_tested=false`. The full S13
  sweep that reports empirical multi-vCPU throughput against the
  [`25-performance-targets.md`](25-performance-targets.md) budget, measures
  race-surfacing yield via the S12 explorer, and closes **D-25** remains deferred
  until S12 passes without fallback. The fallback completed after consuming the
  green sim-mode S11 result at quantum 4096; `race_yield_tested=false` remains
  explicit, and the accepted default-only fallback resolves [RISK-27] without
  closing [D-25]. — satisfies [RISK-27] via the validated fallback; it does not
  close [D-25] yet; spec §30.11c.
- [x] **T-RISK-20** Run **S14** fallback: scan the current debug implementation
  surface, record that no hermetic gdb client package or AOS QEMU gdbstub
  step-mediation hook exists yet, note that the session/backend `open_gdbstub`
  surface is implemented but not a live neutrality proof, and leave live
  read-only attach plus gdb single-step untested. Default to read-only attach +
  Crucible-driven step/reverse-step, with gdb single-step disabled until S14 can
  run against the live debug surface. — resolves [RISK-28] by adopting the
  conservative fallback; satisfies [RISK-28] via the accepted fallback; does not
  yet satisfy [DBG-1] or [SCHED-46] for live debugging; spec §30.11d.
