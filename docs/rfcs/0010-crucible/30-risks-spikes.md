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
  build launch config: -accel tcg -icount shift=N -smp 1 -cpu <no-rdrand>
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

- **[RISK-13]** Spike **S6** MUST determine whether a guest with KASLR/ASLR
  **enabled** boots bit-identically across runs given fully-seeded boot entropy
  (E8/E9, [DET-22], [DET-21]) — i.e. whether `nokaslr`/`norandmaps` are *required*
  or merely *conservative* ([DET-33]). The conservative defaults ([QEMU-13]) MUST
  ship until S6 is green; if S6 passes, randomization MAY be re-enabled to broaden
  any-unmodified-guest fidelity ([G-2]), recorded as a per-image capability, not a
  global default flip. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §30.7;
  satisfies [DET-33]; back-ref §4.9 (E11, E12), §10.2.

### What it could invalidate

Nothing load-bearing — the conservative defaults are always available. S6 is an
*opportunity* spike: passing it improves fidelity; failing it costs nothing beyond
keeping the defaults.

### Fallback

Keep `nokaslr norandmaps` as the shipped default ([QEMU-13]). Guests run with
randomization disabled, which is a minor fidelity reduction (production typically
runs with it on) but does not affect determinism or any capability.

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
that single-threaded round-robin TCG (`-accel tcg,thread=single`), where the
vCPU-switch boundary is itself an icount-commandable quantum, makes an SMP guest
as deterministic as a single-vCPU one — the same source-elimination contract,
extended over N vCPUs and the round-robin cursor. If it does not, the multi-vCPU
restatement of Contract A is false and [G-10]/[G-11] cannot be built.

### Assumption under test

An SMP guest under `-accel tcg,thread=single`, `-smp N`, `-icount shift=K`, a
fixed content-addressed `rr_switch_quantum` in node-icount, the full §4.6 entropy
elimination set applied to **all** vCPUs (including deterministic IPI/SIPI
delivery), and the plugin holding time control, produces a **bit-identical
aggregate-icount instruction stream AND extended fingerprint** — the existing
[DET-29] fingerprint extended to cover all N vCPUs' register files plus the
round-robin cursor — across runs and across adversarial host conditions. Because
round-robin TCG pins every vCPU onto a single host thread, host-core variation is
irrelevant to the interleaving *by construction*; the switch boundary is decided
by virtual time, not by host scheduling.

### What to build / measure

Boot a stock `-smp 4` image twice to a fixed icount horizon under the launch
configuration above, capturing the **extended fingerprint** (all N vCPUs'
register hashes + the RR cursor + the [DET-29] memory/device hash) at a fixed
icount cadence and at the horizon. Drive an SMP-contended microworkload (shared
counter / spinlock ping-pong across vCPUs). Diff the two extended-fingerprint
sequences. Then repeat under adversarial host conditions ([DET-38]): vary host
core count and inject host scheduling jitter/load — which, because RR pins all
vCPUs to one host thread, should be irrelevant by construction.

```text
S11 procedure (throwaway; no engine, no scheduler):
  launch: -accel tcg,thread=single -smp 4 -icount shift=K
          rr_switch_quantum=Q (fixed, content-addressed), §4.6 on all vCPUs,
          deterministic IPI/SIPI, plugin time control active
  run A: boot to horizon H; extended fingerprint at cadence C and at H -> EFP_A[]
         (extended FP = per-vCPU reg hashes + RR cursor + mem/device hash)
  run B: identical config, adversarial host (different cores, injected jitter)
         boot to H; extended fingerprint -> EFP_B[]
  compare: EFP_A == EFP_B  (element-by-element, all vCPUs + RR cursor)
```

### Pass / fail criterion

**Pass:** `EFP_A[i] == EFP_B[i]` for every cadence point `i` and at the horizon,
across all adversarial conditions, where each extended fingerprint covers all N
vCPUs' register files, the RR cursor, and the [DET-29] memory/device hash.

**Fail:** any extended-fingerprint element differs. The harness MUST localize the
first differing node-icount **and the component** — which vCPU's registers, or the
RR cursor — so the leaking source is identified.

- **[RISK-25]** Spike **S11** (Phase-0 blocker ★ for [G-10]) MUST demonstrate
  that an SMP guest under `-accel tcg,thread=single`, `-smp N`, `-icount`, a fixed
  content-addressed `rr_switch_quantum`, the §4.6 elimination set applied to all
  vCPUs (incl. deterministic IPI/SIPI), and plugin time control produces a
  **bit-identical aggregate-icount stream and extended fingerprint** (all N vCPUs'
  register files + the RR cursor) across runs and adversarial host conditions
  ([DET-38]). S11 MUST pass before any multi-vCPU foundation code is built; a
  mismatch MUST be localized to the first differing node-icount and component
  (which vCPU / the RR cursor) and treated as a leaking source to eliminate, never
  a tolerance to accept. *Gate:* `gate:single-vm-fingerprint`,
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

- **[RISK-26]** Spike **S12** MUST demonstrate that a forced `Decision::Preemption`
  (vCPU switch for `N>1`, or timer-interrupt timing for any `N`) at a commanded
  node-icount in `[deadline, horizon]` yields a **different-but-bit-reproducible**
  trajectory, that at least two choices produce different horizon fingerprints, and
  that a known race manifests under one choice and not another; for `N=1`, varying
  the timer-interrupt delivery icount MUST produce distinct reproducible
  trajectories. *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`.
  *Spec:* §30.11b; satisfies [G-11], [SCHED-46], [DET-12]; back-ref §8, §22.

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
  default value (closing open decision **D-25**). The result is **correctness-neutral**
  — any fixed quantum is deterministic per [RISK-25] — so S13 gates only the default
  value, never the contract. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §30.11c;
  resolves [D-25]; satisfies [SCHED-45], [PLUG-3]; back-ref §22, §25.

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
  icount out of band. Until S14 is green, debugging MUST default to **read-only
  attach + Crucible-driven step/reverse-step**, with gdb single-step **disabled**.
  *Gate:* `gate:single-vm-fingerprint`, `gate:replay-oracle`. *Spec:* §30.11d;
  satisfies [DBG-1], [SCHED-46]; back-ref file 36.

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
  KASLR/ASLR not deterministic w/ seeding       M     L       keep nokaslr/norandmaps default (QEMU-13)   S6  (RISK-13)
  next-deadline approx / ceiling overshoot      L     H       TB-split at ceiling; conservative ceiling   S7  (RISK-14)
  TCG-exec coverage too expensive               M     M(perf) edge bitmap / once-per-block / sampling     S8  (RISK-15)
  determinism breaks on QEMU rebuild/bump       M     H       pin build id in artifact; re-gate (DET-35)  S9  (RISK-16)
  aarch64 doorbell can't trap synchronously     L     L       black-box-only aarch64; defer white-box     S10 (RISK-17)
★ multi-vCPU RR-TCG NOT bit-identical            M     H       patch leak / IPI; else revert to -smp 1     S11 (RISK-25)
  (Phase-0 blocker for G-10) [G-10]
  Decision::Preemption not reproducible/discrim  L     M       interrupt-timing-only exploration           S12 (RISK-26)
  rr_switch_quantum default (perf vs races)      M     M(perf) coarser default + per-branch override       S13 (RISK-27)
  gdbstub attach/step disturbs icount            L     M       read-only attach + Crucible-driven step      S14 (RISK-28)
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

- **[RISK-23]** The risk register MUST be kept current: every spike result
  ([RISK-1]) updates its row (retired / re-classified / fallback-adopted), and a
  new load-bearing assumption discovered during implementation MUST be added as a
  new `RISK-n` row with an owning spike before it is built upon. A row whose owning
  spike has not run MUST NOT have its risk treated as retired. *Gate:*
  `gate:harness-lint`. *Spec:* §30.13.

- **[RISK-24]** The four ★ Phase-0 blockers (S1, S2, S4, S3 per the priority of
  [RISK-3]) MUST be green-or-fallback-adopted before their dependent Phase-1 work
  begins: S1 before any single-VM foundation, S4 before any multi-VM/transport
  feature ([DET-7]), S2 before relying on I/O fast-forward performance, and S3
  before relying on fat-snapshot resume/fork (thin/replay is the default until
  then). No later-phase work may proceed on an unmeasured ★ assumption ([G-5],
  [PLAN-4]). *Gate:* `gate:layer0-determinism`, `gate:layer1-injection`,
  `gate:replay-oracle`. *Spec:* §30.13, §30.1.

## 30.14 Summary

```text
Foundation-first (G-5): measure the load-bearing bets BEFORE building on them.

Phase-0 blockers (run/pass first, in priority order):
  S1  ★  icount + entropy elimination => bit-identical single-VM (FATAL if false)
  S2  ★  guest HLTs during blocking I/O (perf: fast-forward; correct either way)
  S4  ★  producer→consumer visibility is icount-not-wallclock (Contract B)
  S3  ★  savevm/loadvm complete (else thin/replay checkpoints — clean fallback)
  S11 ★  deterministic multi-vCPU under RR-TCG + icount (G-10; else revert -smp 1)

Gated-but-not-blocking spikes:
  S5   plugin reads guest VIRTUAL memory at trap (else physical/pinned page)
  S6   deterministic boot WITH KASLR (else keep nokaslr/norandmaps default)
  S7   exact next-deadline + zero ceiling overshoot (else TB-split / conservative)
  S8   TCG-exec coverage cheap enough for fuzzing (else cheaper representation)
  S9   determinism survives AOS QEMU build / version bumps (pin build id; re-gate)
  S10  multi-arch doorbell on aarch64 (else aarch64 black-box only)
  S12  Decision::Preemption reproducible + discriminating (else interrupt-only)
  S13  rr_switch_quantum default: perf vs races (D-25; coarser + per-branch o/r)
  S14  gdbstub attach/step doesn't disturb icount (else read-only + Crucible step)

Secondary validations / standing risks:
  ABI drift can't pass silently · cross-process futex no lost-wake · no leaked
  QEMU child · search-tree explosion bounded · multi-VM parallelism meets target.

Every spike has a concrete fingerprint/metric pass-fail and a fallback; a failed
spike degrades the system (S1 excepted: its failure is fatal and is bisected,
never tolerated). Results live in the decision register (31).
```

## Implementation checklist

> The authoritative, ordered tasks live in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is risks/spikes, copied verbatim per [PLAN-3]. They are
> **Phase 0**: the spikes run before, or at the very start of, the foundation work
> they validate ([G-5], [RISK-2], [RISK-3]). Each task is a throwaway measurement
> that retires a risk and is recorded in [`31-decision-register.md`](31-decision-register.md).

- [ ] **T-RISK-1** Run **S1** (Phase-0 blocker ★, highest priority): boot one
  unmodified guest twice under the §10.2 launch config with §4.6 elimination
  active, capture the execution-fingerprint sequence ([DET-29]) under adversarial
  host conditions, and diff; bisect any mismatch to the leaking entropy source
  (rr-as-diagnostic only). — satisfies [RISK-4], [RISK-5], [DET-1], [DET-5]; spec
  §30.2.
- [ ] **T-RISK-2** Run **S2** (Phase-0 blocker ★): characterize the HLT-vs-busy-poll
  fraction and busy-poll instruction cost for synchronous block/9p reads on the
  target guests; confirm idle fast-forward ([SCHED-28]) applies often enough for
  the perf budget; record the busy-poll mitigation decision. — satisfies [RISK-6],
  [RISK-7], [IO-29], [IO-30]; spec §30.3.
- [ ] **T-RISK-3** Run **S4** (Phase-0 blocker ★): two-VM fixed-schedule
  run-twice-and-diff under artificially skewed producer/consumer timing, asserting
  identical per-frame consumer-visibility icounts and `(delivery_icount, src_node,
  seq)` injection order ([SHM-33], [SHM-34]); localize any transport-timing leak.
  — satisfies [RISK-10], [RISK-11], [DET-6], [DET-34]; spec §30.5.
- [ ] **T-RISK-4** Run **S3** (Phase-0 blocker ★): savevm/loadvm + ring/overlay/RNG
  round-trip vs uninterrupted replay at several snapshot points (incl. mid-I/O
  burst) under the replay oracle; keep thin/replay checkpoints the default until
  green. — satisfies [RISK-8], [RISK-9], [DET-32], [QEMU-21], [QEMU-27]; spec
  §30.4.
- [ ] **T-RISK-5** Run **S5**: plugin reads guest **virtual** memory at the doorbell
  trap icount (resident / page-spanning / paged buffers), reproducibly and
  side-effect-free; default to the physical/pinned identity page until green. —
  satisfies [RISK-12], [GHC-33]; spec §30.6.
- [ ] **T-RISK-6** Run **S6**: KASLR/ASLR-enabled boot fingerprint-identical across
  runs given fully-seeded E8/E9; decide whether `nokaslr`/`norandmaps` are required
  or merely conservative; keep the conservative default until green. — satisfies
  [RISK-13], [DET-33]; spec §30.7.
- [ ] **T-RISK-7** Run **S7**: plugin reports the exact next virtual-clock deadline
  at idle and advances to exactly `max_advance_icount` with zero overshoot (incl.
  mid-TB ceilings); adopt TB-split-at-ceiling or conservative-ceiling fallback if
  not. — satisfies [RISK-14], [DET-12]; spec §30.8.
- [x] **T-RISK-8** Run **S8**: measure TCG-exec coverage overhead (no-plugin /
  hook-registered / coverage-on) and confirm coverage-enabled throughput meets the
  fuzzing budget; adopt a cheaper coverage representation if over budget. —
  satisfies [RISK-15]; spec §30.9.
- [ ] **T-RISK-9** Run **S9**: AOS-built patched QEMU reproduces the S1
  fingerprint, every patch is inert sim-off (`gate:qemu-inert`), and the QEMU build
  identity is recorded in the reproduction artifact so a build change is re-gated,
  never silent. — satisfies [RISK-16], [DET-35], [INV-7]; spec §30.10.
- [ ] **T-RISK-10** Run **S10**: aarch64 doorbell traps synchronously at the exact
  retirement icount, carries its register payload, yields a reproducible marker
  icount, and is inert when disabled; fall back to aarch64-black-box-only if no
  instruction traps precisely. — satisfies [RISK-17], [GHC-16]; spec §30.11.
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
- [ ] **T-RISK-15** Run the **multi-VM-parallelism** spike: vary link latency,
  report achieved host-core parallelism, and confirm the latency floor + lookahead
  budget meet the multi-VM-parallelism target. — satisfies [RISK-22]; spec §30.12.
- [ ] **T-RISK-16** Maintain the **risk register** ([RISK-23]) and enforce the
  Phase-0 gate ([RISK-24]): record each spike result in the decision register,
  block dependent Phase-1 work on the four ★ blockers, and add a new `RISK-n` row
  with an owning spike for any newly-discovered load-bearing assumption. —
  satisfies [RISK-1], [RISK-2], [RISK-3], [RISK-23], [RISK-24]; spec §30.1, §30.13.
- [ ] **T-RISK-17** Run **S11** (Phase-0 blocker ★ for [G-10]): boot a stock
  `-smp 4` image twice under `-accel tcg,thread=single` with a fixed
  `rr_switch_quantum`, the §4.6 elimination set on all vCPUs (incl. deterministic
  IPI/SIPI), and plugin time control; capture the **extended fingerprint** (all N
  vCPUs' registers + RR cursor + [DET-29] mem/device hash) at a cadence and at the
  horizon under an SMP-contended microworkload and adversarial host conditions, and
  diff; localize any mismatch to the first differing node-icount + component. Block
  multi-vCPU foundation work until green; fall back to `-smp 1` if irrecoverable. —
  satisfies [RISK-25], [G-10], [DET-23], [SCHED-45], [PLUG-3]; spec §30.11a.
- [ ] **T-RISK-18** Run **S12**: force a `Decision::Preemption` (vCPU switch for
  `N>1`, timer-interrupt timing for any `N`) at several commanded node-icounts in
  `[deadline, horizon]`, run each twice, and confirm each choice is reproducible,
  that ≥2 choices yield different horizon fingerprints, and that a known race
  manifests under one choice and not another; for `N=1` confirm interrupt-timing
  variation gives distinct reproducible trajectories. Fall back to
  interrupt-timing-only exploration if vCPU-switch injection is unreliable. —
  satisfies [RISK-26], [G-11], [SCHED-46], [DET-12]; spec §30.11b.
- [ ] **T-RISK-19** Run **S13**: sweep `rr_switch_quantum`, reporting per value the
  multi-vCPU throughput against the [`25-performance-targets.md`](25-performance-targets.md)
  budget and the race-surfacing yield via the S12 explorer; record the resolved
  default (closing **D-25**). Correctness-neutral; fall back to a coarser default
  with per-branch explorer overrides. — satisfies [RISK-27], [D-25], [SCHED-45],
  [PLUG-3]; spec §30.11c.
- [ ] **T-RISK-20** Run **S14**: attach the gdbstub at a known icount, confirm
  read-only operations leave the [DET-29] fingerprint and icount unchanged, and
  confirm any gdb single-step is routed through the scheduler's deterministic step
  or refused — never a raw out-of-band icount advance. Default to read-only attach
  + Crucible-driven step/reverse-step (gdb single-step disabled) until green. —
  satisfies [RISK-28], [DBG-1], [SCHED-46]; spec §30.11d.
