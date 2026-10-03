# 09 — Virtual Time and icount

This file defines Crucible's time model: how a node's clock works, what virtual
time *is*, how it relates to the per-node instruction counter, and how the
scheduler reads, commands, and advances it. It is the precise elaboration of
[INV-4] and of the determinism contract's clause [DET-8]–[DET-10]. Running
progress is driven by retirement; an explicit scheduler-owned idle jump adds
logical ticks without adding retired instructions. Everything in
[`08-scheduling.md`](08-scheduling.md)
that talks about a node's *horizon*, and everything in
[`13-shmem-abi.md`](13-shmem-abi.md) that carries a *delivery icount* or a
*max-advance ceiling*, is denominated in the units this file fixes.

Requirement IDs in this file use the prefix `TIME`. Gate names referenced here
(`gate:layer0-determinism`, `gate:single-vm-fingerprint`,
`gate:layer1-injection`, `gate:replay-oracle`) are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). The
QEMU-side mechanisms that make this model real are in
[`10-qemu-integration.md`](10-qemu-integration.md),
[`11-qemu-patches.md`](11-qemu-patches.md), and
[`12-qemu-plugin.md`](12-qemu-plugin.md); the determinism rationale is in
[`04-determinism-contract.md`](04-determinism-contract.md).

## 9.1 The model in one paragraph

Crucible uses one exact simulation tick for each picosecond: 1,000 ticks
per guest nanosecond. A retired guest instruction advances a running `sim`
node by 50 ticks, an initial fixed rate of 20 billion instructions per virtual
second. A scheduler-authorized idle jump can advance logical time
without retiring an instruction, so the raw retired count and logical tick count
are separate coordinates. The scheduler owns logical ticks; the guest-visible
integer nanosecond clock is `floor(logical_ticks / 1000)`. Host wall time never
enters this mapping. An I/O sub-node also schedules completions in exact ticks.
All nodes use the same fixed scale and epoch.

## 9.2 Exact ticks and raw retirement

A virtual nanosecond cannot represent every instruction boundary at the fixed
50 ps instruction rate. Rounding every operation to nanoseconds would merge
1,000 distinct exact coordinates and change horizon, timer, and delivery ordering. The
scheduler therefore uses exact ticks for every ordering-significant quantity.
Raw retired instructions remain available for architectural fingerprints and
instruction-specific fault evidence, but an idle jump changes logical time
without changing raw retirement. Code MUST NOT label a logical tick as a raw
retired-instruction witness.

- **[TIME-1]** A node's canonical scheduling clock MUST be its logical exact
  tick count. A running VM advances it by 50 ticks per retired instruction;
  only an explicit scheduler-authorized idle jump may advance it without a
  retirement. Derived nanoseconds MUST NOT become an independent clock.
  *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`.
  *Spec:* §9.1, §9.2; satisfies [INV-4], [DET-8].

- **[TIME-2]** Architectural trajectory and divergence bisection MUST retain
  the raw retired-instruction coordinate, while scheduler ordering and
  time-derived fingerprints use exact logical ticks. The two coordinates MUST
  be recorded separately after idle jumps. *Gate:* `gate:single-vm-fingerprint`,
  `gate:divergence-bisect`. *Spec:* §9.2; satisfies [DET-2], [INV-4].

## 9.3 Fixed picosecond mapping

The patched `sim` accelerator advances 50 exact ticks per retired instruction.
QEMU's required `-icount shift=0,sleep=off,align=off` is a fixed internal
launch argument; it is not a selectable nanosecond time scale in `sim` mode.
Generic non-`sim` QEMU retains its upstream icount behavior.

- **[TIME-3]** The logical tick is the authoritative time coordinate. The
  conversion at a guest-visible or display boundary MUST be:

  ```text
  guest_ns = floor(logical_ticks / 1000)
  logical_ticks_for_authored_ns = checked(authored_ns * 1000)
  logical_ticks_for_retired = checked(raw_retired * 50 + logical_bias)
  ```

  The conversion MUST use integer arithmetic with overflow rejection. A thousand
  consecutive ticks may share one integer nanosecond, but remain distinct in
  scheduler state, shared memory, event logs, and checkpoints.
  *Gate:* `gate:layer0-determinism`. *Spec:* §9.3; satisfies [DET-8], [INV-4].

- **[TIME-4]** An exact tick horizon, deadline, or delivery coordinate MUST
  remain exact through scheduling and QEMU/plugin handoff. There is no
  per-operation floor/ceil conversion to nanoseconds. Authored whole-nanosecond
  durations enter the model by checked multiplication by 1,000; an exact tick
  duration may be encoded back to a whole-nanosecond field only when divisible
  by 1,000. *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`.
  *Spec:* §9.3; satisfies [DET-11], [INV-4].

  An exact event may fall between two instruction retirement boundaries. The
  CPU budget may stop at the last complete retirement, then the scheduler may
  advance logical time to the exact event tick without a partial retirement.
  The event MUST NOT be snapped to either instruction boundary. If the backend
  cannot attest that time-only advance, it MUST fail closed.

- **[TIME-5]** Crucible MUST launch its patched `sim` QEMU with fixed
  `-icount shift=0,sleep=off,align=off` and MUST reject `shift=auto` or a
  nonzero shift before spawn. This internal argument MUST NOT expose a scenario
  or user shift option. *Gate:* `gate:layer0-determinism`. *Spec:* §9.3;
  satisfies [DET-9], [INV-4].

- **[TIME-6]** The fixed picosecond scale, 50-tick retirement step, and QEMU/plugin build identity
  MUST enter launch and reproduction identity. Exact tick fields in canonical
  material MUST use versioned schemas and domains so older nanosecond material
  cannot be reinterpreted. Replay against a different scale or ABI MUST fail
  closed. *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`.
  *Spec:* §9.3; satisfies [DET-9], [DET-35], [INV-6].

- **[TIME-7]** Every `sim` VM MUST use 1,000 ticks per nanosecond, with one
  retired instruction advancing 50 ticks. The guest-visible nanosecond clock
  floors only at its API boundary. Scenarios MUST NOT offer a shift override.
  *Gate:* `gate:single-vm-fingerprint`. *Spec:* §9.3.

## 9.4 The time types

The host names exact coordinates explicitly. `VirtualInstant`, `SimInstant`,
`SimDuration`, and `VirtualTime` store ticks. `Icount` names a retired-instruction
coordinate only where that is authenticated; `NodeCounter` names the node-local
logical tick coordinate. A scheduler time mapping anchors a backend counter to
the shared timeline and preserves phase across idle jumps and replacements.

- **[TIME-8]** The host engine MUST model time with distinct point, unsigned
  span, and signed offset types. Exact scheduling points and spans MUST store
  ticks. The types MUST prevent adding two instants or constructing a negative
  duration. *Gate:* `gate:harness-lint`. *Spec:* §9.4; satisfies [INV-4],
  [INV-9].

```rust
// Illustrative host-side vocabulary; actual fields and errors are versioned.
pub const TICKS_PER_NS: u64 = 1000;
pub const TICKS_PER_INSTRUCTION: u64 = 50;
pub struct Icount { pub retired: u64 }
pub struct NodeCounter { pub ticks: u64 }
pub struct VirtualInstant { pub ticks: u64 }
pub type SimInstant = VirtualInstant;
pub struct SimDuration { pub ticks: u64 }
pub struct SimOffset { pub ticks: i64 }

impl VirtualInstant {
    pub fn nanoseconds_floor(self) -> u64 { self.ticks / TICKS_PER_NS }
}
```

- **[TIME-9]** A point (`VirtualInstant`, aliased `SimInstant`) MUST be totally
  ordered and support adding a `SimDuration` or taking a non-negative duration
  since another point, but MUST NOT support point + point. `Icount` and
  `NodeCounter` MUST remain distinct from shared timeline points.
  *Gate:* `gate:harness-lint`. *Spec:* §9.4.

- **[TIME-10]** A `SimDuration` MUST be an unsigned exact-tick span; subtraction
  of a later point from an earlier point MUST saturate to zero or fail, never
  wrap. *Gate:* `gate:harness-lint`. *Spec:* §9.4; satisfies [INV-9].

- **[TIME-11]** A signed `SimOffset` MUST remain distinct from a nonnegative
  duration and MUST saturate at the virtual epoch when applied to a point.
  *Gate:* `gate:harness-lint`. *Spec:* §9.4, §9.6.

- **[TIME-12]** Time ordering, comparison, and hashing MUST use exact integer
  coordinates. Clock drift uses fixed-point rational arithmetic with a fixed
  rounding rule, never host floating point. *Gate:* `gate:harness-lint`,
  `gate:layer0-determinism`. *Spec:* §9.4, §9.6; satisfies [INV-9], [DET-26].

## 9.5 Per-node clocks and the shared timeline

Each VM and I/O sub-node has a logical tick counter. The scheduler projects it
onto the shared exact-tick timeline. When a node is idle or powered off, the
scheduler may advance the shared frontier and later re-anchor that node without
inventing raw retired instructions.

- **[TIME-13]** A running VM node MUST advance its logical tick count by 50
  for each retired instruction; an idle node MAY advance only through an
  authenticated scheduler jump. Another node's progress alone MUST NOT move
  this node's counter. *Gate:* `gate:layer0-determinism`. *Spec:* §9.5;
  satisfies [INV-4], [INV-8].

- **[TIME-14]** All nodes MUST share one fixed 1,000-tick-per-nanosecond scale
  and virtual epoch. That fixed scale MUST enter scenario/launch identity;
  no per-node scale or shift setting exists. *Gate:* `gate:layer1-injection`.
  *Spec:* §9.5; satisfies [INV-3], [INV-6].

- **[TIME-15]** Cross-node ordering MUST use exact shared ticks with the
  deterministic total order `(virtual_time, consumer node_id, producer node_id,
  sequence)` of [INV-3]. Device completions and VM frames MUST retain their
  exact tick stamp through delivery. *Gate:* `gate:layer1-injection`.
  *Spec:* §9.5; satisfies [INV-3], references 08.

## 9.6 Clock skew and drift (configured, deterministic)

Real distributed systems run on machines whose clocks disagree: a constant
offset (machine A is 50 ms ahead) and a slow drift (machine B's crystal runs
0.1% fast). Bugs hide in that disagreement — windowed aggregation that assumes
synchronized clocks, lease expiry that straddles a skew boundary. Crucible models
skew *as part of the deterministic scenario*, not as a source of nondeterminism.

- **[TIME-16]** A node MAY be configured with a deterministic **clock skew**: a
  signed `SimOffset` and a `drift_rate` (a fixed-point rational, `1.0` = no
  drift). The skew distorts the *guest-visible* clock reads (RTC, the value
  underlying `clock_gettime`/`gettimeofday`, the TSC base — E4/E5/E6 in
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.6) by a pure
  function of the node's own virtual time:

  ```text
  guest_visible_ns = floor(node.logical_ticks * drift_rate / 1000) + offset_ns
  ```

  Both `offset_ns` and `drift_rate` are part of the scenario content hash. *Gate:*
  `gate:single-vm-fingerprint`, `gate:replay-oracle`. *Spec:* §9.6; satisfies
  [INV-4], [INV-6], references [DET-8].

- **[TIME-17]** Clock skew MUST be applied as exact fixed-point integer
  arithmetic with a fixed, documented rounding rule, never host `f64`
  multiplication whose rounding could vary across builds or hosts. `drift_rate`
  is stored as a rational (e.g. numerator/denominator or a fixed-point scaled
  integer); the multiply-then-floor is reproducible to the nanosecond. *Gate:*
  `gate:layer0-determinism`, `gate:harness-lint`. *Spec:* §9.6; satisfies
  [INV-9], [DET-26].

- **[TIME-18]** Clock skew MUST NOT affect the **scheduling** axis: a node's
  `node.virtual_time` used for horizon computation, cross-node ordering ([INV-3]),
  and delivery-tick decisions ([TIME-4]) is the *unskewed* logical tick
  timeline. Skew is a deterministic distortion of what the guest *reads*, not
  of when the scheduler *runs* the node. This keeps skew a tested feature of the
  deterministic configuration rather than a perturbation of the total order.
  *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §9.6;
  satisfies [INV-3], [INV-4].

The separation in [TIME-18] is the load-bearing subtlety: skew changes the bytes
a guest stores when it reads the clock (so a skewed guest's `T` differs from an
unskewed guest's `T` — *deterministically*, as a function of the configured
skew), but two runs of the *same* skewed scenario produce the identical `T`,
because the skew is a pure function of the node's own logical ticks and the
authenticated idle-jump history. Skew is therefore inside the determinism contract,
not an exception to it.

- **[TIME-19]** The default node clock MUST be a *perfect* clock (offset zero,
  drift_rate one), so that a scenario that does not opt into skew is unaffected
  and the absence of a skew field is byte-identical to the perfect-clock
  configuration. *Gate:* `gate:replay-oracle`. *Spec:* §9.6; satisfies [INV-6].

## 9.7 No realtime, no warp: the plugin owns the clock

The third clause of the exact-tick clock ([DET-10]) is that virtual time advances
*only* by retired instructions and by explicit scheduler-authorized jumps across
idle gaps — never by wall-clock while the guest is idle.

- **[TIME-20]** The guest MUST NOT be able to read host wall-clock or host
  monotonic time. Every guest-visible time source (RTC, TSC, the timer devices
  behind `clock_gettime`/`gettimeofday`) MUST resolve to the node's
  logical-tick-derived virtual time (optionally skewed per §9.6), with a fixed
  configured epoch as the base. No host real-time value may enter `T`. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §9.7;
  satisfies [DET-8], references [DET-10], 04 §4.6 (E4, E5).

- **[TIME-21]** QEMU's idle **warp** — advancing the virtual clock by host
  wall-clock time while the guest is idle — MUST be suppressed whenever the
  Crucible plugin holds time control. Virtual time during idle advances ONLY by
  an explicit, scheduler-authorized jump (§9.8). The suppression is the
  atomic-patch mechanism (E2 in
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.6) and MUST be
  inert unless sim mode is active ([INV-7]). *Gate:* `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §9.7; satisfies [DET-10], [INV-7], forward-refs 11,
  12.

- **[TIME-22]** The instruction budget that bounds a quantum MUST be computed
  from the **virtual** clock only; `QEMU_CLOCK_REALTIME` deadlines MUST NOT enter
  the icount budget (E3 in
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.6). Mixing a
  realtime deadline into the budget would make instructions-per-translation-block
  host-speed-dependent and destroy [DET-1]. This is the fixed-tick (precise)
  budget; the patch enforcing it is inert outside sim mode. *Gate:*
  `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §9.7; satisfies [DET-9],
  [DET-10], [INV-7], forward-ref 11.

- **[TIME-23]** The plugin MUST own the virtual clock for the lifetime of a sim
  run (via the QEMU time-control capability;
  [`12-qemu-plugin.md`](12-qemu-plugin.md)), so that there is a single
  authority — the scheduler, through the plugin — that decides every advancement
  of virtual time ([INV-8]). Time control MUST be acquired before the guest
  retires its first architecturally-visible instruction, so no warp or realtime
  advance can occur before the plugin is in charge. *Gate:*
  `gate:layer0-determinism`, `gate:scheduler-liveness`. *Spec:* §9.7; satisfies
  [INV-8], forward-ref 12.

The consequence of [TIME-20]–[TIME-23] is that "now" inside a VM is a *counter
the host commands*, not a quantity the host races: the only ways the clock moves
are (a) the guest executing instructions up to a commanded ceiling, and (b) the
scheduler authorizing an idle jump to a known deadline. Both are pure functions
of the scenario and schedule.

## 9.8 Next-deadline introspection (exact horizons, not overshoot-and-correct)

When a guest goes idle (executes `HLT` with no runnable work), the scheduler must
know *the exact virtual time of the guest's next self-wakeup* — the earliest
armed guest timer deadline (LAPIC, PIT, HPET, RTC) — so it can compute an exact
local horizon ([`08-scheduling.md`](08-scheduling.md): `horizon(n) = min(next
exact local event, conservative network lookahead)`) and jump the idle node
directly to that deadline. There are two ways to obtain that deadline; Crucible
requires the exact one.

- **[TIME-24]** When a node goes idle, the plugin MUST report the **exact**
  virtual time of the node's next armed guest timer deadline to the scheduler
  (or report "no armed timer"). For a multi-vCPU node, "the node's next armed
  guest timer deadline" is the **minimum over all vCPUs' armed virtual-clock
  deadlines**, expressed on the node's single aggregate timeline; the per-vCPU
  deadlines are plugin-internal and only their minimum surfaces to the scheduler.
  The scheduler MUST use this deadline as the node's *exact local event* in
  horizon computation at the same exact tick ([TIME-4]). This requires the clock-deadline
  introspection capability of the plugin/atomic patch
  ([`12-qemu-plugin.md`](12-qemu-plugin.md),
  [`11-qemu-patches.md`](11-qemu-patches.md)): the plugin reads the next
  `QEMU_CLOCK_VIRTUAL` timer deadline from QEMU's timer subsystem. *Gate:*
  `gate:layer0-determinism`, `gate:scheduler-liveness`. *Spec:* §9.8; satisfies
  [INV-4], [INV-8], references 08, forward-refs 11, 12.

- **[TIME-25]** The "exact next deadline" mechanism is REQUIRED; the inferior
  **overshoot-and-correct** fallback — advance the idle node by a fixed guess,
  observe whether a timer fired, and back off if it overshot — MUST NOT be used
  as the production mechanism. Overshoot-and-correct cannot be made
  bit-deterministic (the guess size and the correction both leak choices that are
  not pure functions of the deadline) and it wastes the very fast-forward it is
  meant to provide. If the exact-deadline capability is unavailable for a given
  QEMU build, the run MUST fail loudly rather than fall back to guessing. *Gate:*
  `gate:layer0-determinism`, `gate:divergence-bisect`. *Spec:* §9.8; satisfies
  [DET-10], [INV-4], [INV-10].

- **[TIME-26]** The deadline reported for horizon computation MUST be derived
  from `QEMU_CLOCK_VIRTUAL` (the logical-tick-derived clock), never from
  `QEMU_CLOCK_REALTIME` or `QEMU_CLOCK_HOST` ([TIME-22]). A deadline read from a
  realtime clock would reintroduce host-time dependence into the horizon and thus
  into the schedule. *Gate:* `gate:layer0-determinism`. *Spec:* §9.8; satisfies
  [DET-9], [INV-4].

Exact introspection is what makes idle fast-forward *both* deterministic and
fast: the scheduler advances an idle node to precisely its next deadline in one
jump (zero wasted instructions, zero host wall-clock), and because the deadline
is a virtual-time quantity, the jump is identical on every run. This is the time
model's contribution to [G-9] (idle time fast-forwarded to zero wall-clock) and
to the exact-horizon discipline of [`08-scheduling.md`](08-scheduling.md).

## 9.9 Exact-tick ceilings and shared-memory handoff

The scheduler computes an exact-tick horizon, publishes the same logical tick
as the max-advance ceiling, and waits for the node's exact reached tick. The
plugin translates this authorization to its raw execution budget while retaining
any idle-bias phase. No nanosecond rounding occurs in the handoff.

- **[TIME-27]** A VM MUST advance only under a published exact logical-tick
  ceiling and MUST report its reached tick before receiving another RUN.
  It MUST NOT advance past that ceiling without a new scheduler authorization.
  *Gate:* `gate:layer0-determinism`, `gate:layer1-injection`. *Spec:* §9.9;
  satisfies [INV-4], [INV-8], [DET-12], references 08.

- **[TIME-28]** The ceiling, current logical tick, and reached tick MUST cross
  the versioned shared-memory protocol ([`13-shmem-abi.md`](13-shmem-abi.md)).
  The futex handoff MUST block without a host busy-wait. A separate raw retired
  count MAY accompany calibration, but MUST NOT be substituted for the logical
  tick. *Gate:* `gate:layer1-injection`, `gate:abi-conformance`. *Spec:* §9.9;
  satisfies [INV-4], [INV-8], forward-ref 13.

- **[TIME-29]** Ceiling arrival, idle, and armed-timer wakeups MUST be reported
  with exact logical tick coordinates. Only the scheduler may decide the next
  ceiling; no host-time path may extend it. *Gate:* `gate:layer0-determinism`,
  `gate:scheduler-liveness`. *Spec:* §9.9; satisfies [INV-8], [INV-4].

- **[TIME-30]** The scheduler horizon, published shared-memory ceiling, and
  reached event MUST denote the same exact tick. An injected input MUST retain
  its exact delivery tick rather than become visible at host arrival time.
  *Gate:* `gate:layer1-injection`. *Spec:* §9.9; satisfies [DET-11], [DET-13],
  [INV-3], references 08, 13.

```text
scheduler horizon (tick) -> shmem ceiling (tick) -> QEMU RUN
        ^                                              |
        +------------- reached tick / idle ------------+
```

## 9.10 Determinism of time

A running VM advances 50 exact ticks per retired instruction. An idle jump is a
separate authenticated change to logical time; raw retirement stays unchanged.
The same scenario, schedule, and inputs must reproduce both coordinates.

- **[TIME-31]** The logical-time trajectory MUST be a deterministic function
  of the raw instruction stream plus scheduler-authorized idle jumps. The same
  inputs MUST reproduce the same `(raw_retired, logical_tick)` sequence on any
  conforming host. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §9.10; satisfies [INV-4], [DET-1],
  [DET-5].

- **[TIME-32]** Horizons, ceilings, delivery ticks, skew, timer deadlines, and
  idle jumps MUST derive only from exact ticks, scenario configuration, and the
  scheduler total order, never host wall time or host thread scheduling.
  *Gate:* `gate:harness-lint`, `gate:layer0-determinism`. *Spec:* §9.10;
  satisfies [INV-4], [INV-9].

- **[TIME-33]** Contract A MUST verify a replay-identical raw-retirement and
  logical-tick trajectory, including an idle jump with preserved subnanosecond
  phase, under adversarial host conditions. Time-derived fingerprints MUST
  match exactly. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §9.10; satisfies [DET-5], [DET-29],
  [INV-4].

### Multi-vCPU nodes: one aggregate clock

All vCPUs execute under the deterministic single-threaded RR schedule. One
aggregate raw retired count records architectural progress; one logical tick
clock adds any scheduler-authorized idle bias.

- **[TIME-34]** The aggregate raw retired count MUST include all vCPUs, with
  per-vCPU counts retained only as separate fingerprint evidence. The shared
  scheduling axis MUST use one aggregate logical tick clock and one epoch;
  no per-vCPU shift or epoch exists. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §9.10; satisfies [INV-4], [DET-5].

- **[TIME-35]** The RR vCPU-switch quantum (`rr_switch_quantum`) MUST be a fixed
  integer number of retired instructions, content-addressed with the scenario.
  It MUST NOT adapt to wall time. *Gate:* `gate:layer0-determinism`,
  `gate:replay-oracle`. *Spec:* §9.10; satisfies [DET-23], [DET-42], [INV-6].

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is virtual time / icount, tracked by [PLAN-3].
> They populate Phase 1 (the determinism / harness / transport / API
> foundation), alongside the determinism-contract tasks of 04.

- [x] **T-TIME-1** Define `VirtualInstant`/`SimInstant` and `SimDuration` in
  exact ticks, `Icount` as a separate raw retired count, and `SimOffset` as a
  signed guest-clock offset. Convert authored whole nanoseconds with checked
  multiplication by 1,000; floor only at guest/API nanosecond boundaries. Ban
  `point + point` and negative `SimDuration`; derive `Ord`/`Eq`/`Hash` on
  integers. — satisfies [TIME-3], [TIME-4], [TIME-8], [TIME-9], [TIME-10],
  [TIME-11], [TIME-12]; spec §9.3, §9.4.
- [x] **T-TIME-2** Pin 1,000 ticks per nanosecond and 50 ticks per retirement into launch identity and
  scenario content hashes; require QEMU's internal `-icount shift=0` profile
  without exposing a shift selector. Reject old shift-based identities and
  document the guest timer implications in the decision register. —
  satisfies [TIME-5], [TIME-6], [TIME-7], [TIME-14]; spec §9.3, §9.5.
- [x] **T-TIME-3** Implement per-node exact logical ticks and the shared
  virtual timeline projection, with the `(virtual_time, consumer node_id, producer node_id, sequence)` total
  order consumed by the scheduler; cover VM nodes and I/O sub-nodes uniformly. —
  satisfies [TIME-1], [TIME-2], [TIME-13], [TIME-15]; spec §9.1, §9.2, §9.5.
- [x] **T-TIME-4** Implement deterministic clock skew (signed `SimOffset` +
  fixed-point `drift_rate`) applied to guest-visible reads only, never to the
  scheduling axis; default perfect clock byte-identical to no-skew; fixed-point
  arithmetic with documented rounding, no `f64` on the path. — satisfies
  [TIME-16], [TIME-17], [TIME-18], [TIME-19]; spec §9.6.
- [ ] **T-TIME-5** Make guest-visible time sources resolve to logical-tick-derived
  virtual time from a fixed epoch; suppress idle warp when the plugin holds time
  control; compute the icount budget from the virtual clock only (no realtime
  deadline); acquire time control before the first visible instruction. —
  satisfies [TIME-20], [TIME-21], [TIME-22], [TIME-23]; spec §9.7.
  `checks.crucible.phase1.timeNoRealtimeWarp` proves the static launch policy,
  registration ordering, and forbidden-host-time scan. T-TIME-5 remains open
  until a loaded production-plugin flight proves ownership before the first
  visible instruction and idle-warp suppression in a running guest.
- [x] **T-TIME-6** Implement exact next-deadline introspection (plugin reads the
  next `QEMU_CLOCK_VIRTUAL` timer deadline) and feed it as the node's exact local
  event to the scheduler horizon; ban the overshoot-and-correct fallback and fail
  loudly if the capability is unavailable. — satisfies [TIME-24], [TIME-25],
  [TIME-26]; spec §9.8.
  Completed by `checks.crucible.phase2.gates.patchMicrotests` and
  `checks.crucible.phase7.productionRustPluginFlight`. The atomic patch gate
  verifies the shipped deadline API, while the loaded production-plugin flight
  observes the exact armed deadline and consumes it as the next idle wake.
- [x] **T-TIME-7** Implement time advancement via the max-advance ceiling: publish
  exact logical tick horizons and reached ticks in the shmem region, preserve
  idle-jump phase through the futex handoff, and forbid any
  node self-extending past the published ceiling. — satisfies [TIME-27],
  [TIME-28], [TIME-29], [TIME-30]; spec §9.9.
  Completed by `checks.crucible.phase1.timeAdvanceCeiling` and
  `checks.crucible.phase7.productionRustPluginFlight`. The component gate covers
  the shared-memory ceiling, futex handoff, conversion, and no-self-extension
  rules. The loaded production-plugin flight advances an all-vCPU-idle guest to
  the exact published deadline without overshoot and reproduces the same wake
  boundary stream after restart.
- [x] **T-TIME-8** Verify determinism of time in isolation under Contract A: a
  single node fed a recorded exact-tick-stamped input list produces a bit-identical
  `(raw_retired, logical_tick)` trajectory and matching time-derived fingerprint
  fields under adversarial host conditions; lint-ban all host-time reads on the
  time path. — satisfies [TIME-31], [TIME-32], [TIME-33]; spec §9.10.
  - Completed by `checks.crucible.phase1.timeContractADeterminism`: the isolated
    `ContractADriver` runs a single node from the same recorded input list
    (`boot`, `network`, and `timer`, each stamped with its delivery tick) under
    fast-many-core, loaded-single-core, and reordered-host-scheduling profiles.
    Every profile produces the same complete `(raw_retired, logical_tick)` trajectory,
    time-derived fingerprint, and execution fingerprint. A payload-independence
    control proves the time-only fingerprint depends on the exact-tick horizon rather
    than input bytes, overflow is rejected, and both the focused gate and the
    workspace harness lint reject host-time reads on the time path.
  - `checks.crucible.phase7.productionRustPluginFlight` corroborates the model
    with exact on-demand boundary samples from the loaded plugin under bounded
    scheduler preemption and proves restart-identical sample and idle-wake
    streams.
- [x] **T-TIME-9** Implement the multi-vCPU single-aggregate-tick clock: derive
  running node ticks from aggregate raw retirements across all `N` vCPUs plus
  the exact idle bias, keep per-vCPU counts plugin-internal, pin the
  `rr_switch_quantum` into the content hash, and compute the node's
  exact next deadline as the minimum over all vCPUs' armed virtual-clock
  deadlines. — satisfies [TIME-24], [TIME-34], [TIME-35]; spec §9.8, §9.10.
  Completed by `checks.crucible.phase1.timeMultiVcpuAggregateClock` and
  `checks.crucible.phase7.productionRustPluginFlight`. The model gate proves the
  aggregate-clock contract. The loaded production flight runs four vCPUs,
  records each vCPU register file, proves the aggregate icount equals the target,
  and observes the exact next deadline and all-vCPU idle wake.
