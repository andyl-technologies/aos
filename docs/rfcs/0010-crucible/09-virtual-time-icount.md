# 09 — Virtual Time and icount

This file defines Crucible's time model: how a node's clock works, what virtual
time *is*, how it relates to the per-node instruction counter, and how the
scheduler reads, commands, and advances it. It is the precise elaboration of
[INV-4] ("a node's virtual time is a pure function of its executed instruction
count") and of the determinism contract's clause [DET-8]–[DET-10] ("icount is
the canonical clock"). Everything in [`08-scheduling.md`](08-scheduling.md)
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

Each node has an **instruction counter** — for a VM node, QEMU's executed-guest-
instruction count under the TCG-derived `-accel sim,thread=single -icount
shift=N` Crucible runtime; for an I/O sub-node, a
host-computed counter advanced by a fixed model
([`15-io-subnodes.md`](15-io-subnodes.md)). This counter is the node's *only*
clock. Virtual nanoseconds are a *derived* view: `ns = icount << shift` for the
fixed integer `shift` recorded in the scenario hash. There is no second clock to
race against — no host monotonic clock, no wall-clock warp, no realtime deadline
folded into the instruction budget. The scheduler ([`08-scheduling.md`](08-scheduling.md))
reads each node's icount-derived virtual time, computes a per-node ceiling (the
*horizon*), tells the node to advance to exactly that ceiling, and waits for it
to arrive there. Because virtual time is a pure function of retired
instructions, two runs of the same `(image, cmdline, seed, injected inputs)`
pass through the identical sequence of `(icount, virtual time)` pairs regardless
of how fast or slow the host executed them.

## 9.2 Why icount is primary, not derived from a nanosecond clock

A naive deterministic-simulation time model makes **virtual nanoseconds**
primary: a global event queue holds events keyed by `ns`, the simulator picks
the earliest, advances every node's clock to that `ns`, runs each node "until it
catches up," and treats instruction count as an unobserved internal detail. This
ns-primary model is adequate when each "node" is in-process host code whose
notion of "now" is a value the harness hands it — there, advancing time *is* just
setting a number, and the node has no independent counter that could disagree.

Crucible's nodes are unmodified guest kernels executing real instructions under a
binary translator. For such a node, "advance the clock to `ns = T`" is not a
free assignment: it is the command *"retire exactly the instructions that fit in
the interval up to `T`."* If the canonical quantity were `ns`, then the number of
instructions executed before a deadline would have to be inferred from the
ns-to-instruction ratio — and the only way to keep that inference stable across
hosts is to fix the ratio, i.e. fix the shift, i.e. *make instruction count the
real unit and `ns` the label*. The ns-primary framing buys nothing and hides the
thing that actually has to be deterministic.

- **[TIME-1]** A node's canonical clock MUST be its executed-instruction count
  (its **icount**); virtual nanoseconds MUST be a derived view of that count, not
  an independent primary quantity. No node may hold a notion of "now" that is not
  a pure function of its own icount. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §9.1, §9.2; satisfies [INV-4], [DET-8].

The instruction-primary choice is what makes the strong contract ([DET-1]:
bit-identical instruction stream `S` and architectural trajectory `T`) even
*statable*. A divergence-bisection ([INV-10], 24) localizes a defect to a single
instruction count precisely because `T` is indexed by icount; if the canonical
axis were `ns`, "the first differing instruction" would be a quantity the model
does not name. Instruction-level determinism and an instruction-primary clock are
the same decision viewed from two sides.

- **[TIME-2]** The time model MUST be designed so that the architectural-state
  trajectory `T` of [DET-1] is indexed by icount, and so that the execution
  fingerprint ([DET-29]) and divergence bisection ([INV-10]) key on icount
  rather than on derived nanoseconds. Derived nanoseconds are a presentation of
  the icount axis, never the axis itself. *Gate:* `gate:single-vm-fingerprint`,
  `gate:divergence-bisect`. *Spec:* §9.2; satisfies [DET-2], [INV-4].

## 9.3 The icount → virtual-ns mapping (fixed shift)

QEMU's `-icount shift=N` models each guest instruction as taking `2^N`
nanoseconds of virtual time. Crucible adopts that mapping verbatim as the single
conversion between the two views of a node's clock.

- **[TIME-3]** Virtual nanoseconds MUST be derived from icount by the fixed
  linear mapping

  ```text
  virtual_ns(icount) = icount << shift          (i.e. icount * 2^shift)
  icount(virtual_ns) = virtual_ns >> shift      (i.e. virtual_ns / 2^shift, floored)
  ```

  for a single configured non-negative integer `shift`. The mapping MUST be
  exact integer arithmetic; no floating point appears on the conversion path.
  *Gate:* `gate:layer0-determinism`. *Spec:* §9.3; satisfies [DET-8], [INV-4].

The forward map (`icount -> ns`) is total and exact. The inverse map
(`ns -> icount`) floors, because a virtual-time deadline rarely lands exactly on
an instruction boundary: a timer programmed for `ns = D` corresponds to "the
first instruction boundary at or after `D >> shift`." This asymmetry is the
entire reason the scheduler reasons in *icount* for advancement and only renders
*ns* for human-facing logs and for guest-visible clock reads (which are
themselves icount-derived inside QEMU; see E4–E6 in
[`04-determinism-contract.md`](04-determinism-contract.md) §4.6).

- **[TIME-4]** When a virtual-time quantity must be converted to an icount that a
  node will be commanded to reach (a horizon, a delivery deadline), the
  conversion MUST round **up** to the next instruction boundary
  (`ceil(virtual_ns / 2^shift)`), so the node never *over*shoots a deadline by
  being told to stop *before* it. When an icount must be rendered as a
  guest-visible or log-visible nanosecond, the conversion uses the exact forward
  map. The rounding direction MUST be fixed and content-addressed with the
  scenario so two builds round identically. *Gate:* `gate:layer1-injection`,
  `gate:single-vm-fingerprint`. *Spec:* §9.3; satisfies [DET-11], [INV-4].

### The shift is fixed, never `auto`

- **[TIME-5]** The icount shift MUST be a fixed integer supplied as
  `-icount shift=N`. Crucible MUST NOT use `-icount shift=auto`, and the harness
  MUST reject a scenario or launch configuration that requests `auto`. *Gate:*
  `gate:layer0-determinism`. *Spec:* §9.3; satisfies [DET-9], [INV-4].

`-icount shift=auto` continuously *recalibrates* the instructions-per-nanosecond
ratio to the measured host execution speed, so that virtual time roughly tracks
wall-clock time. Under `auto`, the number of instructions a guest retires before
a virtual-timer deadline is a function of how fast the host happened to be
running — which is exactly the host-real-time dependence that [INV-4] forbids.
Two runs on hosts of different speeds (or one run under variable host load) would
retire *different instruction counts* before the same timer, producing different
`S` and `T`. A fixed shift makes the ratio a constant of the scenario, so the
instruction count before any deadline is reproducible. This forward-references
the determinism rationale in [`04-determinism-contract.md`](04-determinism-contract.md)
§4.3 [DET-9] and the launch-config pin in
[`10-qemu-integration.md`](10-qemu-integration.md) and
[`11-qemu-patches.md`](11-qemu-patches.md).

- **[TIME-6]** The shift value MUST be part of the scenario's content hash
  ([INV-6]): a change to `shift` is a change to the run, because it changes the
  mapping between deadlines and instruction counts and therefore changes `T`. A
  reproduction artifact ([DET-40]) MUST record the shift, and a run MUST refuse
  to replay against a different shift. *Gate:* `gate:replay-oracle`,
  `gate:e2e-determinism`. *Spec:* §9.3; satisfies [DET-9], [DET-35], [INV-6].

### Choosing the shift

The shift is a modeling knob, not a correctness knob: *any* fixed value yields a
deterministic run. It trades virtual-time *resolution* against the *number of
instructions per virtual nanosecond*.

- A small shift (e.g. `0`–`3`) gives fine virtual-time resolution (1–8 ns per
  instruction) but means a busy guest accumulates virtual time slowly relative to
  the instructions it executes, so virtual deadlines arrive after many
  instructions.
- A large shift (e.g. `8`–`12`) makes each instruction "cost" more virtual time
  (256–4096 ns), so virtual deadlines arrive after fewer instructions and idle
  fast-forward (§9.7) spans more virtual time per jump, at the cost of coarser
  resolution.

- **[TIME-7]** Crucible SHOULD ship a documented default shift chosen so that
  guest-programmed timer intervals (millisecond-to-second scale) resolve to
  instruction counts that are neither so small that timer granularity rounds to
  zero instructions nor so large that a single quantum spans an impractical
  instruction budget; the default and its rationale MUST be recorded in
  [`31-decision-register.md`](31-decision-register.md). A scenario MAY override
  the shift; the override is part of its content hash ([TIME-6]). *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §9.3.

## 9.4 The time types

Crucible's host engine reasons about time with three newtypes plus the icount
itself. They exist to make the icount/ns distinction and the
unsigned/signed distinction *unrepresentable to get wrong*: you cannot add two
instants, cannot construct a negative duration, and cannot silently mix the
node-local icount axis with the shared virtual-time axis.

- **[TIME-8]** The host engine MUST model time with distinct types for *point*,
  *unsigned span*, and *signed offset*, and MUST denominate the canonical per-node
  clock in icount, deriving virtual-time points from it by [TIME-3]. The types
  MUST forbid the meaningless operations (instant + instant; negative duration)
  at the type level. *Gate:* `gate:harness-lint`. *Spec:* §9.4; satisfies
  [INV-4], [INV-9].

The following sketch is illustrative ([CONV-1], 00); the prose requirements are
authoritative.

```rust
// Illustrative sketch — the host-side time vocabulary.
//
// `Icount` is the canonical per-node clock. `VirtualInstant` is the derived
// shared-timeline point. `SimDuration` is an unsigned span; `SimOffset` is a
// signed offset used only for configured clock skew (§9.6). `SimInstant` is a
// re-export alias for `VirtualInstant` used where the shared-timeline reading is
// what matters; the two names denote the same point type.

/// A node's executed-instruction count: the canonical per-node clock (§9.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Icount(pub u64);

/// The fixed instructions-to-nanoseconds shift (`-icount shift=N`), §9.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shift(pub u8);

/// A point on the shared virtual timeline, in virtual nanoseconds since the
/// fixed epoch. Derived from an `Icount` via `Shift` (§9.3). `SimInstant` is an
/// alias for this type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualInstant(pub u64);

/// Alias: the shared-timeline reading of a point.
pub type SimInstant = VirtualInstant;

/// An unsigned span of virtual time. Cannot be negative by construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimDuration(pub u64); // virtual nanoseconds

/// A signed virtual-time offset, used *only* for configured clock skew (§9.6).
/// Distinct from `SimDuration` so a skew (which may be negative) never silently
/// becomes a span (which may not).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimOffset(pub i64); // signed virtual nanoseconds

impl Icount {
    /// Convert to the derived virtual-time point under `shift` (§9.3, exact).
    pub fn to_virtual(self, shift: Shift) -> VirtualInstant {
        VirtualInstant(self.0 << shift.0)
    }
}

impl VirtualInstant {
    pub const EPOCH: Self = Self(0);

    /// Floor-convert to the icount whose instruction *contains* this instant.
    pub fn to_icount_floor(self, shift: Shift) -> Icount {
        Icount(self.0 >> shift.0)
    }

    /// Round up to the first instruction boundary at or after this instant
    /// (§9.3, [TIME-4]): the icount a node is *commanded to reach*.
    pub fn to_icount_ceil(self, shift: Shift) -> Icount {
        let mask = (1u64 << shift.0) - 1;
        Icount((self.0 + mask) >> shift.0)
    }

    /// Saturating span since an earlier instant; never negative (§9.4).
    pub fn duration_since(self, earlier: VirtualInstant) -> SimDuration {
        SimDuration(self.0.saturating_sub(earlier.0))
    }

    /// Apply a signed skew offset, saturating at the epoch (§9.6).
    pub fn with_skew(self, off: SimOffset) -> VirtualInstant {
        VirtualInstant((self.0 as i128 + off.0 as i128).max(0) as u64)
    }
}

impl core::ops::Add<SimDuration> for VirtualInstant {
    type Output = VirtualInstant;
    fn add(self, d: SimDuration) -> VirtualInstant {
        VirtualInstant(self.0 + d.0)
    }
}
// NOTE: there is deliberately no `Add<VirtualInstant> for VirtualInstant`,
// and no `SimDuration` constructor that can take a negative value.
```

- **[TIME-9]** A **point** type (`VirtualInstant`, aliased `SimInstant`)
  represents a position on the shared virtual timeline; it is totally ordered and
  supports `point + SimDuration -> point` and `point.duration_since(point) ->
  SimDuration`, but MUST NOT support `point + point`. `Icount` is the canonical
  per-node point on the instruction axis and converts to `VirtualInstant` by
  [TIME-3]. *Gate:* `gate:harness-lint`. *Spec:* §9.4.

- **[TIME-10]** A **span** type (`SimDuration`) represents an unsigned interval
  of virtual time. It MUST be impossible to construct a negative `SimDuration`;
  `point.duration_since(earlier)` for `earlier > point` MUST saturate to zero
  (or be a programming error caught by the caller), never wrap or go negative.
  Span arithmetic (`span + span`, `span * scalar`) stays non-negative. *Gate:*
  `gate:harness-lint`. *Spec:* §9.4; satisfies [INV-9].

- **[TIME-11]** A **signed offset** type (`SimOffset`, wrapping `i64`
  nanoseconds) represents a directional displacement and MUST be used *only* for
  configured clock skew (§9.6) and similar signed quantities; it MUST be a
  distinct type from `SimDuration` so a skew that may be negative is never
  silently used where a non-negative span is required. Applying a `SimOffset` to
  a `VirtualInstant` MUST saturate at the epoch (virtual time is never negative).
  *Gate:* `gate:harness-lint`. *Spec:* §9.4, §9.6.

- **[TIME-12]** All ordering, comparison, and hashing of time types MUST be exact
  and total: derived `Ord`/`Eq`/`Hash` on integer representations, no
  floating-point comparison on any ordering-significant path ([INV-9]). Where a
  drift rate (§9.6) requires multiplication by a non-integer factor, the
  computation MUST be reduced to fixed-point integer arithmetic with a fixed,
  documented rounding rule, never a host `f64` whose result could vary. *Gate:*
  `gate:harness-lint`, `gate:layer0-determinism`. *Spec:* §9.4, §9.6; satisfies
  [INV-9], [DET-26].

The conversions are intentionally one-directional in ergonomics: `Icount ->
VirtualInstant` is exact and cheap and happens constantly; `VirtualInstant ->
Icount` is a deliberate floor-or-ceil decision ([TIME-4]) the caller must make
explicitly, because it encodes whether a deadline is being *read* (floor: which
instruction are we in) or *commanded* (ceil: which instruction must we reach).

## 9.5 Per-node clocks and the shared virtual timeline

Each node advances its *own* icount independently while it is running. The shared
virtual timeline is the common axis onto which every node's icount-derived
virtual time is projected, and on which the scheduler establishes the total order
of cross-node events ([INV-3]).

- **[TIME-13]** Each node MUST have its own monotone icount and therefore its own
  icount-derived virtual time `node.virtual_time = node.icount << shift`. A
  node's virtual time MUST advance only by that node retiring instructions or by
  a scheduler-authorized idle jump (§9.7); it MUST NOT advance because some other
  node advanced. *Gate:* `gate:layer0-determinism`. *Spec:* §9.5; satisfies
  [INV-4], [INV-8].

- **[TIME-14]** All nodes MUST share a single `shift` and a single virtual-time
  epoch, so that `node.virtual_time` values from different nodes are directly
  comparable points on one axis. The shared `shift`/epoch are part of the
  scenario content hash ([TIME-6]). *Gate:* `gate:layer1-injection`. *Spec:*
  §9.5; satisfies [INV-3], [INV-6].

Using a single shared shift is what makes cross-node comparison meaningful
without a conversion table: a frame stamped "deliver at virtual time `D`"
([DET-11]) means the same instant on every node's timeline, and each receiving
node converts `D` to its own delivery icount with the same `ceil` map ([TIME-4]).
Per-node *skew* (§9.6) is layered on *top* of this shared axis as a configured,
deterministic distortion of guest-visible reads — it does not give nodes
different shifts or different epochs on the scheduling axis.

- **[TIME-15]** Cross-node ordering MUST use the shared virtual timeline, with
  the deterministic total order `(virtual_time, consumer node_id, producer node_id, sequence)` of [INV-3]
  (see [`08-scheduling.md`](08-scheduling.md) §8.6 for the full key; `node_id` here
  is the consumer, with producer and sequence as further tiebreaks)
  resolving simultaneity. The mapping from each node's icount to this shared axis
  is exactly [TIME-3]; the scheduler ([`08-scheduling.md`](08-scheduling.md))
  consumes virtual-time points on this axis and converts each to the relevant
  node's delivery icount. *Gate:* `gate:layer1-injection`. *Spec:* §9.5;
  satisfies [INV-3], references 08.

```text
   node A icount ──(<<shift)──┐
                              ├──► shared virtual timeline ──► total order
   node B icount ──(<<shift)──┘        (virtual_time, consumer node_id, producer node_id, sequence)
                              │
   io sub-node counter ──(<<shift)──┘   (I/O completions, §9.5 / 15)
```

An **I/O sub-node** ([`15-io-subnodes.md`](15-io-subnodes.md)) has a counter
rather than a guest icount, but it participates on the same axis: it computes a
completion at a virtual time derived from its own counter under the same shift,
and that completion is delivered to the requesting VM at a delivery icount via
[TIME-4]. The time model treats VM nodes and I/O sub-nodes uniformly: a node is
anything with a monotone counter projected onto the shared timeline.

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
  guest_visible_ns = floor(node.virtual_time * drift_rate) + offset_ns
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
  and delivery-icount conversion ([TIME-4]) is the *unskewed* icount-derived
  virtual time. Skew is a deterministic distortion of what the guest *reads*, not
  of when the scheduler *runs* the node. This keeps skew a tested feature of the
  deterministic configuration rather than a perturbation of the total order.
  *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §9.6;
  satisfies [INV-3], [INV-4].

The separation in [TIME-18] is the load-bearing subtlety: skew changes the bytes
a guest stores when it reads the clock (so a skewed guest's `T` differs from an
unskewed guest's `T` — *deterministically*, as a function of the configured
skew), but two runs of the *same* skewed scenario produce the identical `T`,
because the skew is a pure function of the node's own virtual time, which is a
pure function of its icount. Skew is therefore inside the determinism contract,
not an exception to it.

- **[TIME-19]** The default node clock MUST be a *perfect* clock (offset zero,
  drift_rate one), so that a scenario that does not opt into skew is unaffected
  and the absence of a skew field is byte-identical to the perfect-clock
  configuration. *Gate:* `gate:replay-oracle`. *Spec:* §9.6; satisfies [INV-6].

## 9.7 No realtime, no warp: the plugin owns the clock

The third clause of icount-as-clock ([DET-10]) is that virtual time advances
*only* by retired instructions and by explicit scheduler-authorized jumps across
idle gaps — never by wall-clock while the guest is idle.

- **[TIME-20]** The guest MUST NOT be able to read host wall-clock or host
  monotonic time. Every guest-visible time source (RTC, TSC, the timer devices
  behind `clock_gettime`/`gettimeofday`) MUST resolve to the node's
  icount-derived virtual time (optionally skewed per §9.6), with a fixed
  configured epoch as the base. No host real-time value may enter `T`. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §9.7;
  satisfies [DET-8], references [DET-10], 04 §4.6 (E4, E5).

- **[TIME-21]** QEMU's idle **warp** — advancing the virtual clock by host
  wall-clock time while the guest is idle — MUST be suppressed whenever the
  Crucible plugin holds time control. Virtual time during idle advances ONLY by
  an explicit, scheduler-authorized jump (§9.8). The suppression is the
  patch-series mechanism (E2 in
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.6) and MUST be
  inert unless sim mode is active ([INV-7]). *Gate:* `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §9.7; satisfies [DET-10], [INV-7], forward-refs 11,
  12.

- **[TIME-22]** The instruction budget that bounds a quantum MUST be computed
  from the **virtual** clock only; `QEMU_CLOCK_REALTIME` deadlines MUST NOT enter
  the icount budget (E3 in
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.6). Mixing a
  realtime deadline into the budget would make instructions-per-translation-block
  host-speed-dependent and destroy [DET-1]. This is the fixed-shift (precise)
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
  horizon computation, converting it to a target icount via the `ceil` map
  ([TIME-4]). This requires the clock-deadline
  introspection capability of the plugin/patch series
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
  from `QEMU_CLOCK_VIRTUAL` (the icount-derived clock), never from
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

## 9.9 Time advancement: ceilings, the shmem ceiling, and the futex handoff

The scheduler advances a node by computing its horizon (a virtual-time point),
converting it to a **max-advance ceiling** (a target icount via [TIME-4]),
publishing that ceiling to the node, letting the node run until it reaches the
ceiling, and waiting for the node to report arrival. This is the per-node
realization of one scheduler quantum ([`08-scheduling.md`](08-scheduling.md)).

- **[TIME-27]** The scheduler MUST advance a node by giving it an explicit
  **max-advance ceiling** in icount (the horizon converted by [TIME-4]) and the
  node MUST run under `-icount` until its icount reaches exactly that ceiling
  (the first translation-block boundary at or after it), then stop and report.
  The node MUST NOT advance past the ceiling without a new authorization. *Gate:*
  `gate:layer0-determinism`, `gate:layer1-injection`. *Spec:* §9.9; satisfies
  [INV-4], [INV-8], [DET-12], references 08.

- **[TIME-28]** The max-advance ceiling and the node's current icount/virtual
  time MUST be carried in the per-node shared-memory region
  ([`13-shmem-abi.md`](13-shmem-abi.md)): the scheduler writes the ceiling, the
  node publishes its reached icount, and the handoff at idle/advance boundaries
  is coordinated by a futex (or equivalent) on that region so the node blocks
  with no busy-wait and resumes when the scheduler raises the ceiling. The
  ceiling and the reached-icount fields are denominated in the icount units of
  this file. *Gate:* `gate:layer1-injection`, `gate:abi-conformance`. *Spec:*
  §9.9; satisfies [INV-4], [INV-8], forward-ref 13.

- **[TIME-29]** A node reaching its ceiling, going idle before its ceiling, or
  hitting an armed deadline MUST be reported to the scheduler as a virtual-time
  / icount fact, and the scheduler — the single authority ([INV-8]) — MUST decide
  the next ceiling. There MUST be no path by which a node sets its own next
  ceiling from host timing or self-extends past the published ceiling. *Gate:*
  `gate:layer0-determinism`, `gate:scheduler-liveness`. *Spec:* §9.9; satisfies
  [INV-8], [INV-4].

- **[TIME-30]** The relationship between the three quantities MUST be exactly:
  the scheduler's **horizon** (08, a virtual-time point) → the **max-advance
  ceiling** (this file, an icount via [TIME-4]) → the **shmem ceiling field**
  (13, the wire form the node reads). All three denote the same instant; the
  conversions between them are [TIME-3]/[TIME-4] and are exact and
  content-addressed. A delivery icount for an injected input ([DET-11]) is
  computed by the same conversion so that the input becomes visible at exactly
  its delivery icount, never at "whenever it arrived." *Gate:*
  `gate:layer1-injection`. *Spec:* §9.9; satisfies [DET-11], [DET-13], [INV-3],
  references 08, 13.

```text
  scheduler (08)            this file (09)              shmem ABI (13)
  ─────────────            ──────────────              ──────────────
  horizon: VirtualInstant  ──ceil(>>shift)──► ceiling: Icount ──► ceiling field
       │                                                              │
       │ run node under -icount                                       │ node reads,
       ▼                                                              ▼ runs, blocks
  node reaches ceiling ◄──── reached: Icount ◄──── reached-icount field (futex wake)
```

## 9.10 Determinism of time (the [INV-4] guarantee)

The whole point of this file is one sentence: a node's virtual time is a pure
function of its executed instruction count, and no node's progress depends on
host real time.

- **[TIME-31]** A node's virtual time MUST be a pure function of its own
  executed-instruction count under the fixed shift ([TIME-3]); given the same
  `(image, cmdline, seed, icount-stamped injected inputs)`, the node MUST pass
  through the identical sequence of `(icount, virtual_time)` pairs on every run
  and on any conforming host, regardless of host CPU speed, host load, host
  scheduling, or number of host cores. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §9.10; satisfies [INV-4], [DET-1],
  [DET-5].

- **[TIME-32]** No quantity on the time path — not a horizon, a ceiling, a
  delivery icount, a skew application, a next-deadline read, or an idle jump —
  may be a function of host wall-clock, host monotonic time, or host thread
  scheduling order. Every such quantity MUST be derived from icount, the fixed
  shift, the scenario configuration, and the scheduler's total order. A code path
  that would read host time on the time path MUST be banned by the harness lint
  ([INV-9]) and MUST fail the build. *Gate:* `gate:harness-lint`,
  `gate:layer0-determinism`. *Spec:* §9.10; satisfies [INV-4], [INV-9].

- **[TIME-33]** The time model MUST be verifiable in isolation as part of
  Contract A ([DET-5]): a single node fed an icount-stamped recorded input list,
  with no scheduler or transport, MUST produce a bit-identical
  `(icount, virtual_time)` trajectory across runs under adversarial host
  conditions ([DET-38]). The time-derived fields of the execution fingerprint
  ([DET-29]) MUST match exactly. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §9.10; satisfies [DET-5], [DET-29], [INV-4].

### Multi-vCPU nodes: one aggregate icount

A multi-vCPU node ([DET-5], [DET-23]) runs all `N` vCPUs single-threaded under
round-robin TCG + `-icount`. This does NOT introduce per-vCPU clocks on the time
axis: the node still has exactly one clock.

- **[TIME-34]** For a multi-vCPU node, the node's icount MUST be the **aggregate
  retired-instruction count across all `N` vCPUs**, and that aggregate icount
  remains THE node clock for every purpose in this file (virtual-time
  derivation [TIME-3], horizon/ceiling [TIME-27], cross-node ordering [TIME-15],
  delivery-icount conversion [TIME-4]). Per-vCPU retired counts are
  plugin-internal and surface only in the execution fingerprint ([DET-29]); the
  shared timeline MUST use the node aggregate, and there MUST be no per-vCPU
  shift or per-vCPU epoch. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §9.10; satisfies [INV-4], [DET-5].

- **[TIME-35]** The RR vCPU-switch quantum (`rr_switch_quantum`) MUST be denominated
  in **node-icount units**, MUST be a fixed integer, and MUST be content-addressed
  with the scenario ([TIME-6], [DET-42]); it MUST NOT be adaptive (never QEMU's
  `rr_quantum`) nor derived from realtime. A change to `rr_switch_quantum` is a
  change to the run because it changes the multi-vCPU interleaving and therefore
  `T`. *Gate:* `gate:layer0-determinism`, `gate:replay-oracle`. *Spec:* §9.10;
  satisfies [DET-23], [DET-42], [INV-6].

If [TIME-31]–[TIME-33] hold, the determinism contract's icount-as-clock clause is
met: `reduce` ([INV-1]) has no free time variable, the replay oracle ([INV-2])
can hold by construction, and a divergence on the time axis localizes to a single
icount. Every other timing-sensitive guarantee in the RFC — exact injection
([DET-11]), total cross-node order ([INV-3]), idle fast-forward to zero
wall-clock ([G-9]) — rests on this file's mapping being fixed, exact, and
instruction-primary.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is virtual time / icount, tracked by [PLAN-3].
> They populate Phase 1 (the determinism / harness / transport / API
> foundation), alongside the determinism-contract tasks of 04.

- [x] **T-TIME-1** Define the host time vocabulary — `Icount`, `Shift`,
  `VirtualInstant`/`SimInstant`, `SimDuration` (unsigned), `SimOffset` (signed) —
  with exact integer `to_virtual`/`to_icount_floor`/`to_icount_ceil` conversions,
  no `point + point`, no negative `SimDuration`, derived `Ord`/`Eq`/`Hash` on
  integers. — satisfies [TIME-3], [TIME-4], [TIME-8], [TIME-9], [TIME-10],
  [TIME-11], [TIME-12]; spec §9.3, §9.4.
- [x] **T-TIME-2** Pin the fixed shift into the launch configuration and scenario
  content hash; reject `-icount shift=auto` and any per-node shift mismatch; ship
  and document a default shift with rationale in the decision register. —
  satisfies [TIME-5], [TIME-6], [TIME-7], [TIME-14]; spec §9.3, §9.5.
- [x] **T-TIME-3** Implement per-node icount-derived virtual time and the shared
  virtual timeline projection, with the `(virtual_time, consumer node_id, producer node_id, sequence)` total
  order consumed by the scheduler; cover VM nodes and I/O sub-nodes uniformly. —
  satisfies [TIME-1], [TIME-2], [TIME-13], [TIME-15]; spec §9.1, §9.2, §9.5.
- [x] **T-TIME-4** Implement deterministic clock skew (signed `SimOffset` +
  fixed-point `drift_rate`) applied to guest-visible reads only, never to the
  scheduling axis; default perfect clock byte-identical to no-skew; fixed-point
  arithmetic with documented rounding, no `f64` on the path. — satisfies
  [TIME-16], [TIME-17], [TIME-18], [TIME-19]; spec §9.6.
- [ ] **T-TIME-5** Make guest-visible time sources resolve to icount-derived
  virtual time from a fixed epoch; suppress idle warp when the plugin holds time
  control; compute the icount budget from the virtual clock only (no realtime
  deadline); acquire time control before the first visible instruction. —
  satisfies [TIME-20], [TIME-21], [TIME-22], [TIME-23]; spec §9.7.
- [x] **T-TIME-6** Implement exact next-deadline introspection (plugin reads the
  next `QEMU_CLOCK_VIRTUAL` timer deadline) and feed it as the node's exact local
  event to the scheduler horizon; ban the overshoot-and-correct fallback and fail
  loudly if the capability is unavailable. — satisfies [TIME-24], [TIME-25],
  [TIME-26]; spec §9.8.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantum`, which records the
  plugin reading the exact next `QEMU_CLOCK_VIRTUAL` timer deadline and feeding it
  to the scheduler as the node's exact local event: at idle onset the gate emits
  `idle_next_deadline_icount` equal to the introspected, ceil-converted deadline
  with no overshoot-and-correct, the scheduler consumes it as the idle horizon,
  and the value is identical on both runs. Advancing the node to that deadline is
  T-TIME-7 / T-PLUG-7. The fail-loud-on-missing-capability and QEMU-export
  microtest halves are held by `checks.crucible.phase1.clockDeadline`.
- [ ] **T-TIME-7** Implement time advancement via the max-advance ceiling: convert
  horizon → ceiling icount ([TIME-4]), publish ceiling and reached-icount in the
  shmem region, coordinate the idle/advance handoff with a futex, and forbid any
  node self-extending past the published ceiling. — satisfies [TIME-27],
  [TIME-28], [TIME-29], [TIME-30]; spec §9.9.
- [ ] **T-TIME-8** Verify determinism of time in isolation under Contract A: a
  single node fed a recorded icount-stamped input list produces a bit-identical
  `(icount, virtual_time)` trajectory and matching time-derived fingerprint
  fields under adversarial host conditions; lint-ban all host-time reads on the
  time path. — satisfies [TIME-31], [TIME-32], [TIME-33]; spec §9.10.
- [ ] **T-TIME-9** Implement the multi-vCPU single-aggregate-icount clock: derive
  the node clock from the aggregate retired-instruction count across all `N`
  vCPUs (no per-vCPU shift/epoch), keep per-vCPU counts plugin-internal, pin the
  node-icount `rr_switch_quantum` into the content hash, and compute the node's
  exact next deadline as the minimum over all vCPUs' armed virtual-clock
  deadlines. — satisfies [TIME-24], [TIME-34], [TIME-35]; spec §9.8, §9.10.
