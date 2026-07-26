# 17 — Fault injection: the deterministic fault model

This file specifies Crucible's **fault model**: the complete taxonomy of
perturbations a scenario may impose on the simulated world, the exact semantics
of each, how every probabilistic fault decision is drawn deterministically from
the seeded decision RNG, where each fault lives in the runtime, how faults are
scheduled declaratively in the `Plan` and injected imperatively over the control
plane, and how a weighted random generator produces reproducible fault campaigns
for fuzzing. Faults are the **one** kind of thing that belongs in the `Plan`
([`06-spatial-graph.md`](06-spatial-graph.md) §5.1, [SPAT-2], [SPAT-33]):
topology lives in the `World`, assertions in the `Properties`, and *only*
faults/events are events.

Requirement IDs in this file use the `FAULT` prefix (see
[`00-conventions.md`](00-conventions.md)). The fault model upholds [INV-1]
(purity of reduction — a fault's effect is a pure function of virtual time and
the seeded RNG), [INV-3] (total order — fault activation is a cross-node event
keyed by `(virtual_time, consumer node_id, producer node_id, sequence)`), and [INV-10] (no silent
nondeterminism — every probabilistic fault routes through the decision RNG or
fails loudly). It feeds the `Plan` component of the `ScenarioDef`
([`06-spatial-graph.md`](06-spatial-graph.md)), is activated by the scheduler at
exact virtual times ([`08-scheduling.md`](08-scheduling.md) §8.9.4, [SCHED-29]),
perturbs delivery on links and I/O sub-nodes
([`15-io-subnodes.md`](15-io-subnodes.md) §15.4, §15.6), is recorded as
`Decision`s in the `Schedule` ([`05-execution-model.md`](05-execution-model.md)),
is exercised by imperative control commands
([`20-session-control-plane.md`](20-session-control-plane.md)), and is generated
for exploration by a `ScenarioFamily`
([`06-spatial-graph.md`](06-spatial-graph.md) §7,
[`22-advanced-features.md`](22-advanced-features.md)).

The code blocks here are illustrative `rust`/`text`/`toml` sketches per
[`00-conventions.md`](00-conventions.md) §"Code sketches in this RFC": they show
the intended type and wire shapes so the spec is concrete, but the authority is
the prose requirement. A sketch that disagrees with a requirement is a defect in
the sketch.

## 17.1 What a fault is, and the one design rule

A **fault** is a perturbation that, while active, alters how the simulated world
behaves: it drops or delays a frame, mutates a payload, stops a node, slows a
node's progress, fails an I/O, or skews a guest's perceived time. A fault is
**not** a topology edit ([SPAT-16]): the node and link it affects remain declared
members of the static `World`; what changes is whether — and how — they *behave*.
A crash is `Fault::Crash` over a still-declared node; a partition is
`Fault::Partition` over still-declared links; a heal removes the perturbation and
restores declared behavior. Membership dynamics (crash/restart, partition/heal,
isolation, rejoin) are *all* expressed this way ([SPAT-17]).

The one design rule that governs the whole model:

> **A fault perturbs the *modeled* behavior, never the host.** Network faults
> perturb a frame's modeled delivery icount and/or payload; I/O faults perturb a
> device's modeled completion icount and/or response; node faults perturb a VM's
> modeled execution. No fault ever consults host wall-clock, host scheduling,
> host filesystem timing, or host entropy. Every probabilistic choice a fault
> makes is a draw from the single seeded decision RNG, consumed in the
> scheduler's total order ([SCHED-30]) and recorded as a `Decision`.

This rule is what makes a fault-injected run as reproducible as a fault-free one:
the fault is part of `reduce(ScenarioDef, Schedule)` ([INV-1]), not an
out-of-band poke at the host.

- **[FAULT-1]** A fault MUST perturb only the *modeled* behavior of a node, link,
  or I/O sub-node — its modeled delivery/completion icount, its modeled payload,
  or its modeled execution — and MUST NOT consult or depend on host wall-clock,
  host thread scheduling, host filesystem timing/ordering, or host entropy. A
  fault MUST NOT mutate the topology of the `World` ([SPAT-16]); the affected node
  or link remains declared and the fault changes only its behavior for the fault's
  active interval. *Gate:* `gate:layer1-injection`, `gate:e2e-determinism`.
  *Spec:* §17.1; cross-ref 06 §4, 15 §15.6.

- **[FAULT-2]** Every probabilistic decision a fault makes (does a lossy link
  drop this frame; how much jitter does a jitter fault add; does a duplicate
  fire; which bits does a bit-flip corruption flip) MUST be a draw from the single
  seeded decision RNG ([`04-determinism-contract.md`](04-determinism-contract.md)
  §4.7), consumed in the scheduler's deterministic total order ([SCHED-30]), and
  recorded as a `Decision` in the `Schedule` so replay reproduces it without
  re-rolling. There MUST be no other source of fault randomness. *Gate:*
  `gate:harness-lint`, `gate:replay-oracle`. *Spec:* §17.1, §17.3; cross-ref 04,
  05, 08 §8.9.4.

## 17.2 The fault taxonomy

The taxonomy is grouped by *where the fault lives* in the runtime: **network**
faults on links/the delivery path; **node** faults on the VM; **block** faults on
the disk sub-node; and **9p** faults on the filesystem sub-node. Block and 9p
faults are, semantically, the I/O specialization of the same vocabulary as
network faults ([IO-25], [IO-26], §17.5): a latency fault shifts a delivery
icount whether the thing delivered is a frame or an I/O response.

```rust,illustrative
/// Every fault kind Crucible can inject. Grouped by where it lives: network
/// faults on links (15 §15.4), node faults on the VM (10), block faults on the
/// disk sub-node (15 §15.2), 9p faults on the filesystem sub-node (15 §15.3).
/// All probabilistic parameters are integer basis points (§17.3), not floats,
/// so the canonical hash is exact across hosts ([SPAT-30], §17.3).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Fault {
    // ── network (on a link / the delivery path) ──────────────────────────
    /// Suppress frame delivery across the affected directed edge(s) for the
    /// fault's active interval. Models split-brain, isolation, asymmetric loss.
    Partition { between: (NodeId, NodeId), direction: PartitionDirection },
    /// Independently drop each frame on the link with probability `rate_bp`.
    MessageLoss { link: Link, rate_bp: Bp },
    /// Add a seeded per-frame extra delay in `[0, window]`, possibly moving a
    /// frame's delivery past a later peer's (reorder via delay perturbation).
    Reorder { link: Link, window: VirtualDuration },
    /// Emit an additional identical frame with probability `rate_bp` (the
    /// duplicate carries its own delivery icount and total-order sequence).
    Duplicate { link: Link, rate_bp: Bp },
    /// Corrupt each frame's payload with probability `rate_bp` per the strategy.
    Corruption { link: Link, rate_bp: Bp, strategy: CorruptionStrategy },
    /// Cap the link's throughput to `bps` bits per virtual second, adding a
    /// deterministic serialization delay proportional to frame length.
    BandwidthLimit { link: Link, bps: u64 },
    /// Add a fixed extra one-way latency to the link (raises lookahead; safe).
    LatencyBump { link: Link, extra: VirtualDuration },

    // ── node (on the VM) ─────────────────────────────────────────────────
    /// Stop the node's runtime: it retires no instructions, its in-flight I/O is
    /// discarded, its connections break. A heal restarts it from the ready point
    /// (or a saved state per `RestartPolicy`).
    Crash { node: NodeId, restart: RestartPolicy },
    /// Slow a node's modeled progress by `factor_bp/10000` (≥ 1.0): the node
    /// retires the same instructions but its virtual-time mapping is stretched.
    Slow { node: NodeId, factor_bp: Bp },
    /// Skew a node's *perceived* wall-clock-style time source by a signed offset
    /// (its instruction-count virtual time is unchanged; only guest-readable
    /// time-of-day / RTC reads are offset).
    ClockSkew { node: NodeId, offset: SignedVirtualDuration },

    // ── block (on the disk sub-node, 15 §15.2) ───────────────────────────
    /// Shift a block response's delivery icount later (latency / jitter).
    BlockLatency { node: NodeId, extra: VirtualDuration, jitter: VirtualDuration },
    /// Return an error-status block response (or drop it) with prob. `rate_bp`.
    BlockFailure { node: NodeId, rate_bp: Bp, mode: IoFailureMode },
    /// Shift one block response's delivery past another within `window`.
    BlockReorder { node: NodeId, window: VirtualDuration },

    // ── 9p (on the filesystem sub-node, 15 §15.3) ────────────────────────
    /// Shift a 9p response's delivery icount later (latency / jitter).
    NinepLatency { node: NodeId, extra: VirtualDuration, jitter: VirtualDuration },
    /// Return a 9p error response (e.g. EIO) with probability `rate_bp`.
    NinepFailure { node: NodeId, rate_bp: Bp, errno: NinepErrno },
}

/// Direction of a partition over a declared link.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartitionDirection {
    /// Both directed edges A→B and B→A suppressed.
    Bidirectional,
    /// Only A→B suppressed; B→A still delivers (asymmetric).
    AtoB,
    /// Only B→A suppressed; A→B still delivers (asymmetric).
    BtoA,
}

/// How a payload is corrupted when a corruption fault fires.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CorruptionStrategy {
    /// Flip `count` seeded-selected bit positions in the payload.
    BitFlip { count: u16 },
    /// Mutate a parsed field to another in-range value (seeded).
    FieldMutation,
    /// Truncate the payload to a seeded shorter length.
    Truncation,
}

/// What a failed block I/O looks like to the guest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoFailureMode {
    /// Return an error-status response at the computed completion icount.
    ErrorStatus,
    /// Drop the response entirely (the request never completes).
    Drop,
}

/// How a crashed node behaves when its crash fault is healed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestartPolicy {
    /// Reboot from the baked genesis ready point (fresh state).
    FromReadyPoint,
    /// Resume from the node's last pre-crash checkpoint (state-preserving),
    /// modeling WAL/persistent-overlay recovery.
    FromLastCheckpoint,
    /// Stay down until explicitly healed/restarted (no automatic restart).
    StayDown,
}

/// An integer probability in basis points: `0..=10_000` (0% .. 100%). Used in
/// place of `f64` so the canonical hash is exact across hosts (§17.3).
pub struct Bp(pub u16);

/// A directed or canonically-ordered link reference between two declared nodes.
pub struct Link(pub NodeId, pub NodeId);
```

- **[FAULT-3]** Crucible MUST support the network fault kinds **partition**
  (bidirectional / A→B / B→A), **message loss**, **reorder**, **duplicate**,
  **corruption** (bit-flip / field-mutation / truncation), and **bandwidth
  limit**, each as a perturbation of a frame's modeled delivery icount and/or
  payload on the affected link ([IO-20]). A **latency bump** that raises a link's
  effective latency MUST also be supported as a network fault. *Gate:*
  `gate:layer1-injection`. *Spec:* §17.2; cross-ref 15 §15.4.

- **[FAULT-4]** Crucible MUST support the node fault kinds **crash** (with a
  `RestartPolicy`), **slow** (a modeled progress factor ≥ 1.0), and **clock
  skew** (a signed offset applied to the guest's *perceived* time-of-day source
  only, never to its instruction-count virtual time, §17.4.4). *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §17.2, §17.4.

- **[FAULT-5]** Crucible MUST support the block fault kinds **latency** (shift the
  response delivery icount), **failure** (error-status or drop), and **reorder**
  (shift one response's delivery past another within a window), each as a
  perturbation of the disk sub-node's modeled completion/response ([IO-25]).
  *Gate:* `gate:layer1-injection`. *Spec:* §17.2; cross-ref 15 §15.2, §15.6.

- **[FAULT-6]** Crucible MUST support the 9p fault kinds **latency** (shift the
  response delivery icount) and **failure** (return a 9p error response), each as
  a perturbation of the 9p sub-node's modeled completion/response ([IO-25]).
  *Gate:* `gate:layer1-injection`. *Spec:* §17.2; cross-ref 15 §15.3, §15.6.

- **[FAULT-7]** A **partition** fault MUST carry a `PartitionDirection` of
  `Bidirectional`, `AtoB`, or `BtoA`, and MUST suppress delivery on exactly the
  directed edge(s) the direction names ([SCHED-38]): `Bidirectional` suppresses
  both A→B and B→A; `AtoB` suppresses only A→B (B→A still delivers); `BtoA`
  suppresses only B→A. Asymmetric partitions MUST be expressible so
  acknowledgment-based and timeout behaviors can be tested. *Gate:*
  `gate:layer1-injection`. *Spec:* §17.2; cross-ref 08 §8.11.

- **[FAULT-8]** A **corruption** fault MUST support the strategies **bit-flip**
  (flip a seeded set of bit positions, count parameterized), **field-mutation**
  (mutate a parsed field to another in-range value, seeded), and **truncation**
  (shorten the payload to a seeded length). Every byte the corruption produces
  MUST be a deterministic function of the original payload and the seeded RNG
  draws ([FAULT-2]); a corrupted payload MUST still be a well-formed transport
  frame (the corruption is in the *payload bytes*, not in the transport framing,
  so the consumer receives a deliverable but semantically-mutated message).
  *Gate:* `gate:layer1-injection`. *Spec:* §17.2; cross-ref 13.

- **[FAULT-9]** A **duplicate** fault MUST emit an *additional* frame identical to
  the original; the duplicate MUST carry its own `delivery_icount` and its own
  total-order `sequence` ([SCHED-18]) so both the original and the duplicate are
  ordered deterministically at the consumer. A **reorder** fault MUST be modeled
  as a per-frame seeded delivery-icount shift that MAY move one frame's delivery
  past another's, and MUST obey [IO-34]: the shifted delivery icount MUST remain
  in the consumer's future at enqueue time, never the consumer's past. *Gate:*
  `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §17.2; cross-ref 15
  §15.4.2.

- **[FAULT-10]** A **bandwidth-limit** fault MUST add a deterministic
  serialization delay proportional to the frame/transfer length and inversely
  proportional to the configured bits-per-virtual-second, computed in integer
  virtual-time arithmetic (no host-dependent float), and MUST shift the delivery
  icount by that delay. A **latency bump** (network) and a **block/9p latency**
  fault MUST likewise shift the delivery icount by a deterministic amount; the
  optional jitter component MUST be a seeded draw in `[0, jitter]` ([FAULT-2]).
  *Gate:* `gate:layer1-injection`. *Spec:* §17.2; cross-ref 15 §15.4.1, §15.6.

## 17.3 Determinism of faults

Faults are the most determinism-sensitive feature in Crucible because they are
the deliberate injection of *choice* into the run. The model is built so that
every choice is anchored to the seeded decision RNG, consumed in a fixed order,
and recorded — so a fault-injected run reduces as purely as a fault-free one.

### 17.3.1 The decision RNG, consumed in total order

Every probabilistic fault choice is a draw from the single seeded **decision
RNG** ([`04-determinism-contract.md`](04-determinism-contract.md)). The draws are
consumed in the scheduler's deterministic total order ([SCHED-15], [SCHED-30]):
when RESOLVE processes the due cross-node events in `(virtual_time, consumer
node_id, producer node_id, sequence)` order, it draws for each fault decision in
that same order, so the *sequence* of draws is itself a pure function of the
total order, never of host scheduling. Per-device and per-link RNG streams are
forked by name-hash ([IO-21], [EXEC-9]) so adding or renaming an unrelated node
or link does not perturb another stream's draw sequence.

- **[FAULT-11]** All probabilistic fault decisions MUST be drawn from the single
  seeded decision RNG in the scheduler's total order ([SCHED-15], [SCHED-30]): the
  draw sequence MUST be a pure function of `(ScenarioDef, Seed, Schedule)` and the
  total order, never of host scheduling or wall-clock. The per-link / per-device
  RNG stream MUST be forked by name-hash so an unrelated `World` edit does not
  shift another stream's draws ([EXEC-9], [IO-21]). *Gate:*
  `gate:harness-lint`, `gate:e2e-determinism`. *Spec:* §17.3.1; cross-ref 04, 08
  §8.6, §8.9.4.

- **[FAULT-12]** Each probabilistic fault decision the scheduler resolves
  (drop/deliver, jitter amount, duplicate yes/no, corrupted bit positions, I/O
  failure yes/no) MUST be recorded as a `Decision` in the `Schedule`
  ([`05-execution-model.md`](05-execution-model.md)), so replay re-applies the
  recorded outcome without re-rolling the RNG. A replay that re-draws instead of
  replaying a recorded decision is a defect and MUST fail the replay oracle
  ([INV-2]). *Gate:* `gate:replay-oracle`. *Spec:* §17.3.1; cross-ref 05.

### 17.3.2 Rates are integer basis points, not floats

A probability or rate that participates in the scenario hash MUST be exactly
representable on every host. Floating-point printing is host-dependent at the
last bit and is therefore forbidden in the hash ([SPAT-30]). Crucible expresses
every fault rate as an **integer in basis points** (`Bp`, `0..=10_000`, i.e.
hundredths of a percent): `0` is never, `10_000` is always, `2_500` is 25%. A
Bernoulli fault decision compares a single integer RNG draw in `[0, 10_000)`
against the rate, so the comparison is exact integer arithmetic with no float
anywhere on the determinism-relevant path.

```text
  fire = (rng.next_u32_below(10_000) < rate_bp)     // exact integer Bernoulli
```

Where a parameter is genuinely continuous in the authoring surface (a
fuzzing-time fault *density* in faults-per-second), it MAY be a float in the
generator's parameter space, but the *generated* `Plan` MUST lower it to integer
basis points before the `Plan` is hashed (§17.7). No float reaches the hash.

- **[FAULT-13]** Every fault rate/probability that participates in the scenario
  hash MUST be expressed as an integer in basis points (`0..=10_000`), and every
  Bernoulli fault decision MUST be an exact integer comparison of an RNG draw
  against the rate. No floating-point value may appear on any determinism-relevant
  path or in the canonical serialization of a `Plan` ([SPAT-30]). A continuous
  authoring/fuzzing parameter (e.g. fault density) MAY be a float in a generator's
  parameter space but MUST be lowered to integer basis points before the generated
  `Plan` is hashed. *Gate:* `gate:e2e-determinism`, `gate:content-address`.
  *Spec:* §17.3.2; cross-ref 06 §8, §7.

- **[FAULT-14]** All durations, windows, offsets, and bandwidth figures in a fault
  MUST be expressed in fixed integer units (virtual nanoseconds for time,
  bits-per-virtual-second for bandwidth) and all derived shifts (serialization
  delay, jitter draw, latency bump) MUST be computed in integer arithmetic, never
  host-dependent float. *Gate:* `gate:e2e-determinism`. *Spec:* §17.3.2;
  cross-ref 09.

### 17.3.3 Deterministic combination of overlapping faults

Two faults of the same kind MAY be active on the same link/node at once (e.g. two
loss faults on one link, from two `Plan` entries plus an imperatively-injected
one). Their combination MUST be deterministic and order-independent, computed
from the *set* of active faults, not from injection order:

| Kind | Combination rule |
| --- | --- |
| message loss | the link is dropped if **any** active loss fault's Bernoulli draw fires; rates are evaluated highest-first in a fixed order |
| latency / bandwidth | delays **sum** (each active fault contributes its delay) |
| reorder window | the **widest** window applies |
| duplicate | the **highest** rate applies (one duplicate per frame at most) |
| corruption | the **highest** rate applies; on fire, strategies apply in a fixed kind order |
| block/9p failure | failure if **any** active failure draw fires; mode is the most-severe (Drop > ErrorStatus) |
| partition | a directed edge is suppressed if **any** active partition covers it |
| crash | crashed if **any** active crash fault names the node |
| slow | the **largest** factor applies |
| clock skew | offsets **sum** (signed) |

- **[FAULT-15]** When multiple faults of the same kind are active on the same
  target, their combination MUST be a deterministic, injection-order-independent
  function of the *set* of active faults (the §17.3.3 table: loss/failure =
  any-fires; latency/bandwidth/skew = sum; reorder = widest; duplicate/corruption
  = highest rate; slow = largest factor; partition = any-covers). The combined
  effect MUST be identical regardless of the order in which the faults were
  declared or injected. *Gate:* `gate:layer1-injection`, `gate:e2e-determinism`.
  *Spec:* §17.3.3.

## 17.4 Where faults live in the runtime

A fault is applied at the point in the runtime that owns the behavior it
perturbs. This locality is what makes the I/O-and-network unification ([IO-25])
clean: a "latency" fault is the same idea wherever it lives — it shifts a
delivery icount — but the *delivery* it shifts differs by locus.

### 17.4.1 Network faults live on links / the delivery path

Network faults are applied by the network-link sub-node when RESOLVE delivers a
frame ([SCHED-29], [IO-20]): the link computes the base `delivery_vt = T_emit +
L(A→B)` and then applies the effective fault table for that directed edge —
partition/loss may drop the frame, latency/jitter/reorder/bandwidth shift
`delivery_vt`, duplicate emits a second frame, corruption mutates the payload.
The fault perturbs the frame's modeled delivery icount and/or payload; it never
touches the host transport ([FAULT-1], [IO-20]).

Because a link's scalar conservative minimum latency feeds the scheduler's
lookahead ([SCHED-6]), a fixed latency fault that **raises** that bound only
widens lookahead (safe — more parallelism), while a fault that would **lower** it
below the minimum floor MUST be clamped to the floor ([IO-33]), and any change to
that bound MUST trigger the scheduler's lookahead/horizon recompute at the
quantum boundary ([SCHED-37]), never mid-RUN. Jitter, reorder, and bandwidth
still shift individual frame deliveries, but their minimum added delay is zero
and therefore does not change the scheduler's lookahead edge.

- **[FAULT-16]** Network faults (partition, loss, reorder, duplicate, corruption,
  bandwidth limit, latency bump) MUST be applied on the network-link sub-node at
  RESOLVE, perturbing the frame's modeled `delivery_icount` and/or payload per the
  effective fault table for the affected directed edge ([SCHED-29], [IO-20]). A
  network fault MUST NOT touch the host transport. A fault that raises the
  conservative minimum latency bound MUST be honored as-is (it widens lookahead);
  a fault that lowers that bound MUST be clamped to the minimum link-latency
  floor ([IO-33]); and any change to that bound MUST trigger the scheduler's
  lookahead recompute at the quantum boundary ([SCHED-37]).
  *Gate:* `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §17.4.1;
  cross-ref 08 §8.7, §8.11, 15 §15.4.

- **[FAULT-17]** A **partition** MUST be modeled as removal of the affected
  directed edge(s) from the *effective* topology for the partition's active
  interval ([SCHED-38]): a removed edge contributes nothing to any node's
  lookahead and delivers no frame; a heal restores it. When a partition removes a
  node's last inbound edge, that node's lookahead becomes `+∞` and it is bounded
  only by its exact local events ([SCHED-38]). The partition/heal lookahead
  recompute MUST use the `min`-inbound-latency rule over the *current* effective
  edge set ([SCHED-6]). *Gate:* `gate:layer1-injection`. *Spec:* §17.4.1;
  cross-ref 08 §8.11.

### 17.4.2 Node faults live on the VM

Node faults are applied to the VM node itself. The two timing-affecting node
faults (slow, clock-skew) perturb the node's modeled execution mapping, and the
membership fault (crash) stops it.

- **[FAULT-18]** Node faults MUST be applied to the VM node: a **slow** fault
  stretches the node's instruction-count→virtual-time mapping by its factor (the
  node retires the *same* instruction stream — preserving the single-VM
  fingerprint, [DET-3] — but its virtual time advances more slowly relative to
  peers, so it appears slower to the rest of the world); a **clock-skew** fault
  offsets only the guest's perceived time-of-day source (§17.4.4); a **crash**
  fault stops the node (§17.4.3). A node fault MUST NOT alter the node's retired
  instruction stream (only its virtual-time mapping and time-of-day reads),
  preserving intra-VM hermeticity. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer1-injection`. *Spec:* §17.4.2; cross-ref 04, 09.

### 17.4.3 Crash semantics

A crash stops a node's runtime. Precisely:

```text
  on Crash{node} activation at virtual time t:
    1. the node retires NO further instructions (its clock does not advance
       on its own; for peers' lookahead its effective clock is frozen / +∞
       inbound as its edges drop, like a partition of all its links)
    2. its in-flight I/O is DISCARDED: pending block/9p responses for this node
       are dropped (they will never be delivered); requests in flight are voided
    3. its connections BREAK: in-flight frames TO the node are dropped (its
       inbound edges are suppressed) and frames FROM it cease (it emits nothing)
    4. its volatile state is gone; on restart its behavior follows RestartPolicy
  on heal (or restart-policy expiry):
    FromReadyPoint     -> reboot from the baked genesis ready point (05 §6)
    FromLastCheckpoint -> resume from the node's last pre-crash checkpoint (07)
    StayDown           -> remain stopped until an explicit restart command (20)
```

A crashed node is, for scheduling purposes, equivalent to a node all of whose
edges are partitioned *and* whose own execution is halted: it neither advances
its own clock nor constrains any peer (its effective clock does not hold the
global minimum back, because it is not "alive" for the liveness argument,
[SCHED-7]). Its discarded I/O is the determinism-critical part: the dropped
in-flight responses are recorded so replay drops exactly the same ones.

- **[FAULT-19]** A **crash** fault MUST, at its exact activation virtual time:
  (a) stop the node's runtime so it retires no further instructions and emits no
  frames; (b) **discard** the node's in-flight I/O — pending block/9p responses
  destined for the node are dropped and never delivered, and in-flight requests
  are voided; (c) **break** the node's connections — inbound frames are dropped
  (its inbound edges are suppressed like a full partition) and it produces no
  outbound frames. The set of discarded in-flight items MUST be deterministic and
  recorded so replay discards exactly the same items ([INV-2]). *Gate:*
  `gate:layer1-injection`, `gate:replay-oracle`. *Spec:* §17.4.3; cross-ref 08
  §8.3.2.

- **[FAULT-20]** A crashed node MUST NOT constrain any peer's progress (it is not
  "alive" for the liveness argument [SCHED-7]; its effective clock does not hold
  the global minimum back) and MUST NOT advance its own clock. On heal, the node
  MUST restart per its `RestartPolicy`: `FromReadyPoint` reboots from the baked
  genesis ready point (05 §6), `FromLastCheckpoint` resumes from the node's last
  pre-crash checkpoint (07), `StayDown` remains stopped until an explicit restart
  control command (20). The restart MUST itself be deterministic and reproduce
  identically on replay. *Gate:* `gate:layer1-injection`, `gate:replay-oracle`.
  *Spec:* §17.4.3; cross-ref 05 §6, 07, 20.

### 17.4.4 Clock skew offsets perceived time, not virtual time

A subtle but load-bearing distinction: a node's **virtual time** is a pure
function of its instruction count ([INV-4]) and is the substrate of all
cross-node ordering — it MUST NOT be perturbable by a fault, or determinism
collapses. What a `ClockSkew` fault offsets is the guest's *perceived*
time-of-day source — the value the guest reads from an emulated RTC / KVM-clock /
time-of-day device — by a signed amount. The guest "thinks" it is a different
wall-clock time (modeling NTP drift / a step correction), but its instruction
stream, its icount, and every cross-node ordering key are unchanged.

- **[FAULT-21]** A **clock-skew** fault MUST offset only the guest-perceived
  time-of-day source (the value read from the emulated RTC / time-of-day device)
  by a signed virtual-duration offset; it MUST NOT alter the node's
  instruction-count-derived virtual time ([INV-4]), its icount, or any cross-node
  total-order key ([SCHED-15]). The skew MUST be applied deterministically (the
  offset is read from the time-of-day path, not injected via host time), so the
  guest observes a reproducibly-skewed time while the simulation's ordering
  substrate is unaffected. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer1-injection`. *Spec:* §17.4.4; cross-ref 04, 09.

### 17.4.5 I/O faults live on the device sub-nodes, uniform with network

Block and 9p faults are applied on their respective I/O sub-nodes when RESOLVE
delivers a completion ([IO-25], [IO-26]), and they are **uniform** with network
faults: latency/jitter shift the response delivery icount; failure returns an
error-status response (or drops it); reorder shifts one response past another;
duplicate emits a second response; corruption flips seeded bits in read data;
bandwidth adds transfer delay ∝ count. The perturbation is on the *modeled
completion/response*, never on the host I/O (the COMPUTE/DELIVER split of
[IO-31]).

- **[FAULT-22]** Block and 9p faults MUST be applied on their I/O sub-nodes at
  RESOLVE as perturbations of the *modeled* completion/response, uniform with
  network-link faults ([IO-25]): latency/jitter shift the response
  `delivery_icount`; failure returns an error-status response or drops it per
  `IoFailureMode`/`NinepErrno`; reorder shifts one response's delivery past
  another within the window ([IO-34]); and any seeded choice is drawn from the
  sub-node's per-device RNG ([IO-21]). An I/O fault MUST NOT perturb the host I/O
  ([IO-2], [FAULT-1]). The set of active I/O faults MUST be part of the scheduler
  state captured in `MaterializedState` ([IO-26], [TEMP-7]). *Gate:*
  `gate:layer1-injection`, `gate:replay-oracle`. *Spec:* §17.4.5; cross-ref 15
  §15.6, 07 §3.

## 17.5 The fault is uniform across loci

The taxonomy reads as four groups, but the *operations* are a small uniform
vocabulary applied at different loci. This is the table that makes the
unification explicit; it is the §15.6 table extended to node faults.

```text
  operation     network link             block / 9p request          node (VM)
  ─────────     ───────────────────      ───────────────────────     ──────────────────────
  delay         shift frame delivery_vt   shift response delivery_vt   (slow: stretch vt map)
  jitter        seeded delay [0,w]        seeded delay [0,w]           —
  drop/fail     drop frame                error-status / drop resp.    (crash: discard I/O)
  reorder       delivery_vt past a peer   one resp. past another       —
  duplicate     emit a second frame       emit a second response       —
  corrupt       flip seeded payload bits  flip seeded read-data bits   —
  bandwidth     serialization delay       transfer delay ∝ count       —
  suppress      partition (edge removal)  —                            crash (all edges + halt)
  skew          —                         —                            offset perceived ToD
```

- **[FAULT-23]** The fault model MUST be a uniform vocabulary applied at the locus
  that owns the perturbed behavior (the §17.5 table): the *same* operation
  (delay, jitter, drop/fail, reorder, duplicate, corrupt, bandwidth) MUST mean the
  same thing — a deterministic perturbation of a modeled delivery icount and/or
  payload — whether applied to a network frame or an I/O response. A new fault
  locus MUST reuse this vocabulary rather than introduce a parallel one. *Gate:*
  `gate:layer1-injection`. *Spec:* §17.5; cross-ref 15 §15.6.

## 17.6 Scheduling faults: the declarative `FaultPlan` and imperative injection

A fault becomes active either **declaratively** — it is part of the `Plan`
component of the `ScenarioDef`, scheduled at an exact virtual time — or
**imperatively** — it is injected by a control command during a live session.
Both routes converge on the same active-fault state the scheduler consults at
RESOLVE. Both are, more generally, the firing of an `InjectFault`/`HealFault`
**`Action`** in the 17a event graph (§17.6.5,
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.4); the
declarative `FaultPlan` below is its degenerate pure-`At`-trigger case.

### 17.6.1 The declarative `FaultPlan` (part of the `Plan`)

The `Plan` ([`06-spatial-graph.md`](06-spatial-graph.md) §5.1) is a canonically
ordered list of `PlanEntry`s. A fault entry schedules a fault to activate at an
exact virtual time, either for a finite **duration** (`at`) or permanently from a
start (`permanent_at`); a heal entry removes a tagged fault at an exact virtual
time. Every entry is scheduled in **virtual time** ([SPAT-20]), never wall-clock,
and the activation/heal is itself a cross-node event resolved in total order
([SCHED-29]).

```rust,illustrative
/// One entry in the declarative `Plan` (06 §5.1). All times are virtual (09).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum PlanEntry {
    /// Activate `fault` at virtual time `at` for `duration`, then auto-heal.
    /// Equivalent to an `Inject` at `at` plus a `Heal{tag}` at `at + duration`.
    At { at: VirtualTime, duration: VirtualDuration, fault: Fault, tag: FaultTag },
    /// Activate `fault` at virtual time `at`, permanently (no auto-heal).
    PermanentAt { at: VirtualTime, fault: Fault, tag: FaultTag },
    /// Remove the tagged fault at virtual time `at`. The tag MUST be injected
    /// somewhere in the Plan ([SPAT-31]).
    Heal { at: VirtualTime, tag: FaultTag },
}

/// A declarative fault campaign — the body of the `Plan` (06 §5.1).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct FaultPlan { pub entries: Vec<PlanEntry> }

impl FaultPlan {
    /// Schedule a finite-duration fault. Auto-heals at `at + duration`.
    pub fn at(self, at: VirtualTime, duration: VirtualDuration, fault: Fault) -> Self;
    /// Schedule a permanent fault (active from `at` to end-of-run unless healed).
    pub fn permanent_at(self, at: VirtualTime, fault: Fault) -> Self;
    /// Explicitly heal a previously-injected tagged fault at `at`.
    pub fn heal(self, at: VirtualTime, tag: impl Into<FaultTag>) -> Self;
}
```

```toml
# A FaultPlan as it appears in the canonical Plan serialization (06 §6.1).
# Rates are integer basis points (§17.3.2); times are virtual (09).
[[plan.entry]]
at = "10s"
duration = "30s"
inject = { fault = "partition", a = "db-0", b = "db-1", direction = "bidirectional", tag = "split" }

[[plan.entry]]
at = "20s"
inject = { fault = "message_loss", a = "db-1", b = "db-2", rate_bp = 2500, tag = "lossy" }

[[plan.entry]]
at = "40s"
heal = { tag = "split" }            # explicit heal; "lossy" auto-heals never (permanent)
```

- **[FAULT-24]** A `FaultPlan` MUST be the body of the `Plan` component of the
  `ScenarioDef` ([SPAT-19]) and MUST support declarative scheduling: `at(start,
  duration, fault)` (finite, auto-healing at `start + duration`), `permanent_at`
  (active from `start` with no auto-heal), and explicit `heal(tag)` at a virtual
  time. Every entry MUST be scheduled in virtual time ([SPAT-20]), MUST reference
  declared nodes/links ([SPAT-19]), and every `heal` tag MUST reference a fault
  injected somewhere in the `Plan` ([SPAT-31]). The `FaultPlan` MUST be
  content-addressed as part of the `Plan` ([SPAT-3]) with rates in integer basis
  points ([FAULT-13]). *Gate:* `gate:content-address`, `gate:e2e-determinism`.
  *Spec:* §17.6.1; cross-ref 06 §5.1, §9.

- **[FAULT-25]** A fault activation, heal, or auto-heal MUST be resolved by the
  scheduler at the entry's **exact** virtual time as a cross-node event in the
  total order of [SCHED-15] ([SCHED-29] fault activation), never deferred to the
  next rendezvous tick ([SCHED-39]). A topology-changing fault (partition, crash,
  latency change) MUST trigger the scheduler's effective-topology swap and
  lookahead recompute atomically at the fault's exact activation time ([SCHED-37],
  [SCHED-39]). *Gate:* `gate:layer1-injection`, `gate:scheduler-liveness`.
  *Spec:* §17.6.1; cross-ref 08 §8.5, §8.11.

### 17.6.2 Imperative injection over the control plane

During a live session, a control command MAY inject or heal a fault at the
*current* virtual time, the same way the declarative plan does at scheduled
times. Imperative injection is for interactive debugging and for
property-conditional fault campaigns (inject a fault *because* an assertion just
became satisfied). The command is applied at a quantum boundary ([SCHED-3], the
[INV-8] yield point), so it lands at a well-defined virtual time and is recorded
in the `Schedule` exactly like a declarative activation — a session that injected
faults imperatively still reduces to a self-contained reproduction artifact
([SPAT-28]).

- **[FAULT-26]** Crucible MUST support **imperative** fault injection and healing
  via control commands ([`20-session-control-plane.md`](20-session-control-plane.md)):
  an `inject(fault, tag)` and a `heal(tag)` applied at the current virtual time.
  An imperative injection MUST be applied only at a quantum boundary ([SCHED-3],
  [SCHED-33]) and MUST be recorded in the `Schedule` as a `Decision`
  ([`05-execution-model.md`](05-execution-model.md)) at that exact virtual time,
  so a session driven by imperative commands reduces to the same self-contained
  reproduction artifact ([SPAT-28]) as an equivalent declarative `Plan`. *Gate:*
  `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §17.6.2; cross-ref 20,
  05.

### 17.6.3 Tag-based activation and heal

Every injected fault carries a **tag** ([`02-glossary.md`](02-glossary.md)): a
stable handle used to heal it. A heal references a tag, not a fault value, so the
exact fault being removed is unambiguous even when several faults of the same
kind are active. Injecting a fault with a tag that is already active replaces the
prior fault under that tag (deterministically). A heal of an unknown tag is a
no-op at runtime but a *declarative* heal whose tag is never injected MUST be
rejected at build time ([SPAT-31]) — the fail-early discipline of
([`06-spatial-graph.md`](06-spatial-graph.md) §9).

- **[FAULT-27]** Every injected fault MUST carry a stable **tag**; a heal MUST
  reference a fault by its tag, not by value. Injecting a fault under a tag that
  is already active MUST deterministically replace the prior fault for that tag.
  A declarative `heal` whose tag is never injected in the `Plan` MUST be rejected
  at build time ([SPAT-31]); an imperative heal of an unknown tag MUST be a
  defined no-op at runtime, never a panic. The active-tag set MUST be part of the
  scheduler state captured in `MaterializedState` so a resumed run heals the same
  tags ([TEMP-7]). *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:*
  §17.6.3; cross-ref 06 §9, 07 §3.

### 17.6.4 The active-fault table the scheduler consults

At runtime, the union of declaratively-activated and imperatively-injected faults
forms the **active-fault table** — the effective fault set the scheduler consults
at RESOLVE to decide each frame's delivery and each I/O response's completion. The
table is keyed for fast lookup by directed edge and by node, is combined per
§17.3.3 when multiple faults overlap, and is recomputed (with a lookahead
recompute) at the quantum boundary whenever an activation/heal changes it
([SCHED-37]).

- **[FAULT-28]** The scheduler MUST maintain a deterministic **active-fault
  table** (the union of declaratively-activated and imperatively-injected faults),
  keyed by directed edge and by node, combined per §17.3.3 when faults overlap,
  and consulted at RESOLVE to decide frame delivery and I/O completion ([SCHED-29],
  [IO-20], [IO-25]). The table MUST be recomputed — with the lookahead/horizon
  recompute of [SCHED-37] — at the quantum boundary on any activation or heal, and
  MUST be part of `MaterializedState` so a resumed/forked run sees the identical
  active-fault set ([TEMP-7]). The table MUST NOT depend on any unordered-map
  iteration order on the ordering-significant path ([INV-9], [SCHED-19]). *Gate:*
  `gate:layer1-injection`, `gate:harness-lint`, `gate:replay-oracle`. *Spec:*
  §17.6.4; cross-ref 08 §8.11, 07 §3.

### 17.6.5 Faults are `Action`s in the 17a event graph

The scheduling story above is one model, not two. A fault is not a special-case
scheduling primitive: it is an **`Action`** in the event graph of
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md). `InjectFault`
and `HealFault` are the canonical actions of that graph ([TRIG-22], 17a §17a.4);
an *event* binds a trigger condition to one of them, and "inject the partition once
the cluster is observed healthy, heal it thirty virtual seconds later" is two
events whose triggers are observable conditions (17a §17a.2), not two `PlanEntry`s.
The condition/trigger vocabulary — the timer-fired, event-fired,
assertion-satisfied/violated, and compound all-of/any-of triggers that
[`06-spatial-graph.md`](06-spatial-graph.md) §5.1 attributes to the `Plan` — is
defined once in 17a; this file does **not** re-specify it and MUST be read as a
consumer of it (a fault is a trigger *action*).

The declarative `FaultPlan` of §17.6.1 (`At` / `PermanentAt` / `Heal`) is the
**degenerate case** of that event graph: the subset whose every trigger is a pure
`At` condition and whose every action is `InjectFault`/`HealFault`. It lowers
mechanically to 17a events — `PermanentAt { at, fault, tag }` ⇒ one event
`(trigger: At{at}, action: InjectFault{tag, fault})`; a finite `At { at, duration,
fault, tag }` ⇒ that inject event plus a heal event `(trigger: At{at+duration},
action: HealFault{tag})`; `Heal { at, tag }` ⇒ `(trigger: At{at}, action:
HealFault{tag})` (17a §17a.7). The `FaultPlan` and the event graph are therefore
**one content-addressed model**: an author who needs only time-scheduled faults
writes the `FaultPlan` and never touches a `ConsoleMatch`; an author who needs
observation-anchored choreography writes richer events; both hash and reduce
identically (17a [TRIG-28], [TRIG-29]). Imperative injection (§17.6.2) is the
control-plane spelling of firing an `InjectFault`/`HealFault` action at the current
virtual time, recorded as a `Decision` ([FAULT-26]) rather than computed from a
trigger — the firing-vs-Decision boundary 17a §17a.3.3 draws.

- **[FAULT-33]** A fault MUST be expressed as an `InjectFault`/`HealFault`
  **`Action`** in the event graph of
  [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) ([TRIG-22],
  17a §17a.4); there MUST be no parallel fault-scheduling mechanism outside that
  action set. The trigger/condition vocabulary that decides *when* a fault fires
  MUST be the single vocabulary of 17a §17a.2 (this file MUST NOT define a separate
  one), and a declarative or imperative fault MUST apply at its firing virtual time
  at a quantum boundary exactly as 17a [TRIG-23] requires. *Gate:*
  `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §17.6.5; cross-ref 17a
  §17a.4, §17a.3.3.

- **[FAULT-34]** The declarative `FaultPlan` (§17.6.1 — `At` / `PermanentAt` /
  `Heal`) MUST be the **degenerate pure-`At` case** of the 17a event graph and MUST
  lower to it mechanically: each `PlanEntry` lowers to one or more events whose
  trigger is a pure `At` condition and whose action is `InjectFault`/`HealFault`
  (a finite `At { duration }` lowering to an inject event plus an `At { at+duration
  }` heal event, 17a §17a.7). The `FaultPlan` and the event graph MUST be one
  content-addressed model sharing one canonicalization, one content hash, and one
  build-time validator (17a [TRIG-28], [TRIG-29]); a pure-`At` `FaultPlan` MUST hash
  and reduce identically whether expressed as a `FaultPlan` or as the equivalent
  `At`-triggered event graph. *Gate:* `gate:content-address`, `gate:e2e-determinism`.
  *Spec:* §17.6.5; cross-ref 17a §17a.7, 06 §5.1.

## 17.7 `RandomFaultConfig`: weighted probabilistic fault generation

For fuzzing and state-space exploration ([G-6],
[`22-advanced-features.md`](22-advanced-features.md)) an author needs not one
hand-written campaign but a *generator* that produces a fresh, reproducible
`FaultPlan` from a seed. `RandomFaultConfig` is that generator's configuration: a
set of nodes, a run duration, per-kind weights, severity bounds, and a seed.
Generation is itself **fully deterministic from the seed** — the same config
produces byte-identical `FaultPlan`s every time — so a discovered failure reduces
to a concrete `ScenarioDef` (the generated `Plan` is pinned and content-addressed)
with no reference back to the generator ([SPAT-27]).

```rust,illustrative
/// Configuration for weighted, reproducible random fault-campaign generation
/// (fuzzing/exploration, file 22). `generate(config)` is a pure function of
/// `config` (including its seed): same config ⇒ byte-identical `FaultPlan`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RandomFaultConfig {
    /// The nodes the generator may target (drawn from the `World`).
    pub nodes: Vec<NodeId>,
    /// The links the generator may target (drawn from the `World`).
    pub links: Vec<Link>,
    /// Total virtual duration of the run; faults are placed within it.
    pub duration: VirtualDuration,
    /// Relative weight of each fault kind (integer; 0 = never generate).
    pub weights: FaultWeights,
    /// Severity bounds (rates in basis points, windows/latencies in vt units).
    pub bounds: SeverityBounds,
    /// Caps: max concurrently-active faults, max partitions, max crashes.
    pub caps: FaultCaps,
    /// The generator seed; the sole source of generation randomness.
    pub seed: Seed,
}

/// Integer relative weights per fault kind (a weighted categorical draw).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FaultWeights {
    pub partition: u32, pub message_loss: u32, pub reorder: u32,
    pub duplicate: u32, pub corruption: u32, pub bandwidth_limit: u32,
    pub latency_bump: u32, pub crash: u32, pub slow: u32, pub clock_skew: u32,
    pub block_latency: u32, pub block_failure: u32, pub block_reorder: u32,
    pub ninep_latency: u32, pub ninep_failure: u32,
}
```

The generator draws, in a fixed order, from a single seeded RNG: for each fault
slot it picks a start time, a duration, a kind (a weighted categorical draw over
`FaultWeights`), a target (node or link), and severity parameters within
`SeverityBounds`. It then enforces `FaultCaps` by deterministically pruning excess
faults (e.g. keep the first `max_partitions` partitions in generation order). The
result is a `FaultPlan` whose rates are integer basis points ([FAULT-13]) and
whose entries are canonically ordered for hashing ([SPAT-30]).

- **[FAULT-29]** Crucible MUST provide a `RandomFaultConfig` that generates a
  `FaultPlan` by weighted probabilistic selection over the fault taxonomy, ranging
  over kind (via integer `FaultWeights`), target (node/link from the `World`),
  start time, duration, and severity (within `SeverityBounds`), subject to integer
  `FaultCaps` (max concurrent faults, max partitions, max crashes). Generation
  MUST be a **pure function of the config including its seed**: the same config
  MUST produce a byte-identical `FaultPlan` on every host (the generator draws
  from one seeded RNG in a fixed order and prunes to caps deterministically).
  *Gate:* `gate:e2e-determinism`, `gate:content-address`. *Spec:* §17.7;
  forward-ref 22.

- **[FAULT-30]** A `FaultPlan` produced by `RandomFaultConfig` MUST lower every
  generated rate to integer basis points ([FAULT-13]) and canonically order its
  entries ([SPAT-30]) before it is hashed, so a generated campaign is
  content-addressed and reproducible like a hand-written one. A failure discovered
  by random fault generation MUST reduce to a concrete, content-addressed
  `ScenarioDef` (with the pinned generated `Plan`) plus a `Schedule`, requiring no
  reference to the generating config to reproduce ([SPAT-27], [SPAT-28]). *Gate:*
  `gate:content-address`, `gate:replay-oracle`. *Spec:* §17.7; cross-ref 06 §7,
  §7.1, 22.

## 17.8 The determinism gate for fault injection

The headline contract for this file is the layer-1 injection gate combined with
end-to-end determinism: *the same seed and plan MUST produce identical fault
activation icounts and identical fault effects.* This is the operational form of
[INV-1] for faults: a fault is part of `reduce`, so two runs of the same
`(ScenarioDef, Seed, Schedule)` — including all their faults — MUST be
bit-identical.

```text
  gate:layer1-injection  (faults half):
    a Plan of every fault kind, applied to a fixed World+Seed, run twice ⇒
      - identical fault ACTIVATION icounts (each fault fires at the same icount)
      - identical fault EFFECTS (same frames dropped, same delivery icounts,
        same corrupted bytes, same I/O failures, same crash discards)
      - identical decision-RNG draw sequence and recorded Decisions
  gate:e2e-determinism  (faults contribution):
    a representative multi-VM, fault-injected scenario runs bit-identically
    across adversarial host conditions and reproduces from its artifact
  gate:replay-oracle (faults contribution):
    re-reducing from an ancestor reproduces every fault decision without
    re-rolling (Decisions are replayed, not redrawn, [FAULT-12])
```

- **[FAULT-31]** A fault-injected run MUST satisfy the determinism gate: for a
  fixed `(ScenarioDef, Seed, Schedule)` — including its `Plan`'s faults — two runs
  MUST produce **identical fault activation icounts and identical fault effects**
  (the same frames dropped, the same delivery icounts, the same corrupted bytes,
  the same I/O failures, the same crash discards) and an identical decision-RNG
  draw sequence and recorded `Decision`s. A divergence MUST localize to the first
  differing fault decision via the divergence path ([INV-10]), never be smoothed
  over. *Gate:* `gate:layer1-injection`, `gate:e2e-determinism`,
  `gate:divergence-bisect`. *Spec:* §17.8; cross-ref 04, 24.

- **[FAULT-32]** The fault model MUST be exercisable by the in-process test double
  ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md),
  [IO-27]) without a real QEMU: a test MUST be able to apply each fault kind to a
  link/device/node sub-node, drive it through a request/frame sequence with a
  fixed seed, and assert the perturbed deliveries, dropped items, and recorded
  decisions — and a run-twice determinism test ([IO-28]) MUST confirm
  byte-identical results. This is where most fault determinism is proved in
  milliseconds before any real-VM run. *Gate:* `gate:layer1-injection`,
  `gate:divergence-bisect`. *Spec:* §17.8; cross-ref 15 §15.7, 24.

## 17.9 Summary

```text
A FAULT perturbs MODELED behavior, never the host (FAULT-1)
  every probabilistic choice = a seeded decision-RNG draw, in total order,
    recorded as a Decision (FAULT-2, 11, 12) — replayed, not redrawn
  rates are INTEGER BASIS POINTS, never floats in the hash (FAULT-13, 14)
  overlapping same-kind faults combine deterministically, order-independent (FAULT-15)
TAXONOMY by locus:
  network (link/delivery): partition[bi/A→B/B→A], loss, reorder, duplicate,
    corruption[bit-flip/field-mutation/truncation], bandwidth, latency bump
    (FAULT-3,7,8,9,10) — perturb frame delivery_icount/payload at RESOLVE (FAULT-16)
    partition = effective-edge removal; recompute lookahead (FAULT-17)
  node (VM): crash, slow, clock-skew (FAULT-4)
    crash = stop runtime, DISCARD in-flight I/O, BREAK connections (FAULT-19,20)
    slow = stretch vt map (same instruction stream); skew = perceived ToD only,
      NOT virtual time (FAULT-18, 21)
  block (disk sub-node): latency, failure, reorder (FAULT-5)
  9p (fs sub-node): latency, failure (FAULT-6)
  I/O faults are UNIFORM with network faults — perturb modeled response (FAULT-22,23)
SCHEDULING:
  declarative FaultPlan in the Plan: at(start,dur,fault) / permanent_at / heal,
    in virtual time, content-addressed, exact-time activation (FAULT-24,25)
  imperative inject/heal over the control plane at quantum boundaries,
    recorded in the Schedule (FAULT-26)
  tag-based: heal by tag, replace-on-retag, active set in MaterializedState (FAULT-27,28)
GENERATION: RandomFaultConfig — weighted, reproducible from seed, lowered to
  basis points + canonical order before hashing; failures pin a concrete def (FAULT-29,30)
GATE: same seed + plan ⇒ identical activation icounts AND effects;
  divergence localizes to the first differing fault decision (FAULT-31,32)
```

If every fault perturbs only modeled behavior, every probabilistic choice is a
recorded seeded draw consumed in total order, and every rate is exact integer
basis points, then a fault-injected run is a pure function of `(ScenarioDef,
Seed, Schedule)` exactly like a fault-free run — which is what
`gate:layer1-injection` and `gate:e2e-determinism` enforce.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is fault injection, tracked here by [PLAN-3]. They
> populate Phase 1 (the determinism / harness / transport foundation), sequenced
> after the L1 scheduler and I/O-sub-node primitives and before any L3+ feature
> built on faults (assertions, search, fuzzing).

- [x] **T-FAULT-1** Define the `Fault` taxonomy enum (network: partition[bi/A→B/
  B→A], loss, reorder, duplicate, corruption[bit-flip/field-mutation/truncation],
  bandwidth, latency bump; node: crash[restart policy], slow, clock-skew; block:
  latency, failure, reorder; 9p: latency, failure) with integer basis-point rates
  and integer time/bandwidth units. — satisfies [FAULT-3], [FAULT-4], [FAULT-5],
  [FAULT-6], [FAULT-7], [FAULT-8], [FAULT-9], [FAULT-10]; spec §17.2.

  Completed by `checks.crucible.phase4.faultTaxonomy`: the engine model now
  exports the closed `Fault` taxonomy with network, node, block, and 9p variants,
  including directed/bidirectional partitions, loss, reorder, duplicate,
  bit-flip/field-mutation/truncation corruption, bandwidth, latency bump, crash
  restart policies, slow, and clock-skew. `FaultRateBasisPoints`,
  `FaultSlowdownFactorBasisPoints`, `FaultDuration`, and
  `FaultBandwidthBitsPerSecond` keep all rates and units integer-only, reject
  out-of-range basis points, below-identity slow factors, zero bandwidth caps,
  and invalid 9p errno values, and feed stable length-delimited canonical
  material plus content hashes. The focused taxonomy test covers every RFC kind,
  directed partition and restart-policy variants, block jitter and failure
  modes, 9p errno, integer-only material, and content-address drift when
  parameters change.
- [x] **T-FAULT-2** Enforce the one design rule: every fault perturbs modeled
  behavior only (no host wall-clock/scheduling/FS/entropy) and never mutates the
  static topology; add a harness-lint check on the fault apply path. — satisfies
  [FAULT-1]; spec §17.1.

  Completed by `checks.crucible.phase4.faultModelRule`: the trigger fault
  application path is now covered by `gate:harness-lint` through a dedicated
  `fault_apply_path_failures` scan that rejects host time, host filesystem,
  host thread scheduling, host entropy/RNG, and topology-mutation tokens inside
  the `InjectFault`/`HealFault` effect arms and requires those arms to be direct
  modeled `active_faults` mutations with no helper calls or assignments. The
  focused `fault_model_rule` engine test applies and heals a partition fault,
  proving the path changes only modeled `active_faults`/causal trigger-action
  log state while the schedule, scheduler static topology, and source `World`
  topology remain unchanged.
- [x] **T-FAULT-3** Route every probabilistic fault decision through the single
  seeded decision RNG in the scheduler's total order, fork per-link/per-device
  streams by name-hash, and record each decision as a `Decision`; prove
  replay re-applies recorded decisions without re-rolling. — satisfies [FAULT-2],
  [FAULT-11], [FAULT-12]; spec §17.3.1.

  Completed by `checks.crucible.phase4.faultDecisionRng`: the scheduler RESOLVE
  path consumes `ScheduledEventPayload::ProbabilisticFault` choices in canonical
  event order, draws through `DecisionRecorder` seeded from the run
  `Configuration`, appends the raw `RngDraw` and derived `FaultFires` decisions,
  and advances per-stream cursors for those recorded draws. Link and device
  fault streams use the name-hashed link/device RNG domains, including the
  block/9p sub-node bridge tests that record device `RngDraw`/`FaultFires`
  outcomes. The focused replay regressions prove recorded `FaultFires` outcomes
  are replayed as schedule material, not by re-rolling or advancing the decision
  RNG, and the check pins the reproduction-artifact replay test that carries
  recorded `FaultFires`/`RngDraw` entries through offline artifact replay.
- [x] **T-FAULT-4** Implement integer-basis-point rates and exact integer
  Bernoulli decisions; ban floats on the determinism-relevant path and in the
  canonical `Plan` serialization; compute all delays/jitter/bandwidth in integer
  arithmetic. — satisfies [FAULT-13], [FAULT-14]; spec §17.3.2.

  Completed by `checks.crucible.phase4.faultIntegerRates`: the shared
  `FaultRateBasisPoints` type now exposes the canonical `10_000` denominator,
  deterministic raw-draw-to-bucket reduction, and the exact
  `bucket < basis_points` Bernoulli rule used by the scheduler's
  `SchedulerResolveFaultChoice` payload and the recorder's
  `decide_fault_basis_points` API, which records the raw `RngDraw` before the
  derived `FaultFires` outcome. The focused regression covers zero, boundary,
  wraparound, and always-on basis-point decisions; exercises the scheduler
  RESOLVE boundary so `bucket == rate` does not fire and `bucket < rate` does;
  verifies canonical fault material emits `rate_basis_points`,
  `factor_basis_points`, `*_nanos`, and `bits_per_second` integer fields without
  decimal rates; and pins scheduled plan TOML fault entries as float-free,
  including rejection of decimal `rate = 1.5` fault parameters. The gate also
  checks the block/9p/link shared device transforms for exact-fraction
  probability, integer serialization delay, and integer jitter/reorder
  arithmetic.
- [x] **T-FAULT-5** Implement deterministic, injection-order-independent
  combination of overlapping same-kind faults per the §17.3.3 table. — satisfies
  [FAULT-15]; spec §17.3.3.

  Completed by `checks.crucible.phase4.faultCombination`: the model layer now
  exposes a pure `CombinedFaults::from_faults` reducer that groups active
  taxonomy faults by target and computes combined effects from the set, not
  declaration or injection order. The reducer implements the §17.3.3 table with
  highest-first loss/block/9p failure rate lists for any-fires evaluation,
  while preserving each 9p failure rate with its errno payload; saturating
  integer sums for latency and clock skew; widest windows for reorder;
  highest-rate duplicate/corruption/slow choices; any-covers partition coverage;
  any-crash node state; and most-severe block failure mode. The focused
  regression reverses the same active set to prove order independence, checks
  network, node, block, and 9p rows explicitly, and includes independent second
  targets to prove same-kind faults do not combine across targets.
- [x] **T-FAULT-6** Apply network faults on the link sub-node at RESOLVE
  (partition/loss drop; latency/jitter/reorder/bandwidth shift delivery_icount;
  duplicate emits a second frame; corruption mutates payload), honor
  conservative-latency-bound raising as-is, clamp bound-lowering to the floor,
  and trigger the lookahead recompute on conservative latency-bound change. —
  satisfies [FAULT-16], [FAULT-17]; spec §17.4.1; cross-ref 08 §8.11, 15 §15.4.

  Completed by `checks.crucible.phase4.networkFaultApplication`: the engine
  bridge lowers combined RFC network faults onto the concrete link sub-node
  before RESOLVE, preserving highest-first any-fires loss rates, summed exact
  bit-rate bandwidth delays, latency-bound raises, duplicate gaps, fixed-order
  corruption strategies, directed partition drops, and directed partition edge
  removals. The link table now carries overlapping loss rates, exact
  bit-per-second caps, and corruption strategy lists while retaining the existing
  floor clamp and lookahead recompute signal for conservative latency changes.
  Partition drops are recorded separately from probabilistic loss decisions, and
  the scheduler-facing application bridge queues the topology mutation with the
  link fault table. The heal bridge re-applies the remaining fault table and
  queues both remaining partition removals and restored directed edges that no
  active partition still covers. The focused regression drives a combined fault
  set through `NetLink::emit`, proves seeded payload mutation, duplicate
  emission, any-fires loss drop, partition drop recording, and applies the
  bridge-produced partition, partial-heal, and full-heal changes through
  `SingleScheduler` so removed directed edges stop authorizing sends or
  contributing lookahead until restored.
- [x] **T-FAULT-7** Apply node faults on the VM: slow stretches the vt map
  without altering the retired instruction stream; clock-skew offsets only the
  perceived time-of-day source, never virtual time/icount. — satisfies
  [FAULT-18], [FAULT-21]; spec §17.4.2, §17.4.4.

  Completed by `checks.crucible.phase4.nodeFaultApplication`: VM timing faults
  now lower combined node-fault effects into an anchored per-node timing
  projection in `SingleScheduler`. Slowdown preserves the VM's current
  faulted virtual time at activation, stretches future counter-to-virtual-time
  mapping by the integer basis-point factor, and computes RUN ceilings by the
  inverse slowed projection, so the VM retires the same counter stream while
  advancing more slowly against peers. Clock skew is stored only in the
  guest-visible projection; effective clocks, frontier computation, RUN
  ceilings, completion event keys, preemption timestamps, and ordering keys
  remain on the scheduler axis. The focused regression covers anchored slow
  projection, slowed scheduler RUN ceilings, slowed preemption and I/O
  completion timestamps, and guest-visible-only clock skew.
- [x] **T-FAULT-8** Implement crash semantics (stop runtime, discard in-flight
  I/O, break connections, deterministic recorded discard set) and restart
  policies (FromReadyPoint / FromLastCheckpoint / StayDown), proving the crashed
  node constrains no peer and replays identically. — satisfies [FAULT-19],
  [FAULT-20]; spec §17.4.3.
  Completed by `checks.crucible.phase4.nodeCrashApplication`: `SingleScheduler`
  now records crash/restart applications, stops crashed VM nodes by removing
  them from PICK/frontier pressure, discards incident scheduler events and
  pending device completions with full delivery keys, suppresses incident
  effective topology edges while retaining later edge updates for restart, and
  applies FromReadyPoint, FromLastCheckpoint from a recorded scheduler
  checkpoint anchor, and StayDown plus explicit restart. The focused regressions
  cover deterministic run-twice replay evidence, unrelated-work survival,
  peer progress, frozen all-crashed frontier behavior, and topology updates
  while a node is down.
- [x] **T-FAULT-9** Apply block/9p faults on their I/O sub-nodes at RESOLVE,
  uniform with network faults (latency/jitter shift; failure error/drop; reorder;
  duplicate; corruption), drawn from the per-device RNG, with active I/O faults in
  `MaterializedState`. — satisfies [FAULT-22], [FAULT-23]; spec §17.4.5, §17.5;
  cross-ref 15 §15.6.
  Completed by `checks.crucible.phase4.ioFaultApplication`: combined block and
  9p fault tables now lower to the concrete `IoFaults` applied on live
  `DeviceSchedulingSubNode`s. Latency, jitter, reorder, duplicate, corruption,
  and bit-rate bandwidth share the per-device RNG path; block failures re-encode
  native block error payloads or record decision-only drop deliveries; 9p failures
  re-encode `Rlerror` with the selected errno and original tag. Active bit-rate
  bandwidth and overlapping failure rates are folded into scheduler active-fault
  state so `MaterializedState` captures the live I/O fault set.
- [x] **T-FAULT-10** Implement the declarative `FaultPlan` (at / permanent_at /
  heal) as the body of the `Plan`, in virtual time, with build-time validation
  (declared refs, heal-tag injected somewhere, in-range params) and integer-bp
  content-addressing; activate/heal at exact virtual times in total order with the
  topology swap + lookahead recompute. Express every fault as an
  `InjectFault`/`HealFault` `Action` in the 17a event graph (no parallel fault
  scheduler) and lower the declarative `FaultPlan` mechanically as the degenerate
  pure-`At` case sharing one canonicalization and content hash. — satisfies
  [FAULT-24], [FAULT-25], [FAULT-33], [FAULT-34]; spec §17.6.1; cross-ref 06 §9,
  08 §8.11, 17a §17a.4, §17a.7.
  Completed by `checks.crucible.phase4.faultPlan`: `Plan` now carries a
  full-taxonomy `FaultPlan` body with canonical `at`, `permanent_at`, and `heal`
  entries, world-time validation for node/link refs and heal tags, integer-param
  TOML parsing, compact-binary round trips, and pure-`At` event-graph lowering
  into `InjectFault`/`HealFault` actions in deterministic same-time order. The
  lowered trigger path projects active taxonomy faults into `CombinedFaults`,
  applies scheduler-owned node/topology/device effects, and exposes a live
  `NetLink` bridge for trigger-owned network faults. The `FaultPlan` content hash
  matches the mechanically equivalent pure-`At` event graph; block/9p device refs
  fail closed until the implemented `World` grows first-class I/O participant
  declarations.
- [x] **T-FAULT-11** Implement imperative inject/heal over the control plane
  applied at quantum boundaries and recorded in the `Schedule`, so an
  imperatively-driven session reduces to the same self-contained repro artifact.
  — satisfies [FAULT-26]; spec §17.6.2; cross-ref 20, 05.
  Completed by `checks.crucible.phase4.imperativeFaultControl`: control
  operations and session commands now carry typed full-taxonomy
  `InjectFault`/`HealFault` actions, apply them only during scheduler boundary
  drain, record each action as a `Decision::ControlFault` with exact virtual
  time and control sequence, and feed the resulting active-fault table through
  the same scheduler-owned node/topology/device application path used by
  declarative trigger faults. Recorded schedule prefixes rehydrate active
  imperative fault state without resubmitting controls, and compact-binary
  schedule round trips include control-fault decisions. Unknown imperative heals
  remain runtime no-ops while still being recorded in the schedule artifact.
- [x] **T-FAULT-12** Implement tag-based activation/heal (heal by tag,
  replace-on-retag, build-time rejection of declarative heal of an uninjected
  tag, runtime no-op heal of an unknown tag) and carry the active-tag set in
  `MaterializedState`. — satisfies [FAULT-27]; spec §17.6.3; cross-ref 06 §9, 07.
  Completed by `checks.crucible.phase4.faultTagState`: trigger and imperative
  control fault application now share tag-keyed activation semantics where
  reinjecting an active tag replaces the prior binding and healing removes only
  the named tag. Declarative `FaultPlan` heals whose tag is never injected remain
  build-time errors, while imperative unknown heals are recorded runtime no-ops.
  `SchedulerState` now materializes the active tag-to-fault binding, hashes it
  into `MaterializedState`, and includes it in symmetry material.
  `SingleScheduler::materialized_scheduler_state` captures declarative
  trigger/fault-plan active tags, while fat checkpoint materialization derives
  imperative tags from recorded `Decision::ControlFault` schedule prefixes so
  resumed checkpoints carry the same healable tags.
- [x] **T-FAULT-13** Implement the scheduler's deterministic active-fault table
  (edge/node-keyed, combined per §17.3.3, recomputed with lookahead at the quantum
  boundary on activation/heal, in `MaterializedState`, no unordered iteration). —
  satisfies [FAULT-28]; spec §17.6.4; cross-ref 08 §8.11, 07 §3.
  Completed by `checks.crucible.phase4.activeFaultTable`: `SchedulerState` now
  carries a materialized `ActiveFaultTable` with directed network-edge keys plus
  combined node, block, and 9p device maps. It is recomputed from active tag
  bindings for recorded `Decision::ControlFault` schedule replay and captured
  directly from `SingleScheduler`'s trigger-owned active projection for
  declarative trigger/fault-plan activations, including legacy crash/partition
  membership faults. The table is hashed into `MaterializedState` with explicit
  `BTreeMap` iteration and field writers, so resumed/forked runs preserve the
  same combined active network, node, block, and 9p lookup table.
- [ ] **T-FAULT-14** Implement `RandomFaultConfig` weighted reproducible
  generation (kind via integer weights, target/start/duration/severity within
  bounds, caps enforced by deterministic pruning), pure from the seed, lowering
  rates to basis points and canonically ordering before hashing; a discovered
  failure pins a concrete content-addressed def. — satisfies [FAULT-29],
  [FAULT-30]; spec §17.7; forward-ref 22.
  Completed by `checks.crucible.phase4.randomFaultConfig`: the model layer now
  exposes `RandomFaultConfig`, `FaultWeights`, `SeverityBounds`, and `FaultCaps`
  and generates a validated canonical `FaultPlan` from one seeded RNG fork. The
  generator draws start time, duration, weighted kind, target, and integer
  severity parameters, lowers rates through `FaultRateBasisPoints`, and prunes
  max-concurrent, partition, and crash caps deterministically in generation
  order. Generated plans validate through the existing `FaultPlan`/`Plan`
  content-addressing path so a random failure can be pinned as a concrete
  `ScenarioDef`. Heterogeneous Worlds now contribute content-derived block/9p
  targets; mixed device weights have a pinned golden plan, target selection stays
  within the selected device family, and the unbiased bounded sampler has a
  forced-rejection regression proving it consumes the biased prefix before the
  next logical field. The item remains open pending the full campaign-to-live-
  session/real-QEMU failure-pinning proof required by its complete scope.
- [x] **T-FAULT-15** Wire the fault determinism gate: a Plan of every currently
  plan-valid fault kind run twice yields identical activation icounts, identical
  effects, and an identical decision-RNG draw sequence; a divergence localizes to
  the first differing fault decision. — satisfies [FAULT-31]; spec §17.8;
  cross-ref 24.
  Completed by `checks.crucible.phase4.faultDeterminismGate`, which
  lowers a deterministic `FaultPlan` containing every plan-valid network, node,
  block, and 9p taxonomy kind, including each network corruption sub-kind. The
  World declares content-addressed block/9p nodes; the gate resolves their real
  immutable artifacts through the production World-backed scheduler constructor,
  activates the Plan through the trigger scheduler, and drives the attached
  concrete `DeviceSchedulingSubNode`s. Two runs compare activation times, active
  tag/table effects, live link/device fault tables, full delivery records, exact
  payload/timing effects, raw `RngDraw`s, and derived `FaultFires` decisions.
  Dedicated link/device probes prevent partition/loss from masking duplicate,
  corruption, and timing effects, while negative regressions localize mutated,
  inserted, truncated, and raw-draw divergences. A separate L4 integration test
  starts the World-backed session and proves a session fault command changes the
  active table of the artifact-backed device owned by that same scheduler. The
  Gate fingerprints now record the live counter of every scheduler node at each
  fault activation in addition to the shift-zero activation icount. The crash
  case starts with an artifact-backed block completion in flight and proves the
  concrete crash application discards that exact completion. The run-twice
  fingerprint includes these activation counters and crash-discard records
  alongside the already concrete failure, timing, duplicate, and corruption
  effects required by [FAULT-31].
- [x] **T-FAULT-16** Exercise every fault kind against the in-process test double
  (apply fault, drive request/frame sequence with a fixed seed, assert perturbed
  deliveries/drops/recorded decisions) with a per-kind run-twice determinism +
  divergence-localization test. — satisfies [FAULT-32]; spec §17.8; cross-ref 15
  §15.7, 24.
  Completed by `checks.crucible.phase4.faultTestDoubleGate`: the in-process
  double now drives every network-link, block, and 9p fault kind through a fixed
  frame/request sequence, asserts the visible perturbation (drop, delay, duplicate
  delivery, error reply/status, byte corruption, bandwidth serialization), checks
  exact recorded `RngDraw` replay and `FaultFires` loss/duplicate/corrupt triples,
  runs each case twice for byte-identical replay, and compares against a
  fault-free run with pinned first-divergence fields. Network partition coverage
  includes A-to-B drops, B-to-A unaffected direction, and bidirectional drops;
  network corruption sub-kinds are split into bit-flip, field-mutation, and
  truncation cases; reorder uses multi-frame/request batches so the observed
  delivery order must change rather than merely delay; block failure covers both
  error-status and drop modes.
