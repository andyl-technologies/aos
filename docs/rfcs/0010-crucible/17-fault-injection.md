# 17 — Deterministic fault effects

This file specifies Crucible's **fault model**: the complete taxonomy of
perturbations a scenario may impose on the simulated world, the exact semantics
of each, how every probabilistic fault decision is derived deterministically,
where each effect lives in the runtime, and how signal programs produce
reproducible fault campaigns for search and fuzzing. Fault signals and bindings
are the **one** fault representation that belongs in the `Plan`
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
is never mutated by session control commands
([`20-session-control-plane.md`](20-session-control-plane.md)), and is generated
for exploration by a scenario family
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

## 17.6 Scheduling faults with signals and bindings

A fault is authored only as a typed binding in `Plan::fault_signals`. The
binding samples one or more immutable signal-program outputs at its declared
boundary or opportunity, maps those values to a typed effect, and contributes
that effect to the target adapter. A persistent contribution is removed when
its activation mapping becomes false; there is no imperative fault mutation or
separate heal operation.

Known-time behavior uses `step`, `pulse`, or `periodic_pulse` sources. Behavior
anchored to an observed event uses the event source and deterministic signal
operators. Recorded physical behavior uses a normalized content-addressed trace.
Synthetic sporadic behavior uses a stable-key stochastic source. All of these
forms enter the same evaluator, binding, adapter, checkpoint, search, and replay
path.

### 17.6.1 The declarative signal/binding plan

```toml
[plan]
fault_model = "signal_bindings_v2"
fault_signal_semantic_version = 2

[[plan.signal]]
id = "split-window"
semantic_version = 1
domain = "virtual_time"
value_type = "bool"
unit = "dimensionless"
scale_decimal_exponent = 0
inputs = []

[plan.signal.node]
kind = "pulse"
start = 10000000000
duration = 30000000000
inactive = false
active = true

[[plan.fault_binding]]
id = "split-db-link"
semantic_version = 1
signals = ["split-window"]
search_policy = { kind = "fixed" }

[plan.fault_binding.sampling]
kind = "at_boundary"

[plan.fault_binding.mapping]
kind = "active_when_true"
invert = false
```

- **[FAULT-24]** `Plan::fault_signals` MUST be the sole fault representation in
  the `ScenarioDef`, MUST use `fault_model = "signal_bindings_v2"`, and MUST be
  content-addressed with the complete program, bindings, resource limits, and
  referenced artifacts. Targets MUST resolve to declared World objects before
  execution. *Gate:* `gate:content-address`, `gate:e2e-determinism`.
  *Spec:* §17.6.1; cross-ref 06 §5.1, §9.

- **[FAULT-25]** A fault activation, heal, or auto-heal MUST be resolved by the
  scheduler at the entry's **exact** virtual time as a cross-node event in the
  total order of [SCHED-15] ([SCHED-29] fault activation), never deferred to the
  next rendezvous tick ([SCHED-39]). A topology-changing fault (partition, crash,
  latency change) MUST trigger the scheduler's effective-topology swap and
  lookahead recompute atomically at the fault's exact activation time ([SCHED-37],
  [SCHED-39]). *Gate:* `gate:layer1-injection`, `gate:scheduler-liveness`.
  *Spec:* §17.6.1; cross-ref 08 §8.5, §8.11.

### 17.6.2 Session control does not mutate faults

The session control plane may pause, resume, save, fork, and select an explorer
candidate, but it cannot add, remove, or rewrite a fault. Interactive fault
experiments create a new scenario or a child configuration with a typed search
override. Both forms are content-addressed and replayable.

- **[FAULT-26]** Session commands MUST NOT provide an out-of-band fault mutation
  path. A changed signal program or binding creates a new scenario identity; an
  explorer selection creates a child configuration whose canonical override is
  bound to the exact parent, choice identity, candidate-set digest, and candidate
  index. *Gate:* `gate:control-responsive`, `gate:state-space-search`,
  `gate:replay-oracle`. *Spec:* §17.6.2; cross-ref 20, 22.

### 17.6.3 Binding identity and persistent contribution state

Every binding has a stable content-addressed identity. A mapping evaluation
either contributes a typed effect or does not; a false transition removes that
binding's prior persistent contribution. Multiple bindings can contribute the
same effect kind without ambiguous handles because adapter state is keyed by
binding and target identity.

- **[FAULT-27]** Binding contribution and hysteresis state MUST be part of the
  authenticated fault-runtime checkpoint. Restore MUST reproduce the same active
  contributions without replaying a control mutation. *Gate:*
  `gate:checkpoint-materialization`, `gate:replay-oracle`. *Spec:* §17.6.3.

### 17.6.4 Adapter state at deterministic opportunities

At each admitted boundary or hardware opportunity, the evaluator samples the
declared signals, resolves mappings in canonical binding order, and commits the
combined typed effects atomically through the owning adapter. Network lookahead
is recomputed at the exact boundary when a committed effect changes causal
delivery bounds.

- **[FAULT-28]** The evaluator, binding ledger, adapter state, and same-boundary
  sequence MUST use canonical ordered collections and MUST be checkpointed as one
  authenticated continuation. No outcome may depend on hash-map iteration or
  host arrival order. *Gate:* `gate:harness-lint`, `gate:replay-oracle`,
  `gate:e2e-determinism`. *Spec:* §17.6.4; cross-ref 08 §8.11, 07 §3.

### 17.6.5 Event observations are signal inputs, not fault actions

The event graph and fault system remain separate, composable parts of the Plan.
The event graph produces deterministic referenced occurrences. Event-domain
signal sources consume those occurrences and bindings map their values to typed
effects. The `Action` taxonomy therefore contains no fault action, and there is
no lowering from an event action into a second fault representation.

- **[FAULT-33]** Observation-anchored faults MUST use a referenced event signal
  source and the same binding runtime as time-, trace-, spatial-, and
  opportunity-driven faults. Event occurrences and signal cursors MUST cross the
  checkpoint and replay boundary. *Gate:* `gate:content-address`,
  `gate:e2e-determinism`. *Spec:* §17.6.5; cross-ref 17a §17a.4.

- **[FAULT-34]** Known-time faults MUST use time-domain signal nodes such as
  `step`, `pulse`, or `periodic_pulse`; they MUST NOT lower through a historical
  activation-row representation. Equivalent authored programs MUST share the
  signal program's canonical identity and evaluation path. *Gate:*
  `gate:content-address`, `gate:e2e-determinism`. *Spec:* §17.6.5.

## 17.7 `RandomFaultConfig`: weighted probabilistic fault generation

For fuzzing and state-space exploration ([G-6],
[`22-advanced-features.md`](22-advanced-features.md)) an author needs not one
hand-written campaign but a *generator* that produces a fresh, reproducible
`signal/binding plan` from a seed. `RandomFaultConfig` is that generator's configuration: a
set of nodes, a run duration, per-kind weights, severity bounds, and a seed.
Generation is itself **fully deterministic from the seed** — the same config
produces byte-identical `signal/binding plan`s every time — so a discovered failure reduces
to a concrete `ScenarioDef` (the generated `Plan` is pinned and content-addressed)
with no reference back to the generator ([SPAT-27]).

```rust,illustrative
/// Configuration for weighted, reproducible random fault-campaign generation
/// (fuzzing/exploration, file 22). `generate(config)` is a pure function of
/// `config` (including its seed): same config ⇒ byte-identical `signal/binding plan`.
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
result is a `signal/binding plan` whose rates are integer basis points ([FAULT-13]) and
whose entries are canonically ordered for hashing ([SPAT-30]).

- **[FAULT-29]** Crucible MUST provide a `RandomFaultConfig` that generates a
  `signal/binding plan` by weighted probabilistic selection over the fault taxonomy, ranging
  over kind (via integer `FaultWeights`), target (node/link from the `World`),
  start time, duration, and severity (within `SeverityBounds`), subject to integer
  `FaultCaps` (max concurrent faults, max partitions, max crashes). Generation
  MUST be a **pure function of the config including its seed**: the same config
  MUST produce a byte-identical `signal/binding plan` on every host (the generator draws
  from one seeded RNG in a fixed order and prunes to caps deterministically).
  *Gate:* `gate:e2e-determinism`, `gate:content-address`. *Spec:* §17.7;
  forward-ref 22.

- **[FAULT-30]** A `signal/binding plan` produced by `RandomFaultConfig` MUST lower every
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

- **[FAULT-32]** Every fault kind MUST be exercised through its production
  link/device/node core with a fixed-seed request or frame sequence, asserting
  perturbed deliveries, dropped items, and recorded decisions. Run-twice
  component coverage ([IO-28]) MUST confirm byte-identical core behavior, and
  the corresponding production adapter MUST pass its live-QEMU gate; a model or
  test-only adapter cannot satisfy acceptance. *Gate:* `gate:layer1-injection`,
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
  one declarative signal/binding plan: time, event, trace, spatial, stochastic,
    and opportunity domains share one content-addressed evaluator (FAULT-24,25)
  session control cannot mutate faults; search selects typed child overrides (FAULT-26)
  binding contribution and adapter state are authenticated continuation state (FAULT-27,28)
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

## Implementation status

The former activation-row implementation checklist has been retired with its
execution model. The authoritative signal-system implementation requirements,
per-effect evidence, and terminal acceptance gate are in
[`RFC-0013`](../0013-signal-driven-fault-model/README.md) and its
[`implementation plan`](../0013-signal-driven-fault-model/07-implementation-plan.md).
