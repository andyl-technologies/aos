# 08 — Cross-Node Scheduling

This file specifies the **scheduler**: the single authoritative source of timing
truth that advances virtual time across all nodes and resolves every cross-node
interaction in one deterministic total order. It is the operational heart of
multi-VM determinism — the place where Contract B
([`04-determinism-contract.md`](04-determinism-contract.md) §4.2.2) is *made*
true. Where [`03-architecture-overview.md`](03-architecture-overview.md) §5
sketched one quantum, this file gives the algorithm, the progress proof, the
horizon derivation, and the edge cases.

Requirement IDs here use the prefix `SCHED`. The scheduler upholds [INV-3]
(total order of cross-node events), [INV-8] (single authoritative scheduler),
[DET-6]/[DET-11]–[DET-14] (the injection contract), and exploits [DET-8]–[DET-10]
(icount-as-clock). It consumes virtual time / icount from
[`09-virtual-time-icount.md`](09-virtual-time-icount.md), drives nodes through
the per-node max-advance ceiling and futex wake of
[`13-shmem-abi.md`](13-shmem-abi.md), schedules I/O completions from
[`15-io-subnodes.md`](15-io-subnodes.md), activates faults from
[`17-fault-injection.md`](17-fault-injection.md), emits the event log of
[`19-observability-event-log.md`](19-observability-event-log.md), and is driven
exclusively by the session actor of
[`20-session-control-plane.md`](20-session-control-plane.md).

This file uses the quantum vocabulary **PICK / RUN / RESOLVE / EMIT / STEP**
exactly as defined in [`03-architecture-overview.md`](03-architecture-overview.md)
§5; that vocabulary is normative and is not redefined here, only elaborated.

## 8.1 The scheduling problem and the design in one page

Crucible runs `k` single-vCPU VMs and some number of I/O sub-nodes, each with
its own icount-derived virtual clock (09, [INV-4]). The whole-system run must be
a pure function `State(t) = reduce(ScenarioDef, Schedule[0..t])` ([INV-1]). The
scheduler's job is to advance those clocks and resolve the events that flow
between nodes — frame deliveries, I/O completions, fault activations — so that
the *icount at which any input becomes visible to any node is a pure function of
virtual time and the total order, never a function of host wall-clock or host
thread scheduling* ([DET-6], [DET-13]).

Four design commitments make this tractable, and they are the spine of the rest
of this file:

1. **One scheduler, realized as an actor that yields between quanta** ([INV-8],
   §8.2). There is exactly one component that advances virtual time and resolves
   cross-node order. It holds no long-lived locks; it yields at quantum
   boundaries so control operations land at well-defined points (forward-ref
   [`20-session-control-plane.md`](20-session-control-plane.md)).

2. **Conservative parallel discrete-event simulation (Chandy–Misra–Bryant)**
   (§8.3). A node advances only into a region of virtual time where *no peer
   could deliver an event earlier*. This is a conservative discipline: it never
   needs to roll back, because it never speculatively executes past a point a
   peer could still affect.

3. **The horizon rule** (§8.4) — the refinement that makes the design fast
   *and* exact: a node's horizon is `min(next exact local event,
   virtual_time + lookahead(node))`. **Exact local events** (timers, disk/9p I/O
   completions) are host-computed and predictable, so they give an *exact*
   horizon with no conservative slack; only *guest→guest network* needs the
   conservative CMB lookahead bound.

4. **Decouple sync FREQUENCY from ordering EXACTNESS** (§8.5). Ordering is
   *always* exact — never a tuning knob. The only knob is how often the
   scheduler rendezvouses non-terminal scheduler nodes for assertion-drain /
   topology-change, and that knob can never affect which instruction sees which
   input.

Everything below makes these precise.

## 8.2 The single authoritative scheduler as a yielding actor

- **[SCHED-1]** There MUST be exactly one scheduler in a running session, and it
  MUST be the sole component that (a) advances any node's virtual clock and (b)
  resolves the order of any cross-node event. No VM plugin, no I/O sub-node, no
  control-plane component, and no second engine instance may advance a clock or
  deliver a cross-node event out of band. *Gate:* `gate:scheduler-liveness`,
  `gate:layer1-injection`. *Spec:* §8.2; routes [INV-8], [ARCH-5].

- **[SCHED-2]** The scheduler MUST be realized as an **actor**: it owns the
  authoritative scheduler state (per-node virtual times, the pending cross-node
  event set, the decision RNG cursor) and mutates it only on its own task. Other
  components interact with it solely by messages, never by shared-state mutation
  of scheduler-owned data. *Gate:* `gate:control-responsive`. *Spec:* §8.2;
  routes [INV-8], [ARCH-9].

- **[SCHED-3]** The scheduler MUST NOT hold any lock across a RUN phase, and MUST
  yield to its message inbox at every quantum boundary (between STEP of one
  quantum and PICK of the next). Control operations (pause, resume, step,
  snapshot, fork, query, topology mutation) MUST be applied only at these
  boundaries, never mid-quantum. *Gate:* `gate:control-responsive`,
  `gate:scheduler-liveness`. *Spec:* §8.2, §8.11; forward-ref
  [`20-session-control-plane.md`](20-session-control-plane.md).

- **[SCHED-4]** The scheduler MUST be the single source of virtual time: there
  is no second clock, no host-wall-clock fallback, and no per-node free-running
  timer that the scheduler does not authorize. A node's clock advances only by
  (a) the scheduler authorizing a RUN up to a ceiling or (b) the scheduler
  jumping the clock across an idle gap. *Gate:* `gate:layer0-determinism`.
  *Spec:* §8.2; routes [INV-4], [INV-8].

The actor shape matters for both determinism and responsiveness. Because the
scheduler mutates its state only on one task, there is no host-thread interleave
to make nondeterministic; because it yields between quanta, a control message can
never observe a torn, mid-quantum state. The quantum is therefore the atomic unit
of *both* advancement and control.

```text
                         ┌──────────────────────────────────────────┐
   session actor (L4) ──►│  scheduler actor (L3) — the one clock     │
   control messages      │                                          │
   (pause/step/fork/…)   │   loop {                                  │
                         │     recv_control_at_boundary();   ◄── yield point (INV-8)
                         │     q = QUANTUM(state);                   │
                         │     PICK → RUN → RESOLVE → EMIT → STEP    │
                         │   }                                       │
                         └───────┬──────────────────────────────────┘
                                 │  per-node max-advance ceiling + futex wake (13)
                                 ▼
            VM nodes (plugin owns time control)   I/O sub-nodes (deterministic completion)
```

## 8.3 Conservative PDES (Chandy–Misra–Bryant)

Crucible's cross-node model is **conservative parallel discrete-event
simulation** in the Chandy–Misra–Bryant (CMB) tradition. The defining property
of a conservative scheme is that *it never executes an event it might later have
to undo*: a node is permitted to advance its clock to a virtual time `t` only
once it is certain that no event with timestamp `< t` can still arrive from any
peer. There is no rollback, no anti-message, no optimism — those belong to the
optimistic (Time-Warp) family, which Crucible deliberately does not use because
rollback of a full VM's architectural state is both expensive and a determinism
hazard.

### 8.3.1 The model

Model the system as a set of nodes `N` connected by directed **links**. A link
`A → B` has a one-way **latency** `L(A→B) > 0` in virtual time. The causal law
that conservative PDES rests on is:

> An event emitted by `A` at virtual time `T_emit` cannot become visible at `B`
> before `T_emit + L(A→B)`.

This is not an approximation; it is the *definition* of the modeled link
([`06-spatial-graph.md`](06-spatial-graph.md), [`15-io-subnodes.md`](15-io-subnodes.md)).
Therefore, if `B`'s clock is at `vt(B)`, the earliest possible timestamp of any
*future* network event reaching `B` from `A` is bounded below by
`vt(A) + L(A→B)` — `A` cannot, even running forward at full tilt, emit a frame
that arrives at `B` earlier than its own current clock plus the link latency.

- **[SCHED-5]** The scheduler MUST follow a *conservative* PDES discipline: a
  node MUST NOT advance its clock into a virtual-time region in which a peer could
  still produce an earlier cross-node event. No node MUST ever be rolled back, and
  the scheduler MUST NOT speculate past an unresolved cross-node dependency.
  *Gate:* `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §8.3;
  routes [INV-3], [DET-6], [DET-12].

- **[SCHED-6]** A node's safe **lookahead** MUST be the minimum inbound link
  latency from any peer that could send to it:
  `lookahead(B) = min over peers A with a live link A→B of L(A→B)`. A peer cannot
  deliver to `B` sooner than `vt(B) + lookahead(B)`, so `B` may safely advance at
  least that far without missing any cross-node dependency. *Gate:*
  `gate:layer1-injection`. *Spec:* §8.3, §8.4; routes [DET-12].

`lookahead` here is the *network* lookahead — the conservative bound for
guest→guest links. Exact local events tighten the horizon further and exactly
(§8.4); the conservative bound governs only the part of the future that depends
on *another node's* not-yet-executed instructions.

### 8.3.2 Progress and liveness (the deadlock argument)

A naïve conservative scheme can deadlock: every node waits for a guarantee from a
peer that is itself waiting. Crucible's structure avoids this because virtual
time has a global minimum and the lookahead is strictly positive.

- **[SCHED-7]** The scheduler MUST guarantee progress: at every quantum, the node
  with the **global-minimum horizon** can always be advanced, so the system never
  deadlocks. With strictly positive link latencies (the minimum-latency floor of
  §8.7) and exact local events for all non-network wakeups, there is always at
  least one node whose horizon is achievable now. *Gate:*
  `gate:scheduler-liveness`. *Spec:* §8.3.2; routes [INV-8].

**Liveness argument.** Let `vt_min = min over alive nodes n of vt(n)` be the
global-minimum virtual time, and let `m` be a node attaining it (ties broken by
`node_id`, §8.6). Consider `m`'s horizon:

- Its **network** component is `vt(m) + lookahead(m) = vt_min + lookahead(m)`.
  Because `lookahead(m) > 0` (positive latencies, §8.7) and `vt(m) = vt_min` is
  the global minimum, *no peer's clock is behind `m`*, so no peer can emit an
  event with timestamp `< vt_min + lookahead(m)` that `m` has not already
  accounted for. The horizon is therefore *achievable*: `m` can run to it without
  waiting on any peer.
- Its **exact-local** component (next timer / I/O completion) is a host-computed
  value that does not depend on any peer at all (§8.4), so it never blocks.

Hence the global-minimum-horizon node can *always* be advanced by a positive
amount of virtual time. After it advances, either `vt_min` rises (progress) or
the node goes idle and is fast-forwarded to its wake time (also progress, §8.8).
Because every quantum strictly advances the minimum-horizon node and virtual time
is bounded below by `0` and monotone, the system cannot livelock: it advances
until quiescence (§8.8) or a configured time/decision budget. This is the
property `gate:scheduler-liveness` checks ([HARN-18]): the scheduler always
reaches quiescence or its limit; never a deadlock or livelock.

- **[SCHED-8]** The scheduler MUST always be able to select a node to advance
  whenever the system is not quiescent (§8.8); a state in which the system is
  non-quiescent yet no node can advance is a defect and MUST fail loudly, never
  spin silently. *Gate:* `gate:scheduler-liveness`. *Spec:* §8.3.2, §8.8; routes
  [INV-8], [INV-10].

## 8.4 The horizon rule

The horizon is the single most important refinement in this file. It is what lets
Crucible be *exact about ordering* while *fast about idle and predictable
events*.

- **[SCHED-9]** For every node `n`, the scheduler MUST compute a **horizon** —
  the furthest virtual time `n` may advance to before it must synchronize — as

  ```text
  horizon(n) = min( next_exact_local_event(n),
                    vt(n) + lookahead(n) )
  ```

  where `next_exact_local_event(n)` is the soonest *host-computed, predictable*
  next wakeup of `n` (next timer deadline, next disk/9p I/O completion, next
  scheduled fault that targets `n` locally) and `lookahead(n)` is the network
  lookahead of [SCHED-6] (minimum inbound link latency). *Gate:*
  `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §8.4; routes
  [INV-3], [DET-11], [DET-12].

### 8.4.1 Why exact local events do not need a conservative bound

The crux: **not every future event is uncertain.** Two classes of next-event are
fundamentally different in their predictability.

- **Exact local events** — a guest timer deadline, a disk read completion, a 9p
  request completion, a locally-scheduled fault — are *computed by the host* from
  state the scheduler already holds. The disk sub-node, given a request and its
  fixed completion model, computes the *exact* virtual time the read finishes
  ([`15-io-subnodes.md`](15-io-subnodes.md)); a timer deadline is set by the
  guest writing a timer register and is read out by the plugin. There is no other
  node whose un-executed instructions could move that time. So the scheduler knows
  the *exact* next instant `n` will need attention from these sources, and can
  let `n` run *exactly* to that instant — no conservative slack, no peer to wait
  on.

- **Guest→guest network events** are different: whether and when peer `A` emits a
  frame to `n` depends on instructions `A` has *not executed yet*. The host cannot
  compute that exactly in advance. This is the *only* source of genuine
  cross-node uncertainty, and it is exactly what the conservative CMB lookahead
  bounds: `n` may run to `vt(n) + lookahead(n)` because no peer can deliver before
  that, but no further without a guarantee.

- **[SCHED-10]** The horizon's `next_exact_local_event(n)` term MUST be an
  *exact* virtual time (no conservative bound applied), because it is a pure
  function of host-held state and depends on no other node's unexecuted
  instructions. The conservative lookahead term MUST apply *only* to the
  guest→guest network dependency. A scheduler that applies the conservative bound
  to a local timer or an I/O completion (thereby under-advancing) is correct but
  *slower*; one that applies *no* bound to a network dependency is *wrong*. *Gate:*
  `gate:layer1-injection`. *Spec:* §8.4.1; routes [DET-11], [DET-12].

This is why I/O is modeled as first-class sub-nodes whose completions are *exact
local events* ([`15-io-subnodes.md`](15-io-subnodes.md), [ARCH-7]): a disk read
does not "finish whenever the host disk finishes" (host-timing — forbidden by
[DET-19]); it finishes at a virtual time the sub-node computes, so it tightens
the requester's horizon *exactly*, giving both determinism and speed.

### 8.4.2 The horizon pseudocode

```text
fn horizon(n, state) -> VirtualTime:
    # Exact, host-computed local next-event for n. None => no local event pending.
    let local = next_exact_local_event(n, state)        # min over:
                                                        #   - n's next guest timer deadline
                                                        #   - n's earliest in-flight I/O completion (15)
                                                        #   - n's next locally-scheduled fault (17)
    # Conservative network bound: no peer can deliver to n before this.
    let net   = vt(n) + lookahead(n)                    # lookahead(n) = min inbound link latency (SCHED-6)
                                                        # if n has no inbound links, lookahead = +inf
    match local:
        Some(t) => min(t, net)
        None    => net                                   # purely network-bounded
    # NOTE: an already-DUE pending input for n (delivery_vt <= vt(n)) is not a
    #       horizon term; it is RESOLVEd this quantum (8.9) before n RUNs further.
```

`next_exact_local_event` returns the *earliest* of every exact, host-known wakeup
for `n`. `lookahead(n)` is computed from the current effective topology (§8.10),
recomputed when faults change the live edge set. When a node has no inbound links
at all (e.g. during boot before any link is active), its network term is `+∞` and
its horizon is purely its next exact local event — which is why nodes boot
independently at full speed with no inter-node synchronization (§8.5, §8.7).

## 8.5 Decoupling sync FREQUENCY from ordering EXACTNESS

This is the central correction over coarse fixed-window scheduling designs, and a
hard normative line.

A fixed-window (epoch/barrier) design rendezvouses *all* nodes at a tunable
interval and only delivers cross-node events at those boundaries. That conflates
two utterly different concerns into one number: how *often* the scheduler does
global bookkeeping, and how *precisely* an event lands at a consumer. Make the
window coarse and events are delivered late (wrong ordering at fine grain); make
it fine and the rendezvous overhead dominates. Worse, if the per-node advance
ceiling is recomputed *inside* the window in a way a plugin can observe at
host-timing-dependent points, a one-instruction butterfly leaks in. Crucible
rejects this conflation.

- **[SCHED-11]** Cross-node **ordering exactness MUST NOT be a tunable knob.**
  Every cross-node event MUST be resolved at the exact virtual time given by its
  delivery rule (`T_emit + link_latency` for a frame; the sub-node's computed
  completion time for I/O; the Plan's virtual time for a fault), and made visible
  to the consumer at exactly the corresponding icount ([DET-11]). No
  configuration value may change which instruction observes which input. *Gate:*
  `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §8.5; routes [INV-3],
  [DET-11], [DET-13], [DET-14].

- **[SCHED-12]** The only schedule-related tunable MUST be the **rendezvous
  frequency** (the interval at which the scheduler brings non-terminal
  scheduler nodes to a common virtual time to drain assertions, evaluate
  triggers, and apply topology changes). This frequency is a *performance and
  observation-latency* knob only:
  it MUST NOT affect the instruction stream, the icount at which any input is
  delivered, the event log's ordering, or any fingerprint. Two runs with
  different rendezvous frequencies MUST produce bit-identical `S` and `T` and
  bit-identical determinism-relevant event-log entries. *Gate:*
  `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §8.5, §8.11; routes
  [INV-1], [INV-3].

- **[SCHED-13]** The scheduler MUST deliver each cross-node event at its exact
  delivery virtual time *independently of* the rendezvous frequency: an event due
  at virtual time `t` MUST be made visible to its consumer at the icount
  corresponding to `t`, even if the next rendezvous is far in the future.
  Delivery is driven by the per-node horizon/RESOLVE machinery (§8.4, §8.9), not
  by the rendezvous clock. *Gate:* `gate:layer1-injection`. *Spec:* §8.5, §8.9;
  routes [DET-11], [DET-13].

The decoupling is realized by the horizon rule: because each node independently
runs to its own horizon and RESOLVE delivers any event whose delivery time has
arrived (§8.9), event delivery is *continuous and exact* at the instruction
level, while the rendezvous is a *separate, coarse* operation used only for work
that genuinely needs non-terminal scheduler nodes at one virtual time (assertion
drain, topology swap). Frequency tunes the latter; it cannot touch the former.

- **[SCHED-14]** A rendezvous MUST be implemented as a special, exact horizon
  term shared by all non-terminal scheduler nodes (a common `rendezvous_vt` that
  participates in `horizon` exactly like an exact local event), so that bringing
  those nodes to a common virtual time is itself an exact, deterministic
  operation — never an approximate "stop everyone roughly here." If a node's
  exact local event or network horizon is earlier than `rendezvous_vt`, that
  earlier horizon governs; the rendezvous only *caps* advancement, it never
  *forces* a node past an earlier exact event. Halted and done nodes are
  terminal and are not members of the active rendezvous set. *Gate:*
  `gate:layer1-injection`. *Spec:* §8.5; routes [INV-3].

## 8.6 The deterministic total order of cross-node events

- **[SCHED-15]** Every cross-node event (frame delivery, I/O completion, fault
  activation, white-box channel write) MUST carry a total-order key
  `(virtual_time, consumer node_id, producer node_id, sequence)` and MUST be
  resolved in ascending key
  order. This order MUST be wall-clock-independent and host-scheduling-independent:
  it is a pure function of the four key fields. *Gate:* `gate:layer1-injection`.
  *Spec:* §8.6; routes [INV-3], [DET-14].

The four key fields, precisely:

- **[SCHED-16]** `virtual_time` MUST be the event's **delivery** virtual time
  (when it becomes visible to its consumer), not its emit time: a frame's key
  uses `T_emit + link_latency`; an I/O completion uses the sub-node's computed
  completion time; a fault uses the Plan's activation virtual time. *Gate:*
  `gate:layer1-injection`. *Spec:* §8.6; routes [INV-3], [DET-11].

- **[SCHED-17]** `consumer node_id` MUST be the **consumer** node's stable
  identity (the node at which the event becomes visible), assigned
  deterministically from the ScenarioDef's content-addressed node ordering
  ([`06-spatial-graph.md`](06-spatial-graph.md)), never from launch order or a
  host pointer. *Gate:* `gate:layer1-injection`. *Spec:* §8.6; routes [INV-3],
  [INV-6].

- **[SCHED-18]** `producer node_id` MUST be the producer's stable
  content-addressed node identity, and `sequence` MUST be a per-`(producer,
  consumer)` monotonic counter assigned by the producer at emit time, breaking
  ties between events that share `virtual_time`, `consumer node_id`, and
  `producer node_id`. The counter MUST be part of saved state so a resumed run
  continues the same sequence. The tie-break MUST be fully specified with no
  residual ambiguity: for two events with equal `(virtual_time, consumer
  node_id)`, order is by ascending `producer node_id` first, then ascending
  `sequence`. *Gate:* `gate:layer1-injection`, `gate:replay-oracle`.
  *Spec:* §8.6; routes [INV-3], [DET-14].

- **[SCHED-19]** The scheduler MUST NOT rely on any iteration order of an
  unordered collection (e.g. a hash map) on the path that produces or resolves
  cross-node order; all ordering-significant collections MUST be ordered
  (sorted/`BTreeMap`-style) and all hashing used for identity MUST be a fixed,
  cross-platform stable hash, never the language's default randomized hasher.
  *Gate:* `gate:harness-lint`. *Spec:* §8.6; routes [INV-9], [DET-26].

This total order is the operational form of [INV-3] and the consumer-side
half of Contract B: even when many events fall on the same delivery icount at the
same consumer ([DET-14]), their visibility order is the fixed key, identical
across runs and across hosts.

## 8.7 The minimum link-latency floor

- **[SCHED-20]** Every guest→guest link MUST have a strictly positive latency,
  and the system MUST enforce a configured **minimum link-latency floor** (the
  same floor used by the spatial-graph link validation,
  [`06-spatial-graph.md`](06-spatial-graph.md)). A scenario that declares a
  zero-latency (or sub-floor) link MUST be rejected at lowering time, not at run
  time. *Gate:* `gate:scheduler-liveness`. *Spec:* §8.7; routes [INV-3],
  forward-ref [`06-spatial-graph.md`](06-spatial-graph.md).

**Rationale.** The network lookahead is `min` inbound link latency (§8.3). If any
link had zero latency, that node's lookahead would be zero, its network horizon
would equal its current clock, and it could advance by no virtual time before
needing a fresh peer guarantee — i.e. the system would degrade to *single-
instruction lockstep* between the linked nodes, with the scheduler rendezvousing
every instruction. That destroys all parallelism (the whole point of conservative
PDES) without buying any extra correctness. A positive floor guarantees a
positive lookahead, which guarantees both progress (§8.3.2) and a usable
parallelism budget (§8.12). This is the same floor referenced by performance
([`25-performance-targets.md`](25-performance-targets.md)): the parallelism a
multi-VM run can extract is exactly the lookahead budget, so the floor is the
lower bound on achievable concurrency.

- **[SCHED-21]** The minimum link-latency floor MUST be part of the scenario's
  content hash, because it bounds the lookahead and therefore the set of
  reachable schedules; two runs that compare for determinism MUST share the same
  floor. The floor MUST NOT be silently widened or narrowed at run time. *Gate:*
  `gate:e2e-determinism`. *Spec:* §8.7; routes [INV-6].

## 8.8 Quiescence detection

- **[SCHED-22]** The scheduler MUST detect **quiescence**: the state in which
  *every* node is idle (no running guest work), there are *no* pending cross-node
  deliveries, *no* pending exact local events (no future timer or I/O
  completion), and *no* future faults due in the Plan. At quiescence, no node has
  a finite horizon and nothing will ever change the system again, so the run is
  complete (or ready for an `AfterQuiescence` property,
  [`18-assertions-properties.md`](18-assertions-properties.md)). *Gate:*
  `gate:scheduler-liveness`. *Spec:* §8.8; routes [INV-8].

- **[SCHED-23]** Quiescence MUST be computed from authoritative scheduler state
  only, deterministically, and MUST NOT depend on a host timeout or a "nothing
  happened for a while in wall-clock" heuristic. A node is idle for quiescence
  purposes when it is HLT/blocked with no finite next exact local event and no
  inbound pending delivery; the system is quiescent when this holds for all alive
  nodes simultaneously and all queues are empty. *Gate:*
  `gate:scheduler-liveness`, `gate:layer0-determinism`. *Spec:* §8.8; routes
  [INV-8], [INV-9].

Quiescence is the natural terminal of the liveness argument (§8.3.2): the
scheduler advances the minimum-horizon node until either a budget is hit, an
`Always` property fails ([`18-assertions-properties.md`](18-assertions-properties.md)),
or no node has a finite horizon — the last case being quiescence. Idle nodes do
*not* hold the system back: an idle node's effective horizon is its wake time
(§8.9.3), so a node idle until virtual time `T` never constrains a peer running
at a time `< T`.

For a multi-vCPU node, "idle" is a property of *all* its vCPUs together: the
node is idle only when every vCPU is halted with no armed timer and no pending
input, and its idle wake icount is the minimum next deadline over its vCPUs.
The effective-horizon projection ([SCHED-44]) is applied at the node level. See
[SCHED-47] (§8.16).

## 8.9 The quantum: PICK / RUN / RESOLVE / EMIT / STEP

The scheduler advances the system one **quantum** at a time, using the five-phase
vocabulary of [`03-architecture-overview.md`](03-architecture-overview.md) §5
exactly. This section is the full algorithm.

- **[SCHED-24]** Each quantum MUST perform the five phases **PICK, RUN, RESOLVE,
  EMIT, STEP** in that order, and the sequence of quanta MUST be a pure function
  of `(ScenarioDef, Seed, Schedule)`. The quantum is the unit of `step`
  ([`05-execution-model.md`](05-execution-model.md)): one quantum appends zero or
  more `Decision`s to the `Schedule` and advances the frontier. *Gate:*
  `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §8.9; routes
  [INV-1], [INV-3], [ARCH-5].

### 8.9.1 PICK

- **[SCHED-25]** **PICK** MUST select the node with the **global-minimum
  horizon**, breaking ties by ascending `node_id` (a stable, content-addressed
  identity), so PICK is a total, deterministic order over nodes. The selected
  node is the one that can advance furthest-soonest without crossing any
  unresolved cross-node dependency. *Gate:* `gate:scheduler-liveness`,
  `gate:layer1-injection`. *Spec:* §8.9.1; routes [INV-3], [INV-8].

- **[SCHED-44]** PICK's global-minimum-horizon argmin MUST be taken over a single
  **unified per-node horizon projection** `effective_horizon(node)`, defined by
  the node's status:

  ```text
  effective_horizon(node) =
      DONE/Halted  →  +∞                  (u64::MAX; a finished node never holds
                                           back the simulation)
      IDLE         →  idle_wake_icount    (its exact wake time, SCHED-28/8.9.3)
      RUNNING      →  current frontier    (horizon(node) of SCHED-9: the min of
                                           next_exact_local_event and the
                                           conservative network bound)
  ```

  The global step MUST pick `argmin over non-DONE nodes of effective_horizon`
  (ties broken by ascending `node_id`, [SCHED-25]). A DONE node MUST contribute
  `+∞` so it is never selected and never lowers the global minimum; when *every*
  node projects `+∞` (all DONE, or all idle/network-bounded with no finite term)
  and all queues are empty, the system is **quiescent** (§8.8, [SCHED-22]) and the
  step yields no advance. This is the single projection used by the liveness
  argument (§8.3.2), quiescence detection (§8.8), and the quantum loop (§8.9.7);
  there is no second, status-specific horizon rule. *Gate:*
  `gate:scheduler-liveness`, `gate:layer1-injection`. *Spec:* §8.9.1, §8.8, §8.9.7;
  routes [INV-3], [INV-8].

### 8.9.2 RUN

- **[SCHED-26]** **RUN** MUST advance the selected node under `-icount` until it
  reaches its horizon — its next *sync point*, which is the earliest of: a
  translation-block boundary at or after the horizon virtual time; an idle (HLT)
  with no earlier wakeup; or an emitted output (a frame the guest sends, an I/O
  request it issues). RUN MUST NOT advance past the horizon. Idle MUST be
  fast-forwarded to the wake time at zero wall-clock cost (§8.9.3). *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer0-determinism`. *Spec:* §8.9.2; routes
  [INV-4], [DET-10].

- **[SCHED-27]** RUN MUST be effected through the per-node **max-advance
  ceiling**: the scheduler publishes the node's horizon (as a virtual time / the
  derived icount) to that node's shared-memory slot, and the node's plugin runs
  until its clock reaches the ceiling and then blocks. The scheduler MUST NOT
  observe any intermediate ceiling value — the horizon is published once per RUN,
  not recomputed mid-RUN — so the plugin observes exactly one deterministic
  ceiling per quantum (no host-timing butterfly). The futex wake / max-advance
  mechanism is specified in [`13-shmem-abi.md`](13-shmem-abi.md). *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer1-injection`. *Spec:* §8.9.2,
  forward-ref [`13-shmem-abi.md`](13-shmem-abi.md); routes [INV-3], [DET-13].

The "exactly one ceiling per RUN" rule is load-bearing for determinism: an
incremental ceiling that the plugin could read at a host-scheduling-dependent
moment would let a single-instruction difference leak into guest timing. The
horizon is a *single* value computed before RUN and published once.

For a multi-vCPU node, the node's instruction budget within one RUN is
sub-divided across vCPUs internally; this sub-division is plugin-internal and
does not change the single-ceiling rule above. See [SCHED-45] (§8.16).

### 8.9.3 RUN and idle: fast-forward without losing exactness

- **[SCHED-28]** When the selected node goes idle (HLT) during RUN with its next
  wakeup at virtual time `T_wake <= horizon`, the scheduler MUST treat `T_wake`
  as the node's effective clock for other nodes' lookahead and MUST be able to
  fast-forward the node's clock to `T_wake` at zero wall-clock cost (no busy
  spin, no host sleep). An idle node MUST NOT constrain a peer whose clock is
  behind `T_wake`. *Gate:* `gate:scheduler-liveness`,
  `gate:single-vm-fingerprint`. *Spec:* §8.9.3, §8.8; routes [INV-4], [DET-10].

Fast-forward is exact, not approximate: `T_wake` is an *exact local event*
(§8.4.1) — the next timer deadline computed from the guest's timer registers, or
the next pending I/O completion, or a rendezvous cap. The clock jumps to a value
the scheduler knows precisely, so idle compression costs no wall-clock yet
changes no instruction ordering. This is how a 60-second idle gap collapses to a
single jump (`G-9`, [`25-performance-targets.md`](25-performance-targets.md))
while every wakeup still lands at its exact icount.

### 8.9.4 RESOLVE

- **[SCHED-29]** **RESOLVE** MUST process every cross-node event that is now
  **due** (delivery `virtual_time <=` the advanced frontier of the affected
  consumer) in the deterministic total order of §8.6
  `(virtual_time, consumer node_id, producer node_id, sequence)`. Each resolved
  event MUST be made visible to its consumer at exactly the icount corresponding
  to its delivery virtual time ([DET-11]); the moment the payload became
  *present* on the transport is irrelevant ([DET-13]). The classes RESOLVE
  handles are:
  - **frame delivery** — `delivery_vt = T_emit + link_latency`, with the
    effective fault table applied ([`17-fault-injection.md`](17-fault-injection.md)):
    partition/loss may drop it, latency/jitter faults may shift `delivery_vt`,
    corruption may mutate the payload;
  - **I/O completion** — a disk/9p sub-node's deterministic completion event
    ([`15-io-subnodes.md`](15-io-subnodes.md));
  - **fault activation** — a Plan entry whose virtual time has arrived
    ([`17-fault-injection.md`](17-fault-injection.md)).
  *Gate:* `gate:layer1-injection`. *Spec:* §8.9.4; routes [INV-3], [DET-11],
  [DET-13], [DET-14], [ARCH-7].

- **[SCHED-30]** Any **probabilistic** choice resolved during RESOLVE (does a
  lossy link drop this frame? how much jitter does a jitter fault add? does a
  duplicate fire?) MUST be drawn from the single seeded decision RNG
  ([`04-determinism-contract.md`](04-determinism-contract.md) §4.7), consumed in
  the total order of §8.6 so the draw sequence is itself deterministic, and
  recorded as a `Decision` in the `Schedule`. There MUST be no other randomness
  in RESOLVE. *Gate:* `gate:harness-lint`, `gate:replay-oracle`. *Spec:* §8.9.4;
  routes [DET-24], [DET-27].

- **[SCHED-31]** RESOLVE MUST enforce the lookahead guarantee: it MUST be
  impossible for a consumer to have advanced *past* the delivery icount of an
  event before that event was made available. If the scheduler ever finds a node
  that has run past a due event's delivery icount, it MUST fail loudly and
  localize the violation, never deliver the event late ([DET-12], [INV-10]).
  *Gate:* `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §8.9.4;
  routes [DET-12], [INV-10].

When the explorer supplies a `Decision::Preemption`
([`05-execution-model.md`](05-execution-model.md) §12), RESOLVE applies it as
the node's interrupt/switch point within the bounded window, recorded in total
order; see [SCHED-46] (§8.16).

### 8.9.5 EMIT

- **[SCHED-32]** **EMIT** MUST append an ordered, content-addressed entry to the
  single event log ([`19-observability-event-log.md`](19-observability-event-log.md))
  for every resolved happening and for every `Decision` taken this quantum. The
  event-log order MUST be the total order of §8.6 so the log is itself a
  deterministic witness of the run. *Gate:* `gate:layer1-injection`,
  `gate:replay-oracle`. *Spec:* §8.9.5; routes [INV-3], [INV-6].

### 8.9.6 STEP

- **[SCHED-33]** **STEP** MUST set `config' = step(config, decisions_taken)` and
  advance the frontier, then **yield** to the scheduler's control inbox before
  the next PICK (the [INV-8] boundary, §8.2). All accepted control operations
  MUST be applied here, never mid-quantum. *Gate:* `gate:control-responsive`,
  `gate:scheduler-liveness`. *Spec:* §8.9.6; routes [INV-8], [ARCH-9].

### 8.9.7 The quantum in pseudocode

```text
fn quantum(state, decision_rng) -> StepResult:
    # ---- PICK -------------------------------------------------------------
    # Global-minimum horizon, ties broken by ascending node_id (SCHED-25).
    let n = argmin over alive nodes by (horizon(node, state), node.id)
    if horizon(n, state) is +inf and queues_empty(state):
        return Quiescent                                  # SCHED-22

    let h = horizon(n, state)                             # SCHED-9, computed ONCE

    # ---- RUN --------------------------------------------------------------
    # Publish exactly one max-advance ceiling for n; run under -icount to h.
    publish_ceiling(n, vt_to_icount(h))                  # SCHED-27, one write
    let run_result = run_until_ceiling(n)                 # TB boundary>=h | idle | output
    match run_result:
        Idle { wake_vt } => set_effective_clock(n, wake_vt)   # SCHED-28 fast-forward
        Output { .. }    => {}                                  # frame/IO emitted
        Reached          => {}                                  # hit ceiling exactly

    # ---- RESOLVE ----------------------------------------------------------
    # All cross-node events now due, in
    # (virtual_time, consumer_node_id, producer_node_id, sequence) order.
    let due = collect_due_events(state)                   # delivery_vt <= frontier
    sort due by (virtual_time, consumer_node_id, producer_node_id, sequence)  # SCHED-15..18
    let decisions = []
    for ev in due:
        assert consumer_has_not_passed(ev)                # SCHED-31 / DET-12: else fail loud
        match ev:
            Frame  => { let d = apply_fault_table(ev, decision_rng);  # SCHED-30
                        if d.delivered { make_visible_at(ev.consumer, ev.delivery_icount, d.payload) }
                        decisions += d.recorded }
            IoDone => make_visible_at(ev.consumer, ev.delivery_icount, ev.completion)
            Fault  => activate_fault(ev); recompute_lookahead(state)   # SCHED-37 topology change

    # ---- EMIT -------------------------------------------------------------
    for ev in due:        append_event_log(ev)            # SCHED-32, same total order
    for d  in decisions:  append_event_log(d)

    # ---- STEP -------------------------------------------------------------
    state = step(state, decisions)                        # SCHED-33
    yield_to_control_inbox()                              # INV-8 boundary
    return Progressing
```

The five phases recur exactly as in 03 §5; this pseudocode adds only the
mechanics (the single ceiling publish, the explicit total-order sort with the
producer-id tie-break, the fail-loud lookahead assertion, the topology recompute
on fault activation). The authority is the prose requirements above; this sketch
is illustrative ([CONV-1], 00).

## 8.10 Integration with virtual time / icount and the shmem ceiling

- **[SCHED-34]** The scheduler MUST treat each node's clock as icount-derived
  per [`09-virtual-time-icount.md`](09-virtual-time-icount.md): it converts a
  horizon virtual time to a per-node icount via the fixed shift (`ns = icount <<
  shift`, using the [TIME-4] ceil map — a node must never stop before a deadline)
  and publishes *that icount* as the node's max-advance ceiling. All
  horizon arithmetic is in virtual time; all per-node ceilings are in icount; the
  conversion is the fixed shift and nothing else. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §8.10;
  forward-ref [`09-virtual-time-icount.md`](09-virtual-time-icount.md); routes
  [INV-4], [DET-8].

- **[SCHED-35]** The scheduler MUST drive a VM node entirely through the
  shared-memory **per-node max-advance ceiling + futex wake** mechanism of
  [`13-shmem-abi.md`](13-shmem-abi.md): it writes the ceiling, the node runs to it
  and blocks, and the scheduler wakes the node (futex) when a new ceiling or a
  due input warrants. The scheduler MUST publish a ceiling that lets a node run to
  its full horizon — never an artificially small slice — so idle and predictable
  spans are crossed in one RUN, not many. *Gate:* `gate:single-vm-fingerprint`,
  `gate:scheduler-liveness`. *Spec:* §8.10; forward-ref
  [`13-shmem-abi.md`](13-shmem-abi.md); routes [INV-4], [DET-13].

- **[SCHED-36]** When the scheduler writes a fresh ceiling that *raises* an idle
  node's bound (e.g. after a rendezvous, or because a new input is due), it MUST
  wake the node's futex *after* any due input has been written to that node's
  inbound queue, so the woken plugin observes a consistent
  `(ceiling, pending-inputs)` snapshot in one wake. A wake that races a half-
  written inbox is a determinism hazard and is forbidden. *Gate:*
  `gate:layer1-injection`. *Spec:* §8.10; forward-ref
  [`13-shmem-abi.md`](13-shmem-abi.md); routes [INV-3], [DET-34].

The ceiling mechanism is the bridge between this file's *what* (run node `n` to
horizon `h`) and the transport's *how* (atomics + futex, 13). The horizon is the
single source of the ceiling value; the transport is a faithful conduit that
never changes *when* an input is visible — only carries the scheduler's exact
decision to the plugin.

## 8.11 Topology-change handling: faults change effective edges

Membership is static (the set of nodes and the declared links is fixed in the
ScenarioDef, [`06-spatial-graph.md`](06-spatial-graph.md)), but **faults change
the *effective* edge set** at run time: a partition removes edges, a heal
restores them, a latency fault changes a link's latency, a node crash removes all
of a node's edges. Because lookahead is derived from the live edge set (§8.3),
the scheduler MUST recompute it when the effective topology changes.

- **[SCHED-37]** When a fault activation, heal, or latency change alters the
  effective edge set or a link latency, the scheduler MUST recompute every
  affected node's `lookahead` (and therefore its horizon) at the quantum boundary
  where the change takes effect — never mid-RUN. A change that *lowers* a node's
  lookahead MUST take effect before that node is next PICKed past the new bound,
  so the conservative guarantee is never violated by a stale lookahead. *Gate:*
  `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §8.11; forward-ref
  [`17-fault-injection.md`](17-fault-injection.md); routes [INV-3], [DET-12].

- **[SCHED-38]** A **partition** MUST be modeled as removing the affected
  directed edges from the effective topology for the partition's duration:
  removed edges no longer contribute to any node's lookahead, and no frame may be
  delivered across them. A **heal** MUST restore them. The lookahead recompute on
  partition/heal MUST use the same `min`-inbound-latency rule (§8.3) over the
  *current* effective edge set. When a partition removes a node's last inbound
  link, its lookahead becomes `+∞` and it is bounded only by its exact local
  events (it may run freely until a heal). *Gate:* `gate:layer1-injection`.
  *Spec:* §8.11; forward-ref [`17-fault-injection.md`](17-fault-injection.md);
  routes [INV-3], [DET-12].

- **[SCHED-39]** Topology changes MUST be applied **atomically at a rendezvous**
  (all non-terminal scheduler nodes at a common virtual time, §8.5/§8.14): the
  scheduler swaps the effective topology while no node is mid-RUN, so every
  non-terminal node observes the change at the same virtual time and no node ever
  runs partly under the old and partly under the new lookahead within one
  quantum. The rendezvous used for topology swap is the *frequency* knob of
  §8.5; the *virtual time* at which the swap takes effect is the fault's exact
  activation time, not "whenever the next rendezvous happens to fall." *Gate:*
  `gate:layer1-injection`,
  `gate:scheduler-liveness`. *Spec:* §8.11; routes [INV-3], [DET-12].

The interaction of [SCHED-39] with [SCHED-14] is the resolution of an apparent
tension: a fault activates at an *exact* virtual time (an exact local event, so
it tightens horizons exactly), and the scheduler ensures that the topology swap
implied by that fault happens with all non-terminal scheduler nodes brought to
that exact time — so the swap is both exactly-timed *and* atomic. The frequency
knob never moves the fault's activation time; it only governs how often *other*
(non-time-critical) global work is batched.

## 8.12 Lookahead is the parallelism budget

- **[SCHED-40]** The scheduler MAY execute nodes whose horizons do not constrain
  each other concurrently, up to the lookahead window: two nodes may run in
  parallel on the host for as much virtual time as the conservative lookahead
  guarantees neither can affect the other. The *resolution* of due events
  (RESOLVE, EMIT) MUST nonetheless be serialized through the single scheduler in
  the total order of §8.6, so concurrency is an *execution* optimization that
  never affects the *order*. *Gate:* `gate:layer1-injection`,
  `gate:e2e-determinism`. *Spec:* §8.12; routes [INV-3], [INV-8].

- **[SCHED-41]** The achievable multi-VM parallelism MUST be understood as the
  lookahead budget: larger minimum link latencies permit larger independent
  advances and thus more host-level concurrency; the minimum-latency floor
  (§8.7) is therefore the floor on parallelism, and the per-node horizon is the
  precise statement of how far each node may run before it must re-synchronize.
  This connects directly to the performance targets
  ([`25-performance-targets.md`](25-performance-targets.md)). *Gate:* (perf, not
  determinism). *Spec:* §8.12; forward-ref
  [`25-performance-targets.md`](25-performance-targets.md); routes [G-9].

Crucially, *parallelism is a speed property, never a correctness property*: with
zero host cores' worth of concurrency (everything serialized) the run is
bit-identical to a run that exploited the full lookahead budget, because the
total order of §8.6 is computed from the keys, not from which node's host thread
happened to finish first. The lookahead budget tells you how *fast* a scenario
can run, not *what* it computes.

## 8.13 Worked example: two VMs across a 1 ms link

A concrete trace makes the horizon rule and the frequency/exactness decoupling
tangible. Two VM nodes `A` and `B`, a bidirectional link of latency `L = 1 ms`
(so `lookahead(A) = lookahead(B) = 1 ms`), shift fixed so 1 ms is a known icount.
`A` has a guest timer due at virtual time `0.4 ms`; `B` is computing and will send
a frame to `A` at its virtual time `2.3 ms`. The rendezvous frequency is set to
`100 ms` (a coarse perf knob).

```text
vt(A)=0, vt(B)=0
  horizon(A) = min(local=0.4ms, net=0+1ms) = 0.4ms      # local event wins, EXACT
  horizon(B) = min(local=+inf,  net=0+1ms) = 1.0ms      # purely network-bounded
PICK A (min horizon).  RUN A to 0.4ms; A's timer fires (exact local event).
  RESOLVE: no cross-node event due.  EMIT timer-fire (local).  STEP.

vt(A)=0.4ms, vt(B)=0
  horizon(A) = min(local=next-timer …, net=0.4+1=1.4ms)
  horizon(B) = min(local=+inf, net=0+1=1.0ms) = 1.0ms
PICK B (min horizon 1.0ms).  RUN B to 1.0ms (no frame yet; B keeps computing).
  RESOLVE: none.  EMIT.  STEP.

vt(B)=1.0ms … B advances in 1ms network-bounded steps until vt(B)=2.3ms,
  at which point B emits a frame to A:  delivery_vt = 2.3 + 1.0 = 3.3ms.
  The frame is queued with key (3.3ms, A, seq).

Now horizon(A) = min(local…, vt(A)+1ms). A is PICKed and RUN whenever it has
the min horizon; it advances in network-bounded 1ms steps. When A's frontier
reaches 3.3ms, RESOLVE makes the frame visible to A at EXACTLY the icount for
3.3ms — regardless of the 100ms rendezvous (which has not even occurred yet).
```

Two observations from the trace, each a normative point above:

- The timer at `0.4 ms` was an *exact local event*: `A` ran *exactly* to it with
  no conservative slack ([SCHED-10]). Only the cross-node frame used the `1 ms`
  conservative bound.
- The frame landed at `A` at the exact icount for `3.3 ms` even though the
  rendezvous interval was `100 ms` ([SCHED-13]). Setting the rendezvous to `1 ms`
  or `1 s` would change *how often the scheduler batches assertion-drain*, and
  *nothing else* — the frame still lands at `3.3 ms` ([SCHED-12]).

## 8.14 What the rendezvous is for (and what it is not for)

To forestall the conflation [SCHED-11] forbids, this is the exhaustive list of
what a rendezvous does and does not do.

- **[SCHED-42]** A rendezvous MUST be used *only* for work that genuinely
  requires all non-terminal scheduler nodes at a common virtual time: draining
  the assertion engine ([`18-assertions-properties.md`](18-assertions-properties.md)),
  evaluating triggers, swapping the effective topology on a topology-changing
  fault ([SCHED-39]), and servicing control operations that request a globally
  consistent snapshot ([`20-session-control-plane.md`](20-session-control-plane.md)).
  A rendezvous MUST NOT be the mechanism for cross-node *event delivery* —
  delivery is continuous and exact via RESOLVE ([SCHED-13]). Halted and done
  nodes are terminal and are excluded from the active rendezvous set. *Gate:*
  `gate:layer1-injection`, `gate:control-responsive`. *Spec:* §8.14; routes
  [INV-3], [INV-8].

- **[SCHED-43]** At a rendezvous the inter-node virtual-time skew among active
  rendezvous members MUST be zero (all non-terminal scheduler nodes brought to
  `rendezvous_vt` via the exact horizon cap of [SCHED-14]), so any global
  recompute (lookahead, topology, fingerprint comparison across those nodes)
  sees a consistent global state. After the rendezvous releases, nodes resume
  independent horizon-bounded advancement. *Gate:* `gate:layer1-injection`.
  *Spec:* §8.14; routes [INV-3].

## 8.15 Summary

```text
ONE scheduler (INV-8), an actor that yields between quanta (SCHED-1..4)
  conservative PDES / CMB: advance only where no peer can deliver earlier (SCHED-5..6)
  liveness: the global-min-horizon node can ALWAYS advance ⇒ no deadlock (SCHED-7..8)
  horizon(n) = min( next_exact_local_event(n),         -- timer/IO: EXACT, no slack
                    vt(n) + lookahead(n) )              -- guest→guest net: conservative
                lookahead(n) = min inbound link latency  (SCHED-9..10)
  ordering EXACTNESS is never a knob; sync FREQUENCY is the only knob (SCHED-11..14)
  total order (virtual_time, consumer node_id, producer node_id, sequence) (SCHED-15..19)
  min link-latency floor ⇒ positive lookahead ⇒ progress + parallelism (SCHED-20..21)
  quiescence = all idle, no deliveries/timers/IO/faults pending (SCHED-22..23)
  quantum = PICK / RUN / RESOLVE / EMIT / STEP  (03 §5 vocab, SCHED-24..33)
  icount-derived clocks; one max-advance ceiling per RUN + futex wake (SCHED-34..36)
  faults change EFFECTIVE edges ⇒ recompute lookahead at rendezvous (SCHED-37..39)
  parallelism = lookahead budget; order is key-derived, not host-timing (SCHED-40..43)
```

If the horizon is exact for local events and conservative only for the network,
and the total order is a pure function of `(virtual_time, consumer node_id,
producer node_id, sequence)`, then the icount at which any input reaches any
node is a pure function of virtual time — which is exactly Contract B ([DET-6]).
The scheduler is the component that
makes `reduce` ([INV-1]) pure across nodes.

## 8.16 Multi-vCPU nodes: RR sub-division and applied preemptions

A node may host more than one vCPU. The scheduler still treats the node as a
single horizon-bearing entity (one ceiling per RUN, [SCHED-27]); the round-robin
sub-division of the node's instruction budget across its vCPUs, and the
application of explorer-supplied preemption decisions
([`05-execution-model.md`](05-execution-model.md) §12), are specified here.

- **[SCHED-45]** RUN MUST advance the selected node to its ceiling *via the
  round-robin loop*: within one RUN the node's instruction budget MUST be
  divided among its vCPUs by the deterministic `rr_switch_quantum` in a fixed
  ascending rotation. The scheduler MUST publish only the **node** ceiling (one
  ceiling per RUN, unchanged from [SCHED-27]); the RR sub-division MUST be
  plugin-internal and MUST NOT be host-timing-dependent. A single-vCPU node is
  the degenerate case (one vCPU consumes the whole budget). *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer1-injection`. *Spec:* §8.16, §8.9.2;
  routes [INV-3], [DET-13].

- **[SCHED-46]** When the explorer supplies a `Decision::Preemption`
  ([`05-execution-model.md`](05-execution-model.md) §12), RESOLVE MUST apply it
  as the node's interrupt/switch point within `[deadline, horizon]`, recorded in
  the total order of §8.6. A preemption MUST NOT move a point past the node's
  authorized ceiling, preserving Contract B and the conservative-PDES guarantee
  ([SCHED-5], [DET-12]). The DEFAULT (round-robin and armed-deadline) preemption
  sequence is deterministic engine behavior and is not a search decision until
  overridden ([EXEC-33]). *Gate:* `gate:layer1-injection`,
  `gate:replay-oracle`. *Spec:* §8.16, §8.9.4; routes [INV-3], [DET-12].

- **[SCHED-47]** An N-vCPU node MUST be considered **idle** for quiescence
  ([SCHED-22], [SCHED-23]) only when *all* N vCPUs are halted with no armed
  timer and no pending input. The node's `idle_wake` icount MUST be the `min`
  over its vCPUs of each vCPU's next deadline, and the `effective_horizon`
  projection ([SCHED-44]) MUST be applied at the **node** level (one projection
  per node, not per vCPU). *Gate:* `gate:scheduler-liveness`,
  `gate:single-vm-fingerprint`. *Spec:* §8.16, §8.8, §8.9.1; routes [INV-8],
  [INV-4].

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is cross-node scheduling, tracked by [PLAN-3].
> They populate Phase 1 (the determinism / harness / transport foundation),
> sequenced after the L0/L1 primitives and before any L3+ feature.

- [x] **T-SCHED-1** Implement the scheduler as a single yielding actor that owns
  per-node virtual times, the pending cross-node event set, and the decision-RNG
  cursor; mutate that state only on its own task; yield to a control inbox at
  every quantum boundary. — satisfies [SCHED-1], [SCHED-2], [SCHED-3], [SCHED-4];
  spec §8.2.
  Completed by `checks.crucible.phase3.schedulerActor`: `SchedulerActor` owns one
  `SingleScheduler` core and exposes a message-only actor surface for control,
  quantum, and read-only snapshot requests. The actor owns scheduler node
  counters, pending events, a boundary-drained control inbox, and the
  scheduler-owned decision-RNG cursor position. The focused actor tests verify
  queued and per-request controls are admitted only through messages and drained
  at a quantum boundary, actor state is exposed only through a read-only snapshot
  reply, non-frontier quantum requests are rejected, and the scheduler yields to
  its inbox before each quantum. The existing scheduler-liveness gate retains the
  no-lock-across-advance evidence. Conservative PDES, horizon integration,
  total-order RESOLVE, seeded probabilistic RESOLVE draws, topology swaps, and
  RR/preemption semantics remain the later unchecked T-SCHED-3 through
  T-SCHED-30 tasks.
- [x] **T-SCHED-2** Implement `lookahead(n)` as the minimum inbound link latency
  over the current effective topology, with `+∞` when a node has no inbound
  links. — satisfies [SCHED-6]; spec §8.3.
  Completed by `checks.crucible.phase3.schedulerLookahead`: the scheduler now
  exposes a canonical directed `SchedulerLookaheadGraph` over caller-supplied
  effective edges, a VM-to-VM adapter for `World::static_topology()` lookahead
  edges, and `NetworkLookahead::{Finite, Infinite}` so `lookahead(n)` is the
  minimum inbound live-link latency or positive infinity when no inbound edge
  targets the node. The focused tests cover min-inbound selection, directionality,
  no-inbound infinity, canonical duplicate-stable edges, and the world-derived
  jitter-reduced minimum latency. Topology-change recompute, partition/heal edge
  swaps, and RESOLVE delivery assertions remain the later unchecked T-SCHED-18
  through T-SCHED-24 tasks.
- [x] **T-SCHED-3** Implement the conservative-PDES advance rule (no node crosses
  an unresolved cross-node dependency; no rollback; no speculation). — satisfies
  [SCHED-5]; spec §8.3.
  Completed by `checks.crucible.phase3.schedulerConservativePdes`: the scheduler
  now extracts unresolved cross-node `BackendInput` dependencies, authorizes each
  requested advance through a conservative-PDES guard, rejects rollback requests,
  clamps the authorized target to the earliest future cross-node dependency, and
  fails loudly if icount-ceiling conversion would round a dependency cap past the
  conservative boundary. The focused tests cover safe targets before a dependency,
  dependency clamping, rollback rejection, cross-node-only dependency extraction,
  the live `SingleScheduler` stop-at-dependency path, an unaligned nonzero-shift
  ceiling-overshoot regression, and the current fail-loud behavior for already-due
  unresolved dependencies. Full horizon composition remains T-SCHED-5, and
  already-due RESOLVE delivery / late-delivery localization remains T-SCHED-16 and
  T-SCHED-18.
- [x] **T-SCHED-4** Implement and test the liveness guarantee: the
  global-minimum-horizon node is always advanceable; wire `gate:scheduler-liveness`
  to assert the scheduler always reaches quiescence or its limit (no
  deadlock/livelock) and fails loudly on a non-quiescent stall. — satisfies
  [SCHED-7], [SCHED-8]; spec §8.3.2, §8.8.
  Completed by `checks.crucible.phase3.gates.schedulerLiveness`: the finite
  scheduler now orders advanceable candidates by their computed post-clamp
  advance target before node-id tie-breaks, so the current gate advances the
  executable global-minimum-horizon candidate rather than merely the earliest
  current-time node. The scheduler-liveness gate drives generated scenarios to
  quiescence or the configured time/quantum limit and includes fail-loud negative
  controls for pending-event/no-runnable deadlock and runnable/no-progress
  livelock. The focused gate tests also cover a case where the minimum-horizon
  node is not the lowest-current-time node and a same-horizon node-id tie. The
  full PICK projection over RUNNING, IDLE, HALTED, and DONE nodes remains
  T-SCHED-13; RESOLVE delivery and late-delivery localization remain T-SCHED-15
  through T-SCHED-18.
- [x] **T-SCHED-5** Implement `horizon(n) = min(next_exact_local_event(n),
  vt(n) + lookahead(n))`, with the exact-local term applying no conservative
  bound and the lookahead term applying only to guest→guest network. — satisfies
  [SCHED-9], [SCHED-10]; spec §8.4.
  Completed by `checks.crucible.phase3.schedulerHorizon`: the scheduler now
  computes the network horizon as `current_vt + NetworkLookahead`, represents
  nodes with no inbound live network edge as an infinite horizon term, and
  composes that term with the current `ExactLocalEvent` abstraction so exact local
  timers select their precise virtual-time deadline without conservative slack.
  `SingleScheduler` consumes this composed horizon, caps an infinite network-only
  horizon at the configured finite run limit without marking the node idle, and
  keeps the conservative-PDES dependency guard downstream of the composed target.
  The focused tests cover finite `vt + lookahead`, exact-local precedence,
  infinite network lookahead with and without an exact local event, and live
  scheduler runs for finite and unbounded network terms. The full PICK projection
  over RUNNING, IDLE, HALTED, and DONE nodes remains T-SCHED-13.
- [x] **T-SCHED-6** Implement `next_exact_local_event(n)` as the earliest of the
  node's next guest timer, earliest in-flight I/O completion (15), and next
  locally-scheduled fault (17). — satisfies [SCHED-9], [SCHED-10]; spec §8.4.1,
  §8.4.2.
  Completed by `checks.crucible.phase3.schedulerExactLocalEvent`: the scheduler
  now reduces the exact-local term from the node's timer report plus pending
  deterministic I/O completions and local fault activations, excludes
  guest-to-guest backend input from that local term, rejects malformed I/O
  completion keys whose payload target or delivery icount disagrees with the
  scheduled event key, and feeds the reduced event into `SingleScheduler` horizon
  composition. The focused gate covers timer/I/O/fault minimum selection, shifted
  I/O icount conversion, backend-input exclusion, malformed completion rejection,
  horizon-source tagging for I/O and fault events, and live scheduler quanta that
  stop on pending I/O and fault exact-local horizons. Deterministic total ordering
  and full RESOLVE behavior remain T-SCHED-8 and T-SCHED-15 through T-SCHED-18.
- [x] **T-SCHED-7** Enforce the frequency/exactness decoupling: ordering is
  always exact, the rendezvous frequency is the only knob, and event delivery is
  frequency-independent; add a gate-backed test that two runs at different
  rendezvous frequencies are bit-identical in `S`, `T`, and determinism-relevant
  event-log entries. — satisfies [SCHED-11], [SCHED-12], [SCHED-13], [SCHED-14];
  spec §8.5.
  Completed by `checks.crucible.phase3.schedulerRendezvous`: the scheduler now
  models rendezvous as an exact shared horizon cap computed once from the
  scheduler frontier and applied to every node candidate for that PICK. Empty
  rendezvous-only quanta advance no canonical schedule decision and do not advance
  the scheduler decision-RNG cursor, so changing the rendezvous interval changes
  only how many empty quanta are needed to reach the same exact event. The focused
  gate compares two runs with different rendezvous intervals and verifies the same
  final configuration, same frontier, same resolved-event count, and same
  determinism-relevant delivery-order decision at the event's exact virtual time.
  Full EMIT/event-log materialization is covered by T-SCHED-19.
- [x] **T-SCHED-8** Implement the deterministic total order
  `(virtual_time, consumer node_id, producer node_id, sequence)` with the fully
  specified tie-break, stable content-addressed node ids, and a per-(producer,
  consumer) sequence counter carried in saved state. — satisfies [SCHED-15],
  [SCHED-16], [SCHED-17], [SCHED-18]; spec §8.6.
  Completed by `checks.crucible.phase3.schedulerEventOrder`. The implementation
  makes `ScheduledEventKey` order by virtual time, consumer scheduler node,
  producer scheduler node, and sequence; promotes scheduler-node identity into
  the model layer so saved sequence counters, delivery-order decisions, canonical
  hashes, binary serialization, and symmetry rendering all carry the same stable
  endpoint identity; and wires `SingleScheduler` control-event emission through
  saved per-`(producer, consumer)` `EventSequenceState` allocation with overflow
  rejection. Focused tests cover tuple ordering, per-pair allocation, scheduler
  node-kind independence, saved-state hashing, and runtime allocation from a
  resumed sequence cursor. Full RESOLVE/EMIT materialization is covered by
  T-SCHED-15 through T-SCHED-19.
- [x] **T-SCHED-9** Ban unordered-collection iteration and default-hasher use on
  the ordering-significant scheduling path; route through `gate:harness-lint`. —
  satisfies [SCHED-19]; spec §8.6.
  Completed by `checks.crucible.phase3.schedulerOrderingLint`. The harness-lint
  surface now rejects `HashMap`/`HashSet`, hash-container iteration, and
  `DefaultHasher`/`RandomState` default randomized hash state, with focused
  regressions for direct paths, spaced paths, custom static analysis, and
  annotated exceptions. The focused phase3 check routes the task through
  `gate:harness-lint`, statically denies unordered/default-hasher tokens in the
  scheduler ordering path, and runs those focused harness-lint regressions plus
  the scheduler event-order regression; the broader phase1 harness-lint gate
  remains a separate multi-policy gate.
- [x] **T-SCHED-10** Enforce the minimum link-latency floor at lowering time,
  include it in the scenario content hash, and reject sub-floor links. —
  satisfies [SCHED-20], [SCHED-21]; spec §8.7.
  Completed by `checks.crucible.phase3.schedulerLinkLatencyFloor`.
  `MIN_LINK_LATENCY=1` is enforced by link construction and world lowering,
  including canonical TOML and compact-binary parsing. Canonical world material
  now records `min_link_latency_ns`, so the scenario `world_ref` changes with
  the configured floor; the focused check runs the scheduler floor regression,
  existing link-transport regressions, and canonicalization hash regression.
- [x] **T-SCHED-11** Implement deterministic quiescence detection from
  authoritative scheduler state only (no host timeout); idle nodes do not
  constrain peers. — satisfies [SCHED-22], [SCHED-23]; spec §8.8.
  Completed by `checks.crucible.phase3.schedulerQuiescence`. `SingleScheduler`
  now exposes deterministic `SchedulerQuiescence` evidence from scheduler-owned
  state only: runnable nodes, queued scheduler events, queued control, and exact
  local wakeups block terminal quiescence. The focused regressions prove that
  idle nodes do not constrain peers: finite idle wakeups and pending inbound
  deliveries are effective idle advance candidates, are clamped by the
  virtual-time limit, and are covered by focused no-deadlock and peer-priority
  regressions with no host-time API use.
- [x] **T-SCHED-12** Implement the quantum loop PICK / RUN / RESOLVE / EMIT /
  STEP as the unit of `step`, ensuring the quantum sequence is a pure function of
  `(ScenarioDef, Seed, Schedule)`. — satisfies [SCHED-24], [SCHED-33]; spec §8.9,
  §8.9.7.
  Completed by `checks.crucible.phase3.schedulerQuantumLoop`. `SingleScheduler`
  now drives the authoritative quantum as PICK, RUN, RESOLVE, EMIT, STEP: it
  drains boundary control, rejects non-frontier configuration requests, selects
  one scheduler candidate, advances it once under the scheduler critical section,
  resolves due events in canonical order, emits schedule decisions for those
  deliveries, and applies them with `step` as the atomic quantum boundary. The
  effective scenario identity now includes scheduler-owned node, pending-event,
  and sequence-cursor material so the checked quantum sequence satisfies the
  pure function of `(ScenarioDef, Seed, Schedule)` boundary. The focused
  regressions cover one-boundary
  PICK/RUN/RESOLVE/decision-EMIT/STEP behavior, identical-input replay purity,
  scheduler-state contribution to scenario identity, control-only EMIT/STEP with
  no runnable node, and fail-loud rejection of stale configuration input. Full
  event-log EMIT materialization is covered by T-SCHED-19.
- [x] **T-SCHED-13** Implement PICK (global-minimum horizon, ties by node_id) and
  RUN (advance under `-icount` to horizon; never past it), taking the argmin over a
  single unified `effective_horizon(node)` projection (DONE/Halted → +∞, IDLE →
  idle wake icount, else running horizon). — satisfies
  [SCHED-25], [SCHED-26], [SCHED-44]; spec §8.9.1, §8.9.2.
  Completed by `checks.crucible.phase3.schedulerEffectiveHorizon`. PICK now
  constructs every candidate through one `effective_horizon` projection:
  runnable nodes use the running advance window, idle nodes use their finite
  idle-wake icount, and halted or done nodes project to `+∞` and are never
  selected. Candidate ordering remains `(effective_horizon, node_id, virtual_time,
  input index)`, so equal projected horizons tie by stable scheduler-node id. RUN
  converts the selected target with the fixed-shift icount ceiling and preserves
  the conservative overshoot guard so a selected node never advances past its
  horizon. The focused regressions cover mixed RUNNING/IDLE/Halted/DONE
  projection, node-id ties after projection, terminal-node quiescence, all-infinite
  no-advance quanta, exact-local horizon stops, and pending-delivery horizon stops.
- [x] **T-SCHED-14** Drive RUN through a single per-node max-advance ceiling
  published once per quantum (no intermediate ceiling), via the shmem ABI. —
  satisfies [SCHED-27], [SCHED-35]; spec §8.9.2, §8.10.
  Completed by `checks.crucible.phase3.schedulerRunCeiling`. The scheduler now
  records one `SchedulerRunCeilingPublication` for each RUN after PICK has chosen
  its candidate and after conservative overshoot validation has fixed the target.
  That publication carries the shmem ABI `max_advance_icount` value, can be
  authorized as a `crucible_shmem::AdvanceCeiling` under `test-double`, and is
  consumed by the node advance path as the RUN target. Focused regressions cover
  one ceiling per RUN, no intermediate publication across consecutive quanta, no
  publication for a no-RUN quantum, target consumption from the published ceiling,
  and acceptance by the existing shared-memory slot publish API. Futex wake /
  inbound-queue ordering remains T-SCHED-21.
- [x] **T-SCHED-15** Implement idle fast-forward: jump an idle node's clock to its
  exact wake time at zero wall-clock cost; idle nodes use wake time as effective
  clock for peers' lookahead. — satisfies [SCHED-28]; spec §8.9.3.
  Completed by `checks.crucible.phase3.schedulerIdleFastForward`.
  `SingleScheduler::effective_clocks` now exposes the peer-facing effective clock
  projection: runnable, halted, and done nodes use their current virtual time,
  while idle nodes with a finite exact wake use that wake time as
  `SchedulerEffectiveClockSource::IdleWake`. Idle candidate selection consumes
  the same projection, clamps it by the configured time limit and rendezvous cap,
  and advances the idle node without adding schedule decisions. Focused
  regressions cover timer wake jumps, pending-delivery wake jumps, time-limit
  clamping, no-wake idle quanta, and a peer advancing while an idle node's
  effective clock is in the future.
- [x] **T-SCHED-16** Implement RESOLVE: process all due cross-node events (frame
  delivery, I/O completion, fault activation) in total order, made visible at the
  exact delivery icount, transport-timing-independent. — satisfies [SCHED-29];
  spec §8.9.4.
  Completed by `checks.crucible.phase3.schedulerResolve`.
  `resolve_due_scheduled_events` now drains every event due for the advanced
  consumer, validates the exact visibility point for frame/backend input, I/O
  completion, and fault activation payloads, and returns the canonical
  `(virtual_time, consumer node_id, producer node_id, sequence)` order regardless
  of pending transport order. The quantum loop consumes that resolver directly
  after RUN, so mixed due frame/I/O/fault events become visible at their delivery
  icount before EMIT/STEP. Focused regressions cover mixed-class due sets,
  pending-order independence, backend target mismatch rejection, and I/O
  delivery-icount mismatch rejection. Event-log materialization is covered by
  T-SCHED-19.
- [x] **T-SCHED-17** Route every probabilistic RESOLVE choice through the seeded
  decision RNG in total order and record each as a `Decision` in the `Schedule`.
  — satisfies [SCHED-30]; spec §8.9.4.
  Completed by `checks.crucible.phase3.schedulerResolveRng`.
  RESOLVE now has an explicit `ScheduledEventPayload::ProbabilisticFault`
  surface carrying a `SchedulerResolveFaultChoice` with fault id, seeded stream,
  and integer fire threshold. `resolve_probabilistic_decisions` consumes resolved
  events in canonical event-key order, uses `DecisionRecorder::decide_fault`, and
  appends the raw `Decision::RngDraw` followed by the derived
  `Decision::FaultFires` outcome. The quantum EMIT path appends those decisions
  after the deterministic delivery-order decision and advances scheduler cursor
  state for each recorded raw draw. Focused regressions cover reversed pending
  transport order, repeated quanta hydrating the same stream from the prior
  schedule, and deterministic RESOLVE events producing no probabilistic
  decisions.
- [x] **T-SCHED-18** Enforce the lookahead guarantee in RESOLVE: a consumer that
  ran past a due event's delivery icount fails loudly and localizes; never
  deliver late. — satisfies [SCHED-31]; spec §8.9.4.
  Completed by `checks.crucible.phase3.schedulerLateDelivery`.
  `resolve_due_scheduled_events` now treats the reached frontier as an exact
  RESOLVE boundary: events whose delivery time equals the frontier are drained in
  canonical order, events ahead of the frontier remain queued, and any event for
  the advanced consumer whose delivery time is behind the frontier raises a
  localized `SchedulerError::BoundaryViolation` instead of being delivered late.
  Focused regressions cover the pure resolver error path and a live scheduler
  self-delivery case that previously was not covered by conservative cross-node
  dependency rejection.
- [x] **T-SCHED-19** Implement EMIT (append ordered, content-addressed event-log
  entries for every resolved happening and Decision) and STEP (advance frontier,
  yield to control inbox). — satisfies [SCHED-32], [SCHED-33]; spec §8.9.5,
  §8.9.6.
  Completed by `checks.crucible.phase3.schedulerEmitStep`.
  `QuantumOutcome` now carries the EMIT delta: dense scheduler event-log entries
  for resolved happenings followed by entries for each Decision, per-entry
  content hashes, and the `EventLogOffset` reached by the quantum segment.
  `SingleScheduler` advances a cumulative event-log prefix across quanta, then
  applies STEP with the existing pure `step(config, decision)` fold. Session
  progress mirrors now consume the emitted event-log offset instead of using the
  resolved-event count as a placeholder. Focused regressions cover happening
  before-decision ordering, stable content hashes across replay, prefix/sequence
  advancement across quanta, and liveness-report determinism.
- [x] **T-SCHED-20** Convert horizon virtual times to per-node icount ceilings
  via the fixed shift and integrate with the virtual-time/icount module. —
  satisfies [SCHED-34]; spec §8.10.
  Completed by `checks.crucible.phase3.schedulerIcountCeiling`.
  `SharedTimeline::max_advance_icount_for_horizon` now owns the SCHED-34/TIME-4
  boundary: scheduler horizon arithmetic remains in virtual time, while RUN
  publications convert the selected horizon through the fixed-shift ceil map into
  the shmem ABI `max_advance_icount`. Conservative virtual-time caps still reject
  a ceil projection that would cross the cap, while exact local wake/deadline
  horizons may command the first instruction boundary at or after the deadline.
  `SchedulerRunCeilingPublication` records the fixed shift used for the
  conversion. Focused regressions cover exact-local, aligned network-lookahead,
  unaligned conservative rejection, and idle-wake horizons with nonzero shifts so
  floor rounding or raw-virtual-time ceilings fail loudly.
- [x] **T-SCHED-21** Implement the ceiling-write + futex-wake ordering so a woken
  plugin observes a consistent `(ceiling, pending-inputs)` snapshot (wake after
  inbox write). — satisfies [SCHED-35], [SCHED-36]; spec §8.10.
  Completed by `checks.crucible.phase3.schedulerWakeOrdering`.
  `RegionAllocation::publish_scheduler_inputs_and_ceiling` is now the typed
  shmem handoff for RUN publication: it prevalidates the destination slot and
  inbox capacity, release-publishes every pending input frame to the directed
  inbox, release-publishes the node ceiling, and only then increments the
  non-private futex wake word, preserving wake after inbox write.
  `NodeSlot::publish_scheduler_inbox_and_ceiling` gives production adapters the
  same borrowed-ring ordering, and the QEMU RUN hot path now publishes through
  that helper; QEMU inbound frame wakeups use it with a nonempty pending-input
  batch and the currently published ceiling. `SchedulerRunCeilingPublication`
  exposes the test-double adapter that routes scheduler publications through
  the typed region handoff. Focused regressions cover single-input and
  batched-input wakeups, borrowed-ring RUN and inbound publication, source-slot
  mismatch rejection, full-inbox and stale-ceiling no-wake failures, and
  source-order checks for
  inbox-before-ceiling-before-futex-wake.
- [x] **T-SCHED-22** Implement topology-change handling: recompute lookahead at
  the quantum boundary when faults alter the effective edge set or a latency;
  apply lowered lookahead before the node is next PICKed past the new bound. —
  satisfies [SCHED-37]; spec §8.11.
  Completed by `checks.crucible.phase3.schedulerTopologyChange`.
  `SchedulerTopologyChange` supports complete effective edge-set replacement
  ordered by boundary sequence and trigger. `SingleScheduler` applies queued
  topology changes at the quantum boundary before the next PICK,
  recomputes every runtime node's `NetworkLookahead` from the new
  `SchedulerLookaheadGraph`, records per-node `SchedulerTopologyLookaheadUpdate`
  evidence, and treats topology-only recomputes as scheduler progress.
  The runtime `queue_topology_change` APIs on `SingleScheduler` and
  `SchedulerActorHandle` let fault/heal/latency handlers enqueue those changes
  after construction. `SingleScheduler::authorize_cross_node_send` freezes
  cross-node sends while a topology change is pending, then authorizes sends only
  against the current effective edge set and topology epoch; SimDouble and QEMU outbound emission paths require an explicit scheduler send authorizer
  before writing or draining VM-to-router frames. Focused regressions cover lowered latency before PICK,
  runtime and actor queueing, pending-change send freeze/unfreeze, no delivery
  of an in-flight frame under a stale horizon, topology-only liveness progress,
  and sim/QEMU outbound authorization.
- [x] **T-SCHED-23** Model partition/heal as effective-edge removal/restoration
  with `min`-inbound-latency lookahead recompute over the current edge set
  (last-inbound-removed ⇒ `+∞`). — satisfies [SCHED-38]; spec §8.11.
  Completed by `checks.crucible.phase3.schedulerPartitionHeal`.
  `SchedulerTopologyChangeEffect` now distinguishes complete edge-set
  replacement from partition and heal deltas. Partition changes remove directed
  effective edges from the current graph at the boundary; heal changes restore
  directed effective edges into the current graph at the boundary. Each applied
  mutation recomputes every runtime node's lookahead from the resulting graph,
  so the next bound is the minimum remaining inbound latency, and the lookahead
  becomes `+∞` when the last inbound edge is removed. Focused regressions cover
  next-minimum recompute after partial partition, last-inbound removal,
  sequential partition-then-heal over the current graph, and send authorization
  blocking/restoration across partition/heal.
- [x] **T-SCHED-24** Apply topology swaps atomically at a rendezvous (all
  non-terminal scheduler nodes brought to the fault's exact activation virtual
  time), never mid-RUN and never shifted to the next arbitrary rendezvous tick.
  — satisfies [SCHED-39],
  [SCHED-14]; spec §8.11, §8.5.
  Completed by `checks.crucible.phase3.schedulerTopologyRendezvous`.
  `SchedulerTopologyChange::with_activation_time` lets fault and latency
  handlers attach the exact activation virtual time to a queued topology
  mutation. Pending timed changes contribute that activation time to the shared
  rendezvous cap, so a fault at time `t` brings every non-terminal scheduler node
  to `t` and is not shifted to the next fixed rendezvous tick. The scheduler
  defers the change until that activation rendezvous is ready, then applies it at
  the following quantum boundary before the next PICK, records the activation
  time on `SchedulerTopologyChangeApplication`, and never applies the topology mutation mid-RUN.
  Nodes that reach an older lookahead horizon before activation remain eligible
  for the activation rendezvous, and idle nodes without a wake can still advance
  to that pending topology rendezvous. Focused regressions cover exact
  activation caps with a later fixed rendezvous interval, deferred application
  until after activation, waiting for all runnable nodes to reach activation,
  old-horizon continuation, idle/no-wake rendezvous advancement, and
  sequence-ordered application when a ready timed change shares a boundary with
  an immediate change.
- [x] **T-SCHED-25** Implement bounded host-level concurrency up to the lookahead
  window while serializing RESOLVE/EMIT through the single scheduler; prove
  serial and concurrent runs are bit-identical via `gate:e2e-determinism`. —
  satisfies [SCHED-40], [SCHED-41]; spec §8.12.
  Completed by `checks.crucible.phase3.schedulerConcurrency`.
  `ConcurrentQuantumLoop` adds a bounded concurrent RUN set that selects a
  deterministic `SchedulerConcurrentRunSet` from the same horizon candidates as
  serial PICK. The run set is bounded by `max_host_workers`, each candidate's
  conservative lookahead target, and a common-frontier/same-target filter so a
  skewed peer is not over-admitted past a possible dependency; zero worker
  budgets fail loudly. The concurrent path publishes the selected ceilings before host dispatch, advances the chosen
  nodes, then serializes each completion through RESOLVE/EMIT/STEP on the single
  scheduler. Focused regressions cover worker-bound run-set selection, invalid
  worker-budget rejection, skewed-peer exclusion, and a serial-vs-concurrent
  comparison proving the same intermediate frontiers, final configuration,
  frontier, event-log offset, and event-log entry hashes for simultaneous due
  inputs. This is the scheduler-side proof used by `gate:e2e-determinism`;
  broader harness coverage continues to own guest fingerprint equality.
- [x] **T-SCHED-26** Restrict the rendezvous to assertion-drain / trigger-eval /
  topology-swap / snapshot-control only (never event delivery), with zero skew at
  the rendezvous and independent resumption after. — satisfies [SCHED-42],
  [SCHED-43]; spec §8.14.
  Completed by `checks.crucible.phase3.schedulerRendezvousPurpose`.
  `SchedulerRendezvousPurpose` exposes only the allowed assertion-drain,
  trigger-eval, topology-swap, and snapshot-control rendezvous purposes; the
  scheduler has no event-delivery rendezvous purpose. Fixed rendezvous
  intervals remain exact advancement caps and are not an event-delivery
  mechanism: due inputs are still delivered only through RESOLVE at their exact
  event time. Timed topology changes record a topology-swap rendezvous only
  after every active scheduler node is at the activation virtual time, with a
  zero-skew guard on the recorded node observations. The regression test also
  proves that after the topology-swap record is emitted the scheduler resumes
  independent horizon-bounded advancement instead of pinning nodes to the
  rendezvous time.
- [x] **T-SCHED-27** Add the scheduler half of `gate:control-responsive`: a
  control op submitted to the scheduler actor is applied within a bounded number
  of quanta, only at quantum boundaries. — satisfies [SCHED-3], [SCHED-33]; spec
  §8.2, §8.9.6.
  Completed by `checks.crucible.phase3.schedulerControlResponsive`.
  `SchedulerControlApplication` records each scheduler-applied control operation
  with the quantum count and boundary-yield count visible at admission and at
  application, and staged records are committed only after the quantum's
  EMIT/STEP work succeeds. `SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA` fixes the
  scheduler half of `gate:control-responsive` at one scheduler quantum, and the
  scheduler rejects application evidence that exceeds that bound. The actor
  drains queued control/topology messages before each drive, so a submitted
  control op is not hidden behind deferred drive requests. Controls admitted
  through the actor mailbox and controls supplied on `QuantumRequest` both become
  scheduler control events only at the quantum-boundary drain before PICK; the
  focused gate proves queued actor controls, same-request controls, mixed
  queued/request controls, deferred-drive responsiveness, and control-only quanta
  with no runnable node all apply only at quantum boundaries and within the
  bound.
- [x] **T-SCHED-28** Implement RR sub-division inside RUN: divide a multi-vCPU
  node's instruction budget among its vCPUs by `rr_switch_quantum` in fixed
  ascending rotation, plugin-internal and host-timing-independent, with the node
  ceiling unchanged (one ceiling per RUN). — satisfies [SCHED-45]; spec §8.16.
  Completed by `checks.crucible.phase3.schedulerRrSubdivision`.
  `SchedulerRunSubdivisionPolicy` adds optional per-node, deterministic RR
  subdivision to scheduler scenarios and canonical material, while
  `SchedulerRunSubdivisionRecord` records plugin-internal vCPU slices against
  the single node-level ceiling already published for the RUN. The pure
  `scheduler_rr_run_subdivision` helper derives slices only from the current
  node icount, the published `max_advance_icount`, `vcpu_count`, and
  `rr_switch_quantum`, keeping the result host-timing-independent. Multi-vCPU
  nodes use fixed ascending rotation by vCPU index at deterministic RR
  boundaries, and the single-vCPU case consumes the whole RUN budget in one
  slice without publishing any extra ceilings.
- [x] **T-SCHED-29** Apply explorer-supplied `Decision::Preemption` in RESOLVE
  within the bounded `[deadline, horizon]` window, recorded in total order, never
  moving a point past the node's authorized ceiling (Contract B / conservative
  PDES). — satisfies [SCHED-46]; spec §8.16.
  Completed by `checks.crucible.phase3.schedulerPreemptionResolve`.
  `SchedulerLivenessScenario::with_preemption_request` carries explorer-supplied
  `PreemptionDecision`s in scenario identity, and `SchedulerPreemptionApplication`
  records each completed RESOLVE application against the single RUN ceiling. The
  scheduler validates each command against the authorized `[deadline, ceiling]` window,
  records valid choices as `Decision::Preemption`, assigns the event-log entry
  at the preemption's commanded virtual time, and rejects out-of-window commands
  loudly. Each RUN admits at most one explorer preemption command so concurrent
  completions can be serialized by commanded time without inventing an
  interleaving the plugin cannot execute. It never clamps or defers a preemption
  past the node ceiling; pending preemptions remain scheduler-owned quiescence
  blockers until applied.
- [x] **T-SCHED-30** Implement all-vCPUs-idle quiescence for N-vCPU nodes: a node
  is idle only when every vCPU is halted with no armed timer and no pending input;
  node `idle_wake` = `min` over vCPUs of next deadline; apply the
  `effective_horizon` projection at the node level. — satisfies [SCHED-47];
  spec §8.16.
  Completed by `checks.crucible.phase3.schedulerAllVcpusIdle`.
  `SchedulerNodeVcpuIdleSnapshot` carries the declared vCPU count plus per-vCPU
  halted/deadline/input state in scenario identity, and validation requires
  exact contiguous coverage of every vCPU in `0..N` before the scheduler starts.
  Quiescence now requires that all vCPUs are halted, timer-free, and input-free;
  otherwise the scheduler reports vCPU-specific blockers for active vCPUs,
  armed timers, or pending input. The node
  `idle_wake` is the minimum per-vCPU deadline folded into the existing
  exact-local wake calculation, and the resulting wake is emitted as one
  scheduler node candidate with one node-level ceiling publication rather than a
  per-vCPU PICK surface. Due per-vCPU deadlines clear when the node advances to
  the wake, so liveness drains the full vCPU deadline set before terminal
  quiescence.
  Summary: all vCPUs are halted, timer-free, and input-free before terminal
  quiescence; one scheduler node candidate carries the minimum per-vCPU wake.
