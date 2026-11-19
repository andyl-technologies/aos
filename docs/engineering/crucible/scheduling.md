# Scheduling

The scheduler is the single authoritative source of timing truth in a Crucible
run. It is the only component that advances a node's virtual clock and the
only component that decides the order in which cross-node events become
visible. Every frame delivery, I/O completion, control operation, and
explorer-supplied preemption passes through it, and the order it produces is a
pure function of virtual time and stable identities, never of host wall-clock
time or host thread scheduling.

This page documents the scheduler as implemented. Virtual-time units and the
counter-to-time mapping are in [virtual-time.md](virtual-time.md); the
shared-memory ceiling and futex handoff is in [shmem-abi.md](shmem-abi.md);
event-log materialization is in [event-log.md](event-log.md); the operator view
of topology and link faults is in the
[topology](../../users/crucible/topology.md) and
[network faults](../../users/crucible/network-faults.md) guides.

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-engine/src/scheduler.rs` | Module root and re-exports |
| `.../scheduler/runtime_state.rs` | `SingleScheduler` state, quiescence and liveness vocabulary |
| `.../scheduler/single_scheduler_drive.rs` | PICK, horizon projection, RUN planning, topology application, the authoritative quantum |
| `.../scheduler/single_scheduler_state.rs` | Public accessors, `quiescence`, `effective_clocks`, `authorize_cross_node_send` |
| `.../scheduler/topology.rs` | Lookahead graph, horizon composition, event keys, RESOLVE, rendezvous, RR subdivision |
| `.../scheduler/control_state.rs` | Ceiling publications, RR and preemption records, topology change types, vCPU idle snapshots |
| `.../scheduler/control_state/actor.rs` | `SchedulerActor`, `SchedulerActorHandle`, actor messages |
| `.../scheduler/concurrent_prepare.rs` | Host-concurrent RUN sets |
| `.../scheduler/liveness.rs` | `check_scheduler_liveness`, `SchedulerCriticalSection`, `ConcurrentQuantumLoop` impl |
| `.../scheduler/event_log.rs` | `QuantumLoop`, `QuantumRequest`, `QuantumOutcome` |
| `crates/crucible/crucible-session/src/session/core.rs` | `drive_engine_quantum`, the single session-side call into the loop |
| `crates/crucible/crucible-qemu-host/src/quantum.rs` | QEMU RUN hot path: ceiling publish, wake, report, frame rings |
| `crates/crucible/crucible-qemu-plugin/src/round_robin.rs` | In-guest round-robin vCPU cursor |
| `crates/crucible/crucible-qemu-plugin/src/idle_loop.rs` | Idle wake planning and the parked idle loop |

All `.../scheduler/` paths are under `crates/crucible/crucible-engine/src/`.

## Design in one page

Four commitments shape the implementation.

1. **One scheduler.** Exactly one `SingleScheduler` advances clocks and
   resolves order for a run. A second source of timing truth could not produce
   one total order without a coordination protocol that is itself a scheduler,
   so the design collapses to one. Control is applied only between quanta, so
   the quantum is the atomic unit of both advancement and control.
2. **Conservative parallel discrete-event simulation** (Chandy-Misra-Bryant). A
   node advances only into virtual time where no peer can still deliver an
   earlier event. Nothing is ever rolled back. Optimistic (Time Warp) schemes
   are not used because rolling back a full VM image is expensive and is itself
   a determinism hazard.
3. **The horizon rule.** A node's horizon is
   `min(next exact local event, vt(n) + lookahead(n))`. Timers and I/O
   completions are computed host-side, so they give an exact horizon with no
   conservative slack. Only guest-to-guest network traffic, which depends on a
   peer's not-yet-executed instructions, pays the conservative lookahead bound.
   Plain CMB applies the bound to every advance and leaves most of the safe
   parallelism and idle fast-forward unused.
4. **Synchronization frequency is separate from ordering exactness.** Every
   event is delivered at its exact delivery time. The only schedule-related
   knob is the rendezvous interval, which caps advancement for global
   bookkeeping. Changing it changes how many quanta a run takes, never which
   instruction observes which input. Lock-step designs that deliver events only
   at fixed windows conflate these two concerns and are not used.

## Ownership and the actor boundary

`SingleScheduler` owns all authoritative scheduler state: per-node counters
and time mappings, the effective topology, pending `ScheduledEvent`s, the
saved per-pair `EventSequenceState`, the decision-RNG cursor
(`decision_rng_cursor: DecisionRngState`), queued topology changes, preemption
requests, the control inbox, and the event-log prefix. No other component
mutates that state.

The session owns the scheduler as a `QuantumLoop` implementation and drives it
one quantum at a time. `drive_engine_quantum` in `crucible-session` is the only
session-side call into `QuantumLoop::drive_quantum`; `SessionDriver` has no
backend-advancement API of its own. Backends implement `SimulationBackend`:
they advance toward a scheduler-supplied ceiling and report what they
observed, but never choose cross-node order or derive their own schedule.

`SchedulerActor` wraps one `SingleScheduler` behind a message-only surface:

| Item | Role |
|------|------|
| `SchedulerActorHandle::queue_control` | Queue a `ControlOperation` for the next boundary |
| `SchedulerActorHandle::drive_quantum` | Request one quantum; reply carries `Result<QuantumOutcome, SchedulerError>` |
| `SchedulerActorHandle::snapshot` | Read-only `SchedulerActorStateSnapshot` |
| `SchedulerActor::run_once` | Apply one deferred or queued message |

Before driving a quantum, the actor drains every queued control message from
its mailbox and defers any other message, so a submitted control operation is
never hidden behind a later drive request.

No lock spans a RUN. RUN planning happens inside a `SchedulerCriticalSection`,
which sets `lock_held`; the plan is produced and the critical section dropped
before `advance_node_after_yield` moves the node. That function fails with
`BoundaryViolation` ("scheduler lock spans node advance") if the flag is still
set, and the liveness gate reports `SchedulerLivenessError::LockHeldAcrossAdvance`
if an advance did not yield first.

## The scheduler graph

Scheduler participants are identified by
`SchedulerNodeId { node: NodeId, kind: SchedulingNodeKind }`, where the kind is
one of `Vm`, `Disk`, `NineP`, `Network`, or `ControlPlane`. Both types derive
`Ord`, so every ordering decision that names a node uses the stable,
scenario-derived identity rather than launch order or a host address.

Each runtime node carries a `SchedulerNodeActivity`:

| Activity | Meaning |
|----------|---------|
| `Runnable` | Has work; may be selected by PICK |
| `Idle` | Parked; advances only to an exact wake |
| `Halted` | Terminal; projects an infinite horizon |
| `Done` | Terminal; never selected |

An `Idle` VM is treated as `Runnable` while any of its vCPU idle states is not
halted or has pending input (`effective_node_activity`).

## Lookahead

Lookahead is the conservative network term. It is computed over the current
effective edge set held in a `SchedulerLookaheadGraph`:

```text
lookahead(n) = min { edge.minimum_latency : edge.to == n, edge.from != n }
             = NetworkLookahead::Infinite   when no inbound edge exists
```

`SchedulerLookaheadGraph::from_edges` sorts and deduplicates directed
`SchedulerLookaheadEdge { from, to, minimum_latency }` values, so the graph is
canonical regardless of construction order. `lookahead_for_node` implements
the rule above; self-loops never contribute.

World links are symmetric and produce two directed VM-to-VM edges. The edge
latency is the link's guaranteed minimum delay, `latency - jitter`
(`link_minimum_latency`), because jitter only subtracts from the base latency
in the model. A node with no inbound edge has `NetworkLookahead::Infinite`;
this is why nodes with no live links run independently at full speed, bounded
only by their own exact local events and the run's time limit.

## The horizon

`horizon_from_network_lookahead` composes the horizon:

```text
horizon(n) = min( next_exact_local_event(n),   -- exact, no slack
                  vt(n) + lookahead(n) )        -- conservative, network only
```

The result is a `SchedulerHorizon` tagged with a `SchedulerHorizonSource`
(`NetworkLookahead`, `ExactLocalTimer`, `ExactLocalIoCompletion`,
`SignalFaultEvaluation`, `TriggerEvaluation`). When the exact term is at or
before the network term, the exact term wins.

### Exact local events

`ExactLocalEvent` is the set of host-predictable wakeups:

| Variant | Source |
|---------|--------|
| `TimerDeadline` | Guest virtual-timer deadline reported by the backend |
| `IoCompletion` | Deterministic completion computed by a disk, 9p, or network sub-node |
| `SignalFaultEvaluation` | Evaluation boundary requested by the signal-driven fault runtime |
| `TriggerEvaluation` | Next event-graph predicate transition |
| `NoArmedTimer` | No exact wakeup |

`next_exact_local_event` takes the earliest candidate from the node's timer
report and its scheduled I/O completions, breaking equal times by variant rank
(timer, I/O, signal-fault, trigger) and then sub-node name. Backend input
(guest-to-guest frames) is deliberately excluded: network input is the
conservative term, not an exact one. An I/O completion whose payload target or
delivery tick disagrees with its event key is rejected as a
`BoundaryViolation`.

The scheduler then folds in further exact terms
(`effective_exact_local_event_with_trigger`): the device sub-node's in-flight
completion head (recomputed before every PICK by `refresh_device_horizons`),
the earliest per-vCPU deadline, the signal-fault wakeup, and the trigger
wakeup. A later term replaces the current one only when strictly earlier.

The device horizon is a horizon *term*, not a deliverable event. Delivery of
the completion still happens only on the RESOLVE path, so a completion is never
counted twice.

These events need no conservative slack because no other node's unexecuted
instructions can move them: a disk completion time is computed by the sub-node
from the request and a fixed latency model, and a timer deadline is read from
guest timer state. Applying the conservative bound to them would be correct but
slow; omitting the bound from a network dependency would be wrong.

### Counter projection

Horizons are virtual times; RUN needs a node counter. The projection keeps the
exact tick scale (see [virtual-time.md](virtual-time.md)); a nanosecond
round-trip never changes an authorization boundary. Each candidate carries a
`SchedulerIcountRounding`:

- `ExactCeil` for exact timer and I/O horizons, so the node reaches the exact
  event in one RUN.
- `ConservativeFloor` for network, rendezvous, time-limit, dependency, and
  pending-input bounds, so the published counter is the greatest one that does
  not pass the bound.

A conservative interval that is positive in time but contains no counter
boundary fails loudly (`scheduler_unrepresentable_advance_error`) instead of
publishing a zero-progress RUN. Before publication, `advance_plan_draft` also
checks that the projected target does not overshoot the network cap, time
limit, rendezvous cap, any unresolved dependency, or any pending event for the
node; an overshoot is a `BoundaryViolation` naming the violated boundary.

## Conservative advance authorization

`authorize_conservative_advance(node, current_time, requested_target,
pending_events)` is the PDES guard applied to every runnable advance window:

- A requested target before `current_time` is rejected as a rollback.
- The earliest unresolved cross-node dependency for the node
  (`unresolved_cross_node_dependencies`, which considers only `BackendInput`
  events whose producer differs from the consumer, sorted by the canonical key)
  caps the target.
- A dependency already due at or before `current_time` fails loudly rather
  than allowing the node to run past it.

The result is a `ConservativeAdvanceAuthorization` carrying the authorized
target and the `blocking_dependency`, if any.

## PICK: the effective-horizon projection

PICK takes the minimum over one projection, `effective_horizon`:

```text
effective_horizon(node) =
    Halted | Done  ->  +inf (never selected, never lowers the minimum)
    Idle           ->  exact idle wake, capped by time limit and rendezvous
    Runnable       ->  advance window: horizon, time limit, rendezvous cap,
                       native boundaries, conservative authorization, and
                       pending inputs for the node
```

`advance_candidates` builds one `AdvanceCandidate` per node with a finite
projection strictly ahead of its current time, then sorts by
`(target_time, node, key virtual time, index)`. Ties on the projected horizon
therefore break by ascending `SchedulerNodeId`. Among candidates at the
minimum target, those without a representable counter advance are skipped in
favor of a representable peer at the same target. A later target never
bypasses the minimum: if every minimum candidate is unrepresentable, the list
is returned unchanged so RUN surfaces the conversion diagnostic.

An `Idle` node with no exact wake can still advance to a pending topology
activation time, so a topology swap is never blocked by a parked node.

### Parking and the moving network cap

When a RUN reaches a genuine local quiescence point (an exact timer or I/O
horizon), the node is parked `Idle`, unless a later device completion is still
owed. A node stopped by the network term is *not* parked: with a live
topology, `vt(n) + lookahead(n)` is a moving cap that rises with the frontier,
and the only path from `Idle` back to `Runnable` requires an unhalted vCPU or
pending input. Parking a network-bounded node would freeze the run, so such a
node keeps no quiescent horizon and stays `Runnable` to be re-picked for its
next interval.

## The quantum

The scheduler advances the system one quantum at a time. Each quantum runs
the phases PICK, RUN, RESOLVE, EMIT, STEP, and `drive_authoritative_quantum`
implements them in this order:

```text
QuantumRequest { configuration, control }
  |
  |  reject unless configuration == scheduler frontier
  |  refresh_device_horizons                 exact I/O terms before PICK
  |  boundary admission                      admit_control_at_boundary
  |  drain_control_events                    control -> ScheduledEvent
  |  apply_topology_changes_at_boundary      lookahead recompute
  v
PICK     pick_global_minimum_horizon_node
  |        none -> control-only EMIT/STEP (or inactive clock advance)
  v
RUN      SchedulerCriticalSection: plan, RR subdivision, publish ONE ceiling
         plan explorer preemption for the window
         advance_node_after_yield            no lock held
  v
RESOLVE  resolve_due_scheduled_events        frames for the advanced node
         resolve_device_completions          I/O completions + their draws
         merge_node_deliveries               one canonical order
  v
EMIT     emit_quantum_decisions              DeliveryOrder, draws, preemption
         emit_quantum_event_log              ordered, content-addressed
  v
STEP     step_quantum                        try_step per decision
         frontier, quanta += 1, yield_to_control_inbox
  v
QuantumOutcome
```

A request whose configuration is not the scheduler's frontier is rejected as a
`BoundaryViolation`. When PICK finds no candidate, the quantum still drains
control, applies topology, and emits and steps any resulting decisions; if all
nodes are terminal, `advance_inactive_clock` may move the frontier to the next
trigger, signal-fault, or topology-activation time.

The frontier is the minimum current virtual time over non-terminal nodes
(`frontier_for`). STEP folds each decision through `try_step`, so a decision
that violates the scenario model fails the quantum. The quantum sequence is a
pure function of `(ScenarioDef, Seed, Schedule)`: scheduler-owned node,
pending-event, and sequence-cursor state is part of the scenario identity.

`QuantumOutcome` carries the new configuration, frontier, advanced node,
resolved events in canonical order, decisions, the event-log entries and
segment bytes, hash, and offset appended by this quantum, and the
`SchedulerQuiescence` evidence after the quantum.

## RUN and the single ceiling

A RUN advances exactly one node to its planned target. The plan publishes
exactly one `SchedulerRunCeilingPublication` per RUN, after PICK has selected
the candidate and the overshoot checks have fixed the target. Its
`max_advance_icount` is the shared-memory ABI field value; `target_time` is
the horizon that produced it. A no-RUN quantum publishes nothing.

The ceiling is computed once and never recomputed mid-RUN. A ceiling that a
plugin could read at a host-scheduling-dependent moment would let a
single-instruction difference leak into guest timing, so the plugin observes
exactly one deterministic ceiling per RUN. The reached counter must lie in
`[before, max_advance_icount]`.

For QEMU nodes the publication becomes a shared-memory handoff
(`crates/crucible/crucible-qemu-host/src/quantum.rs`, `start_quantum`). The
host clamps the effective ceiling to the earliest pending inbound delivery,
then calls `NodeSlot::publish_scheduler_inbox_and_advance`, which:

1. validates the ceiling and preflights inbox capacity,
2. release-publishes every pending input frame to the directed inbox,
3. release-publishes the ceiling, and
4. only then increments the non-private futex wake word.

The woken plugin therefore observes a consistent `(ceiling, pending-inputs)`
snapshot in one wake (wake after inbox write); waking before the inbox write
would be a determinism hazard. The typed region form is
`RegionAllocation::publish_scheduler_inputs_and_advance`. Formats and atomic
orderings are specified in [shmem-abi.md](shmem-abi.md).

## Event ordering

Every scheduler-resolved event carries a `ScheduledEventKey`, ordered as:

```text
(virtual_time, consumer node_id, producer node_id, sequence)
```

| Field | Meaning |
|-------|---------|
| `virtual_time` | Delivery time, when the event becomes visible to the consumer; never the emit time |
| `consumer` | Stable `SchedulerNodeId` of the node that observes the event |
| `producer` | Stable `SchedulerNodeId` of the emitting node |
| `sequence` | Per-`(producer, consumer)` monotonic counter |

The key is stored as a `SharedTimelineKey { virtual_time, node, sequence }`
for the consumer plus the producer, and `Ord for ScheduledEventKey` compares
the four fields in the order above. For two events with equal virtual time and
consumer, the lower producer id resolves first, then the lower sequence. The
order is a pure function of these fields.

`next_scheduled_event_key` allocates the sequence from the saved
`EventSequenceState` and fails on overflow. The counter is part of saved
scheduler state, so a resumed run continues the same sequence. Control
operations use the `control-plane` node of kind `ControlPlane` as both producer
and consumer, keyed at the current frontier.

`ScheduledEventPayload` has three classes (`ScheduledEventResolveClass`):

| Payload | Class | Delivery time |
|---------|-------|---------------|
| `BackendInput` | `FrameDelivery` | Key time; payload target must equal the key consumer |
| `IoCompletion` | `IoCompletion` | `delivery_tick`; must equal the key time |
| `Control` | `Control` | Key time |

### Ordering hygiene

No ordering-significant path iterates an unordered collection or uses a
randomized hasher. Scheduler state uses `Vec` with explicit sorts, `BTreeMap`,
and `BTreeSet`. `checks.crucible.phase3.schedulerOrderingLint` statically
denies `HashMap`, `HashSet`, `DefaultHasher`, `RandomState`, and
`std::collections::hash_map` in the scheduler and model ordering sources, and
runs the harness-lint regressions behind `gate:harness-lint`. Identity hashing
uses fixed, cross-platform stable hashes (see [determinism.md](determinism.md)).

## RESOLVE and late delivery

`resolve_due_scheduled_events(pending, consumer, advanced_to)` drains, for the
node that just ran, every event whose delivery time equals `advanced_to`, and
returns them in canonical key order regardless of the order they were queued
on the transport. Events ahead of `advanced_to` stay queued; events for other
consumers are untouched.

An event for the consumer whose delivery time is *behind* `advanced_to` means
the node ran past an input. That is never delivered late: RESOLVE fails with a
localized `SchedulerError::BoundaryViolation` ("late scheduled event ...")
naming the consumer, delivery time, reached time, producer, and sequence. The
conservative guard and the pending-input bound in the advance window are what
prevent this in correct operation; the RESOLVE check is the fail-loud backstop.

Device completions for the advanced node are drained by
`resolve_device_completions` at their exact delivery tick, with sequences
minted from the scheduler's counter on the live path, and merged with frame
deliveries by `merge_node_deliveries` into one canonical order.

Visibility depends only on the delivery tick, never on when the payload became
present on the transport. A frame due at `t` is visible at the counter for
`t` even when the next rendezvous is far away.

### Probabilistic choices

Probabilistic link and device effects (loss, duplication, corruption, jitter,
reorder, device faults) are drawn from seeded, name-hash-forked streams and
recorded as `Decision::RngDraw` entries in the schedule. `emit_quantum_decisions`
advances the scheduler's per-stream cursor for each recorded draw. There is no
other randomness in RESOLVE. Stream derivation is documented in
[determinism.md](determinism.md) and [io-subnodes.md](io-subnodes.md).

## EMIT and STEP

`emit_quantum_decisions` builds the quantum's decisions: a
`Decision::DeliveryOrder` listing the resolved event keys when any event was
resolved, then pending World-network decisions, device decisions, and
`Decision::Preemption` for applied explorer preemptions.
`scheduler_ordered_decisions` stably sorts them by event-log time, keeping
construction order for ties.

`emit_quantum_event_log` appends, in order: each resolved happening in
canonical key order (with a black-box `network_delivered` observation for
World-link frames), each decision, a stable sort by entry time, and a
`Quantum` evaluation boundary. Entries are dense and content-addressed. The
segment format and causal/observational classes are in
[event-log.md](event-log.md).

STEP folds the decisions into the configuration, advances the frontier,
increments the quantum count, and calls `yield_to_control_inbox`
(incrementing `boundary_yields`). Control applications and preemption
applications are committed only after EMIT and STEP succeed.

## Idle fast-forward and effective clocks

An idle node does not hold peers back. `SingleScheduler::effective_clocks`
projects each node's peer-facing clock as a `SchedulerEffectiveClock`:
runnable, halted, and done nodes use their current time
(`SchedulerEffectiveClockSource::Current`); an idle node with a finite exact
wake later than its current time uses that wake
(`SchedulerEffectiveClockSource::IdleWake`).

The idle wake (`idle_wake_target`) is the earliest of the node's effective
exact local event, any pending input for the node, and any imported native
boundary. PICK moves an idle node directly to that wake, clamped by the time
limit and the rendezvous cap, in a single RUN. The jump costs no wall-clock
time and adds no schedule decision, and because the wake is an exact local
event the jump changes no instruction ordering. A long idle gap collapses into
one advance while every wakeup still lands at its exact counter.

On the QEMU side the parked plugin computes the same kind of wake with
`compute_idle_wake_plan`: the earliest of a host-published device-completion
deadline, the guest timer deadline, and the head inbound delivery, with ties
resolved device, timer, inbound, and the scheduler ceiling as the bound when
nothing is pending (`IdleWakeCause`). See [qemu-plugin.md](qemu-plugin.md).

## Quiescence and liveness

`SingleScheduler::quiescence` computes a `SchedulerQuiescence` from
scheduler-owned state only. The run is quiescent when the blocker list is
empty. Blockers are reported in canonical order:

| Blocker | Cause |
|---------|-------|
| `PendingControl` | Control operation awaiting a boundary |
| `PendingPreemption` | Explorer preemption awaiting its RUN |
| `PendingTopologyChange` | Queued topology change |
| `PendingEvent` | Queued scheduled event |
| `DeviceCompletionInFlight` | Undelivered device or network-link completion |
| `RunnableNode` | Node PICK could still select |
| `ActiveVcpu`, `PendingVcpuTimer`, `PendingVcpuInput` | Per-vCPU work in a multi-vCPU node |
| `PendingExactLocalEvent` | Node with an exact wakeup |
| `PendingGlobalEvaluation` | Future trigger or signal-fault evaluation while all nodes are inactive |

Quiescence never depends on a host timeout or a "nothing happened for a while"
heuristic. Halted and done nodes contribute no blockers.

`check_scheduler_liveness` drives a `SchedulerLivenessScenario` until it is
quiescent (`SchedulerTerminal::Quiescent`) or reaches its virtual-time or
quantum budget (`SchedulerTerminal::TimeLimitReached`). A non-quiescent state
in which no progress occurs fails loudly:

| Error | Condition |
|-------|-----------|
| `Deadlock` | No node advanced, the frontier did not move, no topology recompute, and no runnable node |
| `Livelock` | A node was selected but did not advance, or a runnable node stalled |
| `LockHeldAcrossAdvance` | An advance did not yield before running |
| `EmptyScenario` | The scenario has no nodes |

### Why progress is guaranteed

Let `m` be the node with the minimum virtual time among live nodes. With every
link latency strictly positive, `lookahead(m) > 0`, and no peer is behind `m`,
so no peer can deliver an event to `m` earlier than `vt(m) + lookahead(m)`.
Exact local events depend on no peer. The global-minimum-horizon node can
therefore always advance by a positive amount, or go idle and be fast-forwarded
to its wake. Virtual time is monotone, so the run advances until quiescence or
its budget. The strictly positive link-latency floor below is what makes this
argument hold.

## Rendezvous

`SchedulerRendezvous` is the only schedule-related knob. `disabled()` turns it
off; `every(interval)` sets a fixed interval and rejects zero. The cap is
computed from the global frontier, not from any node's own clock:

```text
rendezvous_cap_for(frontier, every(I)) = (floor(frontier / I) + 1) * I
```

`shared_rendezvous_cap` is the minimum of the fixed cap, the earliest pending
topology activation, and runtime branch and stop caps. The same cap is applied
to every candidate in a PICK, so bringing non-terminal nodes to a common time
is itself exact: an earlier exact event or network bound still governs, and the
cap never forces a node past an earlier event.

A rendezvous-capped quantum that resolves nothing appends no schedule decision
and does not advance the decision-RNG cursor. Changing the interval changes
only how many quanta are needed to reach an event; final configuration,
frontier, resolved events, and delivery-order decisions are identical.

`SchedulerRendezvousPurpose` names the only allowed uses (assertion-drain,
trigger-eval, topology-swap, snapshot-control):

| Purpose | Use |
|---------|-----|
| `AssertionDrain` | Drain the assertion engine at one virtual time |
| `TriggerEvaluation` | Evaluate global triggers at one virtual time |
| `TopologySwap` | Swap the effective topology at an exact activation time |
| `SnapshotControl` | Coordinate a globally consistent snapshot |

There is no event-delivery purpose: delivery happens only through RESOLVE.
`record_rendezvous` produces a `SchedulerRendezvousRecord` only when every
non-terminal node is exactly at the rendezvous time (zero skew); halted and
done nodes are not members of the active rendezvous set. After the record,
nodes resume independent horizon-bounded advancement.

## Topology change

Membership is static, but faults change the effective edge set at run time.
Because lookahead is derived from that set, a change is a scheduler event.

A `SchedulerTopologyChange` has a `sequence`, a
`SchedulerTopologyChangeTrigger` (`EdgeRemoval`, `EdgeRestore`,
`LatencyChange`), an optional `activation_time`, and a
`SchedulerTopologyChangeEffect`:

| Constructor | Effect | Semantics |
|-------------|--------|-----------|
| `new` | `ReplaceEffectiveEdges` | Replace the whole edge set |
| `partition` | `RemoveEffectiveEdges` | Remove directed edges by endpoint |
| `heal` | `RestoreEffectiveEdges` | Restore directed edges into the current set |
| `update_effective_edges` | `UpdateEffectiveEdges` | Replace matching present edges only; never re-adds a partitioned edge |

`with_activation_time` attaches the fault's exact activation time.
`SingleScheduler::schedule_topology_change` lets fault, heal, and latency
handlers queue changes; it rejects an activation time behind the frontier with
`SchedulerError::TopologyActivationInPast`. Queued changes are ordered by
`(sequence, trigger, activation_time)`.

`apply_topology_changes_at_boundary` runs at the quantum boundary before PICK,
never mid-RUN. For each change it builds the new graph, recomputes every
node's `NetworkLookahead` with the same minimum-inbound rule, records a
`SchedulerTopologyLookaheadUpdate` per node in a
`SchedulerTopologyChangeApplication`, and increments the topology epoch. A
partition that removes a node's last inbound edge makes its lookahead
`Infinite`; a lowered lookahead takes effect before the node is next picked.
A topology-only recompute counts as liveness progress.

Timed changes are applied atomically at a rendezvous. A pending activation
time contributes to the shared rendezvous cap, so every non-terminal node is
brought to exactly that time rather than to the next fixed rendezvous tick.
The change is deferred until `topology_activation_ready` sees every
non-terminal node at the activation time, then applied at the following
boundary with a `TopologySwap` rendezvous record. A node found past the
activation time is a `BoundaryViolation`. The fault therefore takes effect at
its exact virtual time, and no node runs partly under the old and partly under
the new lookahead.

### Send authorization

Cross-node sends are authorized against the current topology through
`SchedulerSendAuthorizer::authorize_cross_node_send`. The scheduler refuses a
send while any topology change is pending (sends are frozen until it applies)
and refuses a send with no effective edge. A successful
`SchedulerSendAuthorization` records the topology epoch. The SimDouble and
QEMU outbound emission paths require an explicit authorizer before writing or
draining VM-to-router frames.

### Link latency recompute

`crucible_device::NetLink` raises a one-shot recompute flag when its
conservative minimum effective latency changes.
`SingleScheduler::schedule_link_latency_recompute` consumes the flag and queues
a `LatencyChange` update for the directed edge, failing if the link reports a
zero latency or the edge is absent. Faults that raise the minimum only widen
lookahead; jitter, reorder, and bandwidth delay individual frames but have a
minimum added delay of zero and so never lower the scalar edge.

## Link-latency floor

Every guest-to-guest link must have a strictly positive latency. The floor is
`MIN_LINK_LATENCY` in `crates/crucible/crucible-engine/src/model.rs`, one
virtual nanosecond (`SIM_TICKS_PER_NS = 1000` ticks):

```rust
pub const MIN_LINK_LATENCY: SimDuration = SimDuration {
    ticks: SIM_TICKS_PER_NS,
};
```

The policy depends on where a sub-floor value comes from:

- A declared base latency below the floor is rejected at construction and
  lowering (`LinkDef::with_transport`, `validate_link_transport`) with
  `EngineError::WorldLinkLatencyBelowFloor`. If `latency - jitter` could fall
  below the floor, the link is rejected with
  `EngineError::WorldLinkJitterBelowLatencyFloor`. The device layer rejects a
  sub-floor base latency with `DeviceError::LinkLatencyBelowFloor`. Silently
  clamping a declared value would change the scenario's meaning without the
  author's knowledge.
- A latency-reducing fault that would push an existing link below the floor is
  clamped to the floor by `NetLink`. A fault must not be able to break
  scheduler liveness, and clamping keeps lookahead positive.

The floor is part of scenario identity: canonical World material records
`min_link_latency_ticks`, so two runs compared for determinism share it.

A zero-latency link would make the receiver's lookahead zero, its network
horizon equal to its current clock, and the linked nodes degrade to
single-instruction lockstep, with possible same-time delivery cycles. The
floor is a liveness minimum, not an operating point: achievable multi-VM
parallelism scales with link latency, and realistic scenarios run links well
above the floor.

## Host concurrency

Lookahead is the parallelism budget. Nodes whose horizons cannot affect each
other may run on host threads at the same time, but resolution stays
serialized, so concurrency is an execution optimization that never changes
order.

`SingleScheduler::concurrent_run_set` returns a `SchedulerConcurrentRunSet`
built from the same `advance_candidates` as serial PICK:

- If the canonical first candidate is not at the common frontier (a parked
  peer is holding the frontier back), only that candidate runs, preserving the
  serial PICK order.
- Otherwise the set is every candidate that shares the minimum target and
  starts at the common frontier.

Host worker count is not an input to the semantic set. The concurrent path
(`ConcurrentQuantumLoop::drive_concurrent_quantum`) publishes the selected
ceilings before dispatch, runs the nodes, then commits each completion through
RESOLVE, EMIT, and STEP on the single scheduler in canonical completion order.
Serial and concurrent runs produce the same intermediate frontiers, final
configuration, event-log offset, and event-log entry hashes; this
scheduler-side proof feeds `gate:e2e-determinism`.

## Control responsiveness

`ControlOperation { sequence, kind }` carries a `ControlOperationKind`
(`Pause`, `Resume`, `Step`, `Snapshot`, `Fork`, `Query`). Controls arrive
either through the actor mailbox or on `QuantumRequest::control`; both become
scheduler control events at the boundary drain before PICK, so control is
applied only at quantum boundaries, never mid-quantum.

`SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA` is `1`: a control operation must be
applied within one scheduler quantum of its admission.
`drain_control_events` records a `SchedulerControlApplication` with the quantum
and boundary-yield counts at admission and application and rejects any
application whose delta exceeds the bound. Applications are committed only
after the quantum's EMIT and STEP succeed. A `Snapshot` control also records a
scheduler checkpoint for every VM node. This is the scheduler half of
`gate:control-responsive`; control-only quanta with no runnable node still
apply control at the boundary.

## Multi-vCPU nodes

A node may host several vCPUs, but the scheduler still orders *nodes*. The node
clock is one aggregate counter; per-vCPU state lives inside the plugin and is
folded into the aggregate fingerprint. There are no per-vCPU shared-memory
slots or clocks. Exposing a vCPU dimension to the ABI, the scheduler, and the
total order would leak an internal detail across every boundary, and the
round-robin cursor already orders vCPUs under the aggregate clock.

### Round-robin sub-division

QEMU runs all vCPUs of a node on one host thread under the TCG-derived sim
accelerator (`-accel sim,thread=single`) and switches vCPUs at a fixed
`rr_switch_quantum`, passed as an `-icount` sub-option
(`shift=...,sleep=off,align=off,rr_switch_quantum=N`). Because the switch point
is a counter value rather than a host-scheduling event, the interleaving is a
pure function of the counter. Multi-threaded TCG is not used: it interleaves
memory operations across host threads with no deterministic ordering model.
Stock `tcg` leaves the sim-gated round-robin, IPI, dispatch, and preemption
paths inert and is not a Crucible runtime accelerator.

The launch default is `DEFAULT_RR_SWITCH_QUANTUM = 4096` in
`crates/crucible/crucible-qemu-host/src/launch.rs`. Any fixed value is
deterministic; the value trades race-surfacing granularity against switch
overhead, and 4096 was the smallest measured candidate that met the throughput
floor without losing race discrimination.

The scheduler publishes only the node ceiling, one per RUN. For nodes with a
`SchedulerRunSubdivisionPolicy { node, vcpu_count, rr_switch_quantum }`, it
records the plugin-internal slices as evidence in a
`SchedulerRunSubdivisionRecord`, computed by `scheduler_rr_run_subdivision`
from the current counter, the published `max_advance_icount`, `vcpu_count`,
and `rr_switch_quantum` only:

```text
cursor = current_icount
while cursor < max_advance_icount:
    slot  = cursor / rr_switch_quantum
    vcpu  = slot % vcpu_count                     fixed ascending rotation
    end   = min((slot + 1) * rr_switch_quantum, max_advance_icount)
    emit slice(vcpu, cursor, end); cursor = end
```

A single-vCPU node is the degenerate case: one slice for the whole RUN, or none
for an empty RUN. Zero vCPUs or a zero quantum is rejected. In the plugin,
`RoundRobinConfig` and `RoundRobinRunState` implement the same rotation
(`next_vcpu` wraps from the last vCPU to 0), account retired counter ticks per
turn, skip halted vCPUs, and report when every vCPU is halted.

### All-vCPUs-idle

A `SchedulerNodeVcpuIdleSnapshot { node, vcpu_count, vcpus }` gives one
`SchedulerVcpuIdleState { vcpu, halted, next_deadline, pending_input }` per
vCPU. Construction requires a VM node, a nonzero count, and exact contiguous
coverage of every vCPU in `0..N`; a count that disagrees with the node's RR
policy is rejected.

The node is idle for quiescence only when all vCPUs are halted, timer-free,
and input-free; otherwise quiescence reports `ActiveVcpu`, `PendingVcpuTimer`,
or `PendingVcpuInput` for the specific vCPU. The node's wake is the minimum
per-vCPU deadline, folded into its exact local event, so the node remains one
scheduler candidate with one node-level ceiling. Per-vCPU deadlines at or
before the reached time are cleared after RUN. The plugin computes the same
node deadline with `aggregate_multi_vcpu_deadline`.

When all vCPUs are halted, the patched QEMU round-robin idle callback may
release the BQL around one futex wait and must rescan all vCPUs before doing
any further work; see [qemu-patch.md](qemu-patch.md).

## Preemption

`PreemptionDecision { node, at, kind }` names a point on a node's counter where
a `PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu }` or
`PreemptionKind::InterruptAt { target_vcpu, .. }` occurs. Default round-robin
switches are deterministic engine behavior derived by
`DecisionRecorder::default_rr_preemption` without schedule entries. Only
explorer-supplied preemptions become `Decision::Preemption` entries in the
schedule, which keeps `T = f(Configuration)`: a timing change that is not a
recorded decision would break replay. Interrupt-timing preemption gives even
single-vCPU guests an exploration dimension. Exploration itself is described
in [exploration.md](exploration.md).

Explorer requests enter the scheduler through
`SchedulerLivenessScenario::with_preemption_request` and are part of scenario
identity. For each RUN, `planned_preemptions_for_authorized_run`:

- admits at most one request for the node (more is a `BoundaryViolation`, so
  concurrent completions can be serialized by commanded time without inventing
  an interleaving the plugin cannot execute);
- rejects a request outside `[current counter, authorized horizon]`;
- leaves a request beyond this RUN's ceiling pending for a later RUN; and
- never clamps or defers a request past the node ceiling.

An applied preemption is recorded as a `SchedulerPreemptionApplication` against
the single RUN ceiling, emitted as `Decision::Preemption`, and its event-log
entry is placed at the preemption's commanded virtual time. Pending requests
are quiescence blockers until applied.

## Worked example

Two VMs `A` and `B` share a symmetric link with latency 1 ms and no jitter, so
`lookahead(A) = lookahead(B) = 1 ms` (one virtual millisecond is
1,000,000,000 ticks). `A` has a guest timer at 0.4 ms. `B` computes and sends
a frame to `A` at 2.3 ms. The rendezvous interval is 100 ms.

```text
vt(A)=0, vt(B)=0
  horizon(A) = min(timer 0.4, 0 + 1.0) = 0.4    exact local term wins
  horizon(B) = min(none,      0 + 1.0) = 1.0    network term
PICK A (0.4 < 1.0). RUN A exactly to 0.4; timer fires. RESOLVE: nothing due.

vt(A)=0.4, vt(B)=0
  horizon(A) = 0.4 + 1.0 = 1.4
  horizon(B) = 0   + 1.0 = 1.0
PICK B. RUN B to 1.0.  ...  nodes alternate in network-bounded steps.

At vt(B)=2.3, B emits a frame to A:
  key = (3.3 ms, A, B, seq)          delivery = 2.3 + 1.0
The pending input bounds A's advance window at 3.3, so A stops exactly there,
and RESOLVE makes the frame visible at the counter for 3.3 ms.
```

The timer was reached with no conservative slack; only the frame used the
1 ms bound. The frame lands at 3.3 ms although no rendezvous has occurred.
With a 1 ms or 1 s interval the run takes a different number of quanta, but
the frame still lands at 3.3 ms and the schedule is identical.

## Tests and checks

The scheduler contracts above are pinned by focused Rust tests in
`crates/crucible/crucible-engine/tests/` and Nix checks under
`checks.crucible.phase3`:

| Area | Rust test target | Check attribute |
|------|------------------|-----------------|
| Actor boundary | `scheduler_actor` | `schedulerActor` |
| Lookahead | `scheduler_lookahead` | `schedulerLookahead` |
| Conservative PDES | `scheduler_conservative_pdes` | `schedulerConservativePdes` |
| Horizon, exact local events | `scheduler_horizon`, `scheduler_exact_local_event` | `schedulerHorizon`, `schedulerExactLocalEvent` |
| Rendezvous frequency and purpose | `scheduler_rendezvous`, `scheduler_rendezvous_purpose` | `schedulerRendezvous`, `schedulerRendezvousPurpose` |
| Event order and lint | `scheduler_event_order` | `schedulerEventOrder`, `schedulerOrderingLint` |
| Link-latency floor | `scheduler_link_latency_floor_rejects_subfloor_before_hashing_and_enters_world_material` (engine unit test) | `schedulerLinkLatencyFloor` |
| Quiescence, liveness | `gate_scheduler_liveness` | `schedulerQuiescence`, `gates.schedulerLiveness` |
| Quantum loop and pattern | `scheduler_quantum_loop`, `scheduler_effective_horizon` | `schedulerQuantumLoop`, `schedulerEffectiveHorizon`, `schedulerQuantumPattern` |
| RUN ceiling and tick scale | `scheduler_run_ceiling`, `scheduler_icount_ceiling` | `schedulerRunCeiling`, `schedulerIcountCeiling`, `schedulerWakeOrdering` |
| Idle fast-forward | `scheduler_idle_fast_forward` | `schedulerIdleFastForward` |
| RESOLVE, late delivery | `scheduler_resolve` | `schedulerResolve`, `schedulerResolveRng`, `schedulerLateDelivery` |
| EMIT and STEP | `scheduler_emit_step` | `schedulerEmitStep` |
| Topology | `scheduler_topology_change`, `scheduler_partition_heal`, `scheduler_topology_rendezvous` | `schedulerTopologyChange`, `schedulerPartitionHeal`, `schedulerTopologyRendezvous` |
| Host concurrency | `scheduler_concurrency` | `schedulerConcurrency` |
| Control responsiveness | `scheduler_control_responsive` | `schedulerControlResponsive` |
| Multi-vCPU | `scheduler_rr_subdivision`, `scheduler_all_vcpus_idle` | `schedulerRrSubdivision`, `schedulerAllVcpusIdle` |
| Preemption | `scheduler_preemption_resolve`, `preemption_discrimination` | `schedulerPreemptionResolve` |

Gate structure is described in [testing-and-gates.md](testing-and-gates.md).
