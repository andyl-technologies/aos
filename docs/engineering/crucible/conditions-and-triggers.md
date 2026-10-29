# Conditions, triggers, and fault injection

A Crucible scenario expresses its control flow as an **event graph**: a list
of events, each binding an optional trigger condition to an action and a firing
policy. Conditions come from one shared predicate vocabulary that has exactly
two consumers: assertions grade the run with it, and triggers steer the run
with it. Faults are not actions. They are a separate, signal-driven component
of the same plan, applied by production adapters at exact scheduler
boundaries.

This page documents the condition vocabulary, how conditions are evaluated
deterministically, how events fire and how their actions are applied, how
explicit verdicts compose with assertions, how the graph is validated and
serialized, and how the fault plan reaches the simulated world. Operator-facing
material lives elsewhere:

- the TOML schema for `[[plan.event]]` rows and predicate tables is in the
  [scenario reference](../../users/crucible/reference.md);
- authoring signal-driven faults is covered in
  [signal-driven faults](../../users/crucible/signal-driven-faults.md),
  [network faults](../../users/crucible/network-faults.md), and
  [storage and node faults](../../users/crucible/storage-node-faults.md);
- the assertion layer (property quantifiers and the assertion verdict) is in
  [assertions.md](assertions.md), and the event-log format in
  [event-log.md](event-log.md).

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-engine/src/model/plan_properties.rs` | `Plan`, `Predicate` and its leaf parameter types (`FramePredicate`, `RegexProgram`, `CodePoint`, `MemPlace`, `MemoryCmp`, `IoEventKind`, `NodeLifecycle`, `AssertionPhase`) |
| `.../src/trigger.rs` | `pub type Condition = Predicate`; module root |
| `.../src/trigger/event_graph.rs` | `Event`, `FirePolicy`, `Action`, `EventGraph`, builder, `EventGraphState`, `EventGraphError`, validation |
| `.../src/trigger/evaluation.rs` | `evaluate_condition`, leaf matchers, `ConditionEvaluation`, `ConditionEvaluationPass` |
| `.../src/trigger/conditions.rs` | `ObservableEvent`, `ObservableEventPayload`, `ConditionEvaluator`, `ConditionEventLogPrefix` |
| `.../src/trigger/deadlines.rs` | Projection of future time-leaf transitions |
| `.../src/trigger/observability.rs` | `BlackBoxObservationKind` and the black-box observation contract |
| `.../src/scheduler/control_state.rs` | `SchedulerEventLogPayload`, `TriggerActionState`, `TriggerActionApplication`, verdict composition |
| `.../src/scheduler/event_codec.rs` | `apply_trigger_action`, `apply_trigger_effect`, `apply_trigger_verdict_effect` |
| `.../src/scheduler/single_scheduler_state.rs` | `evaluate_event_graph`, `apply_trigger_firings`, `set_trigger_wakeup` |
| `.../src/model/validation.rs` | Named-predicate DSL expansion |
| `.../src/model/toml.rs`, `.../src/model/binary_plan.rs` | TOML and compact-binary codecs for plans, events, and predicates |
| `.../src/model/fault_signal/` | `FaultSignalPlan`, the effect registry, the binding runtime |
| `crates/crucible/crucible-daemon/src/vm_lifecycle/runtime.rs` | Production settlement of assertions and triggers at each boundary |
| `crates/crucible/crucible-device/src/fault.rs`, `.../src/netlink/fault.rs` | Exact probabilities, `DeviceRng`, `LinkFaults` |
| `crates/crucible/crucible-qemu-host/src/fault_action_sink.rs`, `.../src/production_fault_sink.rs` | Icount-targeted QEMU fault commands and the host/QEMU commit order |

Paths beginning `.../src/` are under `crates/crucible/crucible-engine/`.

## Design in brief

- **Control flow is one graph.** Readiness detection, relative timers,
  savepoint and fork requests, pass, fail, and logging are all events. There is
  no parallel poke path: `EventGraphState` is the only producer of
  `EventFiring` values, and the scheduler applies firings only through
  `apply_trigger_firings`.
- **One predicate type, two consumers.** `Condition` is a type alias for
  `Predicate`, not a second enum. Assertions and triggers both call the single
  non-overridable `evaluate_condition`, so they cannot disagree about compound
  traversal or leaf meaning.
- **Black-box first.** Every leaf except `GuestMarker` is computed from
  host-side observation of an unmodified guest: delivered frames, console
  bytes, translated-block execution, device completions, lifecycle state,
  assertion state, and scheduler quiescence. The white-box marker leaf is
  opt-in and additive. Requiring an in-guest agent would make guest-side state
  load-bearing for determinism and tie scenarios to one guest OS; keeping
  markers observational means a scenario with the white-box channel enabled
  stays fingerprint-identical to one without it.
- **Evaluation is a pure function of the log.** Conditions are evaluated only
  at deterministic points over a checked event-log prefix, never on a host
  timer. Which events fire, and when, is computed, not chosen.
- **A trigger firing is not a `Decision`.** Firings and their applied actions
  are causal event-log entries. Only genuinely nondeterministic choices
  (delivery order, keyed fault draws, preemption) are schedule decisions, so
  exploration branches on those and the trigger graph rides deterministically
  on top of each explored schedule.
- **Faults are a separate plan component.** `Plan` holds an `EventGraph` and a
  `FaultSignalPlan`. No `Action` adds, removes, or edits a fault.

## The plan component

```rust
pub struct Plan {
    id: ContentHash,               // "crucible.model.plan.v6" domain
    graph: EventGraph,             // non-fault control flow
    fault_signals: FaultSignalPlan, // signal programs and fault bindings
}
```

The plan identity is the content hash of the event-graph material (events in
declared order, each with id, policy, canonical trigger material, and action)
followed by the fault-signal plan id. Declared order is part of identity
because it is semantic: it is the order in which events are evaluated and in
which their firings are applied.

Construction always validates against the admitted `World` (and, when known,
the scenario's assertion ids): `Plan::from_event_graph_for_world`,
`Plan::from_event_graph_with_assertions_for_world`,
`Plan::from_canonical_toml_for_world`, and
`Plan::from_compact_binary_for_world`. A scenario is validated with its
`Properties`, so `AssertionState` triggers resolve against declared
assertions.

## The shared condition vocabulary

`Predicate` (alias `Condition`) is a closed enum of leaves and combinators.

| Variant | True at evaluation point `t` when |
|---------|-----------------------------------|
| `At { at }` | `t == at` |
| `After { duration, of }` | event `of` last fired at `f` and `f + duration == t` (checked add) |
| `Timer { name }` | the armed fire time of timer `name` equals `t` |
| `NetworkMatch { link, predicate }` | a `NetworkDelivered` observation at `t` matches `predicate`, on `link` or on any link when `link` is `None` |
| `ConsoleMatch { node, regex }` | a regex match over `node`'s console stream ends inside bytes that became visible at `t` |
| `CoveragePoint { node, point }` | a `CoverageBlock` at `t` on `node` contains the resolved address, and no earlier block did |
| `MemoryPredicate { node, place, cmp, value }` | a `MemorySample` at `t` for `node` and the resolved place satisfies `sample cmp value` |
| `IoPattern { node, kind }` | an `IoCompletion` at `t` on `node` has `kind` (`IoEventKind::Any` matches every kind) |
| `NodeState { node, state }` | a `NodeState` observation at `t` reports `state` for `node` |
| `AssertionState { name, state }` | an `AssertionStateChanged` observation at `t` reports `state` for `name` |
| `Quiescent` | scheduler quiescence evidence is present and has no blockers |
| `Named { name, nodes }` | the leaf oracle says so (see [Named predicates](#named-predicates-and-the-dsl)) |
| `GuestMarker { marker }` | a guest marker named `marker` is observed at `t` on a white-box-enabled node |
| `AllOf { predicates }` | every child is true |
| `AnyOf { predicates }` | at least one child is true |
| `Once { predicate }` | the child is true now or has latched true earlier |
| `Not { predicate }` | the child is false |

Constructors mirror the variants: `Predicate::at`, `after`, `timer`,
`network_match`, `console_match`, `coverage_point`, `memory_predicate`,
`io_pattern`, `node_state`, `assertion_state`, `quiescent`, `guest_marker`,
`all_of`, `any_of`, `once`, `not` (also `!predicate`), `named`, and
`named_for_nodes`.

### Leaves are pulses

Every observational leaf matches only observations whose virtual time equals
the evaluation point (`observable_event_matches` compares `event.at() == t`).
A leaf therefore describes an edge: "a matching frame was delivered now",
not "a matching frame was delivered at some point". Time leaves are likewise
exact equalities, not "at or after". Two consequences follow:

- To remember an edge, wrap it in `Once`. An `AllOf` of two edges that never
  coincide fires only when each is latched with `Once`.
- `Not` of a pulse is true immediately after the pulse ends, which matters for
  repeatable events and is why the deadline projection tracks falling edges
  (see [Time-leaf deadlines](#time-leaf-deadlines)).

`CoveragePoint` is additionally first-time-only: it is false at a point where
the block executes again after an earlier observation.

### Time leaves

`At`, `After`, and `Timer` depend only on virtual time and the graph's own
firing history, never on host time. All durations are exact `SimDuration`
ticks (picoseconds; see [virtual-time.md](virtual-time.md)).

- `After { duration, of }` anchors on the **last** firing of `of`. A
  repeatable anchor event moves the anchor each time it fires.
- `Timer { name }` reads the scheduler-owned armed-timer map. `ArmTimer`
  inserts `firing_time + after` (replacing any earlier arming of that name);
  `CancelTimer` removes it. `ArmTimer` plus `Timer` is the general relative
  delay: one arming can gate several events and the arming can sit inside any
  `Group`. `After` is the one-to-one shorthand that needs no timer name.

### Observable leaves

- **`NetworkMatch`** matches frames at delivery, the cross-node event the
  scheduler orders, not at emission. `FramePredicate` is `Any`, `Exact(bytes)`,
  `Contains(bytes)` (an empty needle matches), or `Prefix(bytes)`.
- **`ConsoleMatch`** concatenates the node's console bytes from all earlier
  observations, appends the bytes observed at `t`, and is true when any match
  of the compiled `regex::bytes::Regex` ends after the start of the bytes
  observed at `t`. The pattern is compiled at graph validation
  (`EventGraphError::InvalidRegex`) and the `regex` crate's finite-automaton
  engine guarantees evaluation terminates in time linear in the input.
- **`CoveragePoint`** is driven by `CoverageBlock` observations harvested from
  the plugin's translated-block execution hook, so it needs no guest
  instrumentation. A block matches when
  `guest_pc <= address < guest_pc + block_len`. `CodePoint::GuestAddress`
  resolves directly; `CodePoint::Symbol` resolves only through host-supplied
  symbol data (`with_resolved_code_points`), and an unresolved symbol is false.
- **`MemoryPredicate`** compares a `MemorySample` observation that carries its
  exact `sample_icount`; the evaluator never reads guest memory itself.
  `MemPlace::PhysicalAddress` and `MemPlace::Register` resolve directly, while
  `VirtualAddress` and `Symbol` resolve only through a host-supplied table
  (`with_resolved_mem_places`), so an unresolvable virtual address is false
  rather than a page-table walk at an arbitrary time. Widths are `U8`, `U16`,
  `U32`, `U64`; comparisons are unsigned `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`.
- **`IoPattern`** kinds are `Any`, `BlockRead`, `BlockWrite`, `Fsync`, `NineP`,
  and `Network`, observed as device completions at their resolved time.
- **`NodeState`** states are `Started`, `Crashed`, `Hung`, and `Exited`.
- **`AssertionState`** closes the loop between grading and steering: a trigger
  can fire because an assertion just became `Satisfied` or `Violated`. The
  production settlement loop appends assertion-state observations before it
  evaluates triggers at the same boundary.
- **`Quiescent`** reads `SchedulerQuiescence`, computed from authoritative
  scheduler state (runnable nodes, pending events, control, preemptions,
  vCPU timers and input, topology changes, exact local wakeups, undelivered
  device completions, pending global evaluations), never from a host timeout.
  An evaluator without quiescence evidence reports false.

`ObservableEventPayload::black_box_observation_kind` classifies the required
host-side surfaces into the seven `BlackBoxObservationKind` values
(`NetworkTraffic`, `DiskOrNinePIo`, `ConsoleSerialOutput`,
`ArchitecturalStateSample`, `RunOutcome`, `CrashOrHangDetection`,
`BasicBlockCoverage`); see [guest-host-channel.md](guest-host-channel.md) for
how each surface is captured.

### The guest-marker leaf

`GuestMarker { marker }` is the only leaf that needs guest participation. It
matches a `GuestMarker` observation, or a `GuestSemanticMarker` with the same
marker name, at `t`, and only when the emitting node's `WhiteBoxPolicy` is
`Enabled`. Assertion markers (`GuestAssertionMarker`) never satisfy it. Graph
validation rejects a `GuestMarker` trigger when the world has no
white-box-enabled node (`GuestMarkerWithoutWhiteBoxOptIn`). Removing every
`GuestMarker` leaf leaves a valid graph; nothing else in the vocabulary
depends on the white-box channel.

### Combinators

`AllOf` and `AnyOf` evaluate **every** child, without short-circuiting, so a
`Once` nested anywhere in the tree latches at the first point where its child
is true even if a sibling already decided the parent. `Once` latches are keyed
by the inner predicate value: identical `Once` subtrees share one latch within
an `EventGraphState`. Empty `AllOf` and `AnyOf` are rejected at validation
(`EmptyCompound`); an empty `AllOf` would fire immediately and an empty
`AnyOf` would be dead.

### Named predicates and the DSL

A predicate in TOML may be a bare string. String predicates parse to
`Predicate::Named` and are expanded against the world before validation
(`resolve_event_graph_dsl_for_world`):

| String | Expansion |
|--------|-----------|
| `no_crashed_nodes` | `not(any_of(node_state(n, crashed) for every VM))` |
| `quiescent` | `quiescent` |
| `node_alive:<node>` | `not(node_state(<node>, crashed))` |
| `node_crashed:<node>` | `once(node_state(<node>, crashed))` |

Unrecognized names stay `Named` and are answered by the evaluator's
`ConditionLeafOracle`. The production trigger loop installs an oracle that
answers false for every named leaf, so an unknown name never fires a trigger.

## Deterministic evaluation

### The checked log prefix

Conditions see the run only through a `ConditionEventLogPrefix`, built from
scheduler event-log entries. Construction fails closed with a
`ConditionEvaluationError` when:

| Error | Cause |
|-------|-------|
| `EmptyEventLogPrefix` | no entries |
| `NonPrefixEventLogSequence` | sequences are not dense from the base |
| `InvalidEventLogEntryHash` | an entry's content hash does not match its material |
| `OutOfOrderEventLogEntry` | black-box observations regress in time |
| `FutureEventLogEntry` | an entry is later than the derived evaluation point |
| `InvalidBlackBoxObservationClass` | a black-box observation is not logged `Observational` |
| `InvalidBlackBoxObservationStamp` | its icount stamp does not match the payload |

Black-box observations are stamped consistently: coverage blocks carry their
`execution_icount` and memory samples their `sample_icount` as the retired
coordinate; console, I/O, and lifecycle observations carry their node's
boundary tick; network deliveries carry the global boundary tick. Backend
observations polled from a VM are normalized to the poll boundary
(`normalize_backend_poll_boundary`) while keeping their physical icount in the
payload, so a pulse cannot fall behind a later scheduler boundary.

The prefix exposes only observable payloads, ordering facts (resolved
happenings and delivery-order decisions), trigger firings, and armed timers.
RNG draws, host worker state, and wall-clock data are not visible to
conditions.

### Evaluation points

`EventEvaluationPoint` pairs a virtual time with an `EventEvaluationKind`:

| Kind | Source |
|------|--------|
| `Genesis` | run start; entrypoints (events with no trigger) fire here and only here |
| `EventBoundary` | any appended event-log entry other than an explicit boundary |
| `QuantumBoundary` | `SchedulerEvaluationBoundaryKind::Quantum` entry |
| `RendezvousBoundary` | `SchedulerEvaluationBoundaryKind::Rendezvous` entry |
| `AssertionDeadline` | a synthetic point derived from pending assertion obligations |

The point is derived from the last entry of the prefix, so the set of points
is a deterministic function of the log. A boundary with no canonical log entry
can be evaluated with
`ConditionEventLogPrefix::from_scheduler_event_log_entries_with_evaluation_boundary`
or `from_evaluation_boundary`, which synthesize the boundary entry for the
pass without mutating the canonical log.

### One evaluator

`ConditionEvaluator` is a sealed trait. Implementors supply only the point,
the prefix identity, leaf oracles, observation sources, quiescence, white-box
policies, symbol resolution, and `Once` latch storage. The recursion lives in
the crate-private `evaluate_condition`, which both
`ConditionEvaluationPass::evaluate_assertion_condition` and
`ConditionEvaluationPass::evaluate_event_graph` use. Neither consumer can
substitute its own combinator semantics.

### Production settlement order

`crates/crucible/crucible-daemon/src/vm_lifecycle/runtime.rs` settles the
graph at each boundary:

```text
settle_genesis_entrypoints:
  at the genesis prefix, before initial node-state observations,
  evaluate only the trigger-less events and apply their firings

settle_trigger_graph, repeated up to MAX_TRIGGER_SETTLE_BATCHES (1024):
  1. recompute the trigger wakeup and activation deadlines; install them with
     set_trigger_wakeup
  2. observe the prefix with the assertion evaluator; append any
     assertion-state observations
  3. evaluate the event graph at the frontier over the updated prefix
  4. if nothing fired and no assertion changed: done
  5. apply firings (one atomic append), then queued topology changes
exceeding the batch limit is a SchedulerError::BoundaryViolation
```

`apply_trigger_firings` refuses firings computed at a different evaluation
point, a different event-log offset, or a different armed-timer map than the
scheduler currently holds, so a stale pass cannot be applied.

### Time-leaf deadlines

Time leaves would never be observed if no log entry happened to land on their
instant, so the lifecycle projects them. `EventGraphState` provides two
projections from durable state (last firings, armed timers, latches):

- `next_evaluation_deadline` returns the next exact time transition of any
  unconsumed event, including the falling edge `t + 1` of a pulse so that
  repeatable events observe false between pulses and `Not` can activate after
  one.
- `next_activation_deadline` returns the next time at which the complete
  condition **can** be true. It ignores bookkeeping points where the whole
  condition is certainly false, so `AllOf([At(t), Quiescent])` still sees an
  idle system at `t` without the bookkeeping wakeup itself blocking
  quiescence. Observational leaves are treated as unknown.

Consumed one-shot events and latched `Once` subtrees request no wakeups. The
projection is derived state: after restore it is recomputed from the graph,
the continuation, and the timers instead of being trusted from a cache.
`set_trigger_wakeup` installs the pair as a cap on every live node, rejects a
deadline that is not strictly after the shared frontier or that a live node
has already passed, and rejects an activation without or before its wakeup.
The cap is independent of signal-fault cadence and rendezvous spacing.

A leading node can report an observation whose time is ahead of the shared
frontier. `evaluate_event_graph_at_frontier` skips any event whose trigger
contains a time leaf (`requires_global_time`) while the evaluation point is
ahead of the frontier, without consuming it, updating its edge state, or
latching anything: a single node's progress is not a global time boundary.
Purely observational triggers still evaluate at their own points.

## Events and firing

```rust
pub struct Event {
    pub id: EventId,                 // unique within the graph
    pub trigger: Option<Condition>,  // None = entrypoint fired at genesis
    pub action: Action,
    pub policy: FirePolicy,          // Once (default) | Repeatable
}
```

At each pass `EventGraphState` walks events in declared order and computes
the trigger's truth. An entrypoint's truth is "this is the genesis point".

| Policy | Fires when | Then |
|--------|------------|------|
| `Once` | truth is true and the event is not yet consumed | the event is consumed |
| `Repeatable` | truth is true and was false (or unknown) at the previous pass | the new truth is remembered |

Every fired event records its `last_firing` time (the anchor for `After`) and
produces an `EventFiring { event, at, condition_summary, action }`. An
entrypoint cannot be `Repeatable` (`RepeatableEntrypoint`).

`EventGraph::builder()` is the code-first authoring surface:

```rust
let graph = EventGraph::builder()
    .event("wait-ready")
    .when(Predicate::all_of(vec![
        Predicate::console_match(db0.clone(), RegexProgram::from_pattern("ready")),
        Predicate::once(Predicate::coverage_point(db0, CodePoint::symbol("join_done"))),
    ]))
    .action(Action::arm_timer(heal_after.clone(), thirty_seconds))
    .event("heal")
    .when(Predicate::timer(heal_after))
    .action(Action::log(LogLevel::Info, "heal window elapsed"))
    .build_for_world(&world)?;
```

`build`, `build_with_assertions`, `build_for_world`, and
`build_with_assertions_for_world` run the same validation as the matching
`EventGraph::new*` constructors.

### Continuation state

`EventGraphState` is the complete evaluator continuation and is checkpointed
in a versioned binary form:

```text
"crucible.event-graph-state.v2\0"
u64 count, then per entry: u64 len + event name        consumed_once
u64 count, then per entry: u64 len + name, u8 0|1      previous_truth
u64 count, then per entry: u64 len + name, u64 ticks   last_firing
u64 count, then per entry: u64 len + compact predicate once_latches
```

All integers are little-endian. Each count is capped at `1 << 20`, and the
decoder rejects a magic mismatch, truncation, non-UTF-8 names, duplicate
keys, invalid truth bytes, invalid predicates, and trailing bytes.

## Actions and their application

| Action | Effect in `TriggerActionState` |
|--------|--------------------------------|
| `ArmTimer { name, after }` | `armed_timers[name] = at + after`; overflow is a `BoundaryViolation` |
| `CancelTimer { name }` | removes `armed_timers[name]` (no-op when absent) |
| `StartNode { node }` | `node_states[node] = Started` |
| `StopNode { node }` | `node_states[node] = Exited` |
| `CreateSavepoint { label }` | appends a `TriggerLabelRecord` to `savepoints` |
| `Fork { label }` | appends a `TriggerLabelRecord` to `forks` |
| `Pass` | records a pass verdict unless a fail is already recorded; requests termination |
| `Fail { reason }` | records a fail verdict unless a fail is already recorded; requests termination |
| `Log { level, message }` | appends a diagnostic record |
| `Group(actions)` | applies children in declared order |

`apply_trigger_action` flattens `Group` recursively and applies each leaf
action as a `TriggerActionApplication { sequence, event, at, path, action }`,
where `sequence` is the monotone count of applications and `path` is the
zero-based index path through nested groups. All actions of one pass are
applied at the firing virtual time and committed in a single event-log
append, so no quantum intervenes between members of a group.

`StartNode` and `StopNode` schedule a node that already exists. Validation
requires a world, a declared participant, and membership in the world's bake
set (`NodeScheduleTargetRequiresWorld`, `UndeclaredNodeScheduleTarget`,
`UnbakedNodeScheduleTarget`), and application rechecks the static topology.
They never add or remove a node, change links, or alter the RNG-stream set,
lookahead graph, or bake set.

### Log records

`apply_trigger_firings` appends, in order, one `TriggerFired` entry per
firing and then one `TriggerActionApplied` entry per flattened application.
Their catalog kinds are `trigger_fired` (attributes `action`, `at`,
`condition`, `event`) and `trigger_action_applied` (`action`, `at`, `event`,
`sequence`), both causal, so they participate in replay comparison. A `Log`
application is rendered as the observational diagnostic `trigger.log` instead.
None of these is a schedule `Decision`.

The condition prefix folds these entries back in: `TriggerFired` updates the
event-firing map, and applied `ArmTimer` and `CancelTimer` update the timer
map. An offline replay of the log therefore reconstructs the same `After` and
`Timer` inputs.

## Verdict composition

`TriggerActionState::compose_run_verdict(assertions)` merges the trigger
verdict with the assertion layer's `AssertionRunVerdict`:

```text
failures = sorted assertion failures
         + the trigger verdict, if it is a fail
if failures is empty: Passed { trigger: optional pass record }
else:                 Failed { failures }
```

- A violated assertion fails the run even if a `Pass` action fired; an
  explicit pass cannot mask an assertion failure.
- A `Fail` action fails the run, and the first fail is sticky: a later
  `Pass` or `Fail` does not replace it.
- `compose_run_verdict_from_event_log` recomputes the same result from
  `TriggerActionApplied` entries alone, after rejecting any entry whose
  content hash is invalid, so online and offline verdicts agree.

Either `Pass` or `Fail` sets `termination_requested`. The daemon records the
terminal verdict from the firings (`merge_terminal_verdict`) and, once a
verdict exists, keeps the scheduler capped at the terminal point instead of
evaluating further triggers.

## Build-time validation

Every `EventGraph` constructor runs the same checks, in this order, and
returns the first failure. Iteration uses declared event order and ordered
maps and sets, so the reported error is identical on every host.

| Check | Errors |
|-------|--------|
| Event identity | `DuplicateEventId`, `RepeatableEntrypoint` |
| Trigger references | `UnknownEventReference` (`After.of`), `UnknownTimerReference` (no `ArmTimer` names the timer), `UnknownAssertionReference`, `EmptyCompound`, `InvalidRegex`, `GuestMarkerWithoutWhiteBoxOptIn`, `NodeReferenceRequiresWorld`, `LinkReferenceRequiresWorld`, `UnknownNodeReference`, `UnknownLinkReference` |
| Action references | `NodeScheduleTargetRequiresWorld`, `UndeclaredNodeScheduleTarget`, `UnbakedNodeScheduleTarget` |
| Cycles | `NonRepeatableCycle { events }` |
| Reachability | `UnreachableEvent { event }` |

Link references use the canonical endpoint-pair id from
`LinkId::for_endpoints`, independent of endpoint order.

**Cycle detection** builds a hard-dependency graph among `Once` events only.
A trigger hard-depends on: the `of` event of `After`; the sole armer of a
`Timer` (a timer with several armers is not a hard dependency); the union of
an `AllOf`'s children; the intersection of an `AnyOf`'s children; and the
child of `Once`. `Not` and every non-time leaf contribute nothing. A
depth-first search with gray and black marks reports the first back edge as
the gray stack segment, closed by the repeated event. Repeatable events are
excluded on both ends because a deliberate re-arming loop is progress, not
deadlock.

**Reachability** is a fixpoint. Each trigger is expanded into alternative
dependency sets (entrypoints have the empty set; `AnyOf` unions alternatives;
`AllOf` takes the cross product; a `Timer` alternative is "one of its
armers"). An event becomes reachable when some alternative is a subset of the
already-reachable set. Any event left over is reported.

## Serialization

The plan has a deterministic TOML form and a compact binary form; both
decode through world validation, and a decoded plan whose recomputed id
differs from the stored id is rejected. Events serialize as
`[[plan.event]]` rows with `id`, optional `trigger`, `action`, and `policy`
(default `once`); predicates and actions are tables tagged by `kind`:

```toml
[[plan.event]]
id = "pass-on-quiescence"
policy = "once"

[plan.event.trigger]
kind = "all_of"

[[plan.event.trigger.predicates]]
kind = "once"

[plan.event.trigger.predicates.predicate]
kind = "assertion_state"
name = "all-requests-succeed"
state = "satisfied"

[[plan.event.trigger.predicates]]
kind = "quiescent"

[plan.event.action]
kind = "pass"
```

Durations are exact ticks (`at_ticks`, `duration_ticks`, `after_ticks`);
frame bytes are hex strings. The full field tables are in the
[scenario reference](../../users/crucible/reference.md).

Binary payloads are prefixed with versioned magic strings: plans
`crucible.plan.v6\0`, standalone predicates `crucible.predicate.v2\0`, and
actions `crucible.action.v2\0`. Inside a payload each predicate is a one-byte
tag followed by its fields:

| Tag | Variant | Tag | Variant |
|-----|---------|-----|---------|
| 0 | `Named` | 9 | `NetworkMatch` |
| 1 | `GuestMarker` | 10 | `ConsoleMatch` |
| 2 | `AllOf` | 11 | `IoPattern` |
| 3 | `AnyOf` | 12 | `NodeState` |
| 4 | `Once` | 13 | `CoveragePoint` |
| 5 | `Not` | 14 | `MemoryPredicate` |
| 6 | `At` | 15 | `AssertionState` |
| 7 | `After` | 16 | `Quiescent` |
| 8 | `Timer` | | |

Unknown tags, malformed fields, and trailing bytes are rejected. The TOML and
binary forms of the same plan produce the same content-addressed id.

## The fault plan and deterministic injection

The event graph never mutates faults. Fault behavior is declared only in
`Plan::fault_signals`, a `FaultSignalPlan` serialized under
`fault_model = "signal_bindings_v2"` with `fault_signal_semantic_version = 2`.
Signal programs produce values; bindings map them to typed effects; adapters
apply the combined effects at deterministic opportunities. The signal and
binding model itself is documented in
[signal-driven faults](../../users/crucible/signal-driven-faults.md); this
section covers how its output is represented and injected.

### Effect kinds

`EffectKind` is a closed registry
(`.../src/model/fault_signal/effect_registry.rs`). Each entry fixes a stable
key, its adapter (`FaultAdapter::Network`, `Storage`, or `Node`), legal
target kinds, legal `FaultPhase` values, legal `EffectLifetime` values
(`Persistent`, `Opportunity`, `Impulse`, `StateMachine`), a
`CompositionAlgebra`, a capability id, and the evidence fields recorded on
replay.

| Adapter | Key families |
|---------|--------------|
| Network (31 kinds) | `network.availability`, latency and jitter, service curves and queues, `network.frame_loss`, `network.duplicate`, `network.reorder`, `network.payload_transform`, MTU, routing, firewall, shared media, contact plans |
| Storage (20 kinds) | `storage.availability`, `storage.latency`, `storage.operation_failure`, completion reorder and duplication, read and write transforms, persistence order and volatile caches, flash and array state, `ninep.result`, `ninep.visibility` |
| Node (20 kinds) | `node.lifecycle`, `node.hang`, `cpu.*`, `interrupt.*`, `memory.*`, `clock.*`, `accelerator.*` |

Overlapping contributions are combined by the entry's algebra, never by
arrival order: `OutageOr` (any outage wins), `CheckedSum` (sum in canonical
binding order, overflow is an error), `Minimum`, `RationalProduct`,
`OrderedTransform` (binding order, each intermediate digest retained),
`Severity` (closed precedence lattice), `StateMachine`, `IndependentHazards`
(every keyed hazard evaluated, any firing applies), `Conflict` (distinct
simultaneous contributions are invalid), and `Composite`.

### Exact arithmetic and seeded draws

No floating-point value appears on a determinism-relevant fault path.
`crucible_device::fault::Probability` is an exact fraction: a draw `d` fires
when `d % denominator < numerator` (a zero denominator never fires). Link loss
declared in the world is stored in millionths. Jitter and reorder shifts are
`draw % (window + 1)`, and bit-flip corruption toggles bit `draw % bits` for
each selector draw.

Every draw comes from a `DeviceRng`, a thin wrapper over the engine's
`DecisionStream`, forked by name hash from the scenario's decision-RNG root
(`DecisionRng::fork_in_domain`). Adding or renaming an unrelated device or
link does not shift another stream's draws, and the stream's draw cursor is
captured in snapshots so a restored stream resumes byte-identically.

### Host-owned effects at RESOLVE

Network and storage effects are applied by the host-side device cores in
`crucible-device` at RESOLVE, as perturbations of the modeled delivery tick
and payload rather than of host I/O. For a directed link the effective table
is `LinkFaults` (`partitioned`, `added_latency_ticks`, `jitter_window_ticks`,
`reorder_window_ticks`, `bandwidth_bits_per_sec`, `loss`, `additional_loss`,
`duplicate`, `duplicate_gap_ticks`, `corrupt`, `corruption_strategies`), and
draws are consumed in a fixed order:

```text
delivery = t_emit + effective latency (sub-floor faults clamped to the floor)
delivery += serialization delay for each bandwidth cap (exact ticks)
delivery += jitter draw, then reorder draw
drop if any loss draw fires
duplicate at delivery + duplicate_gap_ticks if the duplicate draw fires
mutate the payload if the corrupt draw fires
```

A latency-raising fault only widens lookahead; one that would lower a link
below the strictly positive minimum link latency is clamped rather than
rejected, so a fault can never collapse lookahead or break scheduler liveness.
The device cores, the floor, and the into-the-past guard are documented in
[io-subnodes.md](io-subnodes.md).

### Node effects at an exact icount

Node, CPU, interrupt, memory, clock, and accelerator effects mutate live
patched QEMU through the fault-command channel. Each command carries a
`FaultCommandHeaderV1` whose `target_icount` and
`authorization_ceiling_icount` are both set to the node's current exact
boundary; `qemu_execution_coordinate` refuses an action whose target tick is
not the current tick (`FaultRuntimeError::AdapterActionMismatch`), and QEMU
reports `PastBoundary` for a command it can no longer apply at that point.
The header also binds the command to its binding hash, opportunity hash,
expected precondition hash, and payload hash. The ring layout and header
offsets are in [shmem-abi.md](shmem-abi.md).

Commits are two-phase. A `FAULT_COMMAND_FLAG_PREPARE_ONLY` command must come
back `Prepared` with evidence whose before-state digest matches the action's
expected precondition (`ReplayPreconditionMismatch` otherwise); only then is
the mutating command issued, and its authenticated before and after digests
are retained as `CommittedQemuActionEvidence`.

`ProductionFaultActionSink` spans host and QEMU adapters for one boundary.
It prepares the complete batch before making any action visible, commits live
QEMU first, and commits the infallible host ledger only after QEMU has
acknowledged the mutation. A QEMU rejection aborts the still-hidden host
transaction; ambiguous QEMU visibility is terminal rather than being treated
as a rejection.

### Icount-stamped frame injection

Inputs that cross into a VM carry their delivery time in band. A
`FrameEntry` in a shared-memory ring holds `delivery_icount`, `src_node`, and
`seq`; `is_deliverable_at(consumer_icount)` gates visibility on
`delivery_icount <= consumer_icount`, and `FrameDeliveryKey` orders
simultaneous frames by `(delivery_icount, src_node, seq)`. Host timing can
change when a frame is written, never when the guest sees it. This is the
injection half of the determinism contract; see
[determinism.md](determinism.md).

## Verification

| Check or test | Covers |
|---------------|--------|
| `checks.crucible.phase4.sharedConditionVocabulary` | one `Predicate` type shared by assertions and triggers |
| `checks.crucible.phase4.timeConditionLeaves`, `checks.crucible.phase4.triggerRelativeTimers` | `At`, `After`, `Timer`, timer arming and cancellation |
| `checks.crucible.phase4.observableConditionLeaves`, `checks.crucible.phase4.coverageConditionLeaf`, `checks.crucible.phase4.memoryConditionLeaf`, `checks.crucible.phase4.assertionQuiescenceLeaves`, `checks.crucible.phase4.guestMarkerLeaf` | leaf semantics |
| `checks.crucible.phase4.compoundConditionCombinators` | `AllOf`, `AnyOf`, `Once`, `Not` |
| `checks.crucible.phase4.deterministicConditionEvaluation` | checked prefixes and evaluation points |
| `checks.crucible.phase4.eventGraphControlFlow`, `checks.crucible.phase4.triggerFiringCausalLog`, `checks.crucible.phase4.triggerActionApplication` | firing, causal log entries, action application |
| `checks.crucible.phase4.triggerNodeScheduling` | `StartNode` and `StopNode` on baked nodes |
| `checks.crucible.phase4.triggerGraphValidator` | reference, compound, cycle, and reachability validation |
| `checks.crucible.phase4.eventGraphSerialization`, `checks.crucible.phase4.triggerPlanLowering` | TOML and binary round trips and identity |
| `checks.crucible.phase4.triggerVerdictComposition` | trigger and assertion verdict composition |
| `checks.crucible.phase4.blackBoxFirstGuarantee` | complete scenarios without guest components |
| `checks.crucible.phase4.gates.replayOracle` | offline re-derivation of firings and verdicts |
| `checks.crucible.phase1.layer1Injection`, `checks.crucible.phase1.icountStampedInjection` | icount-stamped injection under skewed producer timing |

Rust coverage lives in `crates/crucible/crucible-engine/tests/` (for example
`event_graph_control_flow.rs`, `event_graph_serialization.rs`,
`trigger_deadlines.rs`, `trigger_wakeup.rs`,
`trigger_verdict_composition.rs`) and in
`crates/crucible/crucible-device/tests/gate_layer1_injection.rs` and
`crates/crucible/crucible-qemu-shmem/tests/icount_stamped_injection.rs`.
