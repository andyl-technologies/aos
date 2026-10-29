# Session control plane

A session is one live, controllable run. It turns the pure execution model
(see [execution-model.md](execution-model.md)) and the single authoritative
scheduler (see [scheduling.md](scheduling.md)) into something an operator, the
control API, the CLI, or an exploration driver can start, pause, step, inspect,
save, fork, and stop.

The design has one organizing idea: **the session is an actor that owns all
runtime state, and every control command and every unit of execution is
serviced on that actor's task, one bounded scheduler quantum at a time.** Pause,
step, savepoint, fork, and query are ordinary messages applied at quantum
boundaries, not operations that take a lock over a running engine. Observers
read a lock-free mirror and never enter the mailbox.

The crate is `crates/crucible/crucible-session`. It contains no raw QEMU or
shared-memory access; it drives an engine `QuantumLoop` and is generic over it,
so the same actor runs against the production QEMU loop, the in-process
`SimDouble` adapter, and test loops.

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-session/src/lib.rs` | Crate root, the `engine` re-export module consumed by control-plane clients |
| `.../session/core.rs` | Constants, `SessionDriver`, `drive_engine_quantum`, `EngineState`, `PauseReason`, `Outcome`, `StepMode`, `BreakpointSet`, step stop conditions |
| `.../session/commands.rs` | `SessionCommand`, `CommandReply`, `QueryKind`, `SessionCommandKind`, `lifecycle_transition` |
| `.../session/engine.rs` | `Engine<L>`: command application, `step_quantum`, breakpoints, boundary-control log, fork/resume, control replay |
| `.../session/engine/terminal.rs` | Terminal entry (`enter_stopped`), terminal savepoint capture |
| `.../session/actor.rs` | `SessionActor<L>`, the run loop, `SessionError`, control-log and breakpoint-firing records |
| `.../session/actor/recoverability.rs` | Which rejections keep the actor alive and which terminalize it |
| `.../session/streams.rs` | `SessionEventLog`, `SessionEventLogStream`, `SessionStateTransitionBus`, `SessionReproductionLog` |
| `.../session/exploration.rs` | `LiveSnapshot`, `EngineSnapshot`, `SessionFork`, `SessionResume`, `SessionControlReplayArtifact`, `ExplorationLifecycleDriver` |
| `.../session/debug_coordinator.rs` | Debugger roles, capabilities, and controller leases |
| `.../session/breakpoint_metadata.rs` | Data-only host predicate truths and symbol resolutions for breakpoints |
| `crates/crucible/crucible-session/src/validation.rs` | Replay and validation DAG adapters |
| `crates/crucible/crucible-engine/src/backend.rs` | `SimulationBackend`, the node-level backend contract under the scheduler |
| `crates/crucible/crucible-engine/src/scheduler/event_log.rs` | `QuantumLoop`, `QuantumRequest`, `QuantumOutcome` |

All `.../session/` paths are under `crates/crucible/crucible-session/src/`.

## Why an actor

A naive control plane for a stepping simulator holds a mutex over the engine
for the whole duration of a run command. A QEMU-backed run is seconds to
minutes of held lock, so heartbeats, status queries, and even a `pause` wait
until the run stops on its own. The control plane is unresponsive exactly when
responsiveness matters.

Crucible instead makes the session a single owning task reached only by
message. There is no shared engine to lock: `SessionActor<L>` owns the
`Engine<L>`, which owns the configuration, the cached runtime, the temporal
graph handle, the breakpoint set, the pending scheduler controls, and the
quantum loop. The same discipline is applied to the scheduler itself (one
authoritative scheduler, yielding between quanta), so state mutated on one task
has no host-thread interleaving to make nondeterministic, and a control message
is always serviced at a well-defined boundary instead of mid-quantum. The
quantum is the atomic unit of both advancement and control.

Responsiveness is therefore measured in quanta, never in wall-clock time. A
session whose acknowledgement latency is bounded in quanta is responsive by
construction regardless of how slow one quantum is on a given host.

## Lifecycle state machine

A session is always in exactly one of four run-states. The set is closed so the
transition relation can be checked exhaustively.

```text
                 Start                 Continue / Step
   +--------+  ---------->  +--------+  ------------->  +---------+
   | Loaded |               | Paused |                  | Running |
   +--------+               +--------+  <-------------  +---------+
        |                        |     Pause / breakpoint /   |
        |                        |     step complete / Fork   |
        | Stop / ExhaustBudget   | Stop / ExhaustBudget       | Stop / ExhaustBudget /
        v                        v                            v quiescence / verdict / crash
   +-------------------------------------------------------------------+
   |                    Stopped { outcome }   (terminal)               |
   +-------------------------------------------------------------------+
```

`EngineState` (`.../session/core.rs`) is the full state:

| State | Meaning |
|-------|---------|
| `Loaded` | Configuration loaded; no runtime instantiated yet |
| `Running` | The actor is stepping bounded scheduler quanta |
| `Paused { reason: PauseReason }` | Idle at a quantum boundary |
| `Stopped { outcome: Outcome }` | Terminal |

A pause carries a resumable cause and a terminal state carries a final outcome.
They are distinct types and never substitute for each other.

| `PauseReason` | Produced by |
|---------------|-------------|
| `Instantiated` | `Start`, and every resumed or forked child actor |
| `UserRequested` | `Pause`, and a `Fork` serviced while `Running` |
| `Breakpoint { id }` | A `Suspend` breakpoint firing |
| `StepComplete { mode }` | A bounded `Step` reaching its stop point |

| `Outcome` | Produced by |
|-----------|-------------|
| `Passed` | Scheduler-observed continuous quiescence, a `Pass` terminal verdict, or a `Pass` breakpoint action |
| `Failed { violations }` | A `Fail` terminal verdict or `Fail` breakpoint action; violations are deterministic strings |
| `Timeout` | `ExhaustBudget` (the execution budget was observed exhausted) |
| `Crashed { detail }` | A backend failure while driving a quantum, or an autonomous actor error |
| `Stopped` | Operator `Stop` |

Quiescence stops a run only when no step is active and no breakpoints are
registered (`stop_on_continuous_quiescence`); with a breakpoint armed the run
keeps stepping so the predicate can still fire.

`LifecycleStateKind`, `PauseReasonKind`, and `OutcomeKind` are payload-free
mirrors of these enums with `ALL` constants, used by the transition model and by
the lock-free mirror.

### Terminal entry

Every path into `Stopped` goes through `Engine::enter_stopped`
(`.../session/engine/terminal.rs`). It asks the quantum loop to prepare a
terminal checkpoint for the cause, saves the current boundary as a checkpoint
through the temporal graph, and only then shuts the quantum loop down. The
ordering matters: a production checkpoint needs live, quiesced QEMU processes,
so the resumable boundary is captured before teardown, and shutdown observations
belong to the terminal session record rather than the checkpoint. The saved
checkpoint becomes `EngineSnapshot::terminal_savepoint` and is mirrored into the
live snapshot. Debugger attachment state is dropped on entry.

## The command set

Every interaction with a session is a `SessionCommand` (`.../session/commands.rs`)
sent to the actor's `mpsc` mailbox. The set is closed.

| Command | Effect |
|---------|--------|
| `Start` | Instantiate the loaded configuration; `Loaded -> Paused(Instantiated)` |
| `Continue` | `Paused -> Running`; clears any active step |
| `Pause` | `Running -> Paused(UserRequested)` at the current boundary |
| `Step { mode }` | Start a bounded step (see below); the actor runs until the stop point |
| `SetBreakpoint { spec, reply }` | Register a breakpoint; replies with its `BreakpointId` |
| `RemoveBreakpoint { id, reply }` | Remove a breakpoint; `BreakpointNotFound` if absent |
| `CreateSavepoint { label, reply }` | Save the current boundary; replies with `SavepointInfo` |
| `Fork { from, reply }` | Fork a child session from `CheckpointRef::Current` or a recorded checkpoint |
| `Stop` | Operator stop; terminal `Stopped` |
| `ExhaustBudget` | Terminal `Timeout` after an observed budget exhaustion |
| `Query { kind, reply }` | Read boundary state (`QueryKind` below) |
| `AttachGdb`, `DebugGoto`, `DebugReverseStep`, `DebugReverseContinue` | Debugger attach and repositioning |
| `DebugForkNonCanonical` | Mark further forward or mutating debugger use as a non-canonical branch |
| `GuestIntrospection` | Exchange one bounded record with a white-box node's debug guest agent |
| `Acknowledge { command, reply }` | Apply the inner command and reply with actor-level completion |

Commands that produce a value carry a `CommandReply<T>`, a oneshot wrapper
fulfilled by the actor, so the caller never touches session state. The reply
route is deliberately excluded from command equality and hashing: it routes
completion but is not model state. `CommandReply::with_observation` lets a
caller hold the actor until it has consumed the reply (dropping the signal also
releases it, so a cancelled client cannot wedge the actor); this is a local
scheduling handoff and changes no result or encoding.

`QueryKind` covers `Snapshot` (a full `EngineSnapshot`), `BreakpointFirings`,
`State`, `EventLogLength`, `SearchFrontier`, `ResolvedEffectTrace`,
`ExecutionFingerprint { node }`, and `DebugOperatorEndpoint`. The latter four
read from the quantum loop at the boundary.

Faults are not imperative session commands. The admitted fault plan is part of
scenario identity and its bindings act at deterministic adapter opportunities;
changing it creates a new scenario or fork. See the signal-driven fault pages
for that model.

### Command kinds and the transition model

`SessionCommandKind` is the payload-free projection used by the lifecycle
model. It splits `Step` by mode, so it has 21 kinds (`SessionCommandKind::ALL`).
`lifecycle_transition(state, command)` is a pure, total `const fn` over
(`LifecycleStateKind`, `SessionCommandKind`) that returns either
`Accepted { to }` or `Rejected`. It is the command-kind lifecycle model that the
API uses to pre-screen commands and that tests check exhaustively.

| From \ command | `Start` | `Continue` | `Pause` | `Step*` | `Stop`, `ExhaustBudget` | set/remove bp | `CreateSavepoint` | `Fork` | `Query` | debugger commands |
|---|---|---|---|---|---|---|---|---|---|---|
| `Loaded` | Paused | reject | reject | reject | Stopped | Loaded | reject | reject | Loaded | reject |
| `Running` | reject | reject | Paused | Running | Stopped | Running | Running | Paused | Running | Paused (`GuestIntrospection`: Running) |
| `Paused` | reject | Running | Paused | Running | Stopped | Paused | Paused | Paused | Paused | Paused |
| `Stopped` | reject | reject | reject | reject | reject | reject | reject | Stopped | Stopped | reject |

A running `Fork` first pauses at the boundary and then forks. A `Fork` from a
stopped session forks from its final boundary. `Stopped` accepts only `Fork`
and `Query`.

### Rejection

`Engine::apply_command` rejects an inapplicable command with a typed
`SessionError` (for example `InvalidTransition { state, command }`) and leaves
the engine state unchanged; there is no partial application. Any reply carried
by the command is completed with the same error.

Whether the actor survives a rejection depends on how the command arrived
(`.../session/actor/recoverability.rs`):

- A rejected `Acknowledge`-wrapped command, a rejected debugger command, or a
  reverse operation that reaches unavailable pre-resume history is recoverable:
  the caller gets the typed error and the actor keeps running. The control API
  wraps every dispatched command in `Acknowledge`, so API rejections never stop a
  session.
- Engine-driven failures (`Scheduler`, event-log offset mismatches, breakpoint
  evaluation failures, debugger reposition mismatches) are autonomous: the actor
  terminalizes the session as `Crashed` and publishes the final mirror.
- Any other error returned while applying a bare command ends `SessionActor::run`
  with that error.

## The actor loop

`SessionActor::run` (`.../session/actor.rs`) loops on the engine state:

```text
loop:
  Stopped  -> serve terminal commands (Fork, Query), then return SessionRunReport
  Running  -> 1. service a pending debugger run-control packet, if any
              2. try_recv one mailbox command; if present, apply it and loop
              3. otherwise step exactly one quantum:
                   drive_quantum -> append emitted entries -> evaluate breakpoints
                   -> sync reproduction log -> poll guest activation
                   -> stop on continuous quiescence -> publish live snapshot
              4. tokio::task::yield_now
  Loaded,
  Paused   -> await the mailbox (with a 10 ms timeout used only to poll
              debugger run-control packets) and apply the command
```

Invariants:

- In `Running`, a pending command always wins over stepping, and at most one
  command is applied per iteration, so a busy scheduler cannot starve control.
  A pause or stop is at most one quantum away.
- One iteration drives at most one scheduler quantum. The sole call into the
  engine loop is `drive_engine_quantum` (`.../session/core.rs`); the session owns
  no other backend-advancement API.
- The actor calls `tokio::task::yield_now` after every applied command or
  scheduler quantum, so one session never monopolizes its runtime thread.
- In `Loaded` and `Paused` the actor blocks on the mailbox: no spin, no held
  lock.
- In `Stopped` the actor drains already-queued terminal-accepted commands and
  rejects the rest. With `with_terminal_command_keepalive(true)` it instead keeps
  serving `Fork` and `Query` until it receives an acknowledged `Stop`; the
  control server enables this when it is configured to retain stopped sessions
  for observation until they are destroyed.

`SessionRunReport` returns the final `EngineSnapshot`, the number of applied
commands, the number of quanta, and the number of quanta after which the actor
yielded.

Each quantum validates the scheduler's event-log offsets: an offset older than
the session mirror is `EventLogOffsetRegression`, and one that disagrees with
the emitted entry count is `EventLogOffsetMismatch`. Both are autonomous errors
that crash the session rather than silently diverging the observable log.

## Step modes

`Step { mode }` advances a bounded amount and then pauses with
`PauseReason::StepComplete { mode }`. Each mode resolves to a deterministic stop
point in scheduler terms, so a step lands at the same configuration on every
host.

| `StepMode` | Completes when the quantum's emitted entries include |
|------------|-------------------------------------------------------|
| `Quantum` | Any quantum (always after one) |
| `Event` | A resolved external event: a `BackendInput` or `IoCompletion` happening, or an observable `NetworkDelivered` / `IoCompletion` (`entry_is_resolved_external_event`) |
| `Assertion` | An `AssertionStateChanged` observable (`entry_is_assertion_state_change`) |
| `Timer` | A trigger firing whose condition summary contains the `predicate=timer` line (`entry_is_timer_fire`, `condition_summary_is_timer_fire`) |
| `Duration(SimDuration)` | The scheduler frontier reaching `start + duration` |

The step is built on the breakpoint primitive. `ActiveStep::new(mode, frontier)`
creates a one-shot `Suspend` breakpoint over a stop `Condition`: a
`Condition::Named` leaf (`session.step.quantum`, `session.step.event`,
`session.step.assertion`, `session.step.timer`) answered by a
`StepConditionLeaves` oracle, or `Condition::At { at: target_frontier }` for
`Duration`. Applying the command records it and installs
`self.active_step = Some(ActiveStep::new(*mode, self.frontier));`.

`Duration` completion compares the authoritative cross-node scheduler frontier
(`outcome.frontier >= target`). An individual event or node timestamp at the
target does not complete the step while the global frontier is still behind it.

A step only ever advances by bounded quanta through the ordinary loop, so it is
interruptible: `Pause` and `Stop` clear the active step at the next boundary.
`StepMode::reverse_grain` maps each forward mode except `Duration` to its
`DebugReverseStepGrain`.

## Boundary-deferred application

A command that arrives while `Running` cannot apply mid-quantum: that would put
a mutation at a host-timing-dependent point. Because the actor only reads its
mailbox between quanta, every command takes effect at a quantum boundary, which
is a deterministic position in virtual time. The operator's wall-clock moment of
issuing the command does not matter; only the boundary does.

Commands that steer execution are recorded in the session's
**boundary-control log** (`Engine::boundary_control_log`), one
`SessionControlLogEntry` per command:

```rust
pub struct SessionControlLogEntry {
    pub sequence: u64,                     // contiguous from 1
    pub command: SessionCommandKind,
    pub payload: SessionControlPayload,    // reply-free payload
    pub frontier: VirtualTime,             // boundary where it applied
    pub quanta: u64,                       // quanta completed before it applied
    pub event_log_sequence_before: u64,    // causal prefix visible to it
    pub result: SessionControlResult,      // Accepted
    pub scheduler_batch: u64,              // 0 when no scheduler payload
    pub scheduler_control: Option<ControlOperationKind>,
}
```

The entry is keyed by `frontier: self.frontier` and `quanta: self.quanta`,
never by host time. Which applications are recorded:

| Command | Recorded when |
|---------|---------------|
| `Step`, `Stop`, `ExhaustBudget` | Always |
| `Continue` | Once at least one quantum has run |
| `Pause`, `Fork`, `SetBreakpoint`, `RemoveBreakpoint`, `CreateSavepoint`, `Query` | Only when applied while `Running` |

Breakpoint edits, savepoints, and queries applied while paused land at a
boundary where nothing is advancing and are not recorded.

A `Query` issued while `Running` is additionally admitted to the scheduler as a
`ControlOperationKind::Query` control operation carried into the next quantum.
The scheduler resolves it from its `control-plane` scheduling node within
`SCHEDULER_CONTROL_RESPONSE_BOUND_QUANTA` (one quantum), and the log entry
carries that scheduler control under a scheduler batch so replay re-applies it
at the same boundary. Breakpoint actions that plan scheduler controls go
through `apply_control_operations_at_boundary`, which calls
`QuantumLoop::apply_control_at_boundary` immediately at the boundary.

`Pause` and `Stop` change only whether the loop steps. They take effect at the
next boundary check without an extra quantum; `Stop` also clears pending
controls and shuts the quantum loop down through terminal entry.

## Breakpoints

A breakpoint is a shared `Condition` plus a disposition and a fire policy:

```rust
pub struct BreakpointSpec {
    pub predicate: Condition,
    pub disposition: BreakpointDisposition, // Suspend | Trace | Action(Action)
    pub policy: BreakpointPolicy,           // OneShot | Repeatable (default OneShot)
}
```

The predicate is the same `Condition` vocabulary that triggers and assertions
consume (see [conditions-and-triggers.md](conditions-and-triggers.md)), not a
breakpoint-only language. Every leaf and combinator is available: `At`,
`After`, `Timer`, `NetworkMatch`, `ConsoleMatch`, `CoveragePoint`,
`MemoryPredicate`, `IoPattern`, `NodeState`, `AssertionState`, `Quiescent`,
`Named`, `GuestMarker`, `AllOf`, `AnyOf`, `Once`, and `Not`. An operator can stop
when a node starts, crashes, or exits, or the instant an assertion flips,
without breakpoint-specific cases.

`BreakpointSet` is actor-owned. It stores each spec with its last truth value
and its `Once` latches and hands out monotone `BreakpointId` values.

Evaluation (`Engine::evaluate_breakpoints`) runs after each quantum's entries are
appended. It builds a checked event-log prefix and evaluates each predicate with
a `ConditionEvaluationPass` seeded from data only: host predicate truths and
resolved code points and memory places from `BreakpointHostMetadata`, the
node white-box policies, and the scheduler quiescence observation. No wall
clock, live process state, or unordered host callback can enter evaluation, so
evaluation is a pure function of the log prefix.

A breakpoint fires on a false-to-true transition of its predicate:

| Disposition | Effect at the firing boundary |
|-------------|-------------------------------|
| `Suspend` | `Running -> Paused(Breakpoint { id })`; clears any active step |
| `Trace` | Records the firing and keeps running |
| `Action(action)` | Applies a terminal verdict and keeps or ends the run |

`Action` dispositions support only terminal verdicts: `Action::Pass`,
`Action::Fail { reason }`, and `Action::Group` of those. Groups are prevalidated
before any control is applied; any other action (`ArmTimer`, `StartNode`,
`CreateSavepoint`, `Fork`, `Log`, ...) is rejected as
`UnsupportedBreakpointAction`. A `Fail` stops the session as `Failed`, a `Pass`
as `Passed`.

`OneShot` breakpoints are removed after their first firing; `Repeatable` ones
keep their latches and fire on each new false-to-true transition. Every firing
is appended to a deterministic `BreakpointFiring` record (sequence, id,
predicate, disposition, frontier, quanta, scheduler controls), readable with
`QueryKind::BreakpointFirings`.

Setting, removing, or firing a `Suspend` or `Trace` breakpoint does not change
the configuration, the schedule, or the causal event log; it only decides where
the actor stops stepping.

## Save, resume, and fork

The session implements none of these as bespoke realization logic. Each is a
call into the temporal graph (see [execution-graph.md](execution-graph.md)),
and start, resume, and fork all end in the same `instantiate` of a
configuration.

- **Savepoint.** `CreateSavepoint` calls `save_current_checkpoint`, which runs
  `self.graph.save_checkpoint(&self.configuration)?`, stamps the boundary's
  virtual time, and attaches the quantum loop's captured execution closure when
  the loop produces one. It replies with `SavepointInfo { label, configuration,
  checkpoint }`. Valid in `Running` and `Paused`.
- **Start.** `instantiate_runtime` realizes the loaded configuration with
  `self.graph.resume(&self.configuration)?.runtime` and lands in
  `Paused(Instantiated)`.
- **Resume.** `Engine::resume_session_from_checkpoint` resolves the checkpoint
  record and its recorded configuration, realizes it through
  `self.graph.resume_checkpoint(checkpoint)?`, and builds an independent
  `SessionActor` with `from_realized_checkpoint`, already paused with
  `reason: PauseReason::Instantiated`. A resumed session is not a special
  restored object; it is an ordinary session at the checkpoint's recorded
  configuration and frontier.
- **Fork.** `fork_child` records a branch with `TemporalGraph::fork` (base plus
  appended decisions) and builds a paused child actor. `fork_child_from_checkpoint`
  and the `Fork` command use `build_checkpoint_child`, which records the fork
  with `self.graph.fork(&base, std::iter::empty::<Decision>())?` and an empty
  schedule delta. Direct forks require the parent to be `Paused` or `Stopped`
  (`operation: "fork_child_from_checkpoint"` on rejection); the command form
  first pauses a running parent.

A forked or resumed child is an independent actor with its own mailbox
(`SESSION_FORK_MAILBOX_CAPACITY`, 8), live snapshot, lifecycle, and engine
clone. Copy-on-write sharing lives in the content-addressed store; mutating the
child never affects the parent.

When an actor is built with `SessionActor::new_with_fork_loop_factory`, the
`Fork` command is intercepted by `apply_spawned_fork_command`: the source
checkpoint is resolved first, the factory receives a `SessionForkRequest { id,
checkpoint, configuration }` and returns the child's `QuantumLoop`, and the child
is started with `tokio::spawn(async move { ... run_leaf_child() })`. The reply
`SessionHandle` carries a `SessionChildHandle` (mailbox sender and live
snapshot). Leaf children run without spawning further forks, so the exploration
tree stays bound to canonical replay rather than free-running processes. Without
a factory, `Fork` only resolves the checkpoint and replies with a handle that has
no child transport.

## Determinism of control operations

An interactive run is still `reduce(ScenarioDef, Schedule)`. Two rules keep
operator control reproducible.

**Mutating control is recorded by boundary.** Every command applied while the
session is running is logged with its virtual-time frontier, quantum count,
event-log prefix, and any scheduler control batch. Replaying that log at the
same boundaries, at any speed on any host, reproduces the run.

**Control introduces no nondeterminism.** Commands only take effect at quantum
boundaries, which are pure functions of virtual time, so the wall-clock moment
an operator acts cannot influence state. Lock-free mirror reads and paused
queries touch nothing at all.

`Engine::control_replay_artifact` packages the evidence as a
`SessionControlReplayArtifact { initial_configuration, final_snapshot,
control_log }`. `Engine::replay_control_replay_artifact` (and the
`SessionActor::with_control_replay_artifact` constructor) replays it on a fresh
`Loaded` engine:

1. Reject a different initial configuration
   (`ControlReplayInitialConfigurationMismatch`) or a non-fresh engine.
2. Validate records up front: sequences contiguous from one, every result
   `Accepted`, scheduler batches either zero with no control or contiguous and
   shared only by entries at the identical boundary (`ControlReplayRecordInvalid`,
   `ControlReplayBatchMismatch`).
3. `Start`, `Continue`, then step quanta, applying every record whose `quanta`
   equals the current count. A record behind the replay position is
   `ControlReplayBoundaryMismatch`; a different frontier is
   `ControlReplayFrontierMismatch`; a different event-log boundary is
   `ControlReplayRecordInvalid`. Scheduler controls of one batch are applied
   together with `self.apply_control_operations_at_boundary(controls)?;`.
4. Compare the replayed snapshot with the recorded one
   (`ControlReplayFinalSnapshotMismatch`).

The `..._with_terminal_fingerprints` variant samples backend fingerprints at the
paused boundary immediately before a final recorded `Stop`, because the stop
retires the backend.

The same control log is exposed to API clients as the reproduction context; see
[control-api.md](control-api.md#reproduction-context).

## Lock-free observation

Observers (status queries, the API's `Watch` stream, CLI status lines,
exploration progress) sample the run without entering the stepping path.

### `LiveSnapshot`

`LiveSnapshot` (`.../session/exploration.rs`) is a struct of atomics written
only by the actor and read by anyone holding an `Arc`:

```rust
pub struct LiveSnapshot {
    epoch: AtomicU64,                       // seqlock: odd while writing
    state_kind: AtomicU8,                   // LiveStateKind: 1..=4
    outcome_kind: AtomicU8,                 // 0 = none, 1..=5 OutcomeKind
    terminal_savepoint_present: AtomicU8,
    terminal_savepoint_words: [AtomicU64; 4],
    configuration_words: [AtomicU64; 4],    // ContentHash, big-endian words
    virtual_time_ticks: AtomicU64,
    event_log_len: AtomicU64,
    quanta_stepped: AtomicU64,
    control_acknowledgements: AtomicU64,
    state_transition_sequence: AtomicU64,
}
```

The actor's `publish` sets `epoch` to an odd value, stores every field with
`Ordering::Release`, then stores the next even epoch. `read()` loads the epoch,
all fields, and the epoch again with `Ordering::Acquire`, and retries until both
epoch loads are equal and even. A reader therefore never observes a torn
snapshot, and there is no path by which an observer can write. The actor
publishes after every quantum and every applied command, so the mirror is never
more than one boundary stale.

`LiveSnapshotView` is the copy-out view (`state_kind`, `outcome`,
`terminal_savepoint`, `configuration`, `virtual_time`, `event_log_len`,
`quanta_stepped`, `control_acknowledgements`, `state_transition_sequence`).
`LiveSnapshot::query(LiveQueryKind)` answers `Status`, `State`, and
`EventLogLength` from one `read()` without the mailbox. `SessionActor::live_status`
is `self.live.read()`.

### Event-log stream

`SessionEventLog` (`.../session/streams.rs`) is the session-owned event-log hub.
It retains appended entries behind a short-lived mutex (never held across a
quantum) and fans each appended entry out on a `broadcast` channel of
`SESSION_EVENT_LOG_BROADCAST_CAPACITY` (1024) frames. A subscriber's
`SessionEventLogStream` is cursor based:

1. `subscribe_with_replay_tail(cursor)` subscribes to the broadcast first, then
   captures the current tail. The stream replays retained entries from the
   cursor up to that tail in batches of `SESSION_EVENT_LOG_REPLAY_BATCH_SIZE`
   (64), then delivers the live tail. A cursor beyond the tail skips replay.
2. Frames already delivered by replay are suppressed when they reappear on the
   broadcast, so the subscriber sees each sequence once and in order.
3. A subscriber that lags the bounded broadcast tail calls
   `resume_from_retained_log()` and continues from the retained log at its
   cursor; lag never back-pressures the actor.
4. Debug repositioning can truncate the retained log. Truncation bumps a
   generation counter; streams adopt the new generation and rewind their cursor
   to the truncation point. Each `SessionEventLogFrame` carries `generation`,
   `cursor`, `next_cursor`, and the full `SchedulerEventLogEntry`.

`snapshot_through(cursor)` folds the retained prefix into a
`SessionEventLogSnapshot` (`through`, `event_count`, `causal_count`,
`observational_count`, `last_sequence`) for snapshot-on-attach. Subscribing
never enqueues a session command or awaits the scheduler.

### State-transition bus

`SessionStateTransitionBus` broadcasts `SessionStateTransitionFrame { sequence,
from_state, to_state, from, to }` with a capacity of
`SESSION_STATE_BROADCAST_CAPACITY` (256). Each frame carries the full
`EngineState` before and after and the matching `LiveSnapshotView`s. Run-state
changes are not event-log entries, so they travel on this separate bus.
`SessionStateTransitionStream::recv_latest` coalesces a lagged tail to its
newest frame and enforces a monotone sequence floor; `set_sequence_floor` lets an
attach snapshot suppress transitions it already represents.

### Exploration lifecycle polling

`ExplorationLifecycleDriver` issues `Pause`, `Resume` (`Continue`), and `Stop`
for exploration drivers and polls the mirror for acknowledgement within
`EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA` (1) quantum and at most
`EXPLORATION_LIFECYCLE_MAX_ACTOR_YIELDS` (128) actor yields.

## Debugger commands

The debugger vocabulary is session-level, so the gdb relay and the CLI `debug`
command are thin wrappers over it. `AttachGdb`, `DebugGoto`, `DebugReverseStep`,
and `DebugReverseContinue` are observation-only (`SessionCommand::is_read_only`):
they reposition over checkpoint restore plus deterministic replay and do not
enter the schedule. After a reposition, forward or mutating commands
(`Continue`, `Step`, `SetBreakpoint`, `RemoveBreakpoint`, `GuestIntrospection`)
are rejected with `DebugNonCanonicalBranchRequired` until a
`DebugForkNonCanonical` marks the branch as non-canonical. `DebugCoordinator`
owns debugger roles (`DebugCapability`: `Observe`, `Control`, `Mutate`, `Shell`,
`Admin`) and the exclusive controller lease. The mechanism is described in
[time-travel-debugging.md](time-travel-debugging.md).

## Backends

The session never names a QEMU type. It is generic over the engine's
`QuantumLoop` (`drive_quantum`, `apply_control_at_boundary`, `capture_checkpoint`,
`prepare_terminal_checkpoint`, `shutdown`, fingerprint and debugger hooks), and
the scheduler beneath it drives nodes through the `SimulationBackend` trait
(`crates/crucible/crucible-engine/src/backend.rs`). The core of that trait:

```rust
pub trait SimulationBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError>;
    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError>;
    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError>;
    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError>;
    fn now(&self) -> VirtualTime;
    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError>;
    fn shutdown(&mut self) -> Result<(), BackendError>;
    // plus defaulted capabilities: step_node_to, admission-based RUNs,
    // input staging, I/O inventory, open_gdbstub, guest introspection, ...
}
```

The scheduler remains the only timing authority: callers pass a virtual-time
ceiling and backends report what they observed, without choosing cross-node
order, evaluating properties, or advancing time on their own. Backend objects
are owned by the session actor that drives them, so no `Send` bound is required;
concrete QEMU adapters may wrap thread-affine channel and process-runtime
handles. Optional capabilities default to `BackendError::Unsupported`;
`open_gdbstub` in particular must refuse rather than fake an endpoint, so a
debug session always knows whether a node is gdb-attachable.

Three kinds of backend satisfy the same contract:

| Backend | Where | Use |
|---------|-------|-----|
| Production QEMU loop | `crucible-qemu-host`, composed by `crucible-daemon` | Fidelity |
| `SimDouble` | `crates/crucible/crucible-engine/src/sim_backend.rs` | In-process plugin-side double using the real shmem layout, SPSC queues, and control codec, with synthetic guest behavior |
| `MockSimulationBackend` | `crates/crucible/crucible-engine/src/backend/mock.rs` | State-machine tests; compiled only for tests or the `test-double` feature |

Because the control plane is defined against these traits, its gates run
against the double. `crates/crucible/crucible-session/tests/gate_control_responsive.rs`
declares `CONTROL_RESPONSIVE_BACKEND` as the `SimDouble` quantum-loop adapter and
`CONTROL_RESPONSIVE_REQUIRES_REAL_QEMU = false`; only the fidelity properties
`contract-a`, `guest-non-mutation`, and `patch-inertness` require QEMU. A session
test that needs real QEMU to exercise the control plane, as opposed to guest
fidelity, is a design defect.

## Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `SESSION_EVENT_LOG_BROADCAST_CAPACITY` | 1024 | Live event-log broadcast frames |
| `SESSION_EVENT_LOG_REPLAY_BATCH_SIZE` | 64 | Retained frames cloned per replay batch |
| `SESSION_STATE_BROADCAST_CAPACITY` | 256 | Live state-transition frames |
| `SESSION_FORK_MAILBOX_CAPACITY` | 8 | Mailbox of a forked or resumed child |
| `EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA` | 1 | Exploration lifecycle acknowledgement bound |
| `EXPLORATION_LIFECYCLE_MAX_ACTOR_YIELDS` | 128 | Exploration acknowledgement polling budget |

## Tests

| Check or target | Guards |
|-----------------|--------|
| `checks.crucible.phase5.sessionActor`, `sessionLifecycle`, `sessionCommandSet` | Actor ownership, the closed state and command sets, `lifecycle_transition` totality |
| `checks.crucible.phase5.sessionStepModes` | Step stop points and interruptibility |
| `checks.crucible.phase5.sessionBoundaryControl` | Boundary-control log fields and boundary-only application |
| `checks.crucible.phase5.sessionBreakpoints` | Predicate vocabulary, dispositions, policies |
| `checks.crucible.phase5.sessionSaveResumeFork` | Graph-delegated savepoint, resume, and fork |
| `checks.crucible.phase5.sessionControlDeterminism` | Control replay artifacts and their guards |
| `checks.crucible.phase5.sessionLockFreeObservation` | The seqlock mirror, broadcast capacities, lag recovery |
| `checks.crucible.phase5.sessionSimulationBackend`, `sessionSimDoubleSuite` | The backend trait and double-only control-plane testing |
| `checks.crucible.phase5.sessionDebugTimeTravel` | Debugger commands at the session layer |
| `crates/crucible/crucible-session/tests/gate_control_responsive.rs` | `gate:control-responsive`: mailbox-free live progress and quantum-bounded acknowledgement |

See [testing-and-gates.md](testing-and-gates.md) for the gate catalog.
