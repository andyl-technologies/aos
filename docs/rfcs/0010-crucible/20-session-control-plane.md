# 20 — Session control plane: the session-as-actor

This file specifies the **session**: the control plane that turns the pure
execution model (05) and the single authoritative scheduler (08) into a *live,
controllable run* an operator (or the API in 21, the CLI in 23, or a search
driver in 22) can start, pause, step, inspect, fork, and stop. It is the L4
component named in the layer map (README, 27) — `crucible-session` — and the
boundary across which every interactive and programmatic interaction with a
running scenario flows.

Where 05 gives the algebra (`Configuration` / `step` / `instantiate` / `bake`),
07 gives the recorded graph (the checkpoint DAG), and 08 gives the one scheduler
that advances virtual time, **this file gives the actor that owns them at runtime
and the command vocabulary that drives them.** It satisfies the responsiveness
half of [INV-8] (single authoritative scheduler, yielding between quanta, no
long-held locks) and is the L4 realization of the `Engine` async state machine
sketched in 05 §10. Requirement IDs here use the prefix `SESS`.

The design has one organizing idea, stated once: **the session is an actor that
owns all runtime state and processes every control command and every unit of
execution as a queued message, stepping in bounded quanta and yielding between
them.** That single decision is what makes pause/resume/step/inject ordinary
queued commands serviced at well-defined quantum boundaries instead of
mutex-held-for-seconds operations — which is exactly the `gate:control-responsive`
property. Everything else in this file follows from it.

Forward and cross references: the execution model is
[`05-execution-model.md`](05-execution-model.md); the temporal graph is
[`07-temporal-graph.md`](07-temporal-graph.md); the scheduler this session drives
is [`08-scheduling.md`](08-scheduling.md); faults are
[`17-fault-injection.md`](17-fault-injection.md); assertions are
[`18-assertions-properties.md`](18-assertions-properties.md); the event log this
session appends to and broadcasts is `19-observability-event-log.md` (the
canonical/observational distinction it owns); the programmatic API that wraps
this control plane is `21-api.md`; advanced features (fork-driven search,
fuzzing) built on these commands are
[`22-advanced-features.md`](22-advanced-features.md); the gates are
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

---

## 1. Why session-as-actor: the anti-pattern this design deletes

The naïve control plane for a stepping simulator holds a mutex over the engine
for the entire duration of a run command. `resume()` takes the lock, runs the
scheduler until it pauses, and releases the lock — and a QEMU-backed run is
*seconds to minutes* of held lock. Any observer that wants to read "where are we
now?" must take that same lock, so heartbeats, live queries, and the UI see
nothing until the command returns. Worse, a `pause` request *also* needs the
lock, so the only way to stop a run is to wait for it to stop on its own. The
control plane is unresponsive precisely when responsiveness matters.

Crucible refuses this. The session is an **actor**: a single task that owns all
mutable runtime state and is reached *only* by message. There is no shared mutex
over the engine, because there is no shared engine — there is one task that owns
it. Control operations (pause, resume, step, inject, fork, save, query) are
**messages enqueued to the actor's mailbox**; execution is the actor stepping the
scheduler **one bounded quantum at a time** and checking its mailbox between
quanta. A pause is just a message the actor reads at the next quantum boundary —
which is at most one quantum away ([SESS-3], `gate:control-responsive`). State an
observer needs is mirrored lock-free ([SESS-12]) so reads never enter the
mailbox at all.

- **[SESS-1]** The session MUST be realized as an **actor**: a single owning task
  that holds all mutable runtime state (the `Engine` of 05 §10, the scheduler of
  08, the temporal-graph handle of 07, the breakpoint set, the event-log writer)
  and is mutated *only* on that task. No other component may mutate session-owned
  state by shared reference; all interaction is by message ([SESS-7]). There MUST
  NOT be a long-held lock guarding the engine across a run. *Gate:*
  `gate:control-responsive`, `gate:scheduler-liveness`. *Spec:* §1, §3; routes
  [INV-8].

- **[SESS-2]** The session MUST advance execution in **bounded quanta** (one
  scheduler `STEP` of 08, or a small fixed budget of them) and MUST poll its
  command mailbox between consecutive quanta. The actor MUST NOT execute an
  unbounded run without returning to the mailbox; "run to completion" is
  implemented as repeated bounded quanta with inter-quantum mailbox polls, not as
  one uninterruptible call. *Gate:* `gate:control-responsive`,
  `gate:scheduler-liveness`. *Spec:* §3; cross-ref 05 [EXEC-28], 08 [SCHED-3].

- **[SESS-3]** A control command enqueued while the session is `Running` MUST take
  effect at the **next quantum boundary** and MUST be acknowledged within a
  bounded number of quanta. The bound MUST be expressed and measured in **quanta,
  never wall-clock** (per [HARN-2]/[HARN-19]); a session whose acknowledgement
  latency is bounded in quanta is responsive by construction regardless of how
  slow a single quantum is on a given host. *Gate:* `gate:control-responsive`.
  *Spec:* §1, §3; routes [INV-8].

---

## 2. The lifecycle state machine

A session is at all times in exactly one of four run-states:
**Loaded → Running ↔ Paused → Stopped**. `Loaded` is the freshly-constructed
session whose configuration is set but whose runtime is not yet instantiated.
`Running` is actively stepping the scheduler in bounded quanta. `Paused` is at a
quantum boundary, idle, waiting on the mailbox — the state in which inspect,
step, fork, and save are valid. `Stopped` is terminal. The state machine is small
on purpose: a closed set of states with a closed set of transitions is what makes
"no command sequence can wedge it" provable ([SESS-6]).

```text
                 instantiate            continue / step
       ┌─────────┐  (05 §5)   ┌─────────┐  ────────────►  ┌─────────┐
       │ Loaded  │ ─────────► │ Paused  │  ◄────────────  │ Running │
       └─────────┘            └────┬────┘   pause/bp/step └────┬────┘
                                   │  complete                 │
                          stop     │                  stop /   │  quiescence /
                          (user)   ▼                  outcome  ▼  violation / timeout
                              ┌──────────────────────────────────┐
                              │            Stopped { outcome }    │  (terminal)
                              └──────────────────────────────────┘
```

The pause carries a **reason** (why we stopped stepping) and the terminal state
carries an **outcome** (how the run ended). These are distinct: a reason is a
resumable cause, an outcome is final.

```rust,illustrative
/// The session run-state. A closed set of states; transitions are the only
/// points at which control operations take effect (05 §10, [SESS-2]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Configuration loaded, runtime not yet instantiated (05 §5).
    Loaded,
    /// Actively stepping the scheduler in bounded quanta (08), polling the
    /// mailbox between quanta ([SESS-2]).
    Running,
    /// At a quantum boundary, idle on the mailbox. Inspect / step / fork /
    /// save / inject are valid here.
    Paused { reason: PauseReason },
    /// Terminal. Carries how the run ended.
    Stopped { outcome: Outcome },
}

/// Why the session paused (a resumable cause).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PauseReason {
    /// The runtime was just instantiated (start / resume / fork landing).
    Instantiated,
    /// The user issued an explicit `pause` command.
    UserRequested,
    /// A breakpoint predicate fired with disposition `Suspend` (§6).
    Breakpoint { id: BreakpointId },
    /// A bounded `step` (any mode, §4.3) completed.
    StepComplete { mode: StepMode },
}

/// How the run ended (a final outcome). Distinct from a pause reason: an
/// outcome is terminal; the session does not resume from `Stopped`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Reached quiescence (08) or the property set's success condition with
    /// no violation: every Always held, every required Eventually/Sometimes
    /// was witnessed (18).
    Passed,
    /// One or more properties were violated (18). Carries the violations so
    /// the artifact (24 §12) can reproduce them.
    Failed { violations: Vec<PropertyViolation> },
    /// The run hit its virtual-time / quantum budget before a terminal
    /// condition (08 `TimeLimitReached`).
    Timeout,
    /// A node crashed in a way the scenario did not model as a fault, or the
    /// backend reported an unrecoverable error.
    Crashed { detail: String },
    /// The user issued `stop` (an operator decision, not a verdict).
    Stopped,
}
```

- **[SESS-4]** A session MUST be in exactly one of the run-states
  `Loaded`, `Running`, `Paused { reason }`, `Stopped { outcome }` at all times.
  The set of run-states MUST be closed (no additional or implicit states), so the
  state machine is exhaustively analyzable. *Gate:* `gate:control-responsive`.
  *Spec:* §2.

- **[SESS-5]** A pause MUST carry a `PauseReason` (one of: `Instantiated`,
  `UserRequested`, `Breakpoint`, `StepComplete`) and a terminal state MUST carry
  an `Outcome` (one of: `Passed`, `Failed`, `Timeout`, `Crashed`, `Stopped`). A
  `PauseReason` is a resumable cause; an `Outcome` is final. The two MUST be
  distinct types; a reason MUST NOT appear as an outcome or vice versa.
  *Spec:* §2.

- **[SESS-6]** The transition relation MUST be total over (state, command): for
  every run-state and every command (§4), the session MUST either apply a defined
  transition or **reject the command with a typed error that leaves the state
  unchanged** ([SESS-19]). No (state, command) pair may panic, deadlock, or leave
  the session in an undefined state. A model of the state machine MUST be checked
  (a small exhaustive/property model) to prove no command sequence can wedge it,
  and `gate:scheduler-liveness` MUST exercise it against generated command
  streams. *Gate:* `gate:scheduler-liveness`, `gate:control-responsive`.
  *Spec:* §2; cross-ref [HARN-18].

### 2.1 The transition table

The complete, defined transitions. Every cell not listed is a no-op-with-error
([SESS-6], [SESS-19]).

```text
  from \ command   start/instantiate   continue   pause   step    stop    inject/heal   set/rm bp   savepoint   fork    query
  ──────────────   ─────────────────   ────────   ─────   ────    ────    ───────────   ─────────   ─────────   ────    ─────
  Loaded           → Paused(Instan.)   error      error   error   →Stop   error         ok (stays)  error       error   ok
  Running          error               error*     →Paused →Running† →Stop queued(§5)    queued(§5)  queued(§5)  →Paused** ok(live)
  Paused           error               →Running   ok      →Running† →Stop ok            ok          ok          ok      ok
  Stopped          error               error      error   error   error   error         error       error       ok***   ok
  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  *   already Running  ** fork requires a pause point; a Running fork first pauses (§7)
  *** fork from a Stopped session is fork-from-its-final-checkpoint (a valid prefix is the tip)
  †   bounded step execution has started; it polls the mailbox between quanta and later pauses
      as Paused(StepComplete) when §4.3's deterministic stop point is reached.
```

- **[SESS-7]** Every transition MUST be applied **on the actor task**, never by an
  external caller mutating session state directly. Commands that arrive while
  `Running` and that mutate scheduler-owned state (inject/heal, savepoint, fork,
  set/remove breakpoint) MUST be **queued and applied at a quantum boundary**
  (§5), never mid-quantum, so they take effect at a deterministic point ([SESS-2],
  08 [SCHED-3]). *Gate:* `gate:control-responsive`. *Spec:* §2.1, §5.

---

## 3. The actor loop (illustrative state-machine sketch)

The whole control plane is one loop: in `Running`, poll the mailbox, apply one
queued command if present, else step exactly one quantum, then update the
lock-free mirror and yield; in `Paused`/`Loaded`, block *only* on the mailbox so
control is fully responsive; in `Stopped`, drain and exit. This is the
realization of 05 §10's `run_engine`, named here as the session's own loop.

```rust,illustrative
/// The session actor: owns all runtime state, reached only by message.
pub struct Session {
    engine: Engine,                      // the 05 §10 driver: config + runtime + state
    scheduler: Scheduler,                // the one authoritative scheduler (08)
    graph: TemporalGraph,                // checkpoint DAG + DagStore handle (07)
    backend: Box<dyn SimulationBackend>, // pluggable: QEMU (10), SimDouble (24), mock (§5/8)
    breakpoints: BreakpointSet,          // predicate-based suspension (§6)
    log: EventLogWriter,                 // appends canonical/observational entries (19)
    live: Arc<LiveSnapshot>,             // lock-free mirror for observers (§4 lock-free)
    event_bus: broadcast::Sender<LogEntry>,    // event-log fan-out (19)
    state_bus: broadcast::Sender<StateSnapshot>,// state-transition fan-out
    deferred: VecDeque<Command>,         // commands queued mid-run, applied at boundaries (§5)
    control_log: ControlLog,             // recorded operator interventions (§8, determinism)
}

/// The actor loop. Commands are serviced at quantum boundaries — never
/// mid-quantum, never under a long-held lock (INV-8, gate:control-responsive).
async fn run_session(mut s: Session, mut mailbox: CommandRx) -> Result<(), SessionError> {
    loop {
        match s.engine.state() {
            SessionState::Running => {
                // 1. Apply at most one boundary-deferred command, then any
                //    newly-arrived command, before stepping. Commands win;
                //    a pause is therefore at most one quantum away ([SESS-3]).
                if let Some(cmd) = s.deferred.pop_front().or_else(|| mailbox.try_recv().ok()) {
                    s.apply_command(cmd).await?;   // may transition to Paused/Stopped
                    continue;
                }
                // 2. No pending command: advance exactly one bounded quantum.
                match s.scheduler.step_quantum(&mut *s.backend)? {
                    StepOutcome::Advanced => {}
                    StepOutcome::Quiescent =>
                        s.engine.stop(Outcome::Passed),
                    StepOutcome::Violation(v) =>
                        s.engine.stop(Outcome::Failed { violations: v }),
                    StepOutcome::TimeLimit =>
                        s.engine.stop(Outcome::Timeout),
                    StepOutcome::Breakpoint(id) =>
                        s.engine.pause(PauseReason::Breakpoint { id }),
                }
                // 3. Publish the cheap mirror + buses, then yield cooperatively.
                s.publish_observation();           // lock-free; never blocks
                tokio::task::yield_now().await;    // bounded; cooperative
            }
            SessionState::Loaded | SessionState::Paused { .. } => {
                // Block ONLY on the mailbox — control is fully responsive; no
                // CPU spin, no held lock. Any command lands immediately.
                let cmd = mailbox.recv().await.ok_or(SessionError::ChannelClosed)?;
                s.apply_command(cmd).await?;
            }
            SessionState::Stopped { .. } => {
                // Drain remaining observation commands plus fork-from-final-checkpoint,
                // then exit the task.
                while let Ok(cmd) = mailbox.try_recv() {
                    if cmd.is_terminal_drain_allowed() {
                        s.apply_command(cmd).await?;
                    } else {
                        break;
                    }
                }
                return Ok(());
            }
        }
    }
}
```

- **[SESS-8]** The session actor loop MUST, in `Running`, prefer servicing a
  pending command over stepping: it MUST check the boundary-deferred queue and the
  mailbox *before* each quantum and apply at most one command per iteration, so a
  control operation is never starved by a busy scheduler. In `Loaded`/`Paused` it
  MUST block solely on the mailbox (no spin, no held lock). In `Stopped` it MUST
  service only read-only commands plus `fork` from the final checkpoint, then
  terminate. *Gate:*
  `gate:control-responsive`, `gate:scheduler-liveness`. *Spec:* §3.

- **[SESS-9]** A single quantum MUST be bounded work: one scheduler `STEP` (08
  §8.x: PICK/RUN/RESOLVE/EMIT/STEP) or a small fixed budget thereof, after which
  the loop MUST return to the mailbox check. The session MUST NOT hold any lock
  across a quantum (08 [SCHED-3]) and MUST update the lock-free mirror (§4
  lock-free) at the end of every quantum so observers see continuous progress.
  *Gate:* `gate:control-responsive`. *Spec:* §3; cross-ref 08 [SCHED-3], 05
  [EXEC-29].

---

## 4. The command set

Every interaction with a running scenario is a **command** enqueued to the actor.
The set is closed; each command maps to a defined operation on the execution
model (05), the temporal graph (07), or the scheduler (08). The command set is
the contract the API (21) and CLI (23) wrap and the search driver (22) drives.

```rust,illustrative
/// The closed control-command set. Each maps to a model/graph/scheduler op.
pub enum Command {
    /// Instantiate the runtime from `config` (05 §5: start = genesis,
    /// resume = tip, fork-target = prefix). Loaded → Paused(Instantiated).
    Start,
    /// Step in bounded quanta until a terminal condition or a breakpoint.
    /// Paused → Running.
    Continue,
    /// Stop stepping at the next quantum boundary. Running → Paused(UserRequested).
    Pause,
    /// Advance by a bounded amount, then pause. Modes in §4.3.
    Step { mode: StepMode },
    /// End the run. Any non-terminal state → Stopped(Stopped).
    Stop,
    /// Inject a fault into the scheduler's active-fault set (17), applied at a
    /// quantum boundary. Returns a `FaultTag` for later healing.
    InjectFault { spec: FaultSpec, reply: Reply<FaultTag> },
    /// Heal a previously injected fault by tag (17), applied at a boundary.
    HealFault { tag: FaultTag },
    /// Add a predicate-based breakpoint (§6). Returns its id.
    SetBreakpoint { spec: BreakpointSpec, reply: Reply<BreakpointId> },
    /// Remove a breakpoint by id (§6).
    RemoveBreakpoint { id: BreakpointId },
    /// Materialize the current configuration as a fat checkpoint (07 §3),
    /// keyed by config.id(). Returns the savepoint handle. Save = §7.
    CreateSavepoint { label: String, reply: Reply<SavepointInfo> },
    /// Fork a new session from a checkpoint (07): instantiate a prefix
    /// configuration (05 §5/§6) and return a handle to the child session.
    Fork { from: CheckpointRef, reply: Reply<SessionHandle> },
    /// Read-only point-in-time query (state, virtual time, log length, …).
    /// Served from the lock-free mirror (§4 lock-free) without entering the
    /// stepping path.
    Query { kind: QueryKind, reply: Reply<QueryResult> },
}

/// `Reply<T>` is a oneshot the actor fulfils when the command completes, so a
/// command that produces a value (a fault tag, a savepoint, a fork handle) is
/// still a fire-and-await message — the caller never touches session state.
pub type Reply<T> = tokio::sync::oneshot::Sender<Result<T, SessionError>>;
```

### 4.1 Command → model/graph/scheduler mapping

```text
  command            run-state effect          model / graph / scheduler operation
  ───────────────    ─────────────────────     ─────────────────────────────────────────────
  start              Loaded → Paused           instantiate(genesis(def))           (05 §5/§6)
  continue           Paused → Running          loop step_quantum                   (08 STEP)
  pause              Running → Paused(User)     stop stepping at boundary           (§3, §5)
  step(mode)         →Running→Paused(StepDone)  bounded advance, then pause         (§4.3, 08)
  stop               * → Stopped(Stopped)       scheduler shutdown; backend.shutdown (08, §4)
  inject_fault       queued → applied@boundary  scheduler.active_faults.insert      (17)
  heal_fault         queued → applied@boundary  scheduler.active_faults.remove      (17)
  set/remove bp      ok (any non-terminal)      breakpoints.{add,remove}            (§6)
  create_savepoint   ok at boundary             materialize fat checkpoint @config.id (07 §3/§4)
  fork               ok at a pause point        instantiate(prefix) → child session (05 §5/§6, 07)
  query              ok always (read-only)      read lock-free mirror               (§4 lock-free)
```

- **[SESS-10]** The control-command set MUST be the closed set in §4 — `start`,
  `continue`, `pause`, `step`, `stop`, `inject_fault`, `heal_fault`,
  `set_breakpoint`, `remove_breakpoint`, `create_savepoint`, `fork`, `query` —
  and each MUST map to the operation named in §4.1 on the execution model (05),
  temporal graph (07), or scheduler (08). A command that produces a value MUST
  carry a `reply` oneshot so it remains a message; no command may require the
  caller to touch session-owned state. The API (21) and CLI (23) MUST be thin
  wrappers over this set. *Gate:* `gate:control-responsive`. *Spec:* §4; forward-
  ref 21, 23.

- **[SESS-11]** `start`, `continue`, and `fork` MUST be implemented as the
  *single* `instantiate` of 05 §5 against, respectively, the genesis
  configuration `(def, [])`, the current configuration, and a prefix
  configuration `(def, schedule[0..k])`. The session MUST NOT contain a separate
  boot/resume/fork realization path (05 [EXEC-14]); `start ≡ resume ≡ fork` is the
  control-plane face of the one execution model. *Gate:* `gate:replay-oracle`.
  *Spec:* §4, §7; cross-ref 05 §5/§6.

### 4.4 Debugging and time-travel control commands

The closed command set (§4) additionally carries a small, **read-only by
default** debugging vocabulary that turns the session's existing primitives —
checkpoint-restore (07), deterministic replay (05, [INV-1]), and the lock-free
observation surface (§9) — into an operator-facing time-travel debugger. These
commands are the session substrate over which the gdb-protocol debugger of
[`36-time-travel-debugging.md`](36-time-travel-debugging.md) and the CLI `debug`
subcommand (23 §16) are thin wrappers; they add no new determinism mechanism.

```rust,illustrative
/// The debugging / time-travel control commands. Read-only by default
/// (excluded from the schedule, like query/pause — [SESS-33]); a mutating
/// continue from a debug attach forks a NON-CANONICAL debug branch (§8).
pub enum DebugCommand {
    /// Open QEMU's gdbstub as a FOURTH out-of-band channel (alongside the
    /// event bus, state bus, and control mailbox) on a deterministically
    /// instantiated `node`, listening at `listen`. Observation-only on QEMU;
    /// the in-process double / mock reject this (`open_gdbstub` unsupported).
    AttachGdb { node: NodeId, listen: GdbListen, reply: Reply<GdbAttachInfo> },
    /// Restore the nearest checkpoint at or before `coordinate` and
    /// deterministically replay forward to it (05 [INV-1], 07). `scope`
    /// selects whether one `Node` or the whole `World` is positioned.
    Goto { coordinate: DebugCoordinate, scope: DebugScope },
    /// Step backward by `grain` — defined as a `goto` of the immediately
    /// earlier coordinate of that grain (so reverse-step reuses goto).
    ReverseStep { grain: StepMode },
    /// Continue backward until `condition` (a 17a `Condition`, §6) last held —
    /// defined as a `goto` of the latest earlier coordinate satisfying it.
    ReverseContinue { condition: Condition },
}

/// A position in the run a `goto` can restore-and-replay to.
pub enum DebugCoordinate {
    /// A guest instruction-count position (09).
    Icount(u64),
    /// A virtual-time position (09).
    VirtualTime(VirtualTime),
    /// An event-log sequence position (19).
    EventSeq(u64),
    /// A materialized checkpoint id (07).
    CheckpointId(CheckpointRef),
}

/// Whether a time-travel reposition moves one node or the whole world.
pub enum DebugScope { Node(NodeId), World }
```

- **[SESS-33]** `attach_gdb`, `goto`, `reverse_step`, and `reverse_continue`
  MUST be **read-only control operations** — like `query` and `pause`, they touch
  no canonical state and MUST be **excluded from the schedule** ([SESS-22]); they
  are pure observation/repositioning over checkpoint-restore + deterministic
  replay (05 [INV-1], 07). `goto` MUST restore the nearest checkpoint at or before
  its `coordinate` (`Icount`/`VirtualTime`/`EventSeq`/`CheckpointId`) and replay
  forward to it deterministically; `reverse_step`/`reverse_continue` MUST be
  expressible as a `goto` of an earlier coordinate. **Mutating or continuing
  *forward* from a debug attach** (issuing a control op through the gdbstub, or a
  `continue` past the attach point that injects guest-visible change) MUST fork a
  clearly-marked **NON-CANONICAL debug branch**: it is excluded from the replay
  oracle, is not artifact-reproducible, and MUST be labelled as such on every
  surface that exposes it. *Gate:* `gate:replay-oracle`, `gate:control-responsive`.
  *Spec:* §4.4, §8; cross-ref [`36-time-travel-debugging.md`](36-time-travel-debugging.md),
  [ADV-33], [SESS-22].

### 4.3 Step modes

`step` advances a *bounded* amount and then pauses with
`PauseReason::StepComplete`. The mode selects the boundary. Every mode resolves
to a deterministic stop point expressed in scheduler/virtual-time terms, so a
step lands at the same configuration on every host ([SESS-22]).

```rust,illustrative
/// How far a single `step` advances before pausing.
pub enum StepMode {
    /// Advance exactly one scheduler quantum (08 STEP). The finest grain.
    Quantum,
    /// Advance until the next cross-node event is resolved (a frame delivery,
    /// I/O completion, or fault activation — 08 RESOLVE).
    Event,
    /// Advance until the next assertion state change is recorded (18).
    Assertion,
    /// Advance until the next armed timer fires (08/09).
    Timer,
    /// Advance by a fixed virtual-time duration (09), then pause at the first
    /// quantum boundary at or past it.
    Duration(VirtualDuration),
}
```

- **[SESS-12]** `step` MUST support the modes `Quantum`, `Event`, `Assertion`,
  `Timer`, and `Duration`, each resolving to a **deterministic stop point** in
  scheduler / virtual-time terms (a quantum count, the next RESOLVE, the next
  assertion-state change, the next timer fire, or a virtual-time delta). A `step`
  MUST advance only by bounded quanta with inter-quantum mailbox polls (so it is
  itself interruptible by `pause`/`stop`) and MUST land at the same configuration
  on every host for the same starting configuration and mode. On reaching the stop
  point it MUST transition to `Paused { reason: StepComplete { mode } }`.
  *Gate:* `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §4.3.

---

## 5. Boundary-deferred application: how a mid-run command stays deterministic

A command issued while the session is `Running` cannot take effect *immediately* —
that would apply a state mutation mid-quantum, at a host-timing-dependent point,
which is exactly the nondeterminism Crucible eliminates. Instead, a mutating
command that arrives mid-run is **deferred to the next quantum boundary** and
applied there. Because quantum boundaries are deterministic positions in virtual
time (08), the *effect* of the command lands at a deterministic configuration —
even though the operator's *wall-clock* moment of issuing it is not.

The deferral is short ([SESS-3]: a bounded number of quanta), so this does not
make control sluggish; it makes control *deterministic*. The `pause` and `stop`
commands are special: they do not mutate scheduler state, they only change whether
the loop steps, so they take effect at the very next boundary check with no
deferral queue needed beyond that.

```text
  operator issues inject_fault at wall-clock T_host (Running)
        │
        ▼ enqueued to mailbox
  actor loop, next iteration: pops command BEFORE stepping
        │
        ▼ command recorded in the control log (§8) keyed by the boundary
  applied at the next quantum boundary → scheduler.active_faults.insert
        │
        ▼ takes effect at virtual-time boundary B (deterministic)
  every replay of this run applies the same fault at the same boundary B
```

- **[SESS-13]** A scheduler-state-mutating command (`inject_fault`, `heal_fault`,
  `create_savepoint`, `set_breakpoint`, `remove_breakpoint`, `fork`) issued while
  `Running` MUST be applied at a **quantum boundary**, never mid-quantum, so its
  effect lands at a deterministic configuration in virtual time (08). The session
  MUST record, in the control log (§8), the boundary at which each such command
  was applied, keyed by virtual time / decision index, not by host wall-clock.
  *Gate:* `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §5, §8.

- **[SESS-14]** `pause` and `stop` MUST take effect at the next boundary check
  with bounded latency ([SESS-3]); they change only whether the loop steps, not
  scheduler-owned state, so they need no deferral beyond the boundary. `stop` MUST
  additionally shut the scheduler and backend down cleanly (08, §4) and transition
  to `Stopped`. *Gate:* `gate:control-responsive`. *Spec:* §5.

---

## 6. Breakpoints: predicate-based suspension at event-log entries

A breakpoint is a **`Condition` over the run** plus a **disposition**. The
predicate it matches on is *not* a separate, narrow breakpoint-only vocabulary: it
is the **shared 17a `Condition` predicate vocabulary**
([`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2) that
triggers and assertions also consume, evaluated over the same totally-ordered
event log (19) at the **same deterministic evaluation points** ([TRIG-16]). A
breakpoint is thus a Condition with a disposition (Suspend/Trace/Action): the same
predicate the scenario uses to *steer* the run (a trigger) and to *grade* it (an
assertion) is the one an operator uses to *stop on* it. When the Condition first
becomes true at an evaluation point, the breakpoint fires; its **disposition**
decides what firing does. Breakpoints are how an operator (or the search driver,
22) says "stop when X happens" without polling. Because they are evaluated against
the same event log the determinism oracle uses, at the same evaluation points, a
breakpoint fires at the same point on every run — it is an observation, never a
perturbation ([SESS-17]).

```rust,illustrative
/// A breakpoint: the SHARED 17a `Condition` predicate vocabulary (§17a.2) plus a
/// disposition and a fire policy. The predicate is NOT a breakpoint-only set; it
/// is the same `Condition` triggers and assertions consume, evaluated at the same
/// deterministic evaluation points ([TRIG-16]).
pub struct BreakpointSpec {
    /// What to match: a 17a `Condition` (§17a.2), evaluated over the event log
    /// (19) at deterministic evaluation points. Every 17a leaf is available for
    /// free — `Time`/`At`, `NetworkMatch`, `ConsoleMatch`, `NodeState`
    /// (Started/Crashed/Exited), `AssertionState` (Satisfied/Violated — covers
    /// fault-activated/healed via the fault's assertion/state condition),
    /// `Quiescent`, … — composed with `AllOf`/`AnyOf`/`Once`/`Not`.
    pub predicate: Condition, // = 17a Condition (§17a.2)
    /// What firing does (§6.1).
    pub disposition: Disposition,
    /// One-shot (auto-removed after its first fire) or repeatable. `StepMode`
    /// internally relies on the one-shot primitive (§6).
    pub policy: BreakpointPolicy,
}

/// Whether a breakpoint persists after firing (§6).
pub enum BreakpointPolicy {
    /// Auto-remove after the first fire. The primitive `StepMode` (§4.3) is
    /// built on: a step is a one-shot breakpoint on the mode's stop Condition.
    OneShot,
    /// Persist; fire on each false→true transition of the Condition.
    Repeatable,
}

/// What a firing breakpoint does.
pub enum Disposition {
    /// Suspend the run: transition Running → Paused(Breakpoint{id}). The
    /// classic debugger breakpoint.
    Suspend,
    /// Emit a deterministic control-plane trace marker and keep running.
    Trace,
    /// Run a bounded, side-effect-scoped action (e.g. auto-savepoint, inject a
    /// follow-on fault) at the firing boundary, then keep running.
    Action(BreakpointAction),
}
```

- **[SESS-15]** A breakpoint MUST be a **17a `Condition`**
  ([`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2) plus
  a disposition — the **same shared predicate vocabulary** triggers and assertions
  consume, **not** a separate breakpoint-only predicate set. It MUST be evaluated by
  the scheduler/session over the event log (19) at the **same deterministic
  evaluation points** as triggers and assertions ([TRIG-16], [TRIG-17]). Because it
  is a 17a `Condition`, the vocabulary MUST cover every 17a leaf — including
  virtual-time reach (`At`), `NetworkMatch`/`ConsoleMatch`/`CoveragePoint`,
  `NodeState` (Started/Crashed/Exited), `AssertionState` (Satisfied/Violated),
  `Quiescent`, and the optional white-box `GuestMarker` — composed with the 17a
  combinators (`AllOf`/`AnyOf`/`Once`/`Not`). Predicate evaluation MUST be a pure
  function of the log prefix and MUST NOT read host wall-clock or unordered state
  ([INV-9]). *Gate:* `gate:control-responsive`, `gate:harness-lint`. *Spec:* §6;
  cross-ref 17a §17a.2, §17a.3.

- **[SESS-16]** A breakpoint MUST carry a **disposition**: `Suspend`
  (Running → Paused with `PauseReason::Breakpoint`), `Trace` (emit a marker, keep
  running), or `Action` (run a bounded action at the firing boundary, keep
  running). A firing breakpoint MUST act at the **quantum boundary** of the
  matching entry, never mid-quantum. *Gate:* `gate:control-responsive`.
  *Spec:* §6, §5.

- **[SESS-17]** Breakpoint evaluation MUST be **observation-only** with respect to
  the canonical run: setting, removing, or firing a `Suspend`/`Trace` breakpoint
  MUST NOT change the canonical event log or the schedule (the entries themselves,
  their order, and their virtual times are identical whether or not a breakpoint
  is set). An `Action` disposition that *does* mutate scheduler state (inject a
  fault, savepoint) MUST be recorded in the control log (§8) exactly as an
  operator command would be, so the run remains reproducible. *Gate:*
  `gate:replay-oracle`. *Spec:* §6, §8; cross-ref 19 (canonical vs observational).

- **[SESS-30]** A breakpoint MUST carry a fire **policy**: `OneShot` (auto-removed
  after its first fire) or `Repeatable` (persists, fires on each false→true
  transition of its `Condition`). The session's `step` (§4.3) MUST be expressible
  on the `OneShot` primitive — each `StepMode` resolves to a stop `Condition` whose
  one-shot breakpoint suspends the run on first fire, then is removed — so step and
  breakpoints share one mechanism rather than two. A `OneShot` breakpoint's removal
  MUST itself be observation-only ([SESS-17]) for `Suspend`/`Trace` dispositions.
  *Gate:* `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §6, §4.3.

- **[SESS-31]** Because a breakpoint is a 17a `Condition` ([SESS-15]), the
  vocabulary MUST include — at no extra cost — the richer condition kinds: a
  `NodeState` leaf (Started/Crashed/Exited,
  [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2.7) so an
  operator MAY stop when a node starts, crashes, or exits; and an `AssertionState`
  leaf (Satisfied/Violated, §17a.2.8) so an operator MAY stop the instant a fault
  becomes active or is healed (the fault's state surfaced as an assertion/state
  Condition) or an invariant flips. These MUST be ordinary 17a leaves, not
  breakpoint-special cases, and MUST evaluate at the same deterministic evaluation
  points as all other Conditions ([TRIG-16]). *Gate:* `gate:control-responsive`,
  `gate:harness-lint`. *Spec:* §6; cross-ref 17a §17a.2.7, §17a.2.8.

---

## 7. Save, resume, and fork at the session level

The session exposes save/resume/fork as commands (§4), but it implements **none**
of them as bespoke logic: each is a call into the one execution model (05) over
the one temporal graph (07). This section states the session-level contract;
05 §5/§6/§9 and 07 §10 own the mechanics.

- **create_savepoint** materializes the session's current configuration as a fat
  checkpoint (07 §3/§4) keyed by `config.id()` (05 [EXEC-4]), CoW-shared with its
  parent (07 §5), validated by the replay oracle (07 §6), and returns a handle.
  The thin form `(parent, schedule_delta)` remains the source of truth (07 §4);
  the fat form is a cache.

- **resume** is `instantiate` of the configuration the savepoint records (05 §5):
  `loadvm` of its fat snapshot, or replay-from-nearest-fat-ancestor if it is thin
  (07 §4). A session created from a savepoint is *not* a special "restored"
  object — it is a fresh session whose configuration happens to be non-genesis.

- **fork** is `instantiate` of a *prefix* configuration (05 §6), producing a
  child session that shares the parent's checkpoints CoW (07 §5) and appends
  *different* decisions from the fork point. The fork point may be any checkpoint:
  a session's tip, a savepoint, or a node deep in the temporal graph (07).

The headline (05 §5): **a session is created at genesis OR resumed from any
checkpoint identically** — both are `instantiate` of a configuration, distinguished
only by which configuration. There is no `boot()` distinct from `loadvm()`
distinct from `fork()` at the session level any more than there is at the model
level.

- **[SESS-18]** `create_savepoint`, `resume` (instantiate-from-checkpoint), and
  `fork` MUST be implemented purely as operations on the execution model (05) and
  temporal graph (07): savepoint = materialize a fat checkpoint keyed by
  `config.id()` (07 §3/§4) with oracle validation (07 §6); resume = `instantiate`
  of the recorded configuration (05 §5); fork = `instantiate` of a prefix
  configuration (05 §6) yielding a child session that CoW-shares the parent's
  checkpoints (07 §5). A session created at genesis and a session resumed from any
  checkpoint MUST be the *same kind of object* differing only in their
  configuration; the session MUST NOT have a distinct "restored" or "forked"
  code path. *Gate:* `gate:replay-oracle`, `gate:content-address`. *Spec:* §7;
  cross-ref 05 §5/§6/§9, 07 §10.

- **[SESS-19]** A `fork` MUST be servable from a `Paused` or `Stopped` session
  directly, and from a `Running` session by first pausing at the next quantum
  boundary, then forking (§2.1). The child session MUST be an independent actor
  with its own mailbox, lifecycle, and lock-free mirror; mutating the child MUST
  NOT affect the parent (the CoW sharing is in the store, 07 §5, and is
  copy-on-*write*). *Gate:* `gate:control-responsive`. *Spec:* §7, §2.1.

---

## 8. Determinism of control operations

This is the subtle, load-bearing section. The whole point of Crucible is that a
run is `reduce(ScenarioDef, Schedule)` (INV-1) — but an *interactive* run has an
operator poking at it: injecting faults, healing them, forking, savepointing. If
those interventions were not part of the recorded model, an "interactively
debugged" run would not reproduce, defeating [G-6] (reproduce-then-explore). Two
rules make operator control fully reproducible.

**Rule 1 — control operations are recorded.** Every operator intervention that
changes scheduler-owned state (`inject_fault`, `heal_fault`, and any `Action`
breakpoint that mutates state) is recorded in a **control log** as a `Decision`
(05 §3) or a control-log entry keyed by the **virtual-time boundary** at which it
was applied (§5), not by the host wall-clock at which it was issued. The schedule
(05) therefore *includes* the operator's interventions, so re-reducing the
configuration reproduces them at the same boundaries. An interactively-debugged
run emits the same reproduction artifact (24 §12) as a scripted one.

**Rule 2 — control operations introduce no nondeterminism.** Because every
mutating command takes effect at a deterministic quantum boundary (§5), and
because the boundary is a pure function of virtual time (08), the operator's
wall-clock timing **cannot** influence `State`. Issue the same command at the same
*virtual-time boundary* — whether by hand at 2 a.m. or by a replay driver at full
speed — and the result is bit-identical. Read-only commands (`query`, `pause`,
`set`/`remove` of a `Suspend`/`Trace` breakpoint) touch no canonical state and so
are excluded from the schedule entirely; they are pure observation.

```text
  command class            recorded in schedule?   affects State?   determinism rule
  ──────────────────────   ─────────────────────   ──────────────   ────────────────────────
  inject_fault / heal      yes (as a Decision/      yes, at the      Rule 1 + Rule 2:
                           control-log entry)       boundary         recorded + boundary-applied
  Action breakpoint (mut.) yes                       yes              same as inject_fault
  create_savepoint         no (cache op, 07 §4)      no               materialization is a cache
  fork                     starts a NEW config       no (to parent)   child = prefix + new decisions
  pause / continue / stop  no                        no (control      Rule 2: changes only whether
                                                     flow only)        the loop steps
  Suspend/Trace breakpoint no                        no               observation-only ([SESS-17])
  query                    no                        no               lock-free read (§4 lock-free)
```

- **[SESS-20]** Every control operation that changes scheduler-owned state
  (`inject_fault`, `heal_fault`, a state-mutating `Action` breakpoint) MUST be
  recorded — as a `Decision` (05 §3) or a control-log entry — keyed by the
  virtual-time boundary at which it was applied (§5), so the run's reproduction
  artifact (24 §12) reproduces the operator's interventions bit-identically.
  An interactively-controlled run MUST be as reproducible as a scripted one.
  *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §8; cross-ref 05
  §3, 24 §12.

- **[SESS-21]** Control operations MUST NOT introduce nondeterminism: because each
  mutating command takes effect at a deterministic quantum boundary (§5) that is a
  pure function of virtual time (08), the operator's host wall-clock timing MUST
  NOT influence `State`. Re-applying the recorded control log at the same
  virtual-time boundaries — at any speed, on any host — MUST yield a bit-identical
  run ([INV-1]). The session MUST NOT read host wall-clock on any path that feeds
  `State` ([INV-9]). *Gate:* `gate:replay-oracle`, `gate:adversarial-determinism`,
  `gate:harness-lint`. *Spec:* §8; routes [INV-1], [INV-10].

- **[SESS-22]** Read-only control operations (`query`, `pause`, `continue`,
  `stop`, and setting/removing `Suspend`/`Trace` breakpoints) MUST touch no
  canonical state and MUST be excluded from the schedule; they are pure
  observation or control-flow and MUST NOT appear in the reproduction artifact.
  A run with and without such operations MUST produce the identical canonical
  event log. *Gate:* `gate:replay-oracle`. *Spec:* §8; cross-ref 19 (canonical vs
  observational).

---

## 9. Lock-free observation

Observers — heartbeats, the `Watch` RPC (21), the CLI status line (23), the search
driver's progress meter (22) — must sample "where is this run now?" *without*
entering the stepping path. The session keeps a **lock-free live snapshot** (a
struct of atomics) that the actor updates at the end of every quantum (§3); an
observer reads it with plain atomic loads, never a message, never a lock. This is
the clean realization of 05 [EXEC-29] (the lock-free run-state mirror): it falls
out of the actor design rather than being bolted on, because the actor *already*
owns all writes, so a single-writer/many-reader atomics mirror is sound by
construction.

Two complementary mechanisms sit alongside the actor:

- **The live snapshot (atomics)** — `state_kind`, `virtual_time`,
  `event_log_len`, and a derived wall-clock-since-running, each an atomic the
  actor stores at quantum boundaries and observers load lock-free. A `Query` for a
  point-in-time view is answered from this mirror, so a heartbeat during a long
  `continue` never blocks the stepping path.

- **Broadcast buses** — a `broadcast` channel of every appended event-log entry
  (19) and a `broadcast` channel of every state transition. Subscribers receive
  copies; a slow subscriber lags or drops (bounded buffer) but **never** back-
  pressures the actor. This is how the API streams the event log and state changes
  to many consumers without any of them touching session state.

```rust,illustrative
/// Lock-free mirror of the session's run-state, written only by the actor (a
/// single writer), read lock-free by any observer (05 [EXEC-29]).
#[derive(Debug)]
pub struct LiveSnapshot {
    state_kind: AtomicU8,         // 1=Loaded 2=Running 3=Paused 4=Stopped
    virtual_time_nanos: AtomicU64,
    event_log_len: AtomicU64,
    quanta_stepped: AtomicU64,    // monotone; observers infer progress/liveness
}

/// A cheap, copy-out view. `Query{Status}` returns this without a message.
#[derive(Clone, Copy, Debug)]
pub struct LiveSnapshotView {
    pub state_kind: u8,
    pub virtual_time_nanos: u64,
    pub event_log_len: u64,
    pub quanta_stepped: u64,
}

impl LiveSnapshot {
    /// Read a coherent point-in-time view with plain atomic loads. Never
    /// blocks the stepping path; safe to call from a heartbeat at any rate.
    pub fn read(&self) -> LiveSnapshotView {
        use std::sync::atomic::Ordering::Acquire;
        LiveSnapshotView {
            state_kind: self.state_kind.load(Acquire),
            virtual_time_nanos: self.virtual_time_nanos.load(Acquire),
            event_log_len: self.event_log_len.load(Acquire),
            quanta_stepped: self.quanta_stepped.load(Acquire),
        }
    }
}
```

- **[SESS-23]** The session MUST maintain a **lock-free live snapshot** (a struct
  of atomics) carrying at least the run-state kind, current virtual time,
  event-log length, and a monotone quanta-stepped counter, written only by the
  actor at quantum boundaries (single writer) and readable by any observer with
  plain atomic loads (05 [EXEC-29]). A point-in-time `Query` MUST be answerable
  from this mirror without entering the mailbox or the stepping path, so a
  heartbeat during a long `continue` never blocks or starves the scheduler.
  *Gate:* `gate:control-responsive`. *Spec:* §9; cross-ref 05 [EXEC-29].

- **[SESS-24]** The session MUST expose **broadcast buses** for (a) every appended
  event-log entry (19) and (b) every state transition. Subscribers MUST receive
  copies without taking any session lock; a slow or absent subscriber MUST NOT
  back-pressure or block the actor (bounded buffers, lag-or-drop semantics). The
  event-log bus MUST carry the same entries the canonical log records, so a
  streaming observer and a post-hoc log reader see the identical sequence (modulo
  the observational/canonical schema distinction of 19). *Gate:*
  `gate:control-responsive`. *Spec:* §9; cross-ref 19.

- **[SESS-25]** Lock-free observation MUST be a property of the actor design, not
  a bolted-on cache that can drift: because the actor is the sole writer of both
  the mirror and the buses, a reader MUST never observe a torn or stale-beyond-one-
  quantum view, and there MUST be no code path by which an observer mutates
  session state. The mirror's correctness MUST be tested under
  `gate:control-responsive` (observe a long run, assert continuous, monotone,
  lock-free progress). *Gate:* `gate:control-responsive`, `gate:harness-lint`.
  *Spec:* §9.

---

## 10. The backend trait: the session is backend-agnostic

The session drives VMs through a **pluggable backend trait**, never against a
QEMU-specific type. This is what lets the *same* session, scheduler, and command
set run against three backends interchangeably:

- the **real QEMU backend** (`crucible-qemu`, 10) for fidelity;
- the **in-process test double** (`SimDouble`, 24 §3) for fast, deterministic
  testing of all host orchestration (scheduling, transport, save/restore, fork,
  the whole control plane) without booting a guest;
- a **mock** backend for unit tests of the session state machine and command
  routing alone.

Because the session is defined entirely against the backend trait and the
shmem/protocol boundary (13/14), the double is a *drop-in* (24 [HARN-14]): the
session cannot tell a `SimDouble` node from a real QEMU node through this
interface. That is precisely why the control plane (L4) can be tested against the
double in milliseconds (24 §2, §3) and why `gate:control-responsive` and
`gate:scheduler-liveness` do not require real QEMU.

```rust,illustrative
/// The pluggable simulation backend. The session delegates all node-level
/// operations through this trait, keeping the control plane backend-agnostic.
/// Implemented by the QEMU backend (10), the SimDouble (24 §3), and a mock.
/// The object is owned by the driving session actor; no `Send` bound is required
/// because concrete QEMU adapters may wrap thread-affine channel/runtime handles.
pub trait SimulationBackend {
    /// Advance the backend's nodes by one bounded scheduler quantum toward
    /// `ceiling` virtual time (08), returning what was observed. The backend
    /// does NOT resolve cross-node order or evaluate properties — the
    /// scheduler (08) and session own that; the backend only runs nodes and
    /// reports.
    ///
    /// # Errors
    /// Returns an error if a node fails to advance or the transport faults.
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError>;

    /// Apply a backend-level effect at a quantum boundary (start/stop a node,
    /// activate/heal a fault, set a link property), as directed by the
    /// scheduler after a deferred command (§5).
    ///
    /// # Errors
    /// Returns an error if the effect cannot be applied.
    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime)
        -> Result<(), BackendError>;

    /// Materialize the backend's node state into a content-addressed snapshot
    /// for a fat checkpoint (07 §3). The session composes this with scheduler
    /// state to form the full `MaterializedState`.
    ///
    /// # Errors
    /// Returns an error if a node's state cannot be captured.
    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError>;

    /// Restore the backend to a prior snapshot (the `loadvm` branch of
    /// `instantiate`, 05 §5).
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be restored.
    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError>;

    /// The backend's current virtual time (a mirror of the scheduler's; the
    /// scheduler remains the single source of truth, 08 [SCHED-4]).
    fn now(&self) -> VirtualTime;

    /// Read a node's execution fingerprint (24 §4) for the replay oracle and
    /// divergence bisection — observation-only, must not perturb the stream.
    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError>;

    /// Shut all nodes down cleanly (on `stop`).
    ///
    /// # Errors
    /// Returns an error if a node fails to shut down.
    fn shutdown(&mut self) -> Result<(), BackendError>;
}
```

T-SESS-13 extends this boundary with the optional `open_gdbstub` debugging
capability.

- **[SESS-26]** The session MUST drive nodes exclusively through a pluggable
  `SimulationBackend` trait defined against the shmem/protocol boundary (13/14),
  never against a QEMU-specific type. At least three backends MUST satisfy it
  interchangeably: the real QEMU backend (10), the in-process `SimDouble` (24 §3),
  and a mock. The session, scheduler, command set, and lifecycle MUST be identical
  across backends; only the backend differs. *Gate:* `gate:control-responsive`,
  `gate:abi-conformance`. *Spec:* §10; cross-ref 24 [HARN-14].

- **[SESS-32]** The backend trait MAY expose an **optional `open_gdbstub`
  capability** (§10): an observation-only out-of-band gdbstub channel used by the
  debugging commands of §4.4 ([SESS-33]). The QEMU backend (10) MUST implement it
  against QEMU's gdbstub; the in-process `SimDouble` (24 §3) and the mock MUST NOT
  support it and MUST reject `attach_gdb` with a typed error ([SESS-29]) rather than
  faking a stub. Backends without the capability MUST default to refusing the
  attach, so a debug session always knows whether its node is gdb-attachable.
  *Gate:* `gate:control-responsive`, `gate:abi-conformance`. *Spec:* §4.4, §10;
  cross-ref [`36-time-travel-debugging.md`](36-time-travel-debugging.md), 10.

- **[SESS-27]** The backend trait MUST keep the scheduler (08) as the single
  source of timing truth: the backend advances nodes toward a scheduler-supplied
  `ceiling` and reports observations, but MUST NOT resolve cross-node order,
  evaluate properties, or advance virtual time of its own accord (08 [SCHED-1],
  [SCHED-4]). The backend's `snapshot`/`restore` MUST capture exactly the node
  state the temporal graph's `MaterializedState` requires (07 §3); scheduler and
  decision-RNG state are composed by the session, not the backend. *Gate:*
  `gate:replay-oracle`, `gate:layer1-injection`. *Spec:* §10; cross-ref 08
  [SCHED-1], 07 §3.

- **[SESS-28]** Because the control plane is defined against the backend trait,
  `gate:control-responsive`, `gate:scheduler-liveness`, and the session/lifecycle
  tests MUST run against the in-process `SimDouble` (24 §3) without booting real
  QEMU; only fidelity properties (Contract A, guest non-mutation, patch inertness)
  require the QEMU backend (24 §3.3). A session test that needs real QEMU to
  exercise the *control plane* (as opposed to guest fidelity) is a design defect.
  *Gate:* `gate:control-responsive`, `gate:scheduler-liveness`. *Spec:* §10;
  cross-ref 24 §2, §3.

---

## 11. Errors and rejection: typed, state-preserving

Every command that cannot be applied in the current state MUST be **rejected with
a typed error that leaves the session unchanged** ([SESS-6]). There is no partial
application, no implicit state coercion, and no panic. A rejected command's
`reply` (if any) is fulfilled with the error; the actor loops on.

```rust,illustrative
/// Errors from session control operations. Every variant leaves the session
/// state unchanged (rejection is total and side-effect-free, [SESS-6]).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The command is not valid in the current run-state (§2.1).
    #[error("invalid command {command} in state {state}")]
    InvalidState { command: &'static str, state: &'static str },
    /// An error propagated from the simulation backend (§10).
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    /// A referenced breakpoint / fault tag / checkpoint does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The replay oracle (07 §6) rejected a fat checkpoint on save.
    #[error("replay-oracle violation: {0}")]
    OracleViolation(String),
    /// The actor's mailbox was closed (the session task has exited).
    #[error("session channel closed")]
    ChannelClosed,
}
```

- **[SESS-29]** Every command rejection MUST be **total and side-effect-free**:
  the session state MUST be unchanged after a rejected command, the typed
  `SessionError` MUST name the command and the state, and any `reply` MUST be
  fulfilled with that error. No command may panic or leave the session in an
  undefined state, and no rejection may partially apply. This totality is what
  [SESS-6]'s "no command sequence can wedge it" property checks. *Gate:*
  `gate:scheduler-liveness`, `gate:control-responsive`. *Spec:* §11, §2.

---

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint
> ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-SESS-1** Implement the session actor: a single owning task holding the
  `Engine` (05 §10), scheduler (08), temporal-graph handle (07), breakpoint set,
  and event-log writer, mutated only on the task, reached only by message; assert
  (lint + test) no long-held lock guards the engine across a run. — satisfies
  [SESS-1], [SESS-7]; spec §1, §3.
  - Completed by `checks.crucible.phase5.sessionActor`: `SessionActor` owns
    `Engine<L>` by value, receives all control through an
    `mpsc::Receiver<SessionCommand>`, owns the `SessionEventLog` writer, and the
    `Engine` owns the runtime cache, `TemporalGraph`, `BreakpointSet`, and
    scheduler `QuantumLoop`. The source gate and focused Rust test assert the
    actor has no public mutable engine accessor, no public direct command hook,
    and no locked/shared actor engine field while allowing the lower-level
    `Engine` state-machine APIs used by foundation tests and the separate
    event-log retention mutex.
- [x] **T-SESS-2** Implement the bounded-quantum actor loop (poll mailbox →
  apply one command or step one quantum → publish mirror → yield), with
  inter-quantum mailbox polls and a quanta-measured acknowledgement bound; wire
  `gate:control-responsive`. — satisfies [SESS-2], [SESS-3], [SESS-9];
  spec §3.
  - Completed by `crates/crucible-session/src/lib.rs`: `SessionActor::run`
    delegates to a bounded `run_once` loop that polls
    `mpsc::Receiver::try_recv` before each running quantum, applies at most one
    mailbox command or calls `Engine::step_quantum` once, publishes the
    `LiveSnapshot` mirror after command transitions and quanta, and yields with
    `tokio::task::yield_now` after every applied command or scheduler quantum.
    Focused tests cover
    command-before-quantum ordering, one-quantum running iterations,
    command-driven bounded steps, and monotone live progress; the session-side
    `gate_control_responsive` target observes mailbox-free live progress and
    one-quantum stop acknowledgement. `checks.crucible.phase1.executionEngineStateMachine`
    and `checks.crucible.phase1.executionLiveSnapshot` gate the task.
- [x] **T-SESS-3** Implement the lifecycle state machine (closed run-states
  Loaded/Running/Paused/Stopped; `PauseReason` and `Outcome` types) and the
  total (state, command) transition table; build the exhaustive/property model
  proving no command sequence wedges it and exercise it under
  `gate:scheduler-liveness`. — satisfies [SESS-4], [SESS-5], [SESS-6], [SESS-29];
  spec §2, §2.1, §11.
  - Completed by `checks.crucible.phase5.sessionLifecycle`: `crucible-session`
    now carries closed lifecycle, pause-reason, outcome, and command-kind enums;
    a pure `lifecycle_transition` table is total over every state and the full
    §4 command-kind lifecycle model, including set/remove breakpoint and
    create-savepoint kinds. Focused tests prove representative command coverage,
    RFC table cells such as `Running + Fork = Paused`, bounded command-sequence
    closure, generated command-stream closure, agreement for current
    `Engine::apply_command` pairs, and side-effect-free typed rejection paths
    that name the rejecting state and command. The check depends on
    `checks.crucible.phase3.gates.schedulerLiveness`; the reply-carrying §4
    command payloads and operation mappings are completed separately by
    `T-SESS-4`.
- [x] **T-SESS-4** Implement the closed command set (start/continue/pause/step/
  stop/inject_fault/heal_fault/set+remove breakpoint/create_savepoint/fork/query)
  with `reply` oneshots, mapping each to its model/graph/scheduler operation
  (§4.1); make start/continue/fork single `instantiate` call sites (05 §5). —
  satisfies [SESS-10], [SESS-11]; spec §4, §4.1.
  - Completed by `checks.crucible.phase5.sessionCommandSet`:
    `crucible-session` now carries the reply-bearing §4 command payloads for
    typed fault injection/healing, breakpoint insert/remove, savepoint creation,
    fork, and query. The engine maps breakpoint commands into the actor-owned
    registry, savepoint/fork through `TemporalGraph::save_checkpoint`, running
    fault/query commands through queued scheduler control operations, and actor
    command rejection into typed reply completion. Focused tests cover successful
    reply delivery across engine boundaries and side-effect-free rejection
    replies. Full breakpoint predicate evaluation and independent forked child
    actors remain tracked by `T-SESS-7` and `T-SESS-8`.
- [x] **T-SESS-5** Implement the five step modes (Quantum/Event/Assertion/Timer/
  Duration), each resolving to a deterministic stop point, interruptible by
  pause/stop, landing at the same configuration on every host. — satisfies
  [SESS-12]; spec §4.3.
  - Completed by `checks.crucible.phase5.sessionStepModes`:
    `crucible-session` now carries the forward `StepMode` vocabulary
    (`Quantum`, `Event`, `Assertion`, `Timer`, `Duration`) and engine-owned
    active-step state. The actor starts bounded execution through the mailbox,
    polls between quanta, pauses with `StepComplete { mode }` only after the
    requested event-log or virtual-time stop point, and clears active steps when
    `pause` or `stop` interrupts. Focused tests cover event, assertion, timer,
    duration, and interruptible pause/stop behavior.
- [x] **T-SESS-6** Implement boundary-deferred application of mid-run mutating
  commands (apply at the next quantum boundary, record the boundary in the
  control log) and immediate-at-boundary pause/stop with clean
  scheduler/backend shutdown. — satisfies [SESS-8], [SESS-13], [SESS-14];
  spec §5, §3.
  - Completed by `checks.crucible.phase5.sessionBoundaryControl`:
    `crucible-session` now records accepted running boundary commands in an
    engine-owned `SessionControlLogEntry` sequence keyed by virtual-time frontier
    and completed quantum count, including scheduler control payloads for legacy
    injection and injected/healed faults, plus local boundary effects for
    breakpoint mutation, savepoint creation, fork, pause, and stop.
    Focused tests prove the actor applies these commands at nonzero deterministic
    boundary coordinates, applies scheduler-backed controls synchronously so a
    later pause/stop/fork cannot drop them, rejects stopped-state mutators during
    terminal drain, and that `pause`/`stop` take effect at the boundary check
    without driving an extra quantum while `stop` invokes scheduler shutdown.
- [ ] **T-SESS-7** Implement breakpoints as the shared 17a `Condition` predicate
  vocabulary (§17a.2, including `NodeState` and `AssertionState` leaves and
  `AllOf`/`AnyOf`/`Once`/`Not`) evaluated at the same deterministic evaluation
  points as triggers/assertions, with dispositions Suspend/Trace/Action and a
  OneShot/Repeatable policy (step built on the one-shot primitive), fired at the
  matching evaluation point's quantum boundary, observation-only for Suspend/Trace
  and control-logged for mutating Actions. — satisfies [SESS-15], [SESS-16],
  [SESS-17], [SESS-30], [SESS-31]; spec §6; cross-ref 17a §17a.2.
  - Partial evidence under `checks.crucible.phase5.sessionBreakpoints`:
    `crucible-session` now evaluates actor-owned breakpoints through the shared
    17a `ConditionEventLogPrefix`/`ConditionEvaluationPass` path, including
    scheduler-owned quiescence evidence from `QuantumOutcome` even at no-entry
    boundaries and trigger-derived `After`/`Timer` runtime facts from the
    canonical event-log prefix. It records each firing in an engine-owned
    `BreakpointFiring` sequence keyed by frontier and completed quanta. Focused
    tests cover observation-only suspend firing without canonical event-log
    perturbation, repeatable trace false-to-true transitions, action breakpoints
    that prevalidate, synchronously apply, and record scheduler controls in the
    session control log, typed rejection of unsupported action variants and
    unrepresentable fault actions, `NodeState`/`AssertionState`/`After`/`Timer`/
    `Quiescent` leaves, 17a combinators including persistent `Once` latches, and
    step modes evaluated through one-shot breakpoint stop conditions. Host-oracle
    `Named` predicates and metadata-backed white-box/symbol leaves still require
    a session-visible host metadata/oracle surface before they can fire outside
    the existing shared evaluator.
- [x] **T-SESS-8** Wire save/resume/fork at the session level purely as
  execution-model/temporal-graph operations (fat-checkpoint materialize keyed by
  config.id with oracle validation; instantiate-from-checkpoint; instantiate a
  prefix into an independent child actor), with no bespoke restored/forked code
  path. — satisfies [SESS-18], [SESS-19]; spec §7.
  - Completed by `checks.crucible.phase5.sessionSaveResumeFork`:
    `TemporalGraph` now exposes checkpoint-addressed configuration lookup and
    `resume_checkpoint`, which resolves a checkpoint to its recorded
    configuration before delegating to the existing `resume`/`instantiate` path.
    `crucible-session` routes runtime realization through `TemporalGraph::resume`,
    materializes savepoints through `save_checkpoint`, returns fork handles that
    identify both checkpoint and configuration, and adds `Engine` helpers for
    resume-from-checkpoint and fork-from-checkpoint child actors. The actor
    command path can also be constructed with a fork-loop factory, so a `fork`
    command returns child mailbox/live-snapshot handles for an independently
    spawned actor. Focused tests prove savepoint resume and checkpoint-prefix
    fork produce independent paused actors, child mutation leaves the parent
    snapshot unchanged, and direct checkpoint fork helpers reject loaded/running
    parents until the caller pauses at a boundary.
- [x] **T-SESS-9** Implement control-operation determinism: record every
  state-mutating intervention (inject/heal, mutating Action breakpoints) as a
  Decision/control-log entry keyed by virtual-time boundary; prove an
  interactively-controlled run reproduces bit-identically from its artifact and
  that operator wall-clock timing cannot influence State. — satisfies [SESS-20],
  [SESS-21], [SESS-22]; spec §8; cross-ref 24 §12.
  - Completed by `checks.crucible.phase5.sessionControlDeterminism`:
    accepted inject/heal commands now apply scheduler-owned control and append a
    deterministic `SessionControlLogEntry` at both running and paused
    boundaries, using the current frontier/quanta rather than host time.
    `SessionControlReplayArtifact` captures the producer initial configuration,
    final boundary snapshot, and control log, and
    `Engine::replay_control_replay_artifact` replays every scheduler-control
    payload with a fresh `QuantumLoop` only when the recorded quanta,
    virtual-time frontier, scheduler-control batch, and final boundary snapshot
    match. Focused tests cover paused mutator application/logging, mutating
    breakpoint action logging including grouped action batch replay, replay of a
    control-sensitive scheduler state to the same final configuration/frontier,
    and rejection of artifacts whose recorded boundary or final snapshot has
    drifted.
- [x] **T-SESS-10** Implement lock-free observation: the atomics live snapshot
  (state kind, virtual time, log length, quanta counter) written by the actor at
  quantum boundaries and read lock-free; broadcast buses for event-log entries
  and state transitions with lag-or-drop, no back-pressure. — satisfies
  [SESS-23], [SESS-24], [SESS-25]; spec §9; cross-ref 05 [EXEC-29].
  - Completed by `checks.crucible.phase5.sessionLockFreeObservation`:
    `LiveSnapshot` remains actor-written and atomically read through
    `LiveSnapshot::read`, `LiveSnapshot::query`, and
    `SessionActor::live_status`, while the session actor publishes every
    appended event-log entry through the cursor-backed bounded `SessionEventLog`
    broadcast tail and every full `EngineState` transition through
    `SessionStateTransitionBus`. Slow event-log and state-transition subscribers
    report `Lagged` rather than exerting back-pressure, and focused crate plus
    `gate_control_responsive` tests cover lock-free status reads, mirror-backed
    state/event-log-length queries, event-log cursor streams, state-transition
    streams, and observation-only subscriptions.
- [ ] **T-SESS-11** Define and implement the pluggable `SimulationBackend` trait
  (step_to/apply/snapshot/restore/now/fingerprint/shutdown) with the QEMU
  backend, the `SimDouble`, and a mock satisfying it interchangeably; keep the
  scheduler the single source of timing truth. — satisfies [SESS-26], [SESS-27];
  spec §10; cross-ref 24 [HARN-14].
  - Partial evidence under `checks.crucible.phase5.sessionSimulationBackend`:
    `SimulationBackend` is the shared backend boundary for scheduler-supplied
    `step_to`, boundary-applied effects, backend snapshots/restores,
    scheduler-mirrored `now`, fingerprint sampling, and shutdown. The pure
    mock, `SimBackend`, in-process `SimDouble`, and QEMU `QemuNode` implement the
    same trait, with focused tests covering object-safe mock dispatch,
    scheduler-owned time rejection, full-state SimDouble snapshot/restore,
    rejection of trait-level SimDouble outbound sends without scheduler
    authorization, and QEMU channel routing plus restore-time mirror updates
    without introducing a backend-owned timing source.
- [ ] **T-SESS-12** Run the full session/lifecycle/command suite and
  `gate:control-responsive` / `gate:scheduler-liveness` against the in-process
  `SimDouble` (no real QEMU), asserting only fidelity properties require the QEMU
  backend. — satisfies [SESS-28]; spec §10; cross-ref 24 §2, §3.
  - Partial evidence under `checks.crucible.phase5.sessionSimDoubleSuite`: the aggregate
    runs the full `crucible-session` suite, the API and daemon
    `gate_control_responsive` targets, and `gate:scheduler-liveness` under the
    `test-double` feature with an initialized and stepped `crucible::SimDouble`
    smoke path before the pure scheduler-liveness reduction. Source checks assert
    the session/API/daemon control-responsive paths drive `crucible::SimDouble`
    through quantum-loop adapters, avoid QEMU backend construction or process
    launch, and reserve real QEMU for Contract A, guest non-mutation, and patch
    inertness fidelity properties only.
- [x] **T-SESS-13** Implement the read-only debugging / time-travel command set
  (attach_gdb/goto/reverse_step/reverse_continue) as repositioning over
  checkpoint-restore + deterministic replay, excluded from the schedule like
  query/pause, with mutating/forward-from-attach forking a clearly-marked
  NON-CANONICAL debug branch; add the optional `open_gdbstub` backend capability
  (QEMU binds a mediated listener; SimDouble/mock reject). — satisfies [SESS-33], [SESS-32];
  spec §4.4, §10; cross-ref [`36-time-travel-debugging.md`](36-time-travel-debugging.md).
  - Completed by `checks.crucible.phase5.sessionDebugTimeTravel`: the session
    command enum now exposes `AttachGdb`, `DebugGoto`, `DebugReverseStep`,
    `DebugReverseContinue`, and `DebugForkNonCanonical`; debug repositioning
    delegates to `TemporalGraph::debug_goto` / reverse helpers, updates the
    session boundary mirror without appending scheduler control-log entries, and
    blocks forward/mutating commands until `DebugForkNonCanonical` records a
    marked debug branch and appends its fork marker to the actor event-log
    stream. The backend traits expose optional `open_gdbstub`; `BackendQuantumLoop`
    routes that capability to a wrapped live backend, `QemuNode` binds and
    retains a mediated listener, and `SimDouble`/`MockSimulationBackend` return
    typed `Unsupported` errors.
