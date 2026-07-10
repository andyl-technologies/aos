# 29 — Patterns and code sketches

This file is the **concrete code-sketch reference** for Crucible. Where the
topic files state *what must be true* (the prose requirements that are
authoritative), this file shows *the shape the code takes* when those
requirements are realized idiomatically — the load-bearing patterns, presented
as Crucible's own, with tight, docs.rs-quality Rust.

Every code block here is an **illustrative sketch**, tagged ` ```rust,illustrative `
(or `rust,no_run` / `rust,ignore` where a runnable signature is shown), per the
conventions in [`00-conventions.md`](00-conventions.md) §"Code sketches": the
sketches show intended types, signatures, ownership, and atomic-ordering rules so
the spec is concrete. **The authority is the prose requirement in the cited file;
a sketch that disagrees with a requirement is a defect in the sketch.** The
requirement IDs in this file use the prefix `PAT`, and each `PAT-n` points an
implementor at the section that demonstrates the pattern and the spec file that
*defines* it.

Requirement IDs referenced here are defined in: the execution model
([`05-execution-model.md`](05-execution-model.md)), the determinism contract
([`04-determinism-contract.md`](04-determinism-contract.md)), the temporal graph
([`07-temporal-graph.md`](07-temporal-graph.md)), cross-node scheduling
([`08-scheduling.md`](08-scheduling.md)), the shared-memory ABI
([`13-shmem-abi.md`](13-shmem-abi.md)), the protocol
([`14-protocol.md`](14-protocol.md)), the I/O sub-nodes
([`15-io-subnodes.md`](15-io-subnodes.md)), the session control plane
([`20-session-control-plane.md`](20-session-control-plane.md)), and the
determinism harness ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)).

The nine patterns:

```text
  §29.1  the async session/engine state machine       realizes 05, 20
  §29.2  the scheduler quantum loop                    realizes 08
  §29.3  the lock-free SPSC ring + ceiling + futex     realizes 13
  §29.4  content-addressed store + thin/fat + CoW       realizes 07
  §29.5  name-hash seeded RNG forking                  realizes 04
  §29.6  the SimulationBackend trait + in-proc double  realizes 20, 24
  §29.7  the CoW block overlay                         realizes 15
  §29.8  the framed codec                              realizes 13, 14
  §29.9  the recursive instantiate                     realizes 05
```

---

## 29.1 The async session/engine state machine

**Intent.** The host-side driver that turns the pure execution model (05) into a
live, controllable run is an **explicit enum-of-states machine** owned by a
single actor task. It owns all runtime state, processes control commands and
units of execution as queued messages, advances in **bounded quanta**, and
**yields between quanta** — so a control operation (pause, inspect, fork, save)
lands at a well-defined boundary and is never blocked behind a long-held lock.
This is the pattern the rest of the control plane is built on; get it clean and
"responsive control" falls out by construction instead of being bolted on.

**Invariants.** Exactly one of a closed set of run-states holds at all times
([SESS-4]); the actor is the sole writer of runtime state, reached only by
message ([SESS-1], [SESS-7]); a quantum is bounded work and the loop returns to
the mailbox between quanta with no lock held across a quantum ([SESS-2],
[SESS-9], [INV-8]); a command enqueued while `Running` takes effect at the next
quantum boundary, measured in quanta not wall-clock ([SESS-3]); the
`Configuration` is the source of truth and the `RuntimeState` a rebuildable cache
([EXEC-30]).

**Realizes.** [`05-execution-model.md`](05-execution-model.md) §10 (the `Engine`
async state machine) and [`20-session-control-plane.md`](20-session-control-plane.md)
§§1–3 (session-as-actor, the lifecycle, the actor loop).

```rust,illustrative
/// The session run-state. A closed set; transitions are the only points at
/// which control operations take effect ([SESS-4], 05 §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Configuration set, runtime not yet instantiated (05 §5).
    Loaded,
    /// Actively stepping the scheduler in bounded quanta, polling the mailbox
    /// between quanta ([SESS-2]).
    Running,
    /// At a quantum boundary, idle on the mailbox: inspect / step / fork / save
    /// / inject are valid here. The reason is a *resumable cause*.
    Paused { reason: PauseReason },
    /// Terminal. The outcome is *final* — distinct from a pause reason ([SESS-5]).
    Stopped { outcome: Outcome },
}

/// The session actor: owns all runtime state, reached only by message
/// ([SESS-1]). There is no shared mutex over the engine, because there is no
/// shared engine — there is one task that owns it.
pub struct Session {
    /// The execution-model driver: `Configuration` (truth) + `RuntimeState`
    /// (cache) + the run-state above (05 §10).
    engine: Engine,
    /// The one authoritative scheduler (08); driven only on this task.
    scheduler: Scheduler,
    /// Checkpoint DAG + content-addressed store handle (07).
    graph: TemporalGraph,
    /// Pluggable backend: real QEMU (10), the in-process double (24 §3), or a
    /// mock — the session cannot tell them apart (§29.6).
    backend: Box<dyn SimulationBackend>,
    /// Mid-run mutating commands deferred to the next quantum boundary (§5).
    deferred: VecDeque<Command>,
    /// Lock-free run-state mirror for observers (§29.1 below, [SESS-23]).
    live: Arc<LiveSnapshot>,
}

impl Session {
    /// Advance exactly one bounded quantum, then return control. Pure-ish:
    /// it mutates runtime, never the `Configuration`'s identity, and never
    /// blocks unbounded ([SESS-9]).
    ///
    /// # Errors
    /// Returns an error if the backend faults or the replay oracle (07 §6)
    /// detects divergence while stepping.
    fn step_quantum(&mut self) -> Result<StepOutcome, SessionError> {
        let outcome = self.scheduler.step_quantum(&mut *self.backend)?;
        self.publish_observation(); // lock-free mirror update; never blocks
        Ok(outcome)
    }

    /// Apply one control command on the actor task. Either performs a defined
    /// transition or rejects with a typed, side-effect-free error that leaves
    /// the state unchanged ([SESS-6], [SESS-29]).
    ///
    /// # Errors
    /// Returns [`SessionError::InvalidState`] if the command is not valid in
    /// the current run-state; propagates backend and oracle errors.
    fn apply_command(&mut self, cmd: Command) -> Result<(), SessionError> {
        match (self.engine.state(), &cmd) {
            (SessionState::Paused { .. }, Command::Continue) => self.engine.set_running(),
            (SessionState::Running, Command::Pause) => {
                self.engine.pause(PauseReason::UserRequested)
            }
            // mutating commands issued mid-run are deferred, not applied now (§5)
            (SessionState::Running, c) if c.mutates_scheduler_state() => {
                self.deferred.push_back(cmd);
            }
            (state, c) => {
                return Err(SessionError::InvalidState {
                    command: c.name(),
                    state: state.name(),
                })
            }
        }
        Ok(())
    }
}

/// The actor loop. In `Running`, prefer servicing a pending command over
/// stepping, then step exactly one bounded quantum and yield; in
/// `Loaded`/`Paused`, block *only* on the mailbox; in `Stopped`, drain
/// read-only commands and exit. This is the whole control plane in one loop
/// ([SESS-8], `gate:control-responsive`).
async fn run_session(mut s: Session, mut mailbox: CommandRx) -> Result<(), SessionError> {
    loop {
        match s.engine.state() {
            SessionState::Running => {
                // A pause is therefore at most one quantum away ([SESS-3]).
                if let Some(cmd) = s.deferred.pop_front().or_else(|| mailbox.try_recv().ok()) {
                    s.apply_command(cmd)?;
                    continue;
                }
                match s.step_quantum()? {
                    StepOutcome::Advanced => {}
                    StepOutcome::Quiescent => s.engine.stop(Outcome::Passed),
                    StepOutcome::Violation(v) => s.engine.stop(Outcome::Failed { violations: v }),
                    StepOutcome::TimeLimit => s.engine.stop(Outcome::Timeout),
                    StepOutcome::Breakpoint(id) => s.engine.pause(PauseReason::Breakpoint { id }),
                }
                tokio::task::yield_now().await; // bounded, cooperative; no lock held
            }
            SessionState::Loaded | SessionState::Paused { .. } => {
                // Block ONLY on the mailbox — fully responsive, no spin, no lock.
                let cmd = mailbox.recv().await.ok_or(SessionError::ChannelClosed)?;
                s.apply_command(cmd)?;
            }
            SessionState::Stopped { .. } => {
                while let Ok(cmd) = mailbox.try_recv() {
                    if cmd.is_read_only() {
                        s.apply_command(cmd)?;
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

The shape to copy is the `match engine.state()` at the top of the loop with one
arm per run-state, the *command-before-step* preference inside `Running`, the
single `yield_now().await` per quantum, and the *block-only-on-mailbox* arm for
the idle states. Commands that mutate scheduler-owned state are pushed to
`deferred` and applied at the next boundary (§29.1 ↔ §5 in 20), never mid-quantum.

- **[PAT-1]** The host-side driver SHOULD follow the explicit enum-of-states +
  bounded-quantum poll/step actor-loop shape in §29.1: a closed `SessionState`,
  a single owning task reached only by message, *service a pending command
  before stepping*, exactly one bounded quantum then a cooperative yield, and
  *block only on the mailbox* when idle. No long-held lock may guard the engine
  across a run. *Spec:* [`05-execution-model.md`](05-execution-model.md) §10
  ([EXEC-27], [EXEC-28]), [`20-session-control-plane.md`](20-session-control-plane.md)
  §§1–3 ([SESS-1], [SESS-2], [SESS-8]).

- **[PAT-2]** The driver SHOULD treat the `Configuration` as the source of truth
  and the `RuntimeState` as a rebuildable cache it can drop and re-`instantiate`
  at any quantum boundary with no observable change (memory-pressure eviction
  safety, §29.9). *Spec:* [`05-execution-model.md`](05-execution-model.md) §10
  ([EXEC-30]).

---

## 29.2 The scheduler quantum loop

**Intent.** The single authoritative scheduler (08) advances the whole
multi-node system one **quantum** at a time using the five-phase vocabulary
**PICK / RUN / RESOLVE / EMIT / STEP**. PICK selects the global-minimum-horizon
node; RUN advances it under `-icount` to its horizon (and no further); RESOLVE
processes every now-due cross-node event in one deterministic total order; EMIT
appends the ordered event-log entries; STEP appends the decisions to the schedule
and yields to the control inbox. The quantum is the atomic unit of *both*
advancement and control.

**Invariants.** The horizon is computed *once* per RUN and a single max-advance
ceiling is published — no intermediate ceiling a plugin could read at a
host-timing-dependent moment ([SCHED-27]); local exact events tighten the horizon
*exactly* while only guest→guest network uses the conservative CMB lookahead
([SCHED-9], [SCHED-10]); due events resolve in `(virtual_time, consumer node_id,
producer node_id, sequence)` order ([SCHED-15]–[SCHED-18]); a consumer found past
a due event's delivery icount fails loudly rather than delivering late
([SCHED-31]); the quantum sequence is a pure function of `(ScenarioDef, Seed,
Schedule)` ([SCHED-24]); the loop yields to control between STEP and the next
PICK ([SCHED-3], [SCHED-33]).

**Realizes.** [`08-scheduling.md`](08-scheduling.md) §§8.4, 8.6, 8.9
(the horizon rule, the total order, the quantum algorithm).

```rust,illustrative
/// The furthest virtual time a node may advance to before it must
/// synchronize: `min(next exact local event, vt(n) + lookahead(n))`
/// ([SCHED-9]). The exact-local term carries NO conservative slack; the
/// lookahead term governs ONLY the guest→guest network dependency ([SCHED-10]).
fn horizon(state: &SchedState, n: NodeId) -> VirtualTime {
    let local = state.next_exact_local_event(n); // timer | I/O completion | local fault
    let net = state.vt(n) + state.lookahead(n); // min inbound link latency; +inf if none
    match local {
        Some(t) => t.min(net),
        None => net,
    }
}

/// One scheduler quantum: PICK / RUN / RESOLVE / EMIT / STEP, in that order.
/// The sequence of quanta is a pure function of `(ScenarioDef, Seed, Schedule)`
/// ([SCHED-24]). The authority is the prose of 08; this is illustrative.
///
/// # Errors
/// Returns an error if a node ran past a due event's delivery icount
/// ([SCHED-31], a contract violation that must fail loudly, never deliver late).
fn quantum(
    state: &mut SchedState,
    rng: &mut DecisionRng,
    backend: &mut dyn SimulationBackend,
    log: &mut EventLogWriter,
) -> Result<StepOutcome, SchedError> {
    // ---- PICK: global-minimum horizon, ties by ascending node_id ([SCHED-25]).
    let Some(n) = state.alive_nodes().min_by_key(|&n| (horizon(state, n), n)) else {
        return Ok(StepOutcome::Quiescent);
    };
    let h = horizon(state, n); // computed ONCE for this RUN ([SCHED-27])
    if h.is_infinite() && state.queues_empty() {
        return Ok(StepOutcome::Quiescent); // [SCHED-22]
    }

    // ---- RUN: publish exactly one ceiling; advance n under -icount to h.
    let run = backend.run_to_ceiling(n, state.vt_to_icount(h))?; // one ceiling write
    match run {
        RunResult::Idle { wake } => state.set_effective_clock(n, wake), // fast-forward ([SCHED-28])
        RunResult::Output { .. } | RunResult::ReachedCeiling => {}
    }

    // ---- RESOLVE: all now-due cross-node events in the total order ([SCHED-15..18]).
    let mut decisions = Vec::new();
    let mut due = state.collect_due_events(); // delivery_vt <= advanced frontier
    due.sort_by_key(|e| (e.delivery_vt, e.consumer, e.producer, e.seq));
    for ev in &due {
        if state.consumer_passed(ev) {
            return Err(SchedError::DeliveredLate(ev.key())); // [SCHED-31] fail loud
        }
        match ev.kind {
            EventKind::Frame => {
                let d = state.apply_fault_table(ev, rng); // probabilistic draws recorded ([SCHED-30])
                if d.delivered {
                    state.make_visible_at(ev.consumer, ev.delivery_icount, &d.payload);
                }
                decisions.extend(d.recorded);
            }
            EventKind::IoDone => state.make_visible_at(ev.consumer, ev.delivery_icount, &ev.payload),
            EventKind::Fault => {
                state.activate_fault(ev);
                state.recompute_lookahead(); // topology change ([SCHED-37])
            }
        }
    }

    // ---- EMIT: ordered, content-addressed log entries, same total order ([SCHED-32]).
    for ev in &due {
        log.append_event(ev);
    }
    for d in &decisions {
        log.append_decision(d);
    }

    // ---- STEP: append decisions, advance frontier, yield to control ([SCHED-33]).
    state.commit(&decisions);
    Ok(StepOutcome::Advanced) // caller yields to the control inbox before next PICK
}
```

The discipline to copy: compute `h` once and publish one ceiling; sort due events
by the full four-field key before resolving; route every probabilistic choice
through the seeded `DecisionRng` *in the total order* so the draw sequence is
itself deterministic; and treat "consumer already passed a due event" as a hard
error, never a late delivery.

- **[PAT-3]** The scheduler SHOULD follow the PICK / RUN / RESOLVE / EMIT / STEP
  quantum shape in §29.2: pick the global-minimum-horizon node, compute the
  horizon and publish a single ceiling per RUN, resolve due events in the
  `(virtual_time, consumer, producer, sequence)` total order, draw every
  probabilistic choice from the seeded RNG in that order, emit ordered log
  entries, then step and yield. *Spec:* [`08-scheduling.md`](08-scheduling.md)
  §§8.4, 8.6, 8.9 ([SCHED-9], [SCHED-15]–[SCHED-18], [SCHED-24]–[SCHED-33]).

---

## 29.3 The lock-free SPSC ring + per-node ceiling + futex wake

**Intent.** Cross-node frame delivery and per-node advancement are coordinated
through a single shared-memory region (13) using **atomics plus one cross-process
futex** — no IPC round-trip on the hot path. Each directed `(src, dst)` pair owns
a Lamport single-producer/single-consumer ring whose head and tail sit on
separate cache lines; the producer publishes an entry with a *release* store of
the tail and the consumer reads the tail with *acquire* before touching the entry.
A node that reaches its scheduler-set ceiling parks on its slot's futex word using
the race-free publish-precondition / read-counter / re-check / wait idiom.

**Invariants.** One producer, one consumer per ring; neither endpoint writes the
other's index ([SHM-19]); `release` on publish / `acquire` on observe, no
`SeqCst` ([SHM-20]); capacity a power of two so index→slot is a mask; the futex is
the *non-private* (cross-process) variant and there is no lost-wake window
([SHM-26]); a frame's `delivery_icount` is strictly in the consumer's future at
enqueue, and deliverability is `delivery_icount <= current_icount` —
icount, never wall-clock ([SHM-33], [SHM-35]).

**Realizes.** [`13-shmem-abi.md`](13-shmem-abi.md) §§13.6, 13.7, 13.9
(SPSC mechanics, the ceiling handshake, the futex, icount-not-wallclock delivery).

```rust,illustrative
use std::sync::atomic::{AtomicU64, Ordering};

/// Lamport SPSC ring header. `read_idx` (consumer-owned) and `write_idx`
/// (producer-owned) are monotonic counters on separate cache lines so the
/// producer's store never invalidates the consumer's line ([SHM-12], [SHM-19]).
/// The entry array lives in its own sub-region and is passed in as a slice.
#[repr(C, align(128))]
pub struct RingHeader {
    read_idx: AtomicU64,
    _pad_read: [u8; 56],
    write_idx: AtomicU64,
    _pad_write: [u8; 56],
}
const _: () = assert!(core::mem::size_of::<RingHeader>() == 128);

impl RingHeader {
    /// Enqueue one frame (producer only). The *release* store of `write_idx`
    /// publishes the entry fields written before it ([SHM-20]).
    ///
    /// # Errors
    /// Returns [`QueueFull`] if the ring holds `capacity` live entries.
    pub fn enqueue(&self, entries: &mut [FrameEntry], e: &FrameEntry) -> Result<(), QueueFull> {
        let cap = entries.len() as u64;
        let tail = self.write_idx.load(Ordering::Relaxed); // producer owns it
        let head = self.read_idx.load(Ordering::Acquire); // observe consumer progress
        if tail.wrapping_sub(head) >= cap {
            return Err(QueueFull);
        }
        let slot = &mut entries[(tail % cap) as usize]; // cap is a power of two: a mask
        slot.delivery_icount = e.delivery_icount;
        slot.src_node = e.src_node;
        slot.seq = e.seq;
        slot.len = e.len;
        slot.data[..e.len as usize].copy_from_slice(&e.data[..e.len as usize]);
        self.write_idx.store(tail + 1, Ordering::Release); // publish
        Ok(())
    }

    /// The next entry's delivery icount without consuming it, so the scheduler
    /// can compute a node's next inbound-frame horizon ([SHM-21]).
    pub fn peek_delivery_icount(&self, entries: &[FrameEntry]) -> Option<u64> {
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        (head < tail).then(|| entries[(head % entries.len() as u64) as usize].delivery_icount)
    }
}

/// Park a node at its ceiling on the slot's `wake_signal` word with the
/// race-free idiom: publish the precondition, read the counter, re-check for
/// actionable work, then wait on that exact value. If the waker bumps it before
/// the read, the re-check skips the wait; if it bumps it between the read and
/// wait, the wait returns at once, so there is no lost-wake window ([SHM-26]).
/// The futex is non-private (cross-process): waiter and waker are different
/// processes sharing the word.
fn park_at_ceiling(slot: &NodeSlot, wake_icount: u64) {
    slot.idle_wake_icount.store(wake_icount, Ordering::Release);
    slot.status.store(STATUS_IDLE, Ordering::Release);
    let observed = slot.wake_signal.load(Ordering::Acquire);
    if slot.max_advance_icount.load(Ordering::Acquire) < wake_icount {
        futex_wait_shared(&slot.wake_signal, observed); // FUTEX_WAIT, non-private
    }
    slot.status.store(STATUS_RUNNING, Ordering::Release);
}

/// Wake a parked node (scheduler side): increment the counter with a release
/// add so a concurrent about-to-wait returns immediately, then FUTEX_WAKE. A
/// wake is cheap even when no one is parked ([SHM-27]). The scheduler MUST
/// write any due input to the inbound ring BEFORE this wake, so the woken
/// plugin sees a consistent (ceiling, pending-inputs) snapshot ([SCHED-36]).
fn wake(slot: &NodeSlot) {
    slot.wake_signal.fetch_add(1, Ordering::Release);
    futex_wake_shared(&slot.wake_signal, 1);
}

/// Deliverability is a pure function of two icounts ([SHM-33]): a frame is
/// architecturally visible iff its delivery icount has been reached. The
/// wall-clock moment the producer's store landed is irrelevant.
#[inline]
fn is_deliverable(frame: &FrameEntry, consumer_current_icount: u64) -> bool {
    frame.delivery_icount <= consumer_current_icount
}
```

Two things make this correct and not merely fast: the *release/acquire* pairing
(publish the entry, then the index; read the index, then the entry) and the
*publish-precondition-then-read-counter-then-re-check-then-wait* futex idiom. Off-Linux the
futex calls compile to no-ops so the pure atomic/SPSC logic still unit-tests
([SHM-28]); the blocking path is never exercised off a simulation host.

- **[PAT-4]** The transport SHOULD follow the SPSC + ceiling + futex shape in
  §29.3: one Lamport ring per directed pair with cache-line-separated indices,
  release-on-publish / acquire-on-observe ordering, a power-of-two capacity, the
  non-private race-free futex idiom, *write inbound input before waking*, and
  icount-not-wallclock deliverability. *Spec:* [`13-shmem-abi.md`](13-shmem-abi.md)
  §§13.6, 13.7, 13.9 ([SHM-19], [SHM-20], [SHM-24]–[SHM-27], [SHM-33], [SHM-35]).

- **[PAT-5]** The SPSC ring SHOULD be covered by property-based and `loom`-style
  concurrency tests exhausting the producer/consumer interleavings the ordering
  rules permit (no entry lost, duplicated, torn, or read before its
  release-store publish). *Spec:* [`13-shmem-abi.md`](13-shmem-abi.md) §13.6
  ([SHM-23]).

---

## 29.4 Content-addressed store + thin/fat checkpoint + CoW delta

**Intent.** The temporal graph (07) is a content-addressed DAG of checkpoints
whose identity is `hash(parent_id, schedule_delta)` and whose cached realization
is optional. A **thin** checkpoint stores only `(parent, schedule_delta)` and is
always correct (reconstructed by replay); a **fat** checkpoint additionally
carries a `MaterializedState` stored as a **copy-on-write delta** over its nearest
fat ancestor, so a fork stores only what changed. The content-addressed store
gives equal content equal identity, enabling sharing and dedup across the graph.

**Invariants.** Identity is a pure function of `(parent_id, schedule_delta)` and
of *nothing* in the cached state ([TEMP-4]); a fat checkpoint and its thin
derivation denote the same state and hash-equal under the replay oracle
([INV-2]); every stored piece is a content-addressed reference or a CoW delta, so
unchanged pieces are shared not copied ([INV-6]); a `put` is idempotent — storing
equal bytes twice yields one object.

**Realizes.** [`07-temporal-graph.md`](07-temporal-graph.md) §§2–5 (checkpoint
identity, `MaterializedState`, thin/fat, CoW delta).

```rust,illustrative
/// A 32-byte content address: the fixed, cross-platform stable hash of an
/// object's canonical bytes. Equal content ⇒ equal id ([INV-6]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash([u8; 32]);

/// A content-addressed blob store. `put` is idempotent: storing equal bytes
/// twice returns the same id and stores the object once.
pub trait DagStore {
    /// Store `bytes`, returning their content address. Idempotent.
    ///
    /// # Errors
    /// Returns an error if the backing store cannot persist the object.
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, StoreError>;

    /// Fetch the object at `id`, or `None` if absent.
    ///
    /// # Errors
    /// Returns an error if the backing store cannot be read.
    fn get(&self, id: ContentHash) -> Result<Option<Vec<u8>>, StoreError>;
}

/// One node of the temporal graph. Identity is `hash(parent, schedule_delta)`
/// and of nothing in `state` ([TEMP-4]); `state` is a cache that may be present
/// (fat) or absent (thin), and the two are interchangeable to the model.
pub struct Checkpoint {
    /// `hash(parent, schedule_delta)` — the only identity ([TEMP-4]).
    pub id: ContentHash,
    /// `None` only at genesis.
    pub parent: Option<ContentHash>,
    /// The decision(s) on the incoming edge (sorted; the `schedule_delta`).
    pub schedule_delta: SmallVec<[Decision; 1]>,
    /// `Some` iff fat. A fat checkpoint's state is a CoW delta over its nearest
    /// fat ancestor (07 §5); a thin checkpoint stores nothing here (07 §4).
    pub state: Option<MaterializedState>,
}

/// The cached realization of `reduce(def, schedule)` at a fat checkpoint. Every
/// field is a content-addressed reference or a CoW delta over the parent's
/// `MaterializedState`, so a fat checkpoint stores only what changed (07 §3, §5).
pub struct MaterializedState {
    /// Per-VM memory + device state as CoW deltas over the parent blob (07 §5).
    pub nodes: Vec<NodeBlobRef>,
    /// Serialized scheduler state (per-node clocks, pending events, RNG cursor).
    pub scheduler: ContentHash,
}

/// A VM's state inside any configuration: ALWAYS a content-addressed blob
/// reference. No "initial vs materialized" dichotomy — genesis references the
/// baked blob; later nodes reference CoW deltas over a parent ([EXEC-21]).
pub enum NodeBlobRef {
    /// Genesis: the baked snapshot for this node (05 §6).
    Baked(ContentHash),
    /// A copy-on-write delta over a parent blob (07 §5, 15).
    CowDelta { parent: ContentHash, delta: ContentHash },
}

impl Checkpoint {
    /// Construct a child checkpoint's identity from a parent and a decision
    /// delta — pure, no I/O, no materialization ([TEMP-4], 05 [EXEC-10]).
    pub fn child_id(parent: ContentHash, delta: &[Decision]) -> ContentHash {
        ContentHash::of((&parent, delta))
    }
}
```

The rule to copy: identity is derived from `(parent, schedule_delta)` *before*
anything is run or materialized, the `state` cache is strictly additive, and a
fat checkpoint is validated against its thin derivation by the replay oracle —
the two must hash-equal, which is only *expressible* because the runtime is a
cache, not the identity (05 §2).

- **[PAT-6]** The temporal graph SHOULD follow the content-addressed
  store + thin/fat + CoW-delta shape in §29.4: checkpoint identity is
  `hash(parent_id, schedule_delta)`, the materialized state is an optional cache
  of CoW deltas over the nearest fat ancestor, a VM's state is uniformly a
  content-addressed blob reference, and `put` is idempotent. *Spec:*
  [`07-temporal-graph.md`](07-temporal-graph.md) §§2–5 ([TEMP-4], [EXEC-21],
  [INV-2], [INV-6]).

---

## 29.5 Name-hash seeded RNG forking

**Intent.** All probabilistic decisions derive from a single root seed via
**deterministic forking**: each entity (node, link) gets its own RNG stream
seeded by mixing the root seed with the *hash of the entity's name*. Same
`(seed, name)` always yields the same stream; different names yield independent
streams; and — critically — adding, removing, or renaming an *unrelated* entity
does not perturb any other entity's stream, so a schedule stays interpretable
after the `ScenarioDef` changes only in unrelated parts.

**Invariants.** Streams are forked by name-hash, so an unrelated `World` edit
does not move another stream's draws ([EXEC-9]); the mixing hash is a fixed,
cross-platform stable hash, never the language's randomized default ([SCHED-19],
[INV-9]); every recorded `Decision::RngDraw` carries its `RngStreamId` so a draw
is attributable to its stream after the def changes ([EXEC-9]); node-stream and
link-stream forks of the same name are distinct.

**Realizes.** [`04-determinism-contract.md`](04-determinism-contract.md) §4.7
(the seeded decision RNG; per-entity streams forked by name-hash).

```rust,illustrative
/// Derives every per-entity decision-RNG stream from one root seed by
/// name-hash forking. Same `(seed, name)` ⇒ same stream; unrelated names are
/// independent, so adding a node does not perturb other streams' draws
/// ([EXEC-9], 04 §4.7).
pub struct DecisionRng {
    seed: u64,
}

impl DecisionRng {
    /// A new decision-RNG controller rooted at `seed`.
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Fork the stream for a named node. A fixed, cross-platform stable hash
    /// (never the language's randomized default, [SCHED-19]) mixes the name
    /// into the seed.
    pub fn fork_for_node(&self, name: &str) -> StreamRng {
        StreamRng::seed_from_u64(self.seed ^ stable_hash64(name.as_bytes()))
    }

    /// Fork the stream for a named link (e.g. `"a->b"`). A distinct mixing
    /// constant separates link streams from the node stream of the same name.
    pub fn fork_for_link(&self, name: &str) -> StreamRng {
        const LINK_TWEAK: u64 = 0x9E37_79B9_7F4A_7C15; // fixed domain separator
        StreamRng::seed_from_u64(self.seed ^ stable_hash64(name.as_bytes()) ^ LINK_TWEAK)
    }
}

/// A recorded draw, attributed to its stream so a schedule remains
/// interpretable after the def changes only in unrelated parts ([EXEC-9]).
pub struct RecordedDraw {
    pub stream: RngStreamId,
    pub value: u64,
}
```

The pattern is the per-entity *fork* (not a single shared cursor everyone draws
from): a shared cursor would couple every entity's draws to every other's, so
adding one node would shift the entire stream. Name-hash forking gives each
entity a private, reproducible stream and a stable identity to record draws
against. Use a fixed stable hash and a distinct domain-separation constant per
entity kind.

- **[PAT-7]** The decision RNG SHOULD follow the name-hash forking shape in
  §29.5: derive each per-entity stream by mixing the root seed with a fixed,
  cross-platform stable hash of the entity name (distinct domain constants per
  kind), and record each draw with its `RngStreamId`. Unrelated `World` edits
  MUST NOT perturb other streams. *Spec:*
  [`04-determinism-contract.md`](04-determinism-contract.md) §4.7,
  [`05-execution-model.md`](05-execution-model.md) §3 ([EXEC-9]),
  [`08-scheduling.md`](08-scheduling.md) §8.6 ([SCHED-19]).

---

## 29.6 The backend trait + in-process double

**Intent.** The session drives VMs through a **pluggable `SimulationBackend`
trait** defined against the shmem/protocol boundary (13/14), never against a
QEMU-specific type. This lets the *same* session, scheduler, command set, and
lifecycle run against three interchangeable backends: real QEMU (fidelity), an
**in-process double** (`SimDouble` — fast, deterministic testing of all host
orchestration without booting a guest), and a mock (state-machine unit tests).
The control plane (L4) is therefore testable in milliseconds, and
`gate:control-responsive` / `gate:scheduler-liveness` do not need real QEMU.

**Invariants.** The backend advances nodes toward a scheduler-supplied ceiling
and *reports* — it never resolves cross-node order, evaluates properties, or
advances virtual time of its own accord; the scheduler stays the single source of
timing truth ([SESS-27], [SCHED-1], [SCHED-4]); the double is a drop-in the
session cannot distinguish from real QEMU through the trait ([SESS-26],
[HARN-14]); `snapshot`/`restore` capture exactly the node state the temporal
graph's `MaterializedState` requires ([SESS-27]).

**Realizes.** [`20-session-control-plane.md`](20-session-control-plane.md) §10
(the backend trait) and [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
§3 (the in-process double).

```rust,no_run
/// The pluggable simulation backend. The session delegates all node-level
/// operations through this trait, keeping the control plane backend-agnostic
/// ([SESS-26]). Implemented by the QEMU backend (10), the `SimDouble` (24 §3),
/// and a mock.
#[async_trait::async_trait]
pub trait SimulationBackend: Send {
    /// Advance the backend's nodes by one bounded quantum toward `ceiling`
    /// virtual time and report what was observed. The backend does NOT resolve
    /// cross-node order or evaluate properties — the scheduler (08) owns that
    /// ([SESS-27], [SCHED-1]).
    ///
    /// # Errors
    /// Returns an error if a node fails to advance or the transport faults.
    async fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError>;

    /// Materialize the backend's node state into a content-addressed snapshot
    /// for a fat checkpoint (07 §3).
    ///
    /// # Errors
    /// Returns an error if a node's state cannot be captured.
    async fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError>;

    /// Restore the backend to a prior snapshot (the `loadvm` branch of
    /// `instantiate`, 05 §5).
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be restored.
    async fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError>;

    /// The backend's current virtual time — a mirror of the scheduler's; the
    /// scheduler remains the single source of truth ([SCHED-4]).
    fn now(&self) -> VirtualTime;

    /// Shut all nodes down cleanly (on `stop`).
    ///
    /// # Errors
    /// Returns an error if a node fails to shut down.
    async fn shutdown(&mut self) -> Result<(), BackendError>;
}

/// The in-process double: models each node as a pure deterministic stepping
/// function over the SAME shmem/transport types the real backend uses, so the
/// session cannot tell a `SimDouble` node from a real QEMU node through the
/// trait ([HARN-14]). Boots no guest; runs the whole control plane in millis.
pub struct SimDouble {
    nodes: Vec<DoubleNode>, // pure, seeded, instruction-count-derived clocks
}

#[async_trait::async_trait]
impl SimulationBackend for SimDouble {
    async fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        // Deterministically advance each node's modeled icount to the ceiling
        // and report frames/IO/idle exactly as the real transport would.
        let mut obs = StepObservation::default();
        for node in &mut self.nodes {
            obs.merge(node.advance_to(ceiling));
        }
        Ok(obs)
    }
    async fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Ok(BackendSnapshot::content_addressed(&self.nodes))
    }
    async fn restore(&mut self, s: &BackendSnapshot) -> Result<(), BackendError> {
        self.nodes = s.decode_nodes()?;
        Ok(())
    }
    fn now(&self) -> VirtualTime {
        self.nodes.iter().map(|n| n.vt()).min().unwrap_or_default()
    }
    async fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}
```

The leverage is that the *trait boundary is the shmem/protocol boundary*: because
the session only ever talks ceilings, snapshots, and observations, the double can
be a pure deterministic model and remain a perfect drop-in. A session test that
needs real QEMU to exercise the *control plane* (as opposed to guest fidelity) is
a design defect ([SESS-28]).

- **[PAT-8]** The session SHOULD drive nodes exclusively through a
  `SimulationBackend` trait defined against the shmem/protocol boundary, with the
  backend reporting toward a scheduler-supplied ceiling and never owning timing,
  ordering, or property evaluation; an in-process deterministic double SHOULD be
  a drop-in for testing the whole control plane without a guest. *Spec:*
  [`20-session-control-plane.md`](20-session-control-plane.md) §10 ([SESS-26],
  [SESS-27], [SESS-28]), [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
  §3 ([HARN-14]).

---

## 29.7 The CoW block overlay

**Intent.** An I/O sub-node disk presents a writable device over a **read-only
base image** without ever mutating that image: reads consult an in-memory
copy-on-write overlay first and fall back to the base; writes land *only* in the
overlay, page-aligned. The overlay is the unit of CoW sharing in a fork and of
snapshot delta in a checkpoint, and the device's completions are *exact local
events* whose virtual time the sub-node computes (so they tighten the requester's
horizon exactly, 08 §8.4.1).

**Invariants.** The base image is never written — guest non-modification is a
CoW overlay only ([INV-5]); a snapshot serializes the overlay deterministically
so equal overlay state content-addresses identically ([INV-6]); a completion's
delivery virtual time is host-computed from the request and a fixed completion
model, not from when the host disk happens to finish ([SCHED-10], `DET-19`); a
restore reproduces the overlay exactly.

**Realizes.** [`15-io-subnodes.md`](15-io-subnodes.md) (the block I/O sub-node,
its CoW overlay, and deterministic completions).

```rust,illustrative
const PAGE_SIZE: u64 = 4096;

/// A block I/O sub-node: a read-only base image plus an in-memory copy-on-write
/// overlay. Reads come from the overlay first, then the base; writes go only to
/// the overlay, leaving the base untouched ([INV-5]). Completions are exact
/// local events at a sub-node-computed virtual time (08 §8.4.1).
pub struct BlockOverlay {
    /// Read-only base image; opened read-only and never written.
    base: File,
    /// Total device size in bytes.
    size: u64,
    /// CoW overlay: page-aligned offset -> page. The fork/snapshot unit.
    overlay: BTreeMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
    /// Pages written since the last snapshot — the snapshot *delta*.
    dirty: BTreeSet<u64>,
}

impl BlockOverlay {
    /// Read `count` bytes at `offset`: overlay pages win; the base fills gaps.
    ///
    /// # Errors
    /// Returns an error if the range runs past the end of the device or the
    /// base read fails.
    pub fn read(&mut self, offset: u64, count: u64) -> Result<Vec<u8>, BlockError> {
        if offset + count > self.size {
            return Err(BlockError::OutOfRange);
        }
        let mut buf = vec![0u8; count as usize];
        let mut pos = offset;
        let mut out = 0usize;
        while pos < offset + count {
            let page = pos / PAGE_SIZE * PAGE_SIZE;
            let off = (pos - page) as usize;
            let chunk = ((PAGE_SIZE as usize) - off).min((offset + count - pos) as usize);
            if let Some(p) = self.overlay.get(&page) {
                buf[out..out + chunk].copy_from_slice(&p[off..off + chunk]);
            } else {
                self.base.seek(SeekFrom::Start(pos))?;
                self.base.read_exact(&mut buf[out..out + chunk])?;
            }
            pos += chunk as u64;
            out += chunk;
        }
        Ok(buf)
    }

    /// Write `data` at `offset` into the overlay only (CoW); the base is never
    /// touched. A partially-written page is first faulted in from the base so
    /// the overlay page is complete ([INV-5]).
    ///
    /// # Errors
    /// Returns an error if the range runs past the end of the device.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BlockError> {
        if offset + data.len() as u64 > self.size {
            return Err(BlockError::OutOfRange);
        }
        let mut pos = offset;
        let mut src = 0usize;
        while pos < offset + data.len() as u64 {
            let page = pos / PAGE_SIZE * PAGE_SIZE;
            let off = (pos - page) as usize;
            let chunk = ((PAGE_SIZE as usize) - off).min(offset as usize + data.len() - pos as usize);
            let slot = self.overlay.entry(page).or_insert_with(|| {
                let mut p = Box::new([0u8; PAGE_SIZE as usize]); // fault page in from base
                if page < self.size {
                    let n = PAGE_SIZE.min(self.size - page) as usize;
                    if self.base.seek(SeekFrom::Start(page)).is_ok() {
                        let _ = self.base.read_exact(&mut p[..n]);
                    }
                }
                p
            });
            slot[off..off + chunk].copy_from_slice(&data[src..src + chunk]);
            self.dirty.insert(page);
            pos += chunk as u64;
            src += chunk;
        }
        Ok(())
    }

    /// Serialize only pages dirtied since the last snapshot — the CoW snapshot
    /// *delta* — in deterministic (sorted) order so equal overlay state
    /// content-addresses identically ([INV-6]). The `BTreeMap`/`BTreeSet`
    /// keep iteration order deterministic ([INV-9]).
    pub fn snapshot_delta(&mut self) -> Vec<(u64, Vec<u8>)> {
        let delta = self
            .dirty
            .iter()
            .filter_map(|&off| self.overlay.get(&off).map(|p| (off, p.to_vec())))
            .collect();
        self.dirty.clear();
        delta
    }
}
```

The discipline: open the base read-only; fault a page in from the base before a
partial write so overlay pages are whole; track dirty pages for incremental
snapshot deltas; and use *ordered* containers (`BTreeMap`/`BTreeSet`) so
serialization is byte-deterministic — an unordered map iteration here would break
content addressing.

- **[PAT-9]** The block sub-node SHOULD follow the CoW-overlay shape in §29.7:
  read-only base + in-memory overlay (overlay wins on read, writes go only to
  the overlay), page-fault-in before partial writes, dirty-page tracking for
  incremental snapshot deltas, and ordered containers for deterministic
  serialization. The base image MUST never be written. *Spec:*
  [`15-io-subnodes.md`](15-io-subnodes.md) ([INV-5], [INV-6], [INV-9]).

---

## 29.8 The framed codec

**Intent.** Every wire surface — the control-plane protocol (14) and the
snapshot serialization of the shmem queues (13) — uses an **explicit
length-prefixed framed codec** with a symmetric `encode` / `decode` pair. A frame
is `magic | version | kind | len | payload`; decode validates the magic and
version before trusting a byte, rejects an over-length or truncated frame, and
returns a typed error rather than panicking. The codec is small, total, and
**fuzzable**: `decode(encode(x)) == x` for all `x`, and `decode` never panics on
arbitrary bytes.

**Invariants.** Decode validates `magic` and `version` first and rejects a
mismatch loudly ([SHM-30]); a frame whose `len` exceeds the maximum is rejected
at decode, never silently truncated ([SHM-13]); multi-byte fields are
little-endian and target-pinned ([SHM-6]); the codec is byte-deterministic so a
snapshot content-addresses identically ([SHM-22], [INV-6]); the round-trip and
no-panic properties are fuzz-gated.

**Realizes.** [`13-shmem-abi.md`](13-shmem-abi.md) §13.6 (snapshot/restore
serialization) and [`14-protocol.md`](14-protocol.md) (the framed IPC protocol).

```rust,illustrative
/// Four-byte ASCII magic prefixing every Crucible control frame.
pub const FRAME_MAGIC: u32 = u32::from_le_bytes(*b"CRUC");
/// Protocol version; a decode of a mismatched version is a hard failure.
pub const PROTO_VERSION: u16 = 1;
/// Maximum payload bytes accepted by `decode` (rejected, never truncated).
pub const MAX_PAYLOAD: usize = 1 << 20;

/// A decoded control frame: a kind tag plus an owned payload.
pub struct Frame {
    pub kind: u16,
    pub payload: Vec<u8>,
}

/// Errors from frame decoding. Every variant is a clean rejection — `decode`
/// never panics on arbitrary input (the fuzz invariant).
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("short buffer: need {need} bytes, have {have}")]
    Short { need: usize, have: usize },
    #[error("bad magic: {0:#010x}")]
    BadMagic(u32),
    #[error("unsupported version: {0}")]
    BadVersion(u16),
    #[error("payload too large: {0} > {MAX_PAYLOAD}")]
    TooLarge(usize),
}

/// Encode a frame: `magic(4) | version(2) | kind(2) | len(4) | payload`. All
/// multi-byte fields little-endian and target-pinned ([SHM-6]).
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + frame.payload.len());
    out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    out.extend_from_slice(&PROTO_VERSION.to_le_bytes());
    out.extend_from_slice(&frame.kind.to_le_bytes());
    out.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&frame.payload);
    out
}

/// Decode one frame from the front of `buf`, returning the frame and the number
/// of bytes consumed. Validates magic and version before trusting any field,
/// and rejects an over-length or truncated frame ([SHM-13], [SHM-30]).
///
/// # Errors
/// Returns [`CodecError`] on a short buffer, bad magic, bad version, or an
/// over-`MAX_PAYLOAD` length. Never panics on arbitrary bytes (fuzz invariant).
pub fn decode(buf: &[u8]) -> Result<(Frame, usize), CodecError> {
    if buf.len() < 12 {
        return Err(CodecError::Short { need: 12, have: buf.len() });
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap_or_default());
    if magic != FRAME_MAGIC {
        return Err(CodecError::BadMagic(magic));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap_or_default());
    if version != PROTO_VERSION {
        return Err(CodecError::BadVersion(version));
    }
    let kind = u16::from_le_bytes(buf[6..8].try_into().unwrap_or_default());
    let len = u32::from_le_bytes(buf[8..12].try_into().unwrap_or_default()) as usize;
    if len > MAX_PAYLOAD {
        return Err(CodecError::TooLarge(len));
    }
    if buf.len() < 12 + len {
        return Err(CodecError::Short { need: 12 + len, have: buf.len() });
    }
    Ok((Frame { kind, payload: buf[12..12 + len].to_vec() }, 12 + len))
}
```

The two properties to test (and fuzz): the round-trip `decode(encode(x)).0 == x`
for every frame, and total no-panic `decode` over arbitrary byte slices.
Validating magic and version *before* reading `len`, and bounding `len` against a
fixed maximum, are what make a hostile or corrupt buffer a clean typed error
instead of an out-of-bounds read.

- **[PAT-10]** Every wire surface SHOULD follow the framed-codec shape in §29.8:
  a length-prefixed `magic | version | kind | len | payload` frame, a symmetric
  total `encode`/`decode` pair that validates magic and version before trusting
  any field and bounds `len`, little-endian target-pinned fields, and
  round-trip + no-panic fuzz properties. *Spec:*
  [`13-shmem-abi.md`](13-shmem-abi.md) §13.6 ([SHM-13], [SHM-22], [SHM-30]),
  [`14-protocol.md`](14-protocol.md).

---

## 29.9 The recursive `instantiate` (start ≡ resume ≡ fork)

**Intent.** Producing a runnable `RuntimeState` from *any* configuration —
genesis, the tip of a run, or a non-tip prefix — is **one recursive function**
whose base case is the *baked* genesis snapshot. `instantiate` prefers a stored
snapshot of exactly the configuration; failing that, recurses to the nearest
cached ancestor and replays the missing schedule suffix forward; failing even
that, recurses toward genesis, whose base case is a `loadvm` of the baked blob,
not a cold boot. The only true cold boot in the system lives inside `bake`. This
collapses start, resume, and fork into call sites of one function distinguished
only by which configuration they pass — deleting the lifecycle-bug class of
divergent boot/resume/fork code paths.

**Invariants.** `instantiate` is the single entry point; start/resume/fork differ
only in the configuration argument and there are no separate realization paths
([EXEC-14]); the resolution order is exact-snapshot → ancestor-replay → genesis,
terminating at the baked snapshot ([EXEC-15]); the only cold boot is inside
`bake`, never in the hot loop ([EXEC-16]); every branch yields a content-equal
`RuntimeState` for the same configuration — the branch is a performance decision,
not an observable one (the replay oracle, [EXEC-17], [INV-2]).

**Realizes.** [`05-execution-model.md`](05-execution-model.md) §§5–6 (recursive
`instantiate`, `bake`, start ≡ resume ≡ fork).

```rust,illustrative
/// Materialize a configuration into a live, controllable runtime. Recursive;
/// base case is the baked genesis snapshot (05 §6). Every branch yields a
/// content-equal `RuntimeState` for the same `config` (the replay oracle,
/// [INV-2], [EXEC-17]); the branch chosen is a performance decision only.
///
/// # Errors
/// Propagates store, replay, and backend errors; a replay that diverges from
/// the oracle localizes to the first differing decision (05 §8, [EXEC-24]).
pub fn instantiate(graph: &TemporalGraph, config: &Configuration) -> Result<RuntimeState, ExecError> {
    // 1. Exact snapshot of *this* configuration: warm resume / fork target.
    if let Some(snap) = graph.cached_snapshot(config.id())? {
        return RuntimeState::loadvm(snap);
    }
    // 2. Nearest materialized prefix on this path: recurse, then replay forward.
    if let Some(anc) = graph.nearest_cached_ancestor(config)? {
        let mut rt = instantiate(graph, &anc)?; // recurse to the ancestor
        let suffix = config.schedule.range(anc.schedule.len()..);
        rt.replay(&config.def, suffix)?; // step forward over the missing suffix
        return Ok(rt);
    }
    // 3. Cold case: only genesis reaches here, and its base case is the *baked*
    //    snapshot (a loadvm, not a boot). The one true boot lives in `bake`.
    debug_assert!(config.is_genesis());
    let baked = graph.genesis_snapshot(&config.def)?; // baked once, 05 §6
    RuntimeState::loadvm(baked)
}

/// start / resume / fork are the same call, distinguished only by which
/// configuration is handed to `instantiate` (05 §5 "start ≡ resume ≡ fork",
/// [EXEC-14]). There is no `boot()` distinct from `loadvm()` distinct from
/// `fork()`.
pub fn start(graph: &TemporalGraph, def: ScenarioDef) -> Result<RuntimeState, ExecError> {
    instantiate(graph, &Configuration::genesis(def)) // (def, [])
}
pub fn resume(graph: &TemporalGraph, config: &Configuration) -> Result<RuntimeState, ExecError> {
    instantiate(graph, config) // the tip
}
pub fn fork(graph: &TemporalGraph, config: &Configuration, k: usize) -> Result<RuntimeState, ExecError> {
    let prefix = Configuration { def: config.def.clone(), schedule: config.schedule.prefix(k) };
    instantiate(graph, &prefix) // a non-tip prefix; exploration appends DIFFERENT decisions
}
```

Because start, resume, fork, and snapshot-load are one operation, **one test
validates all four**: instantiate the same configuration twice and assert
identical execution fingerprints (the second realization may have come through a
*different* branch). If they agree, start is deterministic, resume is faithful,
fork is faithful, and snapshot completeness holds — all from a single equality
check, precisely because the model collapsed them into one ([EXEC-31]).

- **[PAT-11]** The runtime realizer SHOULD follow the recursive `instantiate`
  shape in §29.9: resolve exact-snapshot → ancestor-replay → genesis, terminate
  at the baked snapshot, and implement start/resume/fork as call sites differing
  only in the configuration argument with no separate realization paths. The
  only cold boot MUST live inside `bake`. *Spec:*
  [`05-execution-model.md`](05-execution-model.md) §§5–6 ([EXEC-14], [EXEC-15],
  [EXEC-16], [EXEC-17]).

- **[PAT-12]** Because start ≡ resume ≡ fork ≡ snapshot-load, the
  same-configuration-twice fingerprint equality SHOULD be used as the single
  validator of all four. *Spec:* [`05-execution-model.md`](05-execution-model.md)
  §11 ([EXEC-31]), [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

---

## Implementation checklist

> These patterns are mostly *realized by the per-area tasks elsewhere* — the
> sketches here guide *how* those tasks are shaped, not separate deliverables.
> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); each item below
> references the area task(s) that actually build the pattern.

- [x] **T-PAT-1** Ensure the session/engine driver is built to the §29.1
  enum-of-states + bounded-quantum actor-loop shape. — satisfies [PAT-1],
  [PAT-2]; realized by **T-EXEC-14**, **T-SESS-2** (spec 05 §10, 20 §3).
  - Completed by `crates/crucible-session/src/lib.rs`: `EngineState` is the
    closed Loaded/Running/Paused/Stopped run-state enum with typed
    `PauseReason` and `Outcome`, `Engine` keeps `Configuration` as the source of
    truth and `RuntimeState` as a rebuildable cache, and `SessionActor::run`
    delegates to bounded `run_once` iterations that poll deferred/mailbox
    commands before each running quantum, apply one command or one
    `Engine::step_quantum`, publish the `LiveSnapshot` mirror, and yield
    cooperatively. `checks.crucible.phase1.executionEngineStateMachine` and
    `checks.crucible.phase1.executionLiveSnapshot` gate the pattern.
- [x] **T-PAT-4** Ensure the temporal graph follows the §29.4 content-addressed
  store + thin/fat + CoW-delta shape. — satisfies [PAT-6]; realized by the 07
  temporal-graph tasks and **T-EXEC-10** (spec 07 §§2–5).
  - Completed by the temporal-graph model and gates: `crucible::Checkpoint`
    identity is schedule-derived and independent of cached state,
    `crucible::NodeBlobRef` represents both baked and CoW-delta VM state,
    `crucible::CowDeltaRef` records typed VM/device/schedule/log deltas,
    `crucible::DagStore` / `crucible::LocalDagStore` provide idempotent
    content-addressed storage, and `TemporalGraph::persist_checkpoint_closure`
    plus `TemporalGraph::collect_cached_snapshot_store` preserve the
    store-key closure while fat cache entries can be collected back to thin
    checkpoints. `crucible::MaterializationPolicy`,
    `TemporalGraph::evict_fat_checkpoint_to_thin`, and the replay-oracle
    admission path keep materialization a cache policy rather than identity.
    `checks.crucible.phase1.gates.contentAddress` and
    `checks.crucible.phase1.gates.replayOracle` gate the pattern.
- [x] **T-PAT-5** Ensure the decision RNG follows the §29.5 name-hash forking
  shape with recorded `RngStreamId`. — satisfies [PAT-7]; realized by
  **T-EXEC-2** and the 04 determinism-contract tasks (spec 04 §4.7).
  - Completed by `crucible_sim::DecisionRng`,
    `DECISION_RNG_NODE_STREAM_DOMAIN`, `DECISION_RNG_LINK_STREAM_DOMAIN`,
    `stable_domain_name_hash`, and `crucible::decision::DecisionRecorder`:
    streams fork from the root seed through stable name hashes instead of a
    shared root cursor, same-name node/link streams use separate fixed domains,
    construction order and unrelated world edits do not perturb existing
    streams, and every recorded `Decision::RngDraw` / `Decision::AppRandom`
    carries its domain-qualified `RngStreamId` in the schedule.
    `checks.crucible.phase1.decisionRng` and
    `checks.crucible.phase1.decisionRecording` gate the pattern.
- [ ] **T-PAT-6** Ensure the session drives nodes through the §29.6
  `SimulationBackend` trait with an in-process drop-in double. — satisfies
  [PAT-8]; realized by **T-SESS-11**, **T-SESS-12** (spec 20 §10, 24 §3).
  - Partial evidence under `checks.crucible.phase5.sessionSimulationBackend` and
    `checks.crucible.phase5.sessionSimDoubleSuite`: `SimulationBackend` is the
    exported scheduler-timed backend boundary, implemented by the mock,
    `SimBackend`, `SimDouble`, and QEMU `QemuNode`; trait-level stepping cannot
    authorize cross-node sends or own scheduler time; and the session, API,
    daemon, and control-responsive gate exercise the same in-process
    `crucible::SimDouble` quantum-loop adapter, while scheduler-liveness uses an
    initialized `crucible::SimDouble` liveness harness, without constructing
    real QEMU.
- [x] **T-PAT-9** Ensure the runtime realizer follows the §29.9 recursive
  `instantiate` shape with start ≡ resume ≡ fork and the cold boot confined to
  `bake`. — satisfies [PAT-11], [PAT-12]; realized by **T-EXEC-6**,
  **T-EXEC-7**, **T-EXEC-8**, **T-EXEC-17** (spec 05 §§5–6, §11).
  - Completed by `crucible::instantiate`, `TemporalGraph::with_baked_genesis`,
    `crucible::bake`, `crucible_qemu::instantiate_qemu_vm`,
    `crucible_qemu::start_qemu_vm`, `crucible_qemu::resume_qemu_vm`,
    `crucible_qemu::fork_qemu_vm`, and the same-configuration-twice
    fingerprint gate: the model resolves exact snapshot, ancestor replay, then
    baked genesis; QEMU lifecycle wrappers share one instantiate coordinator
    and leave cold boot inside `bake_qemu_genesis_vm`; and the fingerprint gate
    validates start/resume/fork/snapshot-completeness through one equality.
    `checks.crucible.phase1.executionInstantiate`,
    `checks.crucible.phase1.executionBake`,
    `checks.crucible.phase1.executionStartResumeFork`, and
    `checks.crucible.phase1.gates.singleVmFingerprint` gate the pattern.
- [x] **T-PAT-3** Ensure the SPSC ring + ceiling handshake + futex follow the
  §29.3 shape and carry the `loom`/property concurrency tests. — satisfies
  [PAT-4], [PAT-5]; realized by **T-SHM-6**, **T-SHM-8**, **T-SHM-9**,
  **T-SHM-15** (spec 13 §§13.6, 13.7, 13.9).
  - Completed by `cargo test --manifest-path crates/Cargo.toml -p
    crucible-shmem`, `cargo test --manifest-path crates/Cargo.toml -p
    crucible-shmem --test gate_layer1_injection`, `cargo test --manifest-path
    crates/Cargo.toml -p crucible-shmem --test advance_ceiling_handoff`, and
    `cargo test --manifest-path crates/Cargo.toml -p crucible-shmem --test
    icount_stamped_injection`. `crucible_shmem::RingHeader` is the
    cache-line-separated Lamport SPSC queue with release-published frame writes
    and acquire-observed peer indices; `NodeSlot` exposes the scheduler ceiling
    handoff, acquire node-side ceiling loads, race-free idle precondition checks,
    and non-private futex wait/wake path. `RegionAllocation` and the borrowed
    `NodeSlot::publish_scheduler_inbox_and_ceiling` path preflight capacity,
    enqueue pending frames, publish the ceiling, and only then wake. The SPSC
    gate test carries the local loom-style model and seeded property corpus for
    no loss, duplicate, FIFO drift, torn frame, early read, full/empty, and
    wraparound regressions; the handoff tests assert input-before-ceiling-before-
    wake ordering, idle/wake races, non-private futex behavior, and scheduler/
    frame wake triggers.
    Summary: the shared-memory transport now follows the §29.3 SPSC + ceiling +
    futex pattern, with focused model/property and wake-order tests covering the
    concurrency invariants.
- [x] **T-PAT-8** Ensure every wire surface follows the §29.8 framed-codec shape
  with round-trip + no-panic fuzz properties. — satisfies [PAT-10]; realized by
  **T-SHM-7**, **T-SHM-14** and the 14 protocol tasks (spec 13 §13.6, 14).
  - Completed by `checks.crucible.phase2.gates.abiConformance`,
    `checks.crucible.phase2.protocolCodecFuzz`, and the local Rust gates for
    shmem, protocol, and plugin wire codecs. `SpscRingSnapshot` now has a
    symmetric `canonical_bytes` / `from_canonical_bytes` pair with typed
    truncation, trailing-byte, frame-count, and over-length errors; the snapshot
    restore and shmem ABI gates cover byte round-trip, padding normalization, and
    malformed-byte no-panic cases. The control protocol gate keeps frozen
    versioned golden frames plus deterministic decode/no-panic regression corpus
    coverage, and the QEMU plugin ABI owner gate executes the real
    `crucible-qemu-plugin --lib io_wire_fuzz` unit target for block and 9p
    round-trip, truncation, typed rejection, and no-panic properties while
    preserving the plugin's `cdylib` artifact contract. The engine aggregate
    owner and phase2 ABI Nix gate now include the shmem, protocol, API golden
    vector, plugin I/O wire, and engine ABI owner tests. RPC API coverage here is
    limited to frozen encoder/golden-vector ABI checks; full RPC reference-client
    decode coverage remains scoped to pending **T-API-13**.
- [x] **T-PAT-2** Ensure the scheduler is built to the §29.2 PICK/RUN/RESOLVE/
  EMIT/STEP quantum shape with a single ceiling per RUN and total-order
  RESOLVE. — satisfies [PAT-3]; realized by **T-SCHED-12**, **T-SCHED-13**,
  **T-SCHED-16** (spec 08 §8.9).
  Completed by `checks.crucible.phase3.schedulerQuantumPattern`. The aggregate
  gate ties [PAT-3] to the authoritative `drive_authoritative_quantum` path by
  checking the boundary-admission, PICK, RUN, RESOLVE, EMIT, STEP order inside
  that function and rerunning the focused quantum-loop, effective-horizon,
  single-ceiling, RESOLVE, event-order, and EMIT/STEP Rust tests
  `scheduler_quantum_loop`, `scheduler_effective_horizon`,
  `scheduler_run_ceiling`, `scheduler_resolve`, `scheduler_event_order`, and
  `scheduler_emit_step`.
- [x] **T-PAT-7** Ensure the block sub-node follows the §29.7 CoW-overlay shape
  (base never written; ordered, deterministic snapshot deltas). — satisfies
  [PAT-9]; realized by the 15 I/O sub-node tasks (spec 15).
  Completed by `checks.crucible.phase3.blockCowOverlayPattern`. The concrete
  block sub-node uses `BaseImage` as an immutable content-addressed base and
  `CowOverlay` as an in-memory 4 KiB copy-on-write page layer. Overlay pages are
  stored in a `BTreeMap`, dirty page bases in a `BTreeSet`, reads consult the
  overlay before falling back to `BaseImage`, writes copy up from the base and
  patch only overlay pages, and `dirty_delta` captures only pages dirtied since
  the last checkpoint boundary in deterministic order. `BlockSnapshot` carries
  the overlay delta, full overlay page set, dirty set, RNG cursor, active faults,
  in-flight responses, base hash, and device length; restore stacks the delta
  over the parent and reinstates the dirty set, while `BlockDevice::materialize`
  copies base bytes into a fresh image before applying overlay pages, so the
  base image is never mutated.
