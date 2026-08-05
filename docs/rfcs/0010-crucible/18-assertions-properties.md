# 18 — Assertions and properties

This file specifies how Crucible *checks* a run: the vocabulary of temporal
properties an author declares over a scenario, where those properties draw their
truth from, when and in what order they are evaluated, what a violation carries,
and — the property that distinguishes Crucible from ordinary test harnesses — how
the same properties are checkable **offline** against an already-recorded run.

The assertion machinery is small and deliberately so. It is *not* a model checker
and *not* a specification-language evaluator ([NG-3]); it is a fixed vocabulary of
temporal predicates evaluated over a totally-ordered, icount-stamped, complete
event log. The event log ([`19-observability-event-log.md`](19-observability-event-log.md))
does almost all of the work: because the log is the deterministic record of
everything that happened, "checking a property" is a pure fold over that log, and
the difference between checking *during* a run and checking it *a year later* is
only whether the log is being appended to or read back.

Requirement IDs in this file use the prefix `ASRT` (see
[`00-conventions.md`](00-conventions.md)). Gate names referenced here —
`gate:e2e-determinism`, `gate:replay-oracle`, `gate:divergence-bisect`,
`gate:single-vm-fingerprint`, `gate:any-guest`, `gate:harness-lint`,
`gate:scheduler-liveness` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). The
assertion vocabulary is shared at the wire level with the white-box marker kinds
of [`16-guest-host-channel.md`](16-guest-host-channel.md) §16.5.1; the event-log
schema that assertions read is [`19-observability-event-log.md`](19-observability-event-log.md);
the determinism contract that makes offline checking sound is
[`04-determinism-contract.md`](04-determinism-contract.md); the reproduction
artifact a violation links to is defined in [`06-spatial-graph.md`](06-spatial-graph.md)
and [`23-cli.md`](23-cli.md), and replayed bit-identically per
[`07-temporal-graph.md`](07-temporal-graph.md).

The code blocks in this file are **illustrative sketches** per
[`00-conventions.md`](00-conventions.md) §"Code sketches", not the
implementation; the authoritative statement is always the prose requirement. A
sketch that disagrees with a requirement is a defect in the sketch.

## 18.1 What an assertion is, and what it is not

An **assertion** (also a **property**) is a named, declarative statement about a
run that Crucible evaluates and reports as pass or fail. Authors declare
assertions as part of the `ScenarioDef`'s `Properties` ([`02-glossary.md`](02-glossary.md),
[`06-spatial-graph.md`](06-spatial-graph.md)) — they are part of the immutable,
content-addressed definition of the scenario, so the *set of properties checked*
is itself reproducible and hashed into the scenario identity.

An assertion is a **predicate over observable run state** plus a **temporal
quantifier** that says *when* the predicate must hold. That is the entire model.
There is no spec language, no LTL/CTL formula compiler, no state-exploration
engine inside the assertion layer.

The **predicate** here is not a second vocabulary: it is the single `Condition`
type of [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2,
which has **exactly two consumers** (17a [TRIG-4]). An *assertion* is a `Condition`
that is **continuously checked for pass/fail** (this file); a *trigger* (17a) is a
`Condition` that **fires an `Action` once** when it first becomes true. Both
consumers evaluate the **identical** predicate over the **identical** event log at
the **identical** deterministic evaluation points (§18.7, 17a §17a.3) — an author
learns one predicate vocabulary and uses it both to *check* the run (assertions)
and to *steer* it (triggers). The `AssertionState` leaf (17a §17a.2.8) closes the
loop: a trigger can fire *because* an assertion just became satisfied or violated.
The temporal quantifiers below (Always/Sometimes/Eventually/AfterQuiescence/
Reachable) are the *grading discipline* this file layers over that shared
`Condition`; they are not a different predicate type.

- **[ASRT-1]** The assertion layer MUST be a fixed, closed vocabulary of temporal
  property quantifiers (§18.2) evaluated as predicates over the run's recorded
  observable state (§18.3). It MUST NOT include a model checker, a
  specification-language evaluator, or any in-runtime engine that explores or
  proves properties beyond evaluating the declared predicates over the recorded
  trace. Conformance against an external formal specification, if ever wanted, is
  an OPTIONAL **offline** step performed by separate tooling fed Crucible's
  exported trace (§18.10), never part of the runtime. *Gate:*
  `gate:harness-lint`. *Spec:* §18.1, §18.10, satisfies [NG-3].

- **[ASRT-2]** Properties MUST be part of the `ScenarioDef` and therefore part of
  the scenario's content hash ([INV-6]): two scenarios that differ only in their
  declared properties are different scenarios. The *evaluation* of a property MUST
  NOT influence the run — declaring or removing a property MUST NOT change the
  instruction stream, the schedule, or the fingerprint of any node (§18.9). The
  property set is read *from* the run, never written *into* it. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §18.1, §18.9.

The reason this is enough — the reason Crucible can refuse a model checker and
still check rich temporal properties — is the event log. Liveness, ordering,
convergence-after-fault, and "this state was reached" are all questions about a
*single recorded sequence of events in virtual time*, and a single sequence is
foldable. Crucible does not need to enumerate all executions to check a property
of *one* execution; it needs only the complete, ordered record of that one, which
[`19-observability-event-log.md`](19-observability-event-log.md) guarantees it
has. Exploring *other* executions is the job of the schedule-space search and
fuzzing layer ([`22-advanced-features.md`](22-advanced-features.md)), which runs
*many* deterministic runs and checks each one's log with this same vocabulary; it
is not the job of the assertion layer.

## 18.2 The assertion vocabulary and its temporal semantics

Crucible defines exactly five temporal quantifiers. They are the same five whose
wire-level marker forms are carried by the white-box channel
([`16-guest-host-channel.md`](16-guest-host-channel.md) §16.5.1); this section
defines what each *means* for property evaluation, regardless of whether the
predicate is sourced host-side (§18.4) or guest-side (§18.5).

Throughout, an **evaluation point** is a virtual-time instant at which the
relevant assertions are evaluated against the run state as of that instant
(§18.7); the run reaches **quiescence** when all nodes are idle with no pending
deliveries, timers, or due faults ([`02-glossary.md`](02-glossary.md),
[`08-scheduling.md`](08-scheduling.md)).

- **[ASRT-3]** Crucible MUST support exactly the following property quantifiers,
  with the stated temporal semantics, and MUST NOT silently extend this set
  (adding one is a versioned change to the property schema and the marker ABI,
  [GHC-23]):

  - **Always** — an **invariant**. The predicate MUST hold at *every* evaluation
    point from the start of the run (or from a declared activation point) through
    the end. The assertion **fails** the instant the predicate is ever observed
    false; the failing evaluation point's icount/virtual-time is the violation
    site. An Always assertion that is never evaluated (e.g. its scope is never
    entered) is reported per the never-evaluated policy of [ASRT-15], not silently
    passed.

  - **Sometimes** — a **liveness witness** (existential). The predicate MUST hold
    at *at least one* evaluation point during the run. It is satisfied the first
    time the predicate is observed true; if it is never true by the end of the
    run, the assertion **fails**. Its purpose is to prove the run actually
    exercised an interesting state and is not a trivial no-op (e.g. "backpressure
    was triggered at least once", "a leader was elected").

  - **Eventually** — a **bounded liveness** property with an explicit deadline. It
    is a two-part statement: a **trigger** predicate and a **property** predicate,
    plus a **deadline** expressed in virtual time. While the trigger has not
    fired, the assertion is dormant. When the trigger first fires at virtual time
    `t0`, the property MUST become true at some evaluation point in the window
    `[t0, t0 + deadline]`. The assertion **fails** if the deadline passes with the
    property still false (the violation site is the deadline instant), and also
    fails if the run ends while triggered-but-unsatisfied. If the property already
    holds at `t0`, the obligation is discharged immediately. A trigger that never
    fires is *not* a failure (it is a vacuously-discharged obligation), but is
    reported as such so an author can tell a never-triggered Eventually from a
    satisfied one.

  - **AfterQuiescence** — an **end-state** property, checked **once**, at
    quiescence (or at the run's virtual-time limit if quiescence is never
    reached). The predicate MUST hold at that single terminal evaluation point;
    the assertion **fails** if it is false there. It is the natural home for
    "settle then check" properties (all records delivered, all replicas agree, no
    orphaned resources) that are only meaningful once the system stops moving.

  - **Reachable** — a **coverage marker**. It records whether a named state or
    code path was ever reached during the run (predicate observed true at least
    once, or a guest-side `reachable` marker observed at least once). Its
    *never-reached* outcome is, by default, a **warning** rather than a failure;
    whether never-reached is escalated to a failure MUST be configurable per
    marker (§18.2.1, [ASRT-5]). Reachable also has a **dual** form — a
    *never-reached* expectation (the white-box `unreachable` flavor, [GHC-22]) —
    that **fails** if the marked point is *ever* reached. Coverage markers feed the
    fuzzing/search coverage signal ([`22-advanced-features.md`](22-advanced-features.md))
    in addition to being reported.

  *Gate:* `gate:e2e-determinism`. *Spec:* §18.2.

- **[ASRT-4]** Each quantifier's pass/fail/satisfied/violated outcome MUST be a
  **pure function of the recorded run** (the event log plus the declared
  predicates), with no dependence on host wall-clock, host-scheduling order, or
  any value outside the log. The same log and the same property set MUST yield the
  identical set of outcomes on every evaluation, online or offline (§18.6),
  including the identical violation sites and the identical ordering of reported
  outcomes (§18.7). *Gate:* `gate:replay-oracle`, `gate:divergence-bisect`.
  *Spec:* §18.2, §18.6, §18.7.

### 18.2.1 Per-quantifier configuration

- **[ASRT-5]** Each declared property MUST carry, as part of its `ScenarioDef`
  entry and therefore part of the scenario hash ([ASRT-2]): a stable **id**
  (length-prefixed UTF-8, matching the white-box marker id space, [GHC-20]); a
  human-readable **message**; and quantifier-specific parameters — for Eventually,
  the **deadline** in virtual time and the trigger/property pair; for Reachable,
  the **never-reached disposition** (`warn` (default) or `fail`) and whether it is
  the ordinary or `unreachable`-dual form. A property whose parameters cannot be
  reduced to a deterministic, virtual-time-relative form (for example, an
  Eventually deadline expressed in host wall-clock seconds) MUST be rejected at
  scenario validation, mirroring the readiness-heuristic rule of [GHC-6]. *Gate:*
  `gate:harness-lint`. *Spec:* §18.2.1.

### 18.2.2 Illustrative sketch

The following sketch shows the intended shape of the vocabulary and its
evaluation state; it is illustrative, and the prose requirements govern.

```rust
/// A virtual-time instant, derived from per-node icount (see file 09).
/// Crucible's canonical clock; never a host wall-clock value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualTime(pub u64);

/// A snapshot of the run's *observable* state as of one evaluation point,
/// materialized from the event log up to and including `at` (see §18.3).
/// It carries no host-timing data, only icount-stamped run facts.
pub struct ObservedState<'log> {
    /// The evaluation point this snapshot is "as of".
    pub at: VirtualTime,
    /// The node whose retired icount defines `at`, when point-sourced.
    pub node: Option<NodeId>,
    /// Read-only view of the event log prefix [start, at].
    pub log: LogView<'log>,
}

/// The five temporal quantifiers. A closed, versioned set ([ASRT-3]).
pub enum Property {
    /// Invariant: predicate holds at every evaluation point.
    Always(Predicate),
    /// Liveness witness: predicate holds at least once.
    Sometimes(Predicate),
    /// Bounded liveness: after `trigger`, `property` holds within `deadline`.
    Eventually {
        trigger: Predicate,
        property: Predicate,
        deadline: VirtualTime,
    },
    /// End-state: predicate holds at the single quiescence/limit point.
    AfterQuiescence(Predicate),
    /// Coverage: state reached at least once (or, dual, never reached).
    Reachable {
        predicate: Predicate,
        /// `false` = ordinary (warn/fail if never reached);
        /// `true`  = dual (fail if ever reached).
        never_expected: bool,
        /// Disposition when an ordinary marker is never reached.
        on_unreached: Disposition, // Warn | Fail
    },
}

/// A predicate over observed state. Host-side properties evaluate a function;
/// guest-side properties read a recorded white-box marker (§18.5).
pub enum Predicate {
    /// Host-side: a pure, deterministic function of observed state.
    Host(Box<dyn Fn(&ObservedState<'_>) -> bool + Send + Sync>),
    /// Guest-side: the truth of the named white-box assertion marker.
    GuestMarker { id: MarkerId },
}

/// Lifecycle of one declared property over the course of evaluation (§18.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PropertyState {
    /// Declared, not yet evaluated.
    Declared,
    /// Evaluated at least once, no obligation broken so far.
    Passing,
    /// Existential/liveness obligation discharged (Sometimes/Reachable seen,
    /// Eventually property held within deadline).
    Satisfied,
    /// Currently failing-in-progress (e.g. Eventually triggered, deadline open).
    Failing,
    /// Terminally violated; carries the violation site.
    Violated,
}
```

## 18.3 What assertions are evaluated over: observable run state

Every predicate is evaluated against the run's **observable state** as of an
evaluation point, and observable state is *exactly* the icount-stamped record in
the event log up to that point. There is no privileged side channel and no
host-only knowledge in a predicate's input.

- **[ASRT-6]** A property predicate MUST be evaluated only over **observable run
  state** materialized from the event log
  ([`19-observability-event-log.md`](19-observability-event-log.md)): the
  black-box observation surface of [GHC-7] (network frames, disk/9p I/O,
  console/serial output, QMP-readable registers/memory at scheduler-defined
  points, exit codes, crash/hang, basic-block coverage), the cross-node ordering
  facts ([INV-3]), the fault activation/heal record
  ([`17-fault-injection.md`](17-fault-injection.md)), and — when white-box mode is
  enabled — the recorded guest markers ([GHC-22], §18.5). A predicate MUST NOT
  read host wall-clock, host-scheduling state, an unordered map iteration, or any
  source outside the log. *Gate:* `gate:harness-lint`, `gate:single-vm-fingerprint`.
  *Spec:* §18.3.

- **[ASRT-7]** The observed state passed to a predicate at evaluation point `t`
  MUST be the log prefix `[start, t]` — a predicate MUST NOT see events stamped
  later than its evaluation point. This makes a property's truth at `t` a function
  of history-up-to-`t` only, which is what makes online and offline evaluation
  agree (§18.6) and what lets a violation be attributed to a definite earliest
  icount. *Gate:* `gate:replay-oracle`. *Spec:* §18.3, §18.7.

## 18.4 Source of truth #1 — host-side assertions over observable state (default)

The default and always-available source of assertion truth is **host-side**:
predicates the engine evaluates against the black-box observation surface and the
harness/topology facts in the log. Host-side assertions require **zero guest
cooperation** and therefore work on any unmodified guest ([G-2], [G-3],
[GHC-1]).

- **[ASRT-8]** Crucible MUST support **host-side assertions**: predicates
  evaluated by the engine over the black-box observable state of [ASRT-6], with no
  guest instrumentation. Host-side assertions MUST be sufficient on their own for
  all five quantifiers (§18.2) and MUST be the default property source. They are
  what makes property checking work in black-box mode and on a guest that has
  never heard of Crucible. *Gate:* `gate:any-guest`. *Spec:* §18.4.

- **[ASRT-9]** Host-side assertions are the correct home for **harness and
  topology invariants** and **black-box properties** — statements about the
  *machine and the network*, not about in-guest variables. Examples (illustrative,
  not normative): "no node ever observes a frame from a partitioned peer"
  (Always); "every committed write on the disk sub-node is eventually acknowledged
  on the wire within `D` virtual-ns of its completion icount" (Eventually); "at
  quiescence, the two replicas' on-disk block hashes are equal" (AfterQuiescence);
  "a network partition was actually active at some point" (Sometimes); "the crash
  fault path was exercised" (Reachable). These need nothing inside the guest.
  *Gate:* `gate:any-guest`. *Spec:* §18.4.

- **[ASRT-10]** A host-side predicate MUST be a **pure, deterministic function**
  of the observed state it is given: same observed state ⇒ same boolean, with no
  internal nondeterminism (no wall-clock, no thread RNG, no unordered iteration),
  consistent with [INV-9]. The engine MUST evaluate it side-effect-free with
  respect to the run ([ASRT-2], §18.9). A predicate that violates this is a
  harness defect caught by `gate:harness-lint`. *Gate:* `gate:harness-lint`.
  *Spec:* §18.4, §18.9.

## 18.5 Source of truth #2 — guest-side markers over the white-box channel

The second source of truth is **guest-side**: fine-grained, in-guest assertions
emitted as markers over the white-box doorbell channel
([`16-guest-host-channel.md`](16-guest-host-channel.md)). This is the most
*meaningful* source for many properties, because the most interesting invariants
are about in-guest state the black box cannot see — an internal data-structure
invariant, a per-request lifecycle, an in-process consistency check — and the
guest can assert them at the exact instruction where they matter. Guest-side
assertions are an **opt-in white-box enhancement**, never required ([GHC-2],
[GHC-28]).

- **[ASRT-11]** When white-box mode is enabled, Crucible MUST evaluate
  **guest-side assertion markers** ([GHC-22]) using the *same* five-quantifier
  semantics as host-side assertions (§18.2): an `always` marker fails the run if
  its condition is ever observed false; a `sometimes` marker fails if it is never
  observed true; a `reachable` marker fails (or warns, per [ASRT-5]) if it is
  never observed; its `unreachable` dual fails if it is ever observed. The host
  MUST fold guest-originated markers into the *same* property-evaluation pass as
  the host-side observations (§18.7), so a run's outcome set is a single,
  uniformly-evaluated whole. *Gate:* `gate:any-guest`. *Spec:* §18.5, mirrors
  [GHC-25].

- **[ASRT-12]** A guest-side marker MUST be treated as an **observational**
  event-log entry stamped with the exact icount at which its doorbell instruction
  retired ([GHC-13], [GHC-24]): its truth value (`condition`) and its identity
  (`id`) come from the recorded marker, and its evaluation point is the marker's
  icount. Because the marker stream is itself deterministic under the contract
  ([GHC-30]), the guest-side assertion outcomes are deterministic and offline-
  checkable on the same terms as host-side ones (§18.6). Markers are descriptive
  output and MUST be **excluded from the determinism fingerprint comparison**
  ([GHC-24], [DET-29]); declaring or evaluating guest-side assertions MUST NOT
  move a fingerprint (§18.9). *Gate:* `gate:single-vm-fingerprint`. *Spec:* §18.5.

- **[ASRT-13]** The relationship between the two sources MUST be: **host-side is
  the floor; guest-side is the additive enhancement.** Most meaningful, fine-
  grained assertions come from inside the guest when white-box is enabled;
  host-side assertions cover harness/topology invariants and black-box properties
  and are the only source available on an unmodified guest. The *absence* of any
  guest-side markers MUST NOT degrade host-side property checking ([GHC-28]); a
  scenario MUST be able to mix both sources, and both MUST report through one
  unified outcome set (§18.8). *Gate:* `gate:any-guest`. *Spec:* §18.5, §18.4.

## 18.6 Offline checking — the keystone capability

This is the property that makes the assertion layer worth its small size. Because
the event log is **complete** and **icount-stamped** and a property's truth is a
**pure fold over that log** ([ASRT-4], [ASRT-7],
[`19-observability-event-log.md`](19-observability-event-log.md)), a property does
not have to exist *when the run executes*. An author can write a *new* assertion
after the fact and check it against a *recorded* run — without re-executing the
VMs — and get exactly the result that an online evaluation would have produced.

- **[ASRT-14]** Crucible MUST provide an **offline assertion checker** that takes
  (a) a recorded run's event log and (b) a set of properties (the run's original
  `Properties`, or a *new or amended* set supplied at check time) and produces the
  identical outcome set that an online evaluation of those properties over that
  run would produce. The offline checker MUST NOT re-execute the guests: it reads
  the recorded log only. For host-side predicates the checker re-evaluates the
  predicate function over the recorded observed state; for guest-side markers it
  reads the recorded marker entries. *Gate:* `gate:replay-oracle`. *Spec:* §18.6.

- **[ASRT-15]** Online and offline evaluation MUST be **the same code path over
  the same input**: the engine MUST evaluate properties by folding the event log,
  and the only difference between online and offline MUST be whether the log is
  being appended to live or read from storage. Consequently, the **never-evaluated
  / never-triggered** policies (an Always whose scope was never entered, an
  Eventually whose trigger never fired, a Reachable never reached) MUST be applied
  identically in both modes and MUST be reported as a distinct outcome (not folded
  into pass or fail) so the two modes cannot diverge on edge cases. *Gate:*
  `gate:replay-oracle`, `gate:divergence-bisect`. *Spec:* §18.6, §18.8.

- **[ASRT-16]** A property newly checked offline against a recorded run MUST be
  checkable against *any* run whose log is retained, and re-checking the same
  (log, properties) pair MUST be **idempotent** — byte-identical outcome set every
  time — so a fixed corpus of recorded runs can be re-graded as the property suite
  grows. This is what lets a regression in property *coverage* be found without
  re-running the (expensive) simulations: write the assertion once, fold it over
  the whole recorded corpus. *Gate:* `gate:replay-oracle`. *Spec:* §18.6.

- **[ASRT-17]** Offline checking against an external **formal** specification, if
  ever desired, MUST be done by **exporting the trace** (§18.10,
  [`19-observability-event-log.md`](19-observability-event-log.md)) to existing
  external tooling and checking it *there*; Crucible MUST NOT grow an in-runtime or
  in-process formal-spec evaluator to satisfy such a use ([NG-3], [ASRT-1]). The
  offline assertion checker of [ASRT-14] is for Crucible's own five-quantifier
  vocabulary; formal-spec conformance is strictly an external, optional consumer
  of the exported trace. *Gate:* `gate:harness-lint`. *Spec:* §18.6, §18.10.

The offline checker is what turns the event log from a debugging convenience into
the primary correctness substrate: the run is recorded once, deterministically,
and graded as many times as there are properties, forever.

```text
Online and offline are one fold over the same log:

   run executes  ──>  event log (icount-stamped, complete, content-addressed)
                          │
        ┌─────────────────┴───────────────────────────┐
        ▼                                               ▼
  online evaluation                            offline evaluation
  (fold as the log                             (fold the stored log,
   is appended)                                 possibly with NEW or
        │                                        AMENDED properties)
        ▼                                               ▼
        └────────────  identical outcome set  ──────────┘
                       for identical (log, properties)
```

## 18.7 The assertion engine — evaluation timing and ordering

The engine that evaluates properties is a small, deterministic fold driven by the
event log. Its two jobs are to decide *when* each quantifier is evaluated and to
guarantee that evaluation is **deterministically ordered** and **non-perturbing**.

- **[ASRT-18]** The engine MUST evaluate properties at well-defined **evaluation
  points** driven by the event log, not by host time:
  - **Always**, **Sometimes**, **Eventually**, and **Reachable** are evaluated at
    every **relevant event** — an event-log entry of a kind the property's
    predicate (or trigger/property) depends on — and additionally Eventually is
    evaluated at its **deadline instants** so a deadline that falls between events
    is still caught. The engine MAY narrow "relevant event" to the event kinds a
    predicate references for performance, but the *result* MUST be identical to
    evaluating at every event ([ASRT-4]).
  - **AfterQuiescence** is evaluated **once**, at the quiescence point (or the
    virtual-time limit if quiescence is never reached, [ASRT-3]).
  The set of evaluation points for a fixed run MUST be a deterministic function of
  the event log. *Gate:* `gate:scheduler-liveness`. *Spec:* §18.7.

- **[ASRT-19]** At each evaluation point, the engine MUST evaluate the relevant
  properties in a **deterministic order**: properties are ordered by their stable
  id ([ASRT-5]); within one property the predicate is evaluated once against the
  observed state of that point. The engine MUST NOT iterate properties in an
  unordered-map order or any order influenced by host scheduling ([INV-9]). The
  ordered, recorded sequence of evaluation outcomes MUST be identical across runs
  of a fixed `(scenario, seed, schedule)` and identical online vs offline
  ([ASRT-4], [ASRT-15]). *Gate:* `gate:harness-lint`, `gate:replay-oracle`.
  *Spec:* §18.7.

- **[ASRT-20]** Evaluation MUST **terminate** at each point: a predicate is a pure
  total function over a bounded observed-state view, and the engine MUST bound the
  work per evaluation point so that property checking cannot livelock the
  scheduler ([INV-8], `gate:scheduler-liveness`). A predicate that does not return
  is a harness defect, not a run outcome. *Gate:* `gate:scheduler-liveness`.
  *Spec:* §18.7.

```text
Per-quantifier evaluation timing (deterministic, log-driven):

  quantifier        evaluated at                         finalized at
  ----------------  -----------------------------------  ------------------
  Always            every relevant event                 — (fail is immediate)
  Sometimes         every relevant event                 quiescence/limit
  Eventually        every relevant event + deadline pts  quiescence/limit
  AfterQuiescence   — (not during the run)               quiescence/limit (only)
  Reachable         every relevant event                 quiescence/limit
```

## 18.8 Assertion lifecycle and the outcome set

Each declared property moves through a small, deterministic lifecycle, and a run
produces one **outcome set** that records each property's terminal disposition.

- **[ASRT-21]** Each property MUST have a deterministic lifecycle over the run:
  **declared** (registered, not yet evaluated) → **passing** (evaluated at least
  once, no obligation broken) and, depending on quantifier, → **satisfied** (an
  existential/liveness obligation discharged: a Sometimes/Reachable seen, an
  Eventually property met within deadline) or → **failing** (an open obligation in
  progress, e.g. an Eventually triggered with its deadline still open) →
  **violated** (terminal failure, carrying the violation site, §18.9). An Always
  goes directly to **violated** on the first false evaluation; an AfterQuiescence
  is **declared** until the single terminal check, then **passing** or
  **violated**. The lifecycle transitions MUST be a pure function of the event log
  ([ASRT-4]). *Gate:* `gate:replay-oracle`. *Spec:* §18.8.

- **[ASRT-22]** A run MUST produce a single **outcome set**: for every declared
  property, its terminal lifecycle state, and for Reachable markers, the
  coverage report. Each property's outcome MUST distinguish at least: **passed**,
  **violated**, **satisfied**, **never-evaluated/never-triggered** (the
  [ASRT-15] distinct outcome), and for Reachable **never-reached (warn)** vs
  **never-reached (fail)** per its disposition. Host-side and guest-side
  assertions MUST report into this one outcome set uniformly ([ASRT-13]). *Gate:*
  `gate:e2e-determinism`. *Spec:* §18.8.

- **[ASRT-23]** The **run verdict** MUST be a deterministic function of the
  outcome set: a run **fails** if any property is **violated** (any Always false,
  any unsatisfied Sometimes, any Eventually past deadline or triggered-but-
  unsatisfied at end, any AfterQuiescence false at quiescence, any `fail`-
  disposition Reachable never reached, any `unreachable`-dual ever reached);
  otherwise it **passes**, possibly with coverage **warnings** (warn-disposition
  Reachable never reached). The verdict MUST be identical online and offline for
  the same (log, properties) ([ASRT-15], [ASRT-16]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §18.8.

## 18.9 Determinism and non-perturbation of evaluation

The assertion engine must be invisible to the run it grades. This is the safety
contract for assertions, the analogue of [GHC-30] for the white-box channel.

- **[ASRT-24]** Assertion evaluation MUST be **deterministic**: for a fixed run
  (event log) and a fixed property set, the outcome set, the violation sites, and
  the ordering of reported outcomes MUST be bit-identical on every evaluation,
  across hosts and across online/offline modes. The engine MUST contain no host
  wall-clock read, no thread RNG, no unordered-map iteration on an
  outcome-significant path, and a deterministic merge of host-side and guest-side
  evaluation ([INV-9]). *Gate:* `gate:harness-lint`, `gate:divergence-bisect`.
  *Spec:* §18.9.

- **[ASRT-25]** Assertion evaluation MUST NOT **perturb** the run: it MUST be
  side-effect-free with respect to every node's instruction stream, the schedule,
  the decision RNG, and the execution fingerprint ([DET-29]). The fingerprints of
  a run with a given property set and the *same* run with properties added,
  removed, or amended MUST be identical for the determinism-relevant state ([G-1],
  [ASRT-2]) — properties are read *from* the run, never written *into* it. Because
  host-side predicates read only the already-recorded log and guest-side markers
  are observational ([ASRT-12]), this holds by construction; the engine MUST NOT
  acquire any path (e.g. reading live guest memory outside the recorded
  observation points) that could break it. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §18.9.

- **[ASRT-26]** A host-side predicate supplied by an author is **untrusted with
  respect to determinism**: the engine MUST evaluate it in a way that cannot let a
  badly-written predicate perturb the run (it is given a read-only observed-state
  view, never a mutable handle to run state), and a predicate that attempts a
  banned nondeterministic operation MUST be caught by `gate:harness-lint` rather
  than silently corrupting the outcome set. *Gate:* `gate:harness-lint`. *Spec:*
  §18.9.

## 18.10 Violations and reproduction

A violation is only useful if it leads straight back to a *bit-identical*
re-execution of the failure. Crucible's determinism makes that link exact: a
violation names the run point and the reproduction artifact, and replaying that
artifact reproduces the violation to the instruction.

- **[ASRT-27]** Every **violation** MUST carry: the property **id** and message;
  the **icount and virtual-time** of the violation site (the failing evaluation
  point — for Always the first false evaluation, for Eventually the deadline
  instant, for AfterQuiescence the quiescence point, etc.); the **node** the site
  belongs to where the site is node-local; the **detail** (expected vs observed,
  drawn from the recorded observed state); and a link to the **reproduction
  artifact** (§18.10.1). All of these MUST be values read from the deterministic
  event log, so the violation record is itself deterministic and offline-
  reproducible ([ASRT-4], [ASRT-16]). *Gate:* `gate:e2e-determinism`. *Spec:*
  §18.10.

- **[ASRT-28]** A violation MUST link to a self-contained **reproduction
  artifact** — the `(seed, scenario, schedule)` bundle of [G-6],
  [`06-spatial-graph.md`](06-spatial-graph.md), and [`23-cli.md`](23-cli.md) —
  such that replaying that artifact ([`07-temporal-graph.md`](07-temporal-graph.md),
  [TEMP-23]) re-executes the run **bit-identically** and re-produces the *same*
  violation at the *same* icount. The artifact reference MUST be content-addressed
  ([INV-6]) so the link cannot rot. A violation that cannot be reproduced from its
  artifact is a determinism defect, surfaced by `gate:divergence-bisect`, not an
  acceptable outcome. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:*
  §18.10.

- **[ASRT-29]** When a re-run of a violation's artifact does *not* reproduce the
  violation at the recorded icount, Crucible MUST treat this as a **divergence**
  and localize it via `gate:divergence-bisect` ([INV-10]) to the first differing
  decision/instruction, rather than reporting a flaky or smoothed-over result. A
  reproducible violation and a non-reproducible one are categorically different
  and MUST be reported as such. *Gate:* `gate:divergence-bisect`. *Spec:* §18.10.

### 18.10.1 Violation record sketch

```rust
/// A terminal property failure, with everything needed to reproduce it.
pub struct Violation {
    /// Stable property id (matches the white-box marker id space).
    pub id: MarkerId,
    /// Author-supplied human-readable message.
    pub message: String,
    /// Which quantifier failed, for outcome classification (§18.8).
    pub quantifier: QuantifierKind,
    /// The violation site: the exact run point the failure is attributed to.
    pub at_icount: u64,
    pub at_virtual_time: VirtualTime,
    /// The node the site belongs to, when node-local.
    pub node: Option<NodeId>,
    /// Expected-vs-observed detail, drawn from the recorded observed state.
    pub detail: String,
    /// Content-addressed link to the (seed, scenario, schedule) artifact
    /// that reproduces this run — and thus this violation — bit-identically.
    pub repro: ReproArtifactRef,
}
```

### 18.10.2 Failure report sketch

```text
CRUCIBLE VIOLATION: AfterQuiescence "replicas-agree" failed
  property id : replicas-agree
  quantifier  : AfterQuiescence
  site        : icount=842_117_903  vtime=45.003ms  node=storage-b
  expected    : sha256(disk[storage-a]) == sha256(disk[storage-b])
  observed    : a=3f9c… b=7b21…  (diverged at block 4096)
  source      : host-side (black-box disk sub-node observation)
  reproduce   : crucible replay --artifact cas:9d4e…  (bit-identical)
  trace       : crucible trace export cas:9d4e…  (for offline / external tooling)
```

## 18.11 Relationship to the other layers (summary)

```text
Sources of truth:
  host-side  (default, any guest)  : predicates over the black-box observation
                                     surface + harness/topology/fault facts
                                     => harness invariants, black-box properties
  guest-side (opt-in, white-box)   : recorded doorbell markers (file 16 §16.5.1)
                                     => fine-grained in-guest assertions
  both fold into one outcome set, evaluated by one deterministic engine.

Vocabulary (closed, versioned): Always · Sometimes · Eventually(deadline) ·
  AfterQuiescence · Reachable(+unreachable dual).

Substrate: the icount-stamped, complete, content-addressed event log (file 19).
  => evaluation is a pure deterministic fold over the log.
  => ONLINE and OFFLINE checking are the same fold; new assertions re-grade
     recorded runs without re-execution.

NOT a formal-methods engine (NG-3): no model checker, no spec-language evaluator.
  External formal-spec conformance is an optional offline consumer of the
  exported trace, never in-runtime.

Determinism: evaluation is deterministic and side-effect-free; declaring,
  amending, or removing properties never moves a fingerprint.

Reproduction: a violation carries (id, icount/vtime, node, detail) and a
  content-addressed (seed, scenario, schedule) artifact that replays the failure
  bit-identically; non-reproduction is a divergence, localized by bisection.
```

## 18.12 The shared predicate vocabulary, the predicate DSL, and finalize-driving markers

### 18.12.1 One `Condition` vocabulary, two consumers

The predicate every assertion grades is the `Condition` of
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2, shared
with the trigger graph (§18.1, 17a [TRIG-4]). This file does **not** define a
disjoint assertion-only predicate type; a predicate usable as a trigger MUST be
usable as an assertion and vice versa, modulo a leaf whose semantics are inherently
edge-shaped (e.g. 17a's `After`).

- **[ASRT-30]** An assertion's predicate MUST be the single `Condition` vocabulary
  of [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) §17a.2
  (17a [TRIG-4]): an **assertion** is a `Condition` continuously checked for
  pass/fail (this file), a **trigger** (17a) is a `Condition` that fires an
  `Action` once, and both MUST evaluate the identical predicate over the identical
  event log (19) at the identical deterministic evaluation points (§18.7, 17a
  §17a.3). There MUST NOT be a trigger-only predicate vocabulary disjoint from the
  assertion predicate vocabulary; a predicate usable as one MUST be usable as the
  other, modulo an inherently edge-shaped leaf (17a `After`). A trigger MUST be able
  to fire on an assertion outcome via the `AssertionState` leaf (17a §17a.2.8),
  closing the grading↔steering loop with no second mechanism. *Gate:*
  `gate:harness-lint`, `gate:e2e-determinism`. *Spec:* §18.1, §18.12.1; cross-ref
  17a §17a.2, [TRIG-4], [TRIG-12].

### 18.12.2 The predicate DSL — named, TOML-authorable conditions

So that scenarios can express assertions and triggers **declaratively** without
writing closures, Crucible provides a set of **named conditions** — a small
predicate DSL — that desugar to 17a leaf `Condition`s. Each name is sugar for a
concrete 17a leaf (or a compound of them); authoring a property or a trigger in
TOML names a DSL predicate instead of supplying a host closure. The DSL is
*additive*: a host-side closure ([ASRT-10]) remains available for predicates the
named set does not cover.

```toml
# A property and a trigger authored declaratively with the predicate DSL.
# Each named predicate desugars to a 17a leaf Condition (§18.12.2); no closure.

[[properties.assertion]]
name = "no-crashes"
kind = "always"
predicate = "no_crashed_nodes"        # desugars to Not(AnyOf(NodeState{*,Crashed}))

[[properties.assertion]]
name = "settles-clean"
kind = "after_quiescence"
predicate = "no_active_faults"        # no fault tag is active at the check point

[[event]]                              # a trigger sharing the same DSL (17a)
id = "fork-on-quiet"
trigger = "quiescent"                  # desugars to 17a Quiescent
action  = { fork = {} }
```

The named predicates and their desugaring to 17a leaves:

```text
  DSL name              desugars to (17a §17a.2 leaf / compound)
  --------------------  ----------------------------------------------------
  no_crashed_nodes      Not(AnyOf([ NodeState{node=n, Crashed} for all n ]))
  quiescent             Quiescent
  no_active_faults      Not(AnyOf([ <fault-active> for each declared tag ]))
  node_alive:<n>        Not(NodeState{node=<n>, state=Crashed})
  node_crashed:<n>      Once(NodeState{node=<n>, state=Crashed})
```

- **[ASRT-31]** Crucible MUST provide a **predicate DSL**: a set of named,
  TOML-authorable conditions (at least `no_crashed_nodes`, `quiescent`,
  `no_active_faults`, `node_alive:<n>`, `node_crashed:<n>`) that **desugar to 17a
  leaf `Condition`s** (§17a.2), so an author MAY express an assertion or a trigger
  declaratively without writing a host closure. Each DSL name MUST desugar to a
  fixed 17a `Condition` (a leaf or a compound of leaves), MUST be usable wherever a
  `Condition` is (both as an assertion predicate and as a trigger, [ASRT-30]), and
  MUST resolve its node/link/tag references at build time against the `World`/`Plan`
  ([SPAT-6], [SPAT-31], 17a [TRIG-26]). The DSL MUST be strictly additive: a
  host-side closure ([ASRT-10]) remains available for predicates the named set does
  not cover. *Gate:* `gate:harness-lint`, `gate:content-address`. *Spec:* §18.12.2;
  cross-ref 17a §17a.2.

### 18.12.3 White-box doorbell markers MUST carry enough to drive finalize

The OPTIONAL white-box doorbell assertion marker (§18.5,
[`16-guest-host-channel.md`](16-guest-host-channel.md)) is an *observational,
white-box, never-required* leaf. When present, however, its recorded payload MUST
carry enough structure for the engine to **finalize** the quantifier correctly —
in particular, Always and Reachable have *finalize-at-quiescence* obligations
([ASRT-18] table, [ASRT-21]) that depend on knowing a marker's *kind* and whether
it was *declared/expected at all* even when its in-guest instruction was **never
reached**. A `reachable` marker that never fires can only be finalized as
"never-reached (warn/fail)" if the engine knows it was *catalog-declared* and with
what disposition; an `always` marker can only finalize as passing if the engine
knows the assertion's kind and `must_hit` expectation. A bare boolean doorbell is
insufficient.

- **[ASRT-32]** The OPTIONAL white-box doorbell assertion marker (§18.5, 16) MUST,
  when emitted, carry a payload sufficient to drive quantifier finalize semantics:
  the assertion **id** ([ASRT-5], [GHC-20]); the **kind**
  (always/sometimes/reachable/unreachable, mirroring §18.2); a `must_hit` /
  **catalog-declaration** flag so a **never-reached** marker can still be finalized
  (Always/Reachable, [ASRT-21], [ASRT-22]); a structured **details** blob (for the
  violation record, [ASRT-27]); and the source **location**. These markers MUST
  remain **observational, white-box, and OPTIONAL** — never required ([GHC-2],
  [GHC-28], [ASRT-13]) and fingerprint-neutral ([ASRT-12], [GHC-24], [GHC-30]) — but
  when present they MUST let the engine finalize Always/Sometimes/Reachable/
  unreachable identically online and offline ([ASRT-15], [ASRT-23]). The marker
  payload schema MUST be the one carried by the channel ([GHC-36]). *Gate:*
  `gate:any-guest`, `gate:replay-oracle`. *Spec:* §18.12.3; cross-ref §18.5, §18.8,
  16 §16.5.

## 18.13 The assertion-proximity gradient (OPTIONAL, steering-only)

An unsatisfied existential or liveness obligation — an unsatisfied **Sometimes**, an
armed-but-undischarged **Eventually**, the existential **Reachable** — is, at the end
of a run, a bare boolean: it did not happen. For *grading* that is the whole story
([ASRT-23]). For *guided search* ([`22-advanced-features.md`](22-advanced-features.md))
a bare boolean is a flat fitness landscape: every run that misses the obligation
looks equally bad, and the search has nothing to climb. The proximity gradient is an
OPTIONAL, **steering-only** scalar that says *how close* a run came to satisfying such
an obligation, so guided search has a gradient to follow. It is **never** part of any
verdict; it only shapes the next schedule the search tries.

- **[ASRT-33]** The assertion engine MAY compute, for an unsatisfied **Sometimes**,
  an armed-but-undischarged **Eventually**, and the existential **Reachable**, an
  OPTIONAL **distance-to-satisfaction**: a deterministic, non-negative, monotone
  scalar that is **0 exactly when satisfied**, defined **structurally** over the
  predicate's [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md)
  §17a.2 `Condition` tree — numeric-comparison leaves contribute the **threshold
  gap** (how far the observed value is from satisfying the comparison), `And`
  contributes the **sum** of child distances, `Or`/`AnyOf` the **minimum**, and
  boolean-only leaves (no numeric quantity to measure) **degrade to `{0, UNIT}`** (0
  if satisfied, a fixed unit penalty otherwise). The per-run distance MUST be folded
  over the recorded observed state as the **minimum achieved along the run's
  trajectory** (the closest the run ever came). It MUST be a **pure function of the
  event log** ([ASRT-4], [ASRT-7]) — online evaluation MUST equal offline ([ASRT-15])
  — and it MUST **NOT** change any property verdict, the run verdict ([ASRT-23]), or
  any fingerprint ([ASRT-25], [DET-29]); it is **consumed only by the guidance signal
  of [`22-advanced-features.md`](22-advanced-features.md)** and is recorded as an
  observational projection of the event log
  ([`19-observability-event-log.md`](19-observability-event-log.md), [OBS-37]).
  *Gate:* `gate:single-vm-fingerprint`, `gate:replay-oracle`. *Spec:* §18.13;
  cross-ref 17a §17a.2, 19 [OBS-37], 22.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is assertions & properties, tracked by [PLAN-3].

- [x] **T-ASRT-1** Define the closed, versioned five-quantifier property
  vocabulary (Always, Sometimes, Eventually-with-deadline, AfterQuiescence,
  Reachable + unreachable dual) with precise temporal semantics, and forbid a
  model checker / spec-language evaluator in the assertion layer; make an
  assertion's predicate the single shared 17a `Condition` vocabulary (one
  predicate type, two consumers: assertion vs trigger). — satisfies
  [ASRT-1], [ASRT-3], [ASRT-30], [NG-3]; spec §18.1, §18.2, §18.12.1.
  Completed by `checks.crucible.phase4.propertyVocabulary`: `Property` is the
  closed five-kind quantifier enum over the shared 17a `Predicate`/`Condition`
  type, with versioned schema metadata (`PROPERTY_SCHEMA_VERSION = 1`, the
  `crucible.model.properties.v1` domain, binary tags 0..4, canonical labels, and
  TOML `kind` strings) and `PropertyKind` as the single tag source for
  binary/material/TOML encoding. The gate round-trips all five quantifiers plus
  the Reachable warn/fail and unreachable-dual configurations through TOML and
  compact binary, rejects unknown TOML quantifiers and quantifier-specific field
  mismatches before identity validation, proves assertion predicates use the same
  `Condition` value accepted by triggers, and scans the Crucible assertion source
  for runtime model-checker or spec-language evaluator surfaces.
- [x] **T-ASRT-2** Make `Properties` part of the `ScenarioDef` content hash and
  prove property declaration/removal/amendment never changes the run (fingerprint
  unchanged). — satisfies [ASRT-2], [ASRT-25]; spec §18.1, §18.9.
  Completed by `checks.crucible.phase4.propertyFingerprintNeutrality`:
  `ScenarioDef` canonical material includes the `properties_ref` component, so
  declaring, removing, or amending a property changes the scenario content hash
  while preserving the world, plan, and seed components. The gate's Rust proof
  records the same seed-derived decision schedule under removed, declared, and
  amended property sets, drives the `SimBackend` through the backend input,
  horizon-advance, and fingerprint APIs for each scenario form, and includes
  payload/horizon negative controls proving the fingerprint witness would move
  for real node execution changes.
- [x] **T-ASRT-3** Implement per-quantifier configuration (stable id, message,
  Eventually deadline in virtual time, Reachable never-reached disposition) and
  reject non-deterministic / wall-clock-relative parameters at scenario
  validation. — satisfies [ASRT-5]; spec §18.2.1.
  Completed by `checks.crucible.phase4.propertyConfiguration`: assertion
  canonical material includes stable length-prefixed ids and messages,
  Eventually stores only virtual-time `deadline_ticks`, and Reachable carries the
  ordinary warn/fail never-reached disposition or the explicit unreachable dual.
  The gate round-trips these configurations through canonical TOML and compact
  binary, proves ids/messages/deadlines/dispositions move the properties hash,
  defaults omitted ordinary Reachable dispositions to `warn`, keeps the
  reachable/unreachable expectation itself explicit, and rejects host-wall-clock
  or nondeterministic property parameters during TOML scenario validation.
- [x] **T-ASRT-4** Implement observed-state materialization from the event-log
  prefix `[start, t]`, exposing only the black-box surface + ordering/fault facts;
  forbid host-clock/scheduling/unordered-iteration inputs. — satisfies [ASRT-6],
  [ASRT-7]; spec §18.3.
  Completed by `checks.crucible.phase4.observedStateMaterialization`:
  `ConditionEventLogPrefix` now materializes a read-only `ObservedState` view
  from the same checked dense scheduler event-log prefix used by trigger and
  condition evaluation. This completes the materialized-view layer that T-ASRT-5
  will use for host-side assertion evaluation: the view exposes black-box
  `ObservableEvent`s, deterministic scheduler ordering facts, and fault
  activation/outcome/heal facts, while raw RNG draws, app-random draws,
  overrides, preemption decisions, host-worker state, raw scheduler entries, and
  wall-clock sources are excluded. The gate verifies prefix cutoff at the
  evaluation point, invalid-hash/non-dense/future-entry rejection,
  evaluation-pass access to the observed view, and static absence of host time or
  unordered map/set inputs in the observed-state fold.
- [x] **T-ASRT-5** Implement host-side assertions over observable state as the
  default, zero-guest-cooperation source; verify all five quantifiers work in
  black-box mode on an unmodified guest. — satisfies [ASRT-8], [ASRT-9],
  [ASRT-10]; spec §18.4.
  Completed by `checks.crucible.phase4.hostSideAssertions`:
  `HostAssertionEvaluator` grades the five property quantifiers from checked
  `ConditionEventLogPrefix` values using `BlackBoxHostOracle` as the default
  zero-guest-cooperation source. Built-in black-box predicates reuse the shared
  condition evaluator, named host predicates receive the read-only
  `ObservedState` view, warnings do not fail the run, and violations are
  normalized through `AssertionRunVerdict`. A satisfied existential or liveness
  obligation emits its terminal outcome at the exact evaluation boundary, so an
  event graph can consume `AssertionState::Satisfied` online. The gate verifies all five
  quantifiers in black-box mode, failure/warning reporting, named predicate
  access to observed ordering facts, and static absence of host time, thread RNG,
  and unordered map/set inputs in the host assertion evaluator.
- [x] **T-ASRT-6** Implement guest-side marker assertions over the white-box
  channel with the same five-quantifier semantics; fold them into the same
  evaluation pass; keep them observational and fingerprint-neutral; require the
  white-box marker payload to carry id/kind/`must_hit`/details/location so a
  never-reached marker still finalizes Always/Reachable. — satisfies
  [ASRT-11], [ASRT-12], [ASRT-13], [ASRT-32]; spec §18.5, §18.12.3.
  Completed by `checks.crucible.phase4.guestMarkerAssertions`:
  `ObservableEventPayload` now has an assertion-flavored guest marker payload
  carrying id, kind, condition, `must_hit`, structured details, and source
  location. `HostAssertionEvaluator` folds those observational white-box marker
  entries into the same outcome report as host-side properties, using
  world-derived white-box policy rather than self-attested marker data. Generic
  `GuestMarker` predicates match only bare guest-marker events, while assertion
  markers are folded only by `HostAssertionEvaluator` from their recorded
  condition. A canonically authored `AssertionDef::guest_sometimes` declaration
  persists the guest assertion id and message in `ScenarioDef`, pre-seeds that
  same evaluator state, and lets an event graph depend on its validated
  `AssertionState` without a duplicate host-side property. The declared message
  remains authoritative, and a marker whose message drifts from the declaration
  is a violation. The gate verifies
  marker-defined Always/Sometimes/Reachable/
  Unreachable outcomes, all five authored property quantifiers over guest-marker
  predicates, disabled-node rejection, payload finalization fields, terminal
  outcome immutability, kind-mismatch diagnostics, and static absence of host
  time, thread RNG, unordered maps/sets, and scheduler decisions in the guest
  marker assertion evaluator.
- [x] **T-ASRT-7** Implement the offline assertion checker: grade a recorded run's
  log against the original or a new/amended property set with no guest
  re-execution, producing the identical online outcome set. — satisfies [ASRT-14],
  [ASRT-16]; spec §18.6.
  Completed by `checks.crucible.phase4.offlineAssertionChecker`:
  `OfflineAssertionChecker` takes a retained `SchedulerEventLogEntry` slice for
  black-box checking, or a `RecordedAssertionLog` rebuilt from retained
  event-log segments for custom host oracles, reconstructs checked
  `ConditionEventLogPrefix` values from the recorded log, and drives
  `HostAssertionEvaluator` without creating a scheduler or backend. The gate
  verifies whole-report equality with the online evaluator, idempotent re-grading
  of an amended property set, invalid recorded log rejection, default and custom
  host-oracle entry points, missing-offset diagnostics, and static absence of
  guest re-execution or host-time/RNG inputs in the offline checker.
- [x] **T-ASRT-8** Unify online and offline evaluation onto one log-fold code path
  and apply never-evaluated/never-triggered policies identically as a distinct
  outcome. — satisfies [ASRT-15]; spec §18.6, §18.8.
  Completed by `checks.crucible.phase4.assertionLogFold`: the online
  `HostAssertionEvaluator` and offline `OfflineAssertionChecker` both report from
  the same prefix fold/finalization path, and `HostAssertionOutcomeKind` now
  carries distinct `NeverTriggered`, `NeverReachedWarn`, `NeverReachedFail`, and
  empty-log `NeverEvaluated` outcomes instead of folding those edges into generic
  pass/fail/warning. The gate verifies identical streaming online/offline reports
  over the same retained log, fail-only verdict handling for fail-disposition
  reachability, non-failing never-triggered and warn-disposition outcomes, and
  static coverage of the distinct taxonomy. Full scoped lifecycle semantics
  remain with T-ASRT-12.
- [x] **T-ASRT-9** Keep external formal-spec conformance strictly offline via
  trace export to existing tooling; ensure no in-runtime formal-spec evaluator is
  added. — satisfies [ASRT-17], [NG-3]; spec §18.6, §18.10.
  Completed by `checks.crucible.phase4.formalTraceExport`:
  `ExternalFormalTraceExporter` validates retained scheduler event-log entries
  and emits deterministic, content-addressed trace bytes for external consumers
  without changing scheduler event-log encoding.
  The gate verifies deterministic export, invalid-log rejection, public export
  wiring, and a static guard against named in-runtime
  solver/model-checker/spec-evaluator entry points or dependencies.
- [x] **T-ASRT-10** Implement the assertion engine's evaluation timing
  (per-relevant-event + Eventually deadline points; AfterQuiescence once at
  quiescence/limit) as a deterministic function of the log. — satisfies [ASRT-18],
  [ASRT-20]; spec §18.7.
  Completed by `checks.crucible.phase4.assertionEvaluationTiming`:
  `HostAssertionEvaluator` tracks the previous real checked prefix and inserts
  deterministic synthetic `AssertionDeadline` points for pending Eventually
  obligations whose deadlines fall between recorded prefixes. AfterQuiescence
  remains skipped during streaming and is evaluated once during terminal
  finalization. The gate covers synthetic deadline satisfaction, exact-deadline
  event satisfaction inside a later prefix, terminal-only AfterQuiescence
  evaluation, retained offsets at synthetic deadline points, offline every-event
  replay, and static timing wiring.
- [x] **T-ASRT-11** Enforce deterministic evaluation order (by stable id,
  single predicate evaluation per point) identical across runs and online/offline.
  — satisfies [ASRT-19]; spec §18.7.
  Completed by `checks.crucible.phase4.assertionEvaluationOrder`:
  property construction canonicalizes assertions by stable id before building
  `HostAssertionEvaluator`, streaming and deadline folds iterate that canonical
  vector deterministically, and host assertion condition evaluation uses a
  point-local named-leaf cache so repeated leaves inside one assertion are
  resolved once at that point. Guest marker state insertion remains sorted by id,
  and offline checks reuse the same evaluator path. The gate covers compound and
  Eventually duplicate-leaf caching, stable-id order, and identical
  custom-oracle call order plus reports across online/offline replay.
- [x] **T-ASRT-12** Implement the property lifecycle
  (declared/passing/satisfied/failing/violated) and the single unified outcome
  set with the full disposition taxonomy and run verdict. — satisfies [ASRT-21],
  [ASRT-22], [ASRT-23]; spec §18.8.
  Completed by `checks.crucible.phase4.assertionLifecycle`:
  terminal outcome taxonomy now distinguishes safety-style `Passed` from
  existential/liveness `Satisfied`, every outcome carries its terminal
  `PropertyLifecycleState`, and `HostAssertionEvaluator::lifecycle_states`
  exposes deterministic in-flight lifecycle snapshots for host and guest marker
  assertions in the same unified engine. The gate covers declared, passing,
  failing, satisfied, and violated transitions, complete outcome-set emission for
  every declared property, never-evaluated/never-triggered/never-reached edge
  dispositions, and fail-only run verdict derivation from violated plus
  fail-disposition outcomes.
- [x] **T-ASRT-13** Enforce determinism and non-perturbation of evaluation:
  deterministic merge, no banned nondeterminism, read-only observed-state view,
  side-effect-free, fingerprint-neutral. — satisfies [ASRT-24], [ASRT-25],
  [ASRT-26]; spec §18.9.
  Completed by `checks.crucible.phase4.assertionDeterminismNonPerturbation`:
  assertion evaluation now has an assertion-engine-specific gate proving repeated
  online/offline grading yields identical merged host/guest outcomes in stable-id
  order, the observed-state view exposes read-only slices only, and a
  `test-double` backend fingerprint witness is unchanged by assertion evaluation.
  `lint_host_assertion_harness_source` is the host-predicate `gate:harness-lint`
  hook: the evaluator-facing `HostAssertionOracle` is sealed, direct blanket
  implementations are forbidden, and production code exposes no public custom
  wrapper constructor that could pair benign linted source with different
  predicate code. The lint rejects host wall-clock, direct entropy/RNG,
  randomized hashing, unordered-map/set, environment, filesystem/process,
  network, host I/O, threading/scheduling, shared mutable state, interior
  mutability, and unsafe-code access in harness predicate source; the gate also
  statically rejects those patterns in the assertion evaluator path.
- [x] **T-ASRT-14** Implement the violation record (id, icount/virtual-time, node,
  detail, content-addressed reproduction-artifact link) read entirely from the
  deterministic log. — satisfies [ASRT-27], [ASRT-28]; spec §18.10.
  Completed by `checks.crucible.phase4.assertionViolationRecords`: terminal
  assertion reports now expose `HostAssertionViolation` records with assertion id,
  message, quantifier, virtual-time site, optional icount/node site metadata
  captured from the exact predicate evidence that made the assertion terminal,
  expected-vs-observed detail drawn from recorded observed state, and a
  content-addressed retained-log trace hash. The gate covers online/offline
  equality over an icount-stamped guest marker violation, including a same-time
  decoy event that would make timestamp-only attribution choose the wrong node.
- [x] **T-ASRT-15** Wire violation reproduction to bit-identical replay and treat
  non-reproduction as a divergence localized by bisection. — satisfies [ASRT-28],
  [ASRT-29]; spec §18.10.
  Completed by `checks.crucible.phase4.assertionViolationReproduction`:
  `check_assertion_violation_reproduction` now requires replay evidence sealed
  by `AssertionViolationArtifactReplay::from_artifact`, verifies that evidence
  against the self-contained `(seed, scenario, schedule)` `ReproductionArtifact`
  through the reduction oracle, re-grades the recorded and replayed deterministic
  assertion logs with retained offset metadata against the artifact's embedded
  scenario properties, exposes an oracle-aware variant for linted named host
  predicates, rebinds violation links to the artifact id, and reports a localized
  `AssertionViolationDivergence` with a `gate:divergence-bisect` request at the
  first differing event-log prefix when replay fails to reproduce the same
  violation. The gate covers exact replay of the same violation, a deliberately
  altered replay log that localizes to the first changed icount, missing recorded
  violations, and replay evidence reduced from a different artifact schedule.
- [x] **T-ASRT-16** Wire `gate:e2e-determinism` and `gate:replay-oracle` to cover
  assertions: identical outcome sets online vs offline, idempotent re-grading of a
  recorded corpus, and bit-identical violation reproduction. — satisfies [ASRT-4],
  [ASRT-16], [ASRT-23]; spec §18.6, §18.10.
	  Completed by `checks.crucible.phase4.gates.e2eDeterminism` and
	  `checks.crucible.phase4.gates.replayOracle`: the e2e gate now compares
	  assertion outcome sets and run verdicts between scheduler-backed online
	  evaluation and offline retained-log grading, including passing and failing
	  reports from the authoritative and concurrent drives. The replay-oracle gate
	  idempotently re-grades a multi-run retained assertion corpus, re-grades it
	  again after adding an assertion, derives replay logs from the artifact
	  schedule, and runs artifact-bound violation reproduction through
	  `check_assertion_violation_reproduction`. The gate metadata records assertion
	  outcome equality, deterministic verdict composition, idempotent corpus
	  re-grading, artifact-derived replay logs, and bit-identical violation
	  reproduction.
- [x] **T-ASRT-17** Implement the predicate DSL: a set of named, TOML-authorable
  conditions (at least `no_crashed_nodes`, `quiescent`, `no_active_faults`,
  `node_alive:<n>`, `node_crashed:<n>`) that desugar to 17a leaf `Condition`s,
  usable as both assertion predicates and triggers, build-time-resolved against
  the `World`/`Plan`, strictly additive to host closures. — satisfies [ASRT-31];
  spec §18.12.2.
  Completed by `checks.crucible.phase1.gates.contentAddress` and
  `checks.crucible.phase1.gates.harnessLint`: predicate string TOML now parses
  through the shared `Condition` vocabulary, plan-aware property construction and
  event-graph plan construction resolve `no_crashed_nodes`, `quiescent`,
  `no_active_faults`, `node_alive:<n>`, and `node_crashed:<n>` against the
  `World`/`Plan`, and `FaultActive` evaluates recorded injected/healed fault
  facts. Unknown named predicates remain preserved host predicates, so the DSL is
  additive to existing host closures.
- [x] **T-ASRT-18** Implement the OPTIONAL assertion-proximity gradient: a
  deterministic, non-negative, monotone distance-to-satisfaction (0 iff satisfied)
  defined structurally over the 17a `Condition` tree (numeric leaf → threshold gap,
  `And` → sum, `Or`/`AnyOf` → min, boolean-only → `{0, UNIT}`), folded as the
  minimum along the trajectory, for unsatisfied Sometimes / armed Eventually /
  existential Reachable; pure function of the log, online == offline, never moving a
  verdict or fingerprint, consumed only by file-22 guided search and recorded as the
  observational projection of [OBS-37]. — satisfies [ASRT-33]; spec §18.13;
  cross-ref 19 [OBS-37], 22.
  Completed by `checks.crucible.phase4.assertionProximityGradient`,
  `checks.crucible.phase1.gates.singleVmFingerprint`, and
  `checks.crucible.phase4.gates.replayOracle`: `HostAssertionReport::proximities`
  now exposes `HostAssertionProximity` records as report-only steering projections.
  Distances are computed structurally over the retained log (`MemoryPredicate`
  threshold gaps, `AllOf` sums, `AnyOf` minimum, boolean unit distances), folded to
  the minimum checked prefix including armed `Eventually` deadline prefixes, and
  emitted only for unsatisfied `Sometimes`, armed unsatisfied `Eventually`, and
  expected-reachable properties that never reached. The regression tests compare
  online and offline reports and check that proximity does not affect assertion
  verdicts or fingerprints; T-OBS-14 records those report projections as
  observational `assertion_proximity` entries in the unified event log.
