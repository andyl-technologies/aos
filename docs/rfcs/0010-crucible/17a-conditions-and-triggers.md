# 17a — Conditions, triggers, and the event graph

This file specifies how a Crucible scenario expresses **control flow**: the
decisions of *when* to inject a fault, *when* to take a savepoint, *when* to
fork, and *when* to declare the run passed or failed. The answer is a single
mechanism — a **trigger graph** (an **event graph**) whose triggers fire on
**conditions**, and whose conditions are, on the required path, **black-box
observable predicates** over the run's event log. No guest cooperation is needed
to author a complete, expressive scenario; an optional white-box doorbell marker
([`16-guest-host-channel.md`](16-guest-host-channel.md)) is an *additive* leaf
source of conditions for scenarios that opt in.

This file is the real home of the trigger taxonomy that
[`06-spatial-graph.md`](06-spatial-graph.md) §5.1 forward-references ("triggers
… defined in 17"). It defines the `Condition` (predicate) vocabulary that
[`18-assertions-properties.md`](18-assertions-properties.md) *shares* (an
assertion and a trigger are two consumers of one predicate type), that
[`17-fault-injection.md`](17-fault-injection.md) consumes (a fault is a trigger
**action**), that [`19-observability-event-log.md`](19-observability-event-log.md)
*provides the substrate for* (predicates evaluate over the one log), that
[`08-scheduling.md`](08-scheduling.md) *evaluates at deterministic points* (event
and rendezvous boundaries keyed on icount), and that
[`16-guest-host-channel.md`](16-guest-host-channel.md) *optionally enriches* (the
`GuestMarker` leaf).

Requirement IDs in this file use the prefix `TRIG` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates referenced here —
`gate:layer1-injection`, `gate:replay-oracle`, `gate:e2e-determinism`,
`gate:divergence-bisect`, `gate:single-vm-fingerprint`, `gate:content-address`,
`gate:harness-lint`, `gate:scheduler-liveness`, `gate:any-guest` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

The code blocks in this file are **illustrative sketches** per
[`00-conventions.md`](00-conventions.md) §"Code sketches in this RFC": they show
the intended type and wire shapes so the spec is concrete, but the authority is
always the prose requirement. A sketch that disagrees with a requirement is a
defect in the sketch.

## 17a.1 The design principle: control flow is an event graph fired by conditions

A Crucible scenario is not a flat list of time-stamped pokes. It is an **event
graph**: a set of **events**, where each event is a (`trigger`, `action`) pair.
The `trigger` is a **condition** — a predicate over the run — and the `action` is
the thing the engine does when the condition becomes true (inject a fault, arm a
timer, take a savepoint, fork, pass, fail, …). Control flow *emerges* from how
conditions reference each other and the run: "inject a partition once the cluster
is observed healthy, then heal it thirty virtual seconds later" is two events,
the second of which fires on a relative timer that the first event armed.

The single most important property of this design is its relationship to the
black-box principle. **The core requires no guest cooperation.** The leaf
conditions on the required path are all *observable from outside the VM* — a
frame matching a predicate was delivered, a regex matched the console, a basic
block executed, a node crashed, an assertion changed state, the system went
quiescent. Each of these is a projection of the one event log
([`19-observability-event-log.md`](19-observability-event-log.md)), which is
itself populated entirely by host-side observation of an unmodified guest
([`16-guest-host-channel.md`](16-guest-host-channel.md) §16.2). The one leaf that
*does* require the guest to participate — `GuestMarker`, a named doorbell marker
(16) — is strictly optional and strictly additive: the engine MUST function with
zero `GuestMarker` conditions, and a scenario that uses none is fully
authorable, fully expressive, and fully deterministic.

This is the §16.1.2 readiness-detection promise generalized: where 16 says
"begin the workload when the guest is ready can be answered black-box," this file
says "*every* control-flow decision can be answered black-box," using the same
observable surface, lifted into a composable predicate vocabulary.

- **[TRIG-1]** Scenario control flow (when to inject/heal a fault, arm/cancel a
  timer, start/stop a baked node, take a savepoint, fork, pass, fail, or log)
  MUST be expressed as an **event graph**: a set of events, each binding a
  **trigger** (a `Condition`, §17a.2) to an **action** (an `Action`, §17a.4).
  When an event's trigger becomes true at a deterministic evaluation point
  (§17a.3), its action fires. The event graph MUST be the single mechanism for
  control flow; there MUST NOT be a parallel, ad-hoc poke mechanism that bypasses
  it. *Gate:* `gate:layer1-injection`, `gate:e2e-determinism`. *Spec:* §17a.1.

- **[TRIG-2]** Every leaf condition on the **required** path MUST be a **black-box
  observable predicate** — a predicate evaluated over the externally observable
  event log ([GHC-7], [`19-observability-event-log.md`](19-observability-event-log.md))
  of an unmodified guest, requiring **zero guest cooperation**. The engine MUST be
  able to drive a complete, expressive scenario (readiness detection, fault
  injection, property checking, pass/fail) using only observable conditions, and
  MUST function with zero white-box (`GuestMarker`, §17a.2.10) conditions present.
  This is the control-flow realization of [G-2] (any unmodified guest) and [G-3]
  (black-box by default, white-box by opt-in). *Gate:* `gate:any-guest`,
  `gate:e2e-determinism`. *Spec:* §17a.1, §17a.9.

- **[TRIG-3]** A `GuestMarker` leaf condition (§17a.2.10) — a named marker emitted
  via the optional white-box doorbell (16) — MUST be the **only** condition kind
  that requires anything inside the guest, MUST be available only when the node's
  white-box opt-in ([SPAT-9], [GHC-2]) is enabled, and MUST be strictly
  **additive**: removing every `GuestMarker` condition from a scenario MUST leave
  the remaining (observable) event graph fully functional. White-box markers
  enrich the condition vocabulary; they never become a precondition of it.
  *Gate:* `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §17a.1,
  §17a.2.10, §17a.9.

## 17a.2 The shared `Condition` vocabulary: one predicate, two consumers

The center of this file is a single type, the **`Condition`** (equivalently the
**predicate**), and the recognition that it has **exactly two consumers**:

- An **assertion** ([`18-assertions-properties.md`](18-assertions-properties.md))
  is a condition *continuously checked for pass/fail*: an `Always` assertion fails
  the instant its condition is observed false; a `Sometimes` assertion is
  satisfied the first time its condition is observed true. The assertion layer is
  the *grading* consumer of the vocabulary.

- A **trigger** (this file) is a condition that, the first time it becomes true,
  *fires an action once* (or repeatedly, §17a.4). The trigger graph is the
  *control-flow* consumer of the vocabulary.

Both consumers evaluate the **same** predicate over the **same** event log at the
**same** deterministic evaluation points (§17a.3). This unification is
deliberate: a scenario author learns one predicate vocabulary and uses it both to
*check* the run (assertions) and to *steer* the run (triggers). The leaf
`AssertionState` condition (§17a.2.8) closes the loop — a trigger can fire
*because* an assertion just became satisfied or violated — so the two consumers
compose without a second vocabulary.

- **[TRIG-4]** There MUST be a single `Condition` (predicate) type, with exactly
  two consumers: an **assertion** (continuously checked for pass/fail, 18) and a
  **trigger** (fires an action when it first becomes true, this file). Both
  consumers MUST evaluate the identical predicate over the identical event log
  (19) at the identical deterministic evaluation points (§17a.3). There MUST NOT
  be a separate trigger-only predicate vocabulary disjoint from the assertion
  predicate vocabulary; a predicate usable as an assertion MUST be usable as a
  trigger and vice versa, modulo a leaf whose semantics are inherently
  edge-shaped (e.g. `After`, §17a.2.1). *Gate:* `gate:harness-lint`,
  `gate:e2e-determinism`. *Spec:* §17a.2; cross-ref 18 §18.2.

The vocabulary is a small set of **leaf** conditions (each observing one facet of
the run) plus a small set of **compound** combinators (`AllOf`, `AnyOf`, `Once`,
`Not`). The illustrative shape:

```rust,illustrative
/// A predicate over the run, evaluated deterministically over the event log
/// (19) at deterministic evaluation points (§17a.3). Used as both an assertion
/// (continuously graded, 18) and a trigger (fires an action once, §17a.4).
///
/// Every LEAF except `GuestMarker` is BLACK-BOX OBSERVABLE: it needs no guest
/// modification ([TRIG-2]). `GuestMarker` is the single OPTIONAL white-box leaf
/// ([TRIG-3]); the engine functions with zero of them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Condition {
    // ── time leaves (deterministic by construction) ──────────────────────
    /// True at the exact virtual time `at` (a pure-time leaf; §17a.2.1). The
    /// degenerate trigger of the time-scheduled Plan (§17a.7).
    At { at: VirtualTime },
    /// True `duration` of virtual time after the event identified by `of` last
    /// fired; the relative-timer leaf (§17a.2.1, §17a.5). Edge-shaped: it is
    /// armed by another event's firing, not a standing predicate.
    After { duration: VirtualDuration, of: EventId },
    /// True when the named timer (armed by an `ArmTimer` action, §17a.4) fires.
    Timer { name: TimerId },

    // ── observable leaves (black-box; zero guest cooperation) ────────────
    /// True when a frame matching `predicate` is DELIVERED (not merely emitted)
    /// on `link` (or any link if `None`): e.g. the first HTTP 200, a SYN-ACK on
    /// a port. Observed by the network I/O sub-node at RESOLVE (§17a.2.2).
    NetworkMatch { link: Option<LinkId>, predicate: FramePredicate },
    /// True when `node`'s console/serial output matches `regex` (most systems
    /// print a readiness banner). Observed host-side (§17a.2.3, [GHC-7] item 3).
    ConsoleMatch { node: NodeId, regex: RegexProgram },
    /// True when `node` executes the basic block at `addr`/`symbol` — from the
    /// TCG-exec hook (12/22), ZERO guest instrumentation (§17a.2.4).
    CoveragePoint { node: NodeId, point: CodePoint },
    /// True when reading `node`'s memory/register at `addr`/`symbol` at a
    /// deterministic icount (§17a.3.2) satisfies `cmp value`. Host-side symbol
    /// resolution. DEPENDS ON spike S5 (guest-memory read, 30) — §17a.2.5.
    MemoryPredicate { node: NodeId, place: MemPlace, cmp: Cmp, value: u64 },
    /// True when `node` performs an I/O of `kind`: e.g. a block write to a
    /// region, an fsync, a 9p op. Observed at the device sub-node (§17a.2.6).
    IoPattern { node: NodeId, kind: IoEventKind },
    /// True when `node` enters the named lifecycle state (§17a.2.7).
    NodeState { node: NodeId, state: NodeLifecycle }, // Started|Crashed|Exited
    /// True when the named assertion (18) is in the given state — closes the
    /// loop between grading and steering (§17a.2.8).
    AssertionState { name: AssertionId, state: AssertionPhase }, // Satisfied|Violated
    /// True when the whole system is quiescent (08 §8.8): all nodes idle, no
    /// pending deliveries/timers/faults (§17a.2.9).
    Quiescent,

    // ── OPTIONAL white-box leaf (opt-in; additive; NEVER required) ────────
    /// True when a named marker is emitted via the doorbell (16). The ONLY leaf
    /// that needs the guest to participate; the engine MUST run with zero of
    /// these ([TRIG-3]). Requires the node's white-box opt-in (§17a.2.10).
    GuestMarker { name: MarkerId },

    // ── compound combinators (§17a.2.11) ─────────────────────────────────
    /// True when every sub-condition is true. Empty list is rejected (§17a.6).
    AllOf(Vec<Condition>),
    /// True when at least one sub-condition is true. Empty list is rejected.
    AnyOf(Vec<Condition>),
    /// Latches: true once `inner` has EVER been true, and stays true (§17a.2.11).
    Once(Box<Condition>),
    /// True exactly when `inner` is false (§17a.2.11).
    Not(Box<Condition>),
}
```

Each leaf is specified below. For each, the spec states **what it observes** and
that it needs **no guest change** (the lone exception being `GuestMarker`).

### 17a.2.1 Time leaves: `At`, `After`, `Timer`

The three time leaves anchor control flow to virtual time. They are deterministic
by construction (virtual time is icount-derived, [INV-4]) and need no guest
participation at all.

- **`At { at }`** — true at the exact virtual time `at`. This is the *pure-time*
  leaf: an event whose trigger is `At` fires once, at a fixed virtual instant. It
  is the degenerate case that unifies the declarative time-scheduled Plan with the
  event graph (§17a.7): a Plan entry "inject this fault at 10s" *is* an event with
  an `At { at: 10s }` trigger.
- **`After { duration, of }`** — true `duration` of virtual time after the event
  named by `of` last fired. This is the **relative timer**, and it is the leaf
  pure-time scheduling cannot express: "heal 30 virtual seconds *after the
  partition was observed to take effect*" is `After { 30s, of: inject-event }`,
  not a fixed wall instant (§17a.5). `After` is *edge-shaped*: it is meaningful
  only relative to another event's firing, so it is armed when `of` fires rather
  than standing as a continuously-checked predicate; for that reason it is a
  *trigger-side* leaf and is not used as a continuously-graded assertion
  ([TRIG-4]'s "modulo a leaf whose semantics are inherently edge-shaped").
- **`Timer { name }`** — true when the named timer fires. A timer is armed by an
  `ArmTimer` action (§17a.4) at the current virtual time plus a duration, and
  cancelled by `CancelTimer`. `Timer` decouples the *arming* of a relative delay
  (an action, taken when some other condition fired) from the *firing* of it (a
  condition), which is what lets an arbitrary action group arm a delay and an
  arbitrary other event wait on it.

- **[TRIG-5]** The time leaves MUST be: `At { at }` (true at an exact virtual
  time), `After { duration, of }` (true `duration` after the named event last
  fired — the relative timer, §17a.5), and `Timer { name }` (true when a named
  timer armed by an `ArmTimer` action fires, §17a.4). All three MUST be functions
  of virtual time ([INV-4]) and the event graph's own firing history only, never
  of host wall-clock. `After`'s `of` MUST reference a declared event and `Timer`'s
  `name` MUST reference a timer some `ArmTimer` action can arm; both MUST be
  validated at build time (§17a.6). *Gate:* `gate:e2e-determinism`. *Spec:*
  §17a.2.1, §17a.5, §17a.6.

### 17a.2.2 `NetworkMatch` — a matching frame is delivered

`NetworkMatch { link, predicate }` becomes true when a frame matching
`predicate` is **delivered** to its consumer (not merely emitted by a producer)
on the named `link`, or on any link when `link` is `None`. Delivery is the right
edge because it is the cross-node event RESOLVE orders ([SCHED-29]) and stamps
with a `deliver_icount`; the matching frame's delivery icount is the condition's
evaluation point. The predicate is a host-side byte/field match over the observed
frame (a port, a flag, a status line) — the network I/O sub-node already observes
every frame on every link ([GHC-7] item 1,
[`15-io-subnodes.md`](15-io-subnodes.md)), so this needs nothing in the guest.
Typical uses: "the first HTTP 200 was returned", "a SYN-ACK was delivered on port
6443", "a Raft `AppendEntries` reply crossed the link".

- **[TRIG-6]** `NetworkMatch { link, predicate }` MUST become true when a frame
  matching `predicate` is **delivered** (its RESOLVE delivery, [SCHED-29], not its
  emit) on `link` (or on any link when `link` is `None`), with the matching
  frame's `deliver_icount` as the condition's evaluation point. The predicate MUST
  be a deterministic host-side match over the observed frame ([GHC-7] item 1) and
  MUST require no guest instrumentation. *Gate:* `gate:any-guest`,
  `gate:layer1-injection`. *Spec:* §17a.2.2; cross-ref 08 §8.9.4, 15.

### 17a.2.3 `ConsoleMatch` — console/serial output matches a regex

`ConsoleMatch { node, regex }` becomes true when `node`'s console/serial byte
stream matches `regex`. This is the workhorse readiness condition, because almost
every real system prints a readiness banner ("server listening on", a shell
prompt, a "ready to accept connections" line). The console stream is captured
host-side as a pure output sink ([GHC-7] item 3, [GHC-9]); matching it needs
nothing inside the guest and works on any OS ([GHC-4]). The match is over the
deterministic console byte stream, so the icount at which the match completes
(the icount of the last byte of the match) is the condition's deterministic
evaluation point. The `RegexProgram` is a pre-compiled, bounded automaton (no
backtracking blowup) so evaluation terminates ([ASRT-20]-style bound).

- **[TRIG-7]** `ConsoleMatch { node, regex }` MUST become true when `node`'s
  captured console/serial output ([GHC-7] item 3) matches `regex`, with the icount
  of the last byte of the match as the deterministic evaluation point. It MUST be
  a pure host-side match over the deterministic console byte stream, requiring no
  guest cooperation and assuming no guest OS ([GHC-4]). The `regex` MUST be a
  bounded, pre-compiled program whose match evaluation is guaranteed to terminate.
  *Gate:* `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §17a.2.3.

### 17a.2.4 `CoveragePoint` — a basic block executed (zero instrumentation)

`CoveragePoint { node, point }` becomes true the first time `node` executes the
basic block at the given address or symbol. The signal comes from the plugin's
TCG-execution hook ([GHC-7] item 7, 12/22) — the *same* hook that drives
coverage-guided fuzzing — so it requires **zero guest instrumentation**: any
binary, stripped or not, can be observed executing a block. `point` is a host-side
code reference: a raw guest address, or a symbol resolved host-side against the
node's (host-held) symbol table or DWARF. This lets a scenario steer on "the
crash-recovery path was entered" or "the leader-election function ran" without a
single line of in-guest code.

- **[TRIG-8]** `CoveragePoint { node, point }` MUST become true the first time
  `node` executes the basic block named by `point` (a guest address or a
  host-resolved symbol), sourced from the plugin's TCG-execution hook ([GHC-7]
  item 7, 12), with the execution's icount as the deterministic evaluation point.
  It MUST require **zero guest instrumentation** and MUST work on an arbitrary
  (including stripped) guest binary; symbol resolution MUST be host-side. *Gate:*
  `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §17a.2.4; cross-ref 12,
  22.

### 17a.2.5 `MemoryPredicate` — read guest memory/register at a deterministic icount

`MemoryPredicate { node, place, cmp, value }` becomes true when a read of `node`'s
guest memory or register at a *deterministic icount* (§17a.3.2) satisfies
`cmp value` (e.g. `counter >= 3`, `state_byte == 2`). The `place` is a host-side
reference — a guest virtual/physical address or a symbol resolved host-side — read
out-of-band through QMP / the plugin's guest-memory API ([GHC-7] item 4), so no
guest code is involved. This is the most powerful black-box condition (it sees
in-guest state without in-guest cooperation), and also the most delicate, for two
reasons handled elsewhere: its *sampling cadence* must itself be deterministic
(§17a.3.2), and reading a guest **virtual** address safely depends on an
unresolved spike.

**Forward reference and requirement.** Reading guest memory by symbol/virtual
address depends on **spike S5 (guest-memory read)** in
[`30-risks-spikes.md`](30-risks-spikes.md) (the same translation question as
[GHC-33]): whether the plugin's guest-memory API can read a guest virtual address
(translating through the guest page tables at the sample icount) soundly and
reproducibly, or whether only a guest physical address is safe. `MemoryPredicate`
MUST NOT be relied upon until that spike resolves, and until it does the leaf MUST
default to the conservative form the spike permits (physical address / a place the
host can resolve without page-table translation).

- **[TRIG-9]** `MemoryPredicate { node, place, cmp, value }` MUST become true when
  a read of `node`'s guest memory/register at a **deterministic** sample icount
  (§17a.3.2) satisfies `cmp value`. The read MUST be the out-of-band QMP /
  plugin-memory observation of [GHC-7] item 4 (no guest cooperation), with
  host-side symbol resolution. The sampling cadence MUST itself be deterministic
  (§17a.3.2). This leaf MUST be gated on **spike S5** (guest-memory read,
  [`30-risks-spikes.md`](30-risks-spikes.md), mirroring [GHC-33]): until S5
  resolves, `MemoryPredicate` MUST default to the conservative form the spike
  permits and MUST NOT be relied upon for the required black-box path. *Gate:*
  `gate:single-vm-fingerprint`, `gate:divergence-bisect`. *Spec:* §17a.2.5,
  §17a.3.2; forward-ref 30, cross-ref [GHC-33].

### 17a.2.6 `IoPattern` — an I/O of a kind is observed

`IoPattern { node, kind }` becomes true when `node` performs an observable I/O of
the named kind: a block write to a region, an `fsync`/flush, a block read, a 9p
operation. The signal is the disk/9p sub-node's observation of every
request/response ([GHC-7] item 2,
[`15-io-subnodes.md`](15-io-subnodes.md)), and the I/O completion is itself a
cross-node event with a `deliver_icount` ([`19-observability-event-log.md`](19-observability-event-log.md)
§19.7 records it as a `message_delivered`-class entry), so the matching I/O's
completion icount is the evaluation point. This lets a scenario steer on durable
state — "inject a crash *the moment the WAL is fsync'd*", "fork right after the
first block write to the superblock region" — entirely black-box.

- **[TRIG-10]** `IoPattern { node, kind }` MUST become true when `node` performs
  an observable I/O matching `kind` (e.g. a block write to a region, an
  fsync/flush, a 9p op), sourced from the disk/9p sub-node observation of [GHC-7]
  item 2, with the matching I/O's completion icount ([SCHED-29], 19 §19.7) as the
  deterministic evaluation point. It MUST require no guest cooperation. *Gate:*
  `gate:any-guest`, `gate:layer1-injection`. *Spec:* §17a.2.6; cross-ref 15, 19.

### 17a.2.7 `NodeState` — `Started` / `Crashed` / `Exited`

`NodeState { node, state }` becomes true when `node` enters a lifecycle state:
`Started` (reached its ready point, [`06-spatial-graph.md`](06-spatial-graph.md)
§3.1, recorded as `node_started`), `Crashed` (panicked / triple-faulted / hit a
crash fault, recorded as `node_crashed`), or `Exited` (shut down / completed,
recorded as `node_completed`). These are exactly the causal node-lifecycle entries
of the event log (19 §19.7), observed host-side ([GHC-7] items 5,6). A scenario
steers cluster choreography on them: "start the standby once the primary has
`Started`", "fail the run if any node `Crashed` outside an injected crash window".

- **[TRIG-11]** `NodeState { node, state }` MUST become true when `node` enters the
  named lifecycle state — `Started` (ready point reached), `Crashed`
  (panic/reset/crash-fault), or `Exited` (clean shutdown/completion) — sourced from
  the causal `node_started`/`node_crashed`/`node_completed` event-log entries
  (19 §19.7) observed host-side ([GHC-7] items 5, 6), with that entry's icount as
  the evaluation point. It MUST require no guest cooperation. *Gate:*
  `gate:any-guest`, `gate:layer1-injection`. *Spec:* §17a.2.7; cross-ref 06 §3.1,
  19.

### 17a.2.8 `AssertionState` — `Satisfied` / `Violated`

`AssertionState { name, state }` becomes true when the named assertion (18) enters
the given lifecycle state (`Satisfied` or `Violated`,
[`18-assertions-properties.md`](18-assertions-properties.md) §18.8). This is the
leaf that **closes the loop** between the two consumers of the vocabulary: a
*trigger* can fire *because* an *assertion* just changed state. It is what makes
property-conditional fault campaigns possible without a second mechanism — "once
the `leader-elected` Sometimes-assertion is satisfied, inject a partition", "the
moment any `Always` invariant is violated, take a savepoint and fork for
analysis". The signal is the causal `assertion_state_changed` entry (19 §19.7), so
it is deterministic and offline-checkable on the same terms as everything else.

- **[TRIG-12]** `AssertionState { name, state }` MUST become true when the named
  assertion (18) enters the `Satisfied` or `Violated` state, sourced from the
  causal `assertion_state_changed` event-log entry (19 §19.7) with that entry's
  icount as the evaluation point. `name` MUST reference a declared assertion,
  validated at build time (§17a.6). This leaf MUST be the supported way to make a
  trigger fire on an assertion outcome (property-conditional control flow), with no
  separate mechanism. *Gate:* `gate:e2e-determinism`. *Spec:* §17a.2.8; cross-ref
  18 §18.8.

### 17a.2.9 `Quiescent` — the system settled

`Quiescent` becomes true when the whole system reaches quiescence (08 §8.8): every
node idle, no pending cross-node deliveries, no pending timers or I/O completions,
no future faults due. It is the natural trigger for end-of-run choreography
("pass once the cluster has converged and gone quiet") and the temporal companion
of the assertion layer's `AfterQuiescence` ([ASRT-3]). Quiescence is computed from
authoritative scheduler state deterministically ([SCHED-22], [SCHED-23]), never
from a host timeout, so the `Quiescent` condition is as deterministic as any
other.

- **[TRIG-13]** `Quiescent` MUST become true exactly when the scheduler detects
  quiescence ([SCHED-22], [SCHED-23]): all nodes idle, no pending deliveries,
  timers, I/O completions, or due faults, computed from authoritative scheduler
  state, never from a host timeout. Its evaluation point MUST be the quiescence
  virtual time. *Gate:* `gate:scheduler-liveness`, `gate:e2e-determinism`. *Spec:*
  §17a.2.9; cross-ref 08 §8.8.

### 17a.2.10 `GuestMarker` — the one optional white-box leaf

`GuestMarker { name }` becomes true when the guest emits a named marker via the
white-box doorbell (16). It is the **only** condition that requires the guest to
participate, and it is **opt-in, optional, and additive** by construction:

- it is available only when the node's white-box opt-in ([SPAT-9], [GHC-2]) is
  enabled;
- the marker is recorded as an *observational* event-log entry stamped at the
  exact doorbell-retirement icount ([GHC-13], [GHC-24]), so the condition's
  evaluation point is deterministic even though the marker is observational; and
- the engine MUST function with **zero** `GuestMarker` conditions: a scenario that
  uses none is a complete, expressive, deterministic scenario ([TRIG-2],
  [TRIG-3]).

`GuestMarker` is for the rare control-flow decision that genuinely depends on
in-guest state no observable surface exposes ("fork the instant the in-process
compaction begins", named by the guest itself). It *enriches* the vocabulary; it
never *gates* it.

- **[TRIG-14]** `GuestMarker { name }` MUST become true when the guest emits the
  named marker via the white-box doorbell (16), with the marker's recorded
  doorbell-retirement icount ([GHC-13]) as the deterministic evaluation point. It
  MUST be the **only** condition kind requiring guest participation; it MUST be
  available only when the node's white-box opt-in is enabled ([SPAT-9], [GHC-2]);
  and the engine MUST function with zero `GuestMarker` conditions present ([TRIG-3]).
  Because the marker is observational ([GHC-24]), using `GuestMarker` conditions
  MUST NOT move any node's determinism fingerprint relative to the same scenario
  with the white-box channel compiled out ([GHC-30]). *Gate:* `gate:any-guest`,
  `gate:single-vm-fingerprint`. *Spec:* §17a.2.10; cross-ref 16 §16.5.

### 17a.2.11 Compound combinators: `AllOf`, `AnyOf`, `Once`, `Not`

Leaf conditions compose through four combinators:

- **`AllOf(subs)`** — true when *every* sub-condition is true.
- **`AnyOf(subs)`** — true when *at least one* sub-condition is true.
- **`Once(inner)`** — *latches*: true once `inner` has *ever* been true, and stays
  true thereafter. This is the combinator that turns an instantaneous edge (a
  frame delivered, a block executed) into a standing fact, so an `AllOf` of two
  edges that never coincide on one evaluation point can still both be "remembered"
  and fire together. (Most leaf conditions over the log are naturally latching
  once their generating event has occurred; `Once` makes that explicit and
  composable, and is the precise semantics the cycle/reachability analysis of
  §17a.6 reasons over.)
- **`Not(inner)`** — true exactly when `inner` is false.

The combinators nest arbitrarily: `AllOf([ConsoleMatch{…ready…},
Once(CoveragePoint{…recovery-entered…})])` fires when the node is ready *and* the
recovery path has been entered at some point. An empty `AllOf`/`AnyOf` is a
construction error rejected at build time (§17a.6), because an empty `AllOf` is
vacuously true (a footgun that fires immediately) and an empty `AnyOf` is
vacuously false (dead).

- **[TRIG-15]** The compound combinators MUST be `AllOf` (all sub-conditions
  true), `AnyOf` (at least one true), `Once` (latches true once `inner` has ever
  been true), and `Not` (true iff `inner` is false), nesting arbitrarily. Their
  truth MUST be a pure function of their sub-conditions evaluated over the same
  event-log prefix at the same evaluation point (§17a.3). An empty `AllOf` or
  `AnyOf` MUST be rejected at build time (§17a.6), never silently treated as
  vacuously true/false. *Gate:* `gate:harness-lint`, `gate:e2e-determinism`.
  *Spec:* §17a.2.11, §17a.6.

## 17a.3 Determinism of evaluation (the critical section)

Conditions are predicates over the run, and the run is `reduce(ScenarioDef,
Schedule)` ([INV-1]). For triggers to compose with determinism, the *evaluation*
of conditions must be as deterministic as the run itself. Two rules make it so:
conditions are evaluated only at **deterministic points**, and a trigger firing is
**engine behavior, not a `Decision`**.

### 17a.3.1 Evaluate only at deterministic points over the event log

A condition MUST be evaluated **only** over the event log
([`19-observability-event-log.md`](19-observability-event-log.md)) and **only** at
the deterministic evaluation points the scheduler already defines: at the relevant
**event boundaries** (an event-log entry of a kind a condition depends on,
[ASRT-18]) and at **rendezvous / quantum boundaries** keyed on virtual time /
icount (08). A condition MUST NEVER be polled on host wall-clock, on a host timer,
or "as fast as the host loops" — that would inject exactly the arrival-driven
nondeterminism the whole system bans ([INV-1], [INV-3], [DET-13]). Because the
evaluation points are a deterministic function of the log (the same log produces
the same set of evaluation points, [ASRT-18]), the *truth* of every condition at
every point — and therefore *which triggers fire and when* — is a pure function of
`(ScenarioDef, Seed, Schedule)`.

This is the same evaluation discipline the assertion engine uses (18 §18.7), and
that is by design: triggers and assertions share not only the predicate vocabulary
(§17a.2) but the evaluation timing. The engine evaluates the relevant conditions —
both trigger conditions and assertion conditions — in one deterministic pass per
evaluation point, ordered by a stable key (§17a.3.3).

- **[TRIG-16]** A `Condition` MUST be evaluated **only** over the event log (19)
  and **only** at deterministic evaluation points: the relevant event boundaries
  (an entry of a kind the condition depends on, [ASRT-18]) and the rendezvous /
  quantum boundaries keyed on virtual time / icount (08). It MUST NEVER be polled
  on host wall-clock, a host timer, or a host loop. The set of evaluation points
  MUST be a deterministic function of the log, so the truth of every condition at
  every point — and thus which triggers fire and when — is a pure function of
  `(ScenarioDef, Seed, Schedule)` ([INV-1], [INV-3]). *Gate:*
  `gate:e2e-determinism`, `gate:harness-lint`. *Spec:* §17a.3.1; cross-ref 08, 18
  §18.7, 19.

- **[TRIG-17]** Trigger evaluation MUST be evaluated in the **same deterministic
  pass** as assertion evaluation (18 §18.7) at each evaluation point: both consume
  the same `Condition` vocabulary over the same log prefix `[start, t]` ([ASRT-7]),
  so a trigger's leaf and an assertion's leaf observing the same fact observe it
  identically. A condition at evaluation point `t` MUST see only the log prefix up
  to and including `t` (never a later entry), which is what makes online and
  offline evaluation agree ([ASRT-15]) and a firing attributable to a definite
  earliest icount. *Gate:* `gate:replay-oracle`. *Spec:* §17a.3.1; cross-ref 18
  §18.3, §18.7.

### 17a.3.2 Sampling cadence of `MemoryPredicate` and `CoveragePoint` is itself deterministic

Two leaves — `MemoryPredicate` (a memory/register read) and, where it requires an
active sample rather than a logged event, `CoveragePoint` — could in a naïve
implementation be *sampled* at a host-chosen moment, which would make their truth
host-timing-dependent even though the underlying guest state is deterministic. The
spec forbids this: the **sampling cadence must itself be deterministic**, tied to
icount or to the relevant logged events, never to host time.

Concretely: `CoveragePoint` is driven by the TCG-exec hook, so its "sample" is the
deterministic block-execution event itself — there is no separate cadence to make
deterministic, only the requirement that the event is recorded at its execution
icount. `MemoryPredicate` is the one that needs an explicit deterministic cadence:
its read MUST be taken at a deterministic sample icount — bound to the evaluation
points of §17a.3.1 (relevant events and rendezvous boundaries), or to an
author-declared deterministic stride in virtual time (a "sample every `S` virtual
ns" that resolves to fixed icounts), never "whenever the host engine happened to
poll." Two runs of the same `(ScenarioDef, Seed, Schedule)` MUST read guest memory
at the identical set of sample icounts and therefore observe the identical truth
sequence.

- **[TRIG-18]** The sampling cadence of `MemoryPredicate` (and of any condition
  that requires an active guest-state sample rather than a logged event) MUST
  itself be **deterministic**, tied to icount or to the relevant logged events of
  §17a.3.1 — the evaluation points, or an author-declared deterministic
  virtual-time stride resolving to fixed icounts — and MUST NEVER be a host-timed
  poll. Two runs of the same `(ScenarioDef, Seed, Schedule)` MUST sample at the
  identical set of icounts and observe the identical truth sequence. A
  `CoveragePoint` MUST be sampled by the deterministic block-execution event itself
  (its execution icount), with no separate host-timed cadence. *Gate:*
  `gate:single-vm-fingerprint`, `gate:divergence-bisect`. *Spec:* §17a.3.2;
  cross-ref §17a.2.4, §17a.2.5, 09.

### 17a.3.3 A trigger firing is deterministic engine behavior, not a `Decision`

This is the load-bearing distinction that lets triggers compose with fork, search,
and fuzzing (22). A **`Decision`** ([`05-execution-model.md`](05-execution-model.md)
§3, [`02-glossary.md`](02-glossary.md)) is a *resolved nondeterministic choice*:
the delivery order of simultaneous events, *whether a probabilistic fault fires*,
a draw from the seeded decision RNG. Decisions are the **edges of the temporal
graph** — the things that *vary between runs of one `ScenarioDef`* and that
state-space search enumerates.

A **trigger firing is none of those.** Given the event log up to evaluation point
`t`, whether a condition is true at `t` is *computed*, not *chosen*: it is a pure
function of the log, with no RNG draw and no resolution of ambiguity. A trigger
that fires fires *deterministically* because its condition became true
deterministically. Therefore a trigger firing MUST be recorded as ordinary causal
engine behavior in the event log (an `event_activated` / `fault_activated` /
`timer_armed` causal entry, 19 §19.7), **not** as a `Decision` appended to the
`Schedule`.

The consequence is exactly what makes the model compose cleanly with exploration:

- **Only resolved choices are Decisions.** A signal binding with a stochastic
  source or finite search policy produces Decisions at its declared opportunity,
  but the referenced event firing remains deterministic causal input. This keeps
  the boundary crisp.
- **Search enumerates Decisions, not triggers.** Because triggers are not
  Decisions, state-space search (22) does not "branch on whether a trigger fired"
  — a trigger fires or not as a function of the schedule it is exploring. Search
  branches on the genuine choices (delivery order, probabilistic faults), and the
  trigger graph rides deterministically on top of each explored schedule. A fork
  at a checkpoint re-derives the same trigger firings on the same schedule prefix
  by construction ([INV-2]).

- **[TRIG-19]** A trigger firing MUST be **deterministic engine behavior**, not a
  `Decision` (05 §3): given the event log up to an evaluation point, whether a
  condition is true is *computed* (a pure function of the log), never *chosen* (no
  RNG draw, no ambiguity resolution). A trigger firing MUST be recorded as an
  ordinary **causal** event-log entry (`event_activated`/`fault_activated`/
  `timer_armed`, 19 §19.7), and MUST NOT be appended to the `Schedule` as a
  `Decision`. *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:*
  §17a.3.3; cross-ref 05 §3, 19 §19.7.

- **[TRIG-20]** Only **probabilistic outcomes** of a trigger's *action* MUST be
  `Decision`s: a trigger whose action injects a probabilistic fault produces
  Decisions for the *fault's* per-frame draws ([FAULT-2], [FAULT-12]) when the
  fault is active, never for the deterministic *firing*. State-space search and
  coverage-guided fuzzing (22) MUST enumerate `Decision`s (delivery order,
  probabilistic faults), and the trigger graph MUST ride deterministically on top
  of each explored schedule — a fork at a checkpoint re-derives identical trigger
  firings on the same schedule prefix ([INV-2]). *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §17a.3.3; cross-ref 22, 05.

## 17a.4 Events and actions

An **event** binds a trigger condition to an action and a firing policy:

```rust,illustrative
/// One node of the event graph: when `trigger` becomes true at a deterministic
/// evaluation point (§17a.3), `action` fires. `policy` controls re-firing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Event {
    /// Stable, author-assigned identity, unique within the event graph. The key
    /// for `After { of }` (§17a.2.1), cycle/reachability analysis (§17a.6), and
    /// the causal `event_activated` log entry (19 §19.7).
    pub id: EventId,
    /// The condition that fires this event. `None` is an ENTRYPOINT — fired once
    /// at run start (the genesis evaluation point), the root of reachability
    /// (§17a.6); equivalently `Some(At { at: 0 })`.
    pub trigger: Option<Condition>,
    /// What happens when the trigger fires.
    pub action: Action,
    /// Fire once (default) or every time the trigger is (re-)satisfied (§17a.4).
    pub policy: FirePolicy,
}

/// Whether an event fires once or repeatedly (§17a.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirePolicy {
    /// Fire exactly once, the first time the trigger is true, then consumed.
    Once,
    /// Fire each time the trigger transitions false→true (repeatable).
    Repeatable,
}

/// What an event does when it fires. Fault behavior belongs to signal bindings;
/// the action set covers timers, baked-node scheduling, savepoints, forks,
/// pass/fail, logging, and grouping.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Action {
    // ── timers (the relative-delay primitive, §17a.5) ────────────────────
    /// Arm a named timer to fire `after` virtual time from now; its firing is
    /// observed by a `Timer { name }` condition (§17a.2.1).
    ArmTimer { name: TimerId, after: VirtualDuration },
    /// Cancel a previously-armed timer (no-op if not armed / already fired).
    CancelTimer { name: TimerId },

    // ── baked-node scheduling (NOT topology mutation, §17a.4.1) ───────────
    /// Start a BAKED, declared node at the firing point (it was inactive until
    /// now). Scheduling a declared node, not adding one (§17a.4.1).
    StartNode { node: NodeId },
    /// Stop a declared node at the firing point (it stays declared).
    StopNode { node: NodeId },

    // ── temporal-graph control (07, 20, 22) ──────────────────────────────
    /// Take a savepoint (a checkpoint) at the firing point (07).
    CreateSavepoint { label: Option<Label> },
    /// Fork the temporal graph at the firing point for exploration (07, 22).
    Fork { label: Option<Label> },

    // ── verdict (the run's terminal control flow) ────────────────────────
    /// Declare the run passed and request termination (§17a.8).
    Pass,
    /// Declare the run failed and request termination, with a reason.
    Fail { reason: Str },

    // ── observability / composition ──────────────────────────────────────
    /// Append an observational `diagnostic` log entry (19), never causal.
    Log { level: Level, message: Str },
    /// Fire several actions, in declared order, atomically at the firing point.
    Group(Vec<Action>),
}
```

The action set is small and complete. Fault effects are not actions: signal
bindings sample event-domain inputs and add or remove typed persistent
contributions at the same deterministic boundaries. `ArmTimer` / `CancelTimer`
are the relative-delay primitive (§17a.5).
`StartNode` / `StopNode` schedule a *baked* declared node (§17a.4.1).
`CreateSavepoint` / `Fork` drive the temporal graph (07, 22). `Pass` / `Fail` are
the run verdict (§17a.8). `Log` is observational. `Group` fires several actions
atomically at one firing point, in declared order, so "arm a heal timer *and* take
a savepoint *and* log" is one event.

- **[TRIG-21]** An `Event` MUST be a `(id, trigger, action, policy)` tuple where
  `trigger` is an `Option<Condition>` (`None` = an **entrypoint** fired once at the
  genesis evaluation point, the root of reachability §17a.6, equivalent to
  `Some(At { at: 0 })`), `action` is an `Action`, and `policy` is `Once` (fire
  once, then consume) or `Repeatable` (fire on each false→true transition). `id`
  MUST be unique within the event graph and is the key for `After { of }`
  (§17a.2.1) and for cycle/reachability analysis (§17a.6). *Gate:*
  `gate:e2e-determinism`. *Spec:* §17a.4, §17a.6.

- **[TRIG-22]** The `Action` set MUST include exactly:
  `ArmTimer`/`CancelTimer` (§17a.5); `StartNode`/`StopNode` (baked-node
  scheduling, §17a.4.1); `CreateSavepoint`/`Fork` (07, 22); `Pass`/`Fail`
  (§17a.8); `Log` (observational); and `Group` (several actions fired atomically
  in declared order at one firing point). Fault behavior MUST be expressed only
  by the signal/binding model in 17. *Gate:* `gate:layer1-injection`,
  `gate:e2e-determinism`. *Spec:* §17a.4; cross-ref 17 §17.6.2.

- **[TRIG-23]** Every action MUST be applied **deterministically at the firing
  virtual time**, at a quantum boundary ([SCHED-3], [SCHED-33], the [INV-8] yield
  point). An action's effect
  MUST be a function of `(ScenarioDef, Seed, Schedule)` and the firing point only.
  A `Group`'s constituent actions MUST be applied in declared order at the single
  firing point, atomically with respect to the run (no other quantum intervenes
  between them). *Gate:* `gate:layer1-injection`, `gate:replay-oracle`. *Spec:*
  §17a.4; cross-ref 08 §8.9.6, 17 §17.6.2.

### 17a.4.1 `StartNode` / `StopNode` schedule a baked node — not topology mutation

`StartNode` and `StopNode` are the subtle actions, because they must be reconciled
with the **static-`World`** rule ([SPAT-16], [SPAT-18]): the set of nodes and links
is fixed for the life of a `ScenarioDef`; there is no `add_node`. `StartNode` does
**not** add a node and `StopNode` does **not** remove one. Both operate on a node
that is **already declared and already baked** ([EXEC-18], 05 §6) — a participant
that exists in the `World`, was booted once to its ready point by `bake`, and is
held *inactive* until a scheduled point activates it.

This is exactly the membership model 06 already mandates: a "not-yet-joined"
participant is a declared node whose `node.lifecycle` binding holds it inactive
until a `Plan` event activates it ([SPAT-17]). `StartNode` is the activation;
`StopNode` is the inverse. Semantically a `StopNode` is the choreography sibling
of a `node.lifecycle` crash transition ([FAULT-19]) restricted to a clean stop,
and a `StartNode` is the choreography sibling of a lifecycle recovery that
restarts from the baked ready point ([FAULT-20] `FromReadyPoint`). The
distinction this file draws: `StartNode`/`StopNode` are
*deliberate scheduling of a baked node's activity* (rolling-restart choreography,
"bring the standby online at 30s"), expressed as a first-class action so the
author need not phrase routine choreography as a crash fault. They schedule a
baked node; they never mutate the topology, the participant set, the RNG-stream
set, the lookahead graph, or the bake set ([SPAT-18]).

- **[TRIG-24]** `StartNode { node }` and `StopNode { node }` MUST operate only on a
  **declared, baked** node ([SPAT-16], [EXEC-18], 05 §6): `StartNode` activates a
  node held inactive (the [SPAT-17] "not-yet-joined" participant), and `StopNode`
  cleanly stops a declared node that stays declared. They MUST NOT add or remove a
  node, change the link set, or alter the participant set, per-entity RNG-stream
  set, lookahead graph, or bake set, all of which remain functions of the `World`
  alone ([SPAT-18]). `node` MUST reference a declared node, validated at build time
  (§17a.6). *Gate:* `gate:content-address`, `gate:e2e-determinism`. *Spec:*
  §17a.4.1; cross-ref 06 §4, 05 §6, 17 §17.4.3.

## 17a.5 Relative timers and phases (what pure-VT scheduling cannot do)

The event graph provides **relative timing anchored to observations.** A
time-domain signal can start at 40s, but observation-relative behavior instead
uses a referenced event occurrence as signal input:

```text
Observe (cluster ready AND recovery path observed), then emit one occurrence.

  event "ready":
    trigger = AllOf([ ConsoleMatch{node=db-0, regex="ready to accept"},
                      ConsoleMatch{node=db-1, regex="ready to accept"} ])
    action  = Log{level="info", message="cluster ready"}

  signal "split-window":
    source = EventPulse{event="ready", duration=30s}

  binding "split":
    mapping = ActiveWhenTrue
    effect = NetworkAvailability{state=Unavailable}
```

Equivalently, the `After { duration, of }` leaf folds the arm-and-wait into one
condition: the `heal` event's trigger is `After { 30s, of: "inject" }`, which is
true 30 virtual seconds after the `inject` event last fired — no explicit timer
name needed. The two spellings are equivalent; `ArmTimer`+`Timer` is the general
form (the arming action can live in any `Group`, and one timer can gate several
events), while `After` is the sugar for the common one-to-one case.

The point is the **phase**: the inject event and the heal event form a
*partition-then-recover phase* whose *start* is an observation and whose *end* is a
relative offset from that observation — a phase that is the same shape regardless
of *when* the cluster happens to become ready in any given run. This is the
expressive core a fixed virtual-time Plan lacks.

- **[TRIG-25]** The event graph MUST express **relative timing anchored to an
  observation**: an action MAY arm a relative timer (`ArmTimer { after }`) whose
  firing (`Timer`) or the equivalent `After { duration, of }` leaf becomes true a
  fixed amount of **virtual time** after a triggering observation fired — a thing a
  flat virtual-time Plan cannot express because the anchor (the observation's
  virtual time) is run-dependent. `ArmTimer`+`Timer` MUST be the general form
  (armable from any `Group`, gating any number of events) and `After { duration,
  of }` MUST be the equivalent sugar for the one-to-one case. All relative timing
  MUST be in virtual time, deterministic ([INV-4]). *Gate:* `gate:e2e-determinism`,
  `gate:layer1-injection`. *Spec:* §17a.5; cross-ref §17a.2.1, §17a.4.

### 17a.5.1 Worked example: a partition-recovery scenario over observable conditions

A complete partition-recovery scenario with an unmodified guest kernel and image:
readiness by console banner, an additional coverage gate, observable fault
injection, a relative-timer heal, and a structured assertion from the
user-controlled test application:

```toml
# A partition-recovery scenario. Host facts are directly observable; the
# application reports semantic convergence with a guest assertion. Times are virtual (09).

[[event]]
id = "wait-ready"
# fire once both replicas print readiness AND the cluster-join path has run —
# console banner + coverage point, both observable with zero instrumentation.
trigger = { all_of = [
  { console_match = { node = "db-0", regex = "ready to accept connections" } },
  { console_match = { node = "db-1", regex = "ready to accept connections" } },
  { once = { coverage_point = { node = "db-0", symbol = "cluster_join_complete" } } },
] }
# Arm the relative timer used by the `split` signal binding's pulse interval.
action = { group = [
  { arm_timer = { name = "heal-after", after = "30s" } },
] }

# `split` is a persistent network.availability binding driven by a Boolean
# pulse anchored to wait-ready. Signal deactivation removes the contribution;
# there is no imperative heal action.

[[event]]
id = "pass-when-converged"
# once the guest reports reconciliation AFTER the heal, and the system settles,
# declare pass.
trigger = { all_of = [
  { once = { assertion_state = { name = "replicas-converge", state = "satisfied" } } },
  { quiescent = {} },
] }
action  = { pass = {} }

# The recovery PROPERTY is an assertion sharing the SAME predicate vocabulary (18):
[[properties.assertion]]
name = "replicas-converge"
kind = "eventually"
trigger   = { assertion_state = { name = "split-active", state = "satisfied" } }  # after the split
property  = { assertion_state = { name = "replicas-converge", state = "satisfied" } }
deadline  = "60s"
```

The scenario reads as phases — wait-ready, inject, heal-after-30s, pass-on-converge
— each gated on an observable condition, with the heal anchored *relative* to the
observed readiness. The host owns readiness, fault, timer, and quiescence facts;
the user-controlled test application supplies the richer semantic convergence
assertion without requiring a modified kernel or root image.

## 17a.6 The trigger-graph validator (build-time)

An ill-formed event graph MUST be rejected at **parse/build time**, never at
runtime — the same fail-early discipline as the spatial graph
([`06-spatial-graph.md`](06-spatial-graph.md) §9): a graph that reaches the
scheduler is already known well-formed. The validator runs four checks:

1. **Dangling-reference** — every reference resolves: a condition's `node`/`link`
   references a declared node/link ([SPAT-6], [SPAT-10]); `After { of }` and a
   cycle edge reference a declared event; `Timer { name }` references a timer some
   `ArmTimer` action can arm; `AssertionState { name }` references a declared
   assertion (18); event-domain signals reference a declared event;
   `GuestMarker` is used only on a white-box-opted-in node
   ([SPAT-9]).
2. **Empty-compound** — no `AllOf`/`AnyOf` is empty (an empty `AllOf` is a
   fire-immediately footgun; an empty `AnyOf` is dead, §17a.2.11).
3. **Cycle detection (DFS)** — the dependency graph among **non-repeatable** events
   (an edge `A → B` when `B`'s trigger depends on `A` having fired) MUST be acyclic.
   A cycle of fire-once events can never make progress (each waits on another that
   waits on it), so it is a construction error. Cycle detection is a depth-first
   search with white/gray/black coloring; a back-edge to a gray node is a cycle,
   reported with the participating event ids. (Repeatable events are excluded from
   the acyclicity constraint, because a deliberate repeatable feedback loop —
   "re-arm on each fire" — is a legitimate construction, not a deadlock.)
4. **Reachability** — every event MUST be reachable from an entrypoint (an event
   with `trigger: None`, or one whose trigger is satisfiable from the genesis
   point). An event no path can ever reach is dead config and a likely authoring
   error; it MUST be reported.

```rust,illustrative
/// Build-time event-graph validation failures. Every variant is caught before
/// the graph is hashed/run ([TRIG-26]); none is deferred to runtime.
#[derive(Debug)]
pub enum TriggerGraphError {
    /// A condition references an undeclared node/link/event/timer/assertion/tag,
    /// or a GuestMarker on a node without the white-box opt-in.
    DanglingRef { site: EventId, detail: RefDetail },
    /// An `AllOf`/`AnyOf` with no sub-conditions.
    EmptyCompound { site: EventId },
    /// A cycle among non-repeatable events (the participating ids).
    Cycle { events: Vec<EventId> },
    /// An event no path from any entrypoint can ever reach.
    UnreachableEvent { event: EventId },
}
```

- **[TRIG-26]** The event graph MUST be validated at **parse/build time** and an
  ill-formed graph rejected with a precise, localized error *before* it is
  content-addressed or run, with no well-formedness check deferred to runtime (the
  [SPAT-32] discipline). The validator MUST check: (a) **dangling references** —
  every `node`/`link`/`of`/`Timer name`/`AssertionState name`
  reference resolves to a declared entity ([SPAT-6], [SPAT-10], [SPAT-31]) and
  `GuestMarker` is used only on a white-box-opted-in node ([SPAT-9]); (b)
  **empty-compound** — no `AllOf`/`AnyOf` is empty; (c) **cycles** — the dependency
  graph among non-repeatable events is acyclic (DFS, white/gray/black coloring;
  repeatable events are excluded from the constraint); (d) **reachability** — every
  event is reachable from an entrypoint. *Gate:* `gate:content-address`,
  `gate:harness-lint`. *Spec:* §17a.6; cross-ref 06 §9.

- **[TRIG-27]** Cycle detection MUST be a depth-first search over the
  non-repeatable-event dependency graph using white/gray/black coloring, reporting
  the first detected cycle's participating event ids; a back-edge to a gray node is
  a cycle. Reachability MUST be a traversal from the entrypoint set (events with
  `trigger: None`) reporting every event no path reaches. Both MUST run over a
  canonical (sorted) event/edge ordering so the *error reported* is itself
  deterministic across hosts ([INV-9], [SPAT-30]). *Gate:* `gate:harness-lint`.
  *Spec:* §17a.6.

## 17a.7 Relationship to signal-driven faults

The Plan carries both an event graph and a `FaultSignalPlan`. They are distinct
typed submodels with one-way data flow: an event firing emits a referenced
occurrence, an event-domain signal source consumes that occurrence, and a fault
binding maps the signal value to an adapter effect. Event actions never add or
remove faults.

Known-time fault behavior does not need an event. It uses a time-domain signal
node directly. Observation-anchored behavior names the referenced event source,
including its occurrence policy, and checkpoints the event cursor alongside the
signal runtime. This preserves one fault representation and one event-action
taxonomy while still supporting relative, observable choreography.

- **[TRIG-28]** Event-domain signal sources MUST reference declared event IDs,
  define exact occurrence and repeat semantics, and reject dangling references
  at admission. Their consumed occurrence cursors MUST be checkpointed and
  authenticated. *Gate:* `gate:content-address`, `gate:e2e-determinism`.
  *Spec:* §17a.7; cross-ref 17 §17.6.5.

- **[TRIG-29]** A scenario that needs only time-scheduled faults MUST express
  them as time-domain signal nodes without adding event-graph actions. Adding an
  observation-anchored event MUST NOT change the meaning or identity of an
  existing independent time-domain signal program
  entries ([SPAT-5], meaning-not-spelling). *Gate:* `gate:content-address`. *Spec:*
  §17a.7; cross-ref 06 §2, §8.

## 17a.8 Pass/fail and the run verdict

`Pass` and `Fail` actions are the event graph's terminal control flow: an event
can declare the run passed or failed and request termination. They are the
imperative, *control-flow* sibling of the assertion layer's declarative verdict
(18 §18.8): an author may either declare properties and let the assertion verdict
decide pass/fail, or steer the verdict directly with a `Pass`/`Fail`-actioned event
(e.g. "pass once the cluster has converged and gone `Quiescent`", "fail the moment
`AssertionState{any-Always, Violated}`"). The two interoperate through the
`AssertionState` leaf (§17a.2.8): a `Fail` event can fire *on* an assertion
violation, and a `Pass` event can fire *on* a Sometimes-assertion being satisfied.

The run verdict MUST be a deterministic function of the run: a `Fail` action
fires the run is failed; a `Pass` action with no prior `Fail` and no violated
assertion is a pass; the assertion verdict ([ASRT-23]) composes with the
explicit verdict so the two cannot silently disagree (an explicit `Pass` does not
mask a violated `Always` assertion — a violated `Always` is a failure regardless,
[ASRT-23]).

- **[TRIG-30]** `Pass` and `Fail { reason }` actions MUST declare the run's
  verdict and request termination deterministically; their firing is deterministic
  engine behavior ([TRIG-19]), recorded as causal event-log entries. The explicit
  verdict MUST compose with the assertion verdict ([ASRT-23]) so the two cannot
  silently disagree: a violated `Always` assertion MUST fail the run even if a
  `Pass` action fired, and a `Fail` action MUST fail the run. The composed run
  verdict MUST be a pure function of the event log, identical online and offline
  ([ASRT-15]). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:*
  §17a.8; cross-ref 18 §18.8.

## 17a.9 The black-box-first guarantee, restated

The headline guarantee of this file, stated as a standalone contract because it is
the thing the whole design exists to protect:

> A **complete, expressive scenario** — readiness detection, fault injection,
> property checking, and pass/fail — MUST be authorable with **zero guest-side
> components**, using only observable conditions. Guest markers strictly enrich;
> they never gate.

Every leaf condition except `GuestMarker` is black-box observable (§17a.2); the
worked example (§17a.5.1) is a real partition-recovery scenario with no in-guest
content; and `GuestMarker` is the single opt-in, additive, fingerprint-neutral
exception ([TRIG-3], [TRIG-14]). This is the control-flow face of [G-2]
(any unmodified guest) and [G-3] (black-box by default), and it is the same
posture 16 takes at the transport layer ([GHC-1], [GHC-28]) lifted into the
control-flow layer.

- **[TRIG-31]** A complete, expressive scenario — readiness detection (e.g.
  `ConsoleMatch`/`NetworkMatch`/`CoveragePoint`), signal-driven faults,
  property checking (shared `Condition` assertions,
  18), and pass/fail (`Pass`/`Fail`) — MUST be authorable with **zero guest-side
  components**, using only observable conditions. Removing every `GuestMarker`
  condition from any scenario MUST leave a functional, deterministic event graph;
  `GuestMarker` conditions MUST be strictly additive and MUST NOT degrade or gate
  any observable-condition capability ([G-2], [G-3], [GHC-1], [GHC-28]). *Gate:*
  `gate:any-guest`, `gate:e2e-determinism`. *Spec:* §17a.9; cross-ref 16 §16.1.

## 17a.10 Authoring surface

Consistent with 06's code-first discipline ([SPAT-23], [SPAT-24]), the event graph
is authored **code-first** with a Rust builder and has a **serializable,
content-addressed** form (the TOML of §17a.5.1 and a compact binary form, both
serializing to the same canonical bytes for hashing, [SPAT-30]). The builder
constructs and validates (§17a.6) the graph before it is hashed; the serialized
form is for storage, exchange, and reproduction.

```rust,illustrative
/// Code-first event-graph authoring. Builds and validates (§17a.6) the event
/// graph; orthogonal to the World/Properties/Seed layers (06 §10). The graph
/// is carried in the `Plan` component of the ScenarioDef (06 §5.1) — the Plan
/// IS the event graph (§17a.7).
let plan = EventGraph::builder()
    // wait-ready: observable readiness + a coverage gate (zero instrumentation)
    .event("wait-ready")
        .when(Condition::all_of([
            Condition::console_match("db-0", r"ready to accept connections"),
            Condition::console_match("db-1", r"ready to accept connections"),
            Condition::coverage_point("db-0", sym("cluster_join_complete")).once(),
        ]))
        .action(Action::arm_timer("heal-after", secs(30)))
    // The separate `split` fault binding consumes a Boolean pulse anchored to
    // wait-ready; its false transition removes network.availability after 30s.
    // pass: observable convergence + quiescence
    .event("pass-when-converged")
        .when(Condition::all_of([
            Condition::network_match(link("db-0", "db-1"), frame::raft_ack()).once(),
            Condition::quiescent(),
        ]))
        .action(Action::pass())
    .build()?;   // validates (§17a.6), canonicalizes (§8), content-addresses (§2)
```

The builder enforces the §17a.6 validation at `.build()` and produces a
content-addressed value that *is* the `Plan` component of the `ScenarioDef`
(06 §5.1) — the Plan IS the event graph (§17a.7). It stays orthogonal to the
`World`, `Properties`, and `Seed` (06 §10): conditions *reference* `World` nodes
and `Properties` assertions by id, but the graph is its own independently-hashed
component.

- **[TRIG-32]** The event graph MUST be authorable **code-first** with a Rust
  builder that constructs, validates (§17a.6), canonicalizes ([SPAT-30]), and
  content-addresses ([SPAT-3]) it, and MUST have an equivalent **serializable
  content-addressed** form (deterministic TOML for authoring/inspection and a
  compact binary form, both serializing to the same canonical bytes for hashing)
  that round-trips to an equal graph with the same id and re-runs the same
  validation ([SPAT-24]). The graph MUST be the `Plan` component of the
  `ScenarioDef` (06 §5.1, §17a.7), orthogonal to `World`/`Properties`/`Seed`
  ([SPAT-2], [SPAT-33]): conditions reference declared nodes/assertions by id but
  the graph is independently hashed. *Gate:* `gate:content-address`. *Spec:*
  §17a.10; cross-ref 06 §6, §10.

## 17a.11 Summary

```text
CONTROL FLOW = an EVENT GRAPH of (trigger, action) events (TRIG-1)
  triggers fire on CONDITIONS; the core needs NO guest cooperation (TRIG-2)
  GuestMarker is the ONLY guest-needing leaf — opt-in, additive, never required (TRIG-3,14,31)

ONE Condition vocabulary, TWO consumers (TRIG-4):
  an ASSERTION (continuously graded pass/fail, 18) and a TRIGGER (fires once)
  LEAVES (black-box observable except GuestMarker):
    At / After(rel) / Timer            time (TRIG-5)
    NetworkMatch                       a matching frame delivered (TRIG-6)
    ConsoleMatch                       console/serial regex (TRIG-7)
    CoveragePoint                      basic block executed, ZERO instrumentation (TRIG-8)
    MemoryPredicate                    guest mem/reg at deterministic icount; SPIKE S5 (TRIG-9)
    IoPattern                          block write / fsync / 9p op (TRIG-10)
    NodeState                          Started|Crashed|Exited (TRIG-11)
    AssertionState                     Satisfied|Violated — closes grading↔steering loop (TRIG-12)
    Quiescent                          system settled (TRIG-13)
    GuestMarker                        OPTIONAL white-box doorbell marker (TRIG-14)
  COMPOUND: AllOf, AnyOf, Once(latch), Not (TRIG-15)

DETERMINISM (critical):
  evaluate ONLY at deterministic points over the event log (event/quantum
    boundaries keyed on icount); NEVER host-clock polled (TRIG-16,17)
  MemoryPredicate/CoveragePoint sampling cadence is itself deterministic (TRIG-18)
  a trigger FIRING is deterministic ENGINE BEHAVIOR, NOT a Decision (05 §3);
    only probabilistic fault OUTCOMES are Decisions ⇒ composes with fork/search/fuzz (TRIG-19,20)

ACTIONS (TRIG-22): ArmTimer/CancelTimer · StartNode/
  StopNode (a BAKED node, NOT topology mutation, TRIG-24) · CreateSavepoint/Fork ·
  Pass/Fail · Log · Group(atomic). Applied at the firing VT, quantum boundary (TRIG-23)

RELATIVE TIMERS (TRIG-25): "heal 30s AFTER the partition was OBSERVED" — the thing
  pure-VT scheduling can't do; ArmTimer+Timer (general) or After{of} (sugar)

VALIDATOR build-time (TRIG-26,27): dangling-ref · empty-compound · CYCLE (DFS) ·
  reachability — fail early, not at runtime (06 §9 discipline)

FAULT INPUT (TRIG-28,29): referenced event occurrences feed event-domain signals;
  known-time faults use time-domain signal nodes directly

VERDICT (TRIG-30): Pass/Fail compose with the assertion verdict — a violated Always
  fails regardless. AUTHORING (TRIG-32): code-first builder + serializable form,
  the Plan component of the ScenarioDef, orthogonal to World/Properties/Seed.

BLACK-BOX FIRST (TRIG-31): a COMPLETE scenario is authorable with ZERO guest-side
  components, using only observable conditions; guest markers strictly enrich.
```

If every leaf condition but one is black-box observable, every condition is
evaluated only at deterministic icount-keyed points, and a trigger firing is
computed (not chosen) so it is never a `Decision`, then the event graph that steers
a run is as pure a function of `(ScenarioDef, Seed, Schedule)` as the run it steers
— which is what unifies it with 17's fault Plan, lets it share 18's predicate
vocabulary, and lets it compose cleanly with the fork/search/fuzz of 22.

## Implementation status

The former fault-action lowering checklist has been retired with that execution
model. Event actions retain the closed taxonomy in §17a.4; signal-driven fault
bindings consume referenced event occurrences as specified by
[`RFC-0013`](../0013-signal-driven-fault-model/README.md).

Historical gate aliases retained for the executable event-graph checks:

- Completed by `checks.crucible.phase4.assertionQuiescenceLeaves`
- Completed by `checks.crucible.phase4.blackBoxFirstGuarantee`
- Completed by `checks.crucible.phase4.compoundConditionCombinators`
- Completed by `checks.crucible.phase4.coverageConditionLeaf`
- Completed by `checks.crucible.phase4.deterministicConditionEvaluation`
- Completed by `checks.crucible.phase4.eventGraphControlFlow`
- Completed by `checks.crucible.phase4.eventGraphSerialization`
- Completed by `checks.crucible.phase4.gates.e2eDeterminism` and its replay gate
- Completed by `checks.crucible.phase4.gates.replayOracle`
- Completed by `checks.crucible.phase4.guestMarkerLeaf`
- Completed by `checks.crucible.phase4.memoryConditionLeaf`
- Completed by `checks.crucible.phase4.observableConditionLeaves`
- Completed by `checks.crucible.phase4.sharedConditionVocabulary`
- Completed by `checks.crucible.phase4.timeConditionLeaves`
- Completed by `checks.crucible.phase4.triggerActionApplication`
- Completed by `checks.crucible.phase4.triggerFiringCausalLog`
- Completed by `checks.crucible.phase4.triggerGraphValidator`
- Completed by `checks.crucible.phase4.triggerNodeScheduling`
- Completed by `checks.crucible.phase4.triggerPlanLowering`
- Completed by `checks.crucible.phase4.triggerRelativeTimers`
- Completed by `checks.crucible.phase4.triggerVerdictComposition`
