# Assertions and properties

Crucible checks a run with a small, closed vocabulary of temporal properties
evaluated as a deterministic fold over the run's event log. The same fold runs
live while the log is appended and offline over a retained log, so a property
written after a run was recorded grades that run exactly as a live evaluation
would have. The assertion layer is not a model checker and contains no
specification-language evaluator.

This page documents the assertion engine as implemented. The event log that
assertions read is in [event-log.md](event-log.md); the shared predicate
vocabulary and trigger graph are in
[conditions-and-triggers.md](conditions-and-triggers.md); the white-box doorbell
that carries guest assertion markers is in
[guest-host-channel.md](guest-host-channel.md). Authoring guidance and the TOML
reference live in the user guides:
[properties and evidence](../../users/crucible/properties-and-evidence.md) and
the [reference](../../users/crucible/reference.md).

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-engine/src/model/plan_properties.rs` | `Predicate`, `Property`, `PropertyKind`, `AssertionDef`, `Properties`, schema constants |
| `.../model/guest_assertion.rs` | `AssertionDef::guest_always`, `guest_sometimes`, `guest_reachable`, `guest_unreachable` |
| `.../model/validation.rs` | Property validation, canonical ordering, predicate DSL expansion |
| `.../model/toml.rs` | `PropertiesToml`, `AssertionToml`, `PropertyToml`, `property_from_toml` |
| `.../trigger/assertions.rs` | `HostAssertionEvaluator`, outcomes, lifecycle, violations, proximity, `OfflineAssertionChecker`, `RecordedAssertionLog`, `ExternalFormalTraceExporter`, violation reproduction |
| `.../trigger/evaluation.rs` | Host condition evaluation, leaf cache, distance-to-satisfaction |
| `.../trigger/evidence.rs` | Violation evidence, outcome sorting, verdict rule, formal trace bytes, guest marker finalization |
| `.../trigger/guest_assertion_declarations.rs` | Splitting declared properties into host and guest marker state |
| `.../trigger/guest_assertion_observation.rs` | Online evaluation of guest assertion markers |
| `.../trigger/conditions.rs` | `ConditionEventLogPrefix`, `ObservedState`, `ObservableEvent`, `GuestAssertionMarker` |
| `.../trigger/conditions/host_oracle.rs` | `HostAssertionOracle`, `BlackBoxHostOracle`, `LintedHostAssertionOracle`, `lint_host_assertion_harness_source` |
| `.../scheduler/control_state.rs` | `AssertionRunVerdict`, `AssertionVerdictFailure` |
| `crates/crucible/crucible-daemon/src/vm_lifecycle/runtime.rs` | Live per-boundary assertion observation in the VM runtime |
| `crates/crucible/crucible-test-support/src/assertion.rs` | Determinism-gate assertion vocabulary (`crucible-assert.v1`), not runtime assertions |

All `.../` paths are under `crates/crucible/crucible-engine/src/`.

Runtime assertion semantics and evaluation are owned by `crucible-engine`. The
`crucible_test_support::assertion` module is a separate, test-only vocabulary of
digest-equality, total-order-stability, and decision-stream-stability checks
used by determinism gates; its report identifier `crucible-assert.v1` is stable.

## Design in brief

- **A closed vocabulary.** Five quantifiers cover the common temporal shapes:
  invariant, liveness witness, bounded liveness, end state, and coverage. Adding
  or removing one is a schema change, not a runtime extension point.
- **Checking is a fold.** The event log is the deterministic, totally ordered,
  complete record of a run, so grading a property needs only that one recorded
  sequence. Exploring other executions is the job of the search layer
  ([exploration.md](exploration.md)), which runs many deterministic runs and
  grades each one's log with this same engine.
- **No in-runtime formal engine.** A model checker or LTL/CTL evaluator would
  be a large subsystem whose own determinism would have to be proven. When
  conformance against an external formal specification is wanted, the retained
  log is exported (see [Formal trace export](#formal-trace-export)) and checked
  by external tooling.
- **Read from the run, never written into it.** Evaluation reads a checked,
  read-only view of the log. Declaring, removing, or amending a property changes
  the scenario identity but never the instruction stream, schedule, or node
  fingerprints.

## Property vocabulary

A property is a `Property` value carried by an `AssertionDef`:

```rust
pub struct AssertionDef {
    pub id: AssertionId,     // stable id; canonical order and reports
    pub message: String,     // author-facing failure or coverage message
    pub property: Property,
}

pub enum Property {
    Always { predicate: Predicate },
    Sometimes { predicate: Predicate },
    Eventually { trigger: Predicate, property: Predicate, deadline: VirtualTime },
    AfterQuiescence { predicate: Predicate },
    Reachable { predicate: Predicate, expectation: ReachabilityExpectation },
}

pub enum ReachabilityExpectation {
    Reachable { on_unreached: ReachableDisposition }, // Warn | Fail
    Unreachable,
}
```

`PropertyKind` is the single tag source for every encoding of the quantifier:

| `PropertyKind` | Binary tag | Canonical label | TOML `kind` |
|----------------|-----------:|-----------------|-------------|
| `Always` | 0 | `always` | `always` |
| `Sometimes` | 1 | `sometimes` | `sometimes` |
| `Eventually` | 2 | `eventually` | `eventually` |
| `AfterQuiescence` | 3 | `after-quiescence` | `after_quiescence` |
| `Reachable` | 4 | `reachable` | `reachable` |

The schema is versioned by `PROPERTY_SCHEMA_VERSION = 2`; properties bundles are
content-addressed under the domain `PROPERTY_SCHEMA_DOMAIN =
"crucible.model.properties.v2"`, so a quantifier schema change cannot collide
with an older properties component. `PROPERTY_QUANTIFIER_COUNT` is 5 and
`PropertyKind::ALL` fixes the canonical order.

Temporal semantics as implemented:

| Quantifier | Holds when | Fails when |
|------------|------------|------------|
| `Always` | The predicate is true at every evaluation point after genesis | The first evaluation point where it is false; that point is the violation site |
| `Sometimes` | The predicate is true at least once; satisfied at the first true point | The run ends without a true point |
| `Eventually` | After the trigger first holds at `t0`, the property holds at some point in `[t0, t0 + deadline]` | The deadline passes with the property false (site is the deadline instant), or the run ends while the obligation is open |
| `AfterQuiescence` | The predicate is true at the single terminal evaluation | It is false there |
| `Reachable` (`Reachable`) | The predicate is true at least once | Never reached with `on_unreached = Fail`; never reached with `Warn` only warns |
| `Reachable` (`Unreachable`) | The predicate never becomes true | The first point where it is true |

Details that the table compresses:

- An `Always` is not evaluated at the zero-entry genesis prefix. If it is never
  evaluated at all (an empty log), its outcome is `NeverEvaluated` rather than
  a pass.
- `Eventually` arms at most one obligation: the first point where the trigger
  holds. The deadline is `t0 + deadline`, saturating. If the property already
  holds at `t0`, the obligation is discharged immediately. A trigger that never
  fires yields `NeverTriggered`, which does not fail the run.
- `AfterQuiescence` is skipped while streaming and evaluated exactly once, at
  finalization, with the scheduler's terminal quiescence evidence when the
  caller supplied it through `with_terminal_scheduler_quiescence`.

## One predicate vocabulary, two consumers

The **predicate** here is not a second vocabulary: `Condition` is a type alias
for `Predicate` (`crates/crucible/crucible-engine/src/trigger.rs`). An assertion
is a `Predicate` graded for pass or fail; a trigger is the same `Predicate`
firing an action once (see
[conditions-and-triggers.md](conditions-and-triggers.md)). Both evaluate the
same leaves over the same checked event-log prefix.

Two leaves are edge-shaped and only make sense as triggers. Property validation
rejects `After` and `Timer` with `EngineError::PropertyPredicateTriggerOnly`.
In the other direction, the `AssertionState` leaf lets a trigger fire when a
named assertion becomes `Satisfied` or `Violated`, closing the loop between
grading and steering without a second mechanism (see
[Online evaluation](#online-evaluation)).

### Predicate DSL

TOML may name a predicate with a string instead of a structured table. A string
parses to `Predicate::Named { name, nodes: [] }`;
`Properties::from_assertions_for_world_and_plan` and
`from_canonical_toml_for_world_and_plan` then expand the recognized names
against the `World` before validation and hashing:

| DSL name | Expands to |
|----------|------------|
| `no_crashed_nodes` | `Not(AnyOf([NodeState{n, Crashed} for each VM node]))`, or an always-true predicate when the world has no VM nodes |
| `quiescent` | `Quiescent` |
| `node_alive:<n>` | `Not(NodeState{<n>, Crashed})` |
| `node_crashed:<n>` | `Once(NodeState{<n>, Crashed})` |

Expansion recurses through `AllOf`, `AnyOf`, `Once`, and `Not`. Any other name
stays a `Named` predicate and is resolved by a host assertion oracle, so the
DSL is additive to custom host predicates. The same expansion is applied to
event-graph triggers.

## Configuration, validation, and identity

`Properties::from_assertions_for_world` validates every assertion against the
world and then stores the assertions in canonical order: sorted by `id`, ties
broken by canonical assertion material. Validation errors:

| Error | Cause |
|-------|-------|
| `PropertyDuplicateAssertionId` | Two assertions share an id |
| `PropertyPredicateUnknownNode` | A predicate names an undeclared node |
| `PropertyPredicateUnknownAssertion` | An `AssertionState` leaf names no declared assertion |
| `PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn` | A `GuestMarker` leaf is used but no node has white-box enabled |
| `PropertyPredicateEmptyCompound` | An `AllOf` or `AnyOf` has no children |
| `PropertyPredicateTriggerOnly` | `After` or `Timer` is used in a property |
| `PropertyPredicateInvalidRegex` | A console regex does not compile |

The bundle's content hash is computed over canonical material that includes
each assertion's length-prefixed id and message, the quantifier label, the
predicate material, `deadline_ticks` for `Eventually`, and
`expectation=reachable\non_unreached=warn|fail` or `expectation=unreachable`
for `Reachable`. The scenario's canonical material embeds that hash as
`properties_ref` alongside `world_ref` and `plan_ref`, so two scenarios that
differ only in their properties are different scenarios.

TOML is parsed into `PropertiesToml`, `AssertionToml`, and `PropertyToml`, all
with `deny_unknown_fields`. `property_from_toml` requires exactly the fields of
the chosen kind and rejects the rest:

| Kind | Required | Rejected |
|------|----------|----------|
| `always`, `sometimes`, `after_quiescence` | `predicate` | `trigger`, `property`, `deadline_ticks`, `expectation` |
| `eventually` | `trigger`, `property`, `deadline_ticks` | `predicate`, `expectation` |
| `reachable` | `predicate`, `expectation` | `trigger`, `property`, `deadline_ticks` |

Deadlines exist only as virtual-time `deadline_ticks`. A host wall-clock
parameter such as `deadline_seconds` is an unknown field and fails parsing. An
omitted `on_unreached` defaults to `warn` and is not serialized back; the
`reachable`/`unreachable` expectation itself is always explicit.

```toml
[[properties.assertion]]
id = "io-probe-eventually-restarts"
message = "After the I/O probe crashes, it eventually restarts"

[properties.assertion.property]
kind = "eventually"
deadline_ticks = 40000000000000

[properties.assertion.property.trigger]
kind = "node_state"
node = "io-probe"
state = "crashed"

[properties.assertion.property.property]
kind = "node_state"
node = "io-probe"
state = "started"
```

## What assertions read

Every predicate is evaluated against a `ConditionEventLogPrefix`: a checked
prefix of scheduler event-log entries, reconstructed at one deterministic
`EventEvaluationPoint`. Building a prefix fails closed with a
`ConditionEvaluationError` when the entries are not dense from the base
sequence, an entry's content hash does not match its material, a black-box
observation regresses in time, an entry lies after the derived evaluation point,
or a black-box observation is not recorded as observational or carries the wrong
icount stamp.

Host predicates see that prefix only through `ObservedState`, a `Copy`
read-only view:

```rust
pub struct ObservedState<'log> {
    point: EventEvaluationPoint,          // evaluation point and its virtual time
    event_log_offset: EventLogOffset,     // identity of the backing prefix
    observable_events: &'log [ObservableEvent],
    ordering_facts: &'log [ObservedOrderingFact],
}
```

`ObservableEvent` carries the black-box surface (delivered frames, console
output, basic-block coverage, memory samples, I/O completions, node lifecycle)
plus assertion-state changes and white-box markers. `ObservedOrderingFact`
records resolved scheduler happenings and chosen delivery orders. Raw scheduler
entries, RNG draws, app-random draws, overrides, preemption decisions,
host-worker state, and wall-clock data are not part of the view. A predicate
therefore sees exactly the history up to its evaluation point, which is what
lets online and offline evaluation agree and lets a violation be attributed to
a definite earliest point.

## Host-side assertions

Host-side assertions are the default source of truth and need no guest
cooperation. Every built-in leaf (`NetworkMatch`, `ConsoleMatch`,
`CoveragePoint`, `MemoryPredicate`, `IoPattern`, `NodeState`, `AssertionState`,
`Quiescent`, `At`, and the compounds) is evaluated by the engine directly from
the checked prefix. Only two leaf shapes are delegated to an oracle,
`ConditionLeaf::Named` and `ConditionLeaf::GuestMarker`:

```rust
pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed {
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}
```

- `BlackBoxHostOracle` is the default. It answers `false` for every delegated
  leaf, so properties built from the black-box vocabulary evaluate with no
  harness code at all.
- `HostAssertionOracle` is sealed. Custom host predicates implement
  `HostAssertionPredicate` and must be wrapped in `LintedHostAssertionOracle`,
  which carries a `HostAssertionHarnessLint` proof. Production code exposes no
  public constructor for that wrapper; only test-support builds can create one
  without a lint proof.
- `lint_host_assertion_harness_source` is the assertion layer's
  `gate:harness-lint` hook. It rejects host predicate source that names host
  wall-clock types (`SystemTime`, `Instant`, `std::time`, `chrono::`), entropy
  and RNG (`thread_rng`, `OsRng`, `getrandom`, `rand::`, `from_entropy`),
  randomized hashing and unordered collections (`HashMap`, `HashSet`,
  `DefaultHasher`, `RandomState`), environment, filesystem, process, network,
  threading, shared mutable state, interior mutability, and `unsafe`.

A host predicate receives a read-only view, never a mutable handle to run
state, so a badly written predicate cannot perturb the run; banned
nondeterminism is caught by the lint rather than silently corrupting outcomes.

## Guest-side marker assertions

When a node opts into white-box mode, the guest can assert in-guest invariants
at the exact instruction where they matter. Each doorbell assertion arrives as
an `ObservableEventPayload::GuestAssertionMarker` stamped with the retired
icount of the doorbell instruction and carrying a `GuestAssertionMarker`:

| Field | Meaning |
|-------|---------|
| `id` | Assertion id in the shared marker/assertion namespace |
| `message` | Human-readable message |
| `kind` | `GuestAssertionKind`: `Always`, `Sometimes`, `Reachable`, `Unreachable` |
| `condition` | Truth value at the doorbell retirement point |
| `must_hit` | Whether the marker is catalog-declared and must be hit |
| `details` | Ordered `GuestAssertionDetail { key, value }` list for violation records |
| `location` | Source location supplied by the emitter |

The `kind` and `must_hit` fields exist so the engine can finalize a marker
whose in-guest instruction never ran. A bare boolean doorbell cannot
distinguish "never reached" from "never declared".

A scenario declares a guest assertion with `AssertionDef::guest_always`,
`guest_sometimes`, `guest_reachable`, or `guest_unreachable`. Each builds the
ordinary `Property` over `Predicate::GuestMarker` with the marker id equal to
the assertion id. `HostAssertionEvaluator::new` recognizes that canonical shape
and pre-seeds a guest marker state instead of a host state, so an event graph
can depend on the assertion's `AssertionState` without a duplicate host
property. `with_guest_assertion_catalog` pre-seeds markers from an external
catalog the same way.

Guest marker evaluation:

- Markers from a node whose `WhiteBoxPolicy` is not `Enabled` are ignored. The
  policy comes from the world (`with_world_white_box_policies`), never from the
  marker itself.
- A marker whose message differs from its scenario declaration, or whose kind
  differs from the declared kind, is a `Violated` outcome with a diagnostic
  reason.
- `Always` with `condition = false` and `Unreachable` with `condition = true`
  violate immediately. `Sometimes` and `Reachable` with `condition = true` are
  satisfied immediately.
- At finalization an untouched `Always` passes, an unsatisfied `Sometimes` is
  violated, an unreached `Reachable` is `NeverReachedFail` when `must_hit` is set
  and `NeverReachedWarn` otherwise, and an untouched `Unreachable` passes.
  Scenario-declared guest `Reachable` markers always set `must_hit`.

Guest markers fold into the same evaluator pass and the same outcome report as
host properties; a run's outcome set is one uniformly ordered whole. The bare
`Predicate::GuestMarker` leaf used outside this canonical shape matches only
plain guest-marker events, never assertion-flavored markers.

## Evaluation timing and order

`HostAssertionEvaluator` is a streaming fold:

```rust
let mut evaluator = HostAssertionEvaluator::new(&properties)
    .with_world_white_box_policies(&world);

// once per published event-log boundary
let outcomes = evaluator.observe_prefix(&prefix, &mut oracle);

// once, at the terminal prefix
let report = evaluator.finalize_prefix(&terminal_prefix, &mut oracle);
```

| Quantifier | Evaluated at | Finalized at |
|------------|--------------|--------------|
| `Always` | Every observed prefix after genesis | Terminal prefix (fail is immediate) |
| `Sometimes` | Every observed prefix | Terminal prefix |
| `Eventually` | Every observed prefix, plus synthetic deadline points | Terminal prefix |
| `AfterQuiescence` | Not during the run | Terminal prefix only |
| `Reachable` | Every observed prefix | Terminal prefix |

Ordering rules:

- **Deadlines between prefixes.** Before observing a new prefix, the evaluator
  collects every pending `Eventually` deadline strictly between the previous
  prefix's time and the new one, and evaluates those obligations at synthetic
  `EventEvaluationKind::AssertionDeadline` points, in deadline order, using the
  facts visible through each deadline. A deadline that falls between recorded
  events is therefore still caught at its exact instant.
- **Stable-id order.** Host states are kept in canonical property order, guest
  marker states are kept sorted by id, and the outcomes returned from each call
  are sorted by assertion id, time, outcome rank, and reason. No unordered map
  or host scheduling influences order.
- **One evaluation per leaf per point.** A point-local leaf cache
  (`BTreeMap<HostConditionLeafKey, bool>`) resolves repeated leaves inside one
  assertion once at that point, including an `Eventually`'s trigger and
  property.
- **`Once` latches** are owned by the evaluator, so a latching leaf stays true
  across later prefixes.
- **Termination.** Each point evaluates a bounded set of total predicates over
  a bounded view; terminal states are never revisited.

The evaluator state can be suspended and resumed across checkpoints.
`HostAssertionEvaluator::checkpoint` captures every mutable field;
`HostAssertionEvaluatorCheckpoint::canonical_bytes` encodes it under the magic
`crucible.host-assertion-continuation.v2\0` with a 256 MiB ceiling, and
`restore_into` rejects a continuation whose assertion identities or event-log
prefix do not match. Resume therefore neither forgets a witness nor restarts a
deadline.

## Lifecycle and outcome set

Each property moves through `PropertyLifecycleState`:

```text
Declared --(first evaluation)--> Passing --(witness)----------> Satisfied
                                    |
                                    +--(Eventually trigger)--> Failing --(property holds)--> Satisfied
                                    |                             |
                                    |                             +--(deadline / run end)--> Violated
                                    +--(Always false, Unreachable reached, ...)------------> Violated
```

`HostAssertionEvaluator::lifecycle_states` returns in-flight states for host
and guest assertions in canonical order. Terminal outcomes are
`HostAssertionOutcome { assertion, quantifier, at, kind, lifecycle, message,
reason }`; `quantifier` is an `AssertionQuantifierKind`, which adds
`GuestAlways`, `GuestSometimes`, `GuestReachable`, and `GuestUnreachable` to the
five host quantifiers.

| `HostAssertionOutcomeKind` | Terminal lifecycle | Fails the run |
|----------------------------|--------------------|---------------|
| `Passed` | `Passing` | no |
| `Satisfied` | `Satisfied` | no |
| `Warning` | `Passing` | no |
| `NeverEvaluated` | `Declared` | no |
| `NeverTriggered` | `Passing` | no |
| `NeverReachedWarn` | `Passing` | no |
| `NeverReachedFail` | `Violated` | yes |
| `Violated` | `Violated` | yes |

`Passed` is the safety-style terminal (an `Always`, `AfterQuiescence`, or
`Unreachable` that held); `Satisfied` is the existential or liveness terminal.
The edge dispositions `NeverEvaluated`, `NeverTriggered`, `NeverReachedWarn`,
and `NeverReachedFail` are distinct outcomes, never folded into pass or fail, so
online and offline evaluation cannot diverge on edge cases.

`finalize_prefix` returns a `HostAssertionReport` containing every declared
property's outcome in canonical order, the violation records, the proximity
records, and an `AssertionRunVerdict`. The verdict is
`AssertionRunVerdict::failed(failures)` over the outcomes whose kind fails the
run; an empty failure list normalizes to `Passed`, and failures are sorted.
Warnings never fail a run.

## Violation records

Each `Violated` or `NeverReachedFail` outcome yields a `HostAssertionViolation`:

| Field | Source |
|-------|--------|
| `assertion`, `message`, `quantifier` | The declaration and outcome |
| `event_kind` | Catalog kind of the event-log site that produced the violation |
| `at_icount` | Exact retired icount when the evidence is icount-stamped |
| `at_virtual_time` | Violation site: the failing point, the deadline instant, or the terminal point |
| `node` | Node owning the site when the log identifies one |
| `detail` | Expected-versus-observed text drawn from the outcome and observed state |
| `reproduction_artifact` | Content-addressed link for this run |

Site metadata comes from the exact predicate evidence that made the assertion
terminal, not from a timestamp lookup, so a same-time event on another node
cannot be misattributed. While a run is being folded, `reproduction_artifact` is
the BLAKE3 hash of the formal trace bytes of the terminal prefix. Violation
reproduction rebinds it to the reproduction artifact id.

## Violation reproduction

`check_assertion_violation_reproduction` links a violation to a bit-identical
re-execution:

1. The caller reduces the self-contained `(seed, scenario, schedule)`
   `ReproductionArtifact` and binds the replayed assertion log with
   `AssertionViolationArtifactReplay::from_artifact`. The type has no public
   field constructor, so replay evidence cannot be forged from raw parts.
2. The check re-runs the reduction oracle on the artifact and rejects replay
   evidence reduced from a different artifact tuple
   (`ReplayArtifactMismatch`).
3. It re-grades both the recorded and the replayed logs against the scenario
   properties embedded in the artifact. A recorded log with no violation is
   `MissingRecordedViolation`.
4. Equal reports succeed as an `AssertionViolationReplayReport` with violation
   links rebound to the artifact id. Any event-log or report mismatch is a
   `Divergence` carrying an `AssertionViolationDivergence`: the first differing
   prefix length and icount, the first differing causal entry, both entries and
   violations at that slot, and an `AssertionViolationBisectionRequest` handed to
   `gate:divergence-bisect`.

`check_assertion_violation_reproduction_with_oracles` is the variant for linted
named host predicates. A violation that does not reproduce is a determinism
defect localized by bisection (see [failure-triage.md](failure-triage.md)),
never a flaky result.

## Online evaluation

In the VM runtime (`crates/crucible/crucible-daemon/src/vm_lifecycle/runtime.rs`)
the assertion evaluator runs at each scheduler boundary before the trigger
graph:

```text
scheduler boundary
  -> evaluator.observe_prefix(scheduler.condition_event_log_prefix())
  -> Satisfied / Violated outcomes become assertion_state_changed entries
     appended through the scheduler's observable-event path
  -> trigger graph evaluates over the extended prefix
     (AssertionState leaves can now fire)
  -> repeat until no trigger fires and no assertion changed
```

A satisfied existential or liveness obligation emits its terminal outcome at
the exact evaluation boundary, so the event graph can consume
`AssertionState::Satisfied` online.

## Offline checking

`OfflineAssertionChecker` grades a retained log without creating a scheduler or
backend and without re-executing any guest. It rebuilds checked
`ConditionEventLogPrefix` values from the recorded entries and drives the same
`HostAssertionEvaluator`, so online and offline are one code path over the same
input and differ only in whether the log is being appended or read.

- `check_run(properties, entries)` uses `BlackBoxHostOracle` and accepts a
  plain `SchedulerEventLogEntry` slice.
- `check_run_with_oracle(properties, log, oracle)` takes a
  `RecordedAssertionLog`. `RecordedAssertionLog::from_segments` folds retained
  segments with the scheduler's canonical segment and prefix hashing and records
  an `EventLogOffset` at every segment boundary, including genesis, so named
  predicates that read `ObservedState::event_log_offset` see the same offsets
  they saw online. Intermediate prefixes without a retained offset are skipped;
  the terminal prefix must have one (`MissingEventLogOffset`), and a supplied
  offset whose event count does not match is `EventLogOffsetMismatch`.
- The checker observes every valid intermediate prefix, deferring an
  observable prefix that falls behind an earlier point only when a trailing
  evaluation boundary proves it was part of an atomic batch, and lets
  `finalize_prefix` see the terminal prefix exactly once.

Builder methods mirror the evaluator: white-box policies, guest assertion
catalog, resolved code points and memory places, and terminal quiescence. The
property set may be the run's original `Properties` or a new or amended one, and
re-checking the same `(log, properties)` pair is idempotent, so a retained
corpus can be re-graded as the property suite grows. In-tree consumers include
schedule search (`model/runtime/search.rs`), failure material
(`model/failure/material.rs`), and the campaign driver.

```text
run executes --> event log (icount-stamped, complete, content-addressed)
                    |
        +-----------+---------------------------+
        v                                       v
  online fold                             offline fold
  (observe_prefix as entries               (OfflineAssertionChecker over
   are appended)                            retained entries, possibly
        |                                   with new or amended properties)
        v                                       v
        +--------- identical HostAssertionReport ----------+
                   for identical (log, properties)
```

## Assertion-proximity gradient

For guided search a bare "never happened" is a flat fitness landscape. The
evaluator therefore records a steering-only distance-to-satisfaction for
unsatisfied liveness and existential obligations. It never changes an outcome,
the run verdict, or any fingerprint.

`HostAssertionReport::proximities` returns `HostAssertionProximity { assertion,
quantifier, distance, at, event_log_offset }` records, produced only for:

- a `Sometimes` that ended `Violated`;
- an `Eventually` that was triggered and ended `Violated`;
- a `Reachable` with the reachable expectation that ended `NeverReachedWarn` or
  `NeverReachedFail`.

The distance is a `u128` computed structurally over the `Condition` tree:

| Node | Distance |
|------|----------|
| `MemoryPredicate` | Threshold gap between the sampled value and the expected value (`Eq`: absolute difference; `Lt`/`Gt`: gap plus one; `Le`/`Ge`: gap; `Ne`: 0 or 1) |
| `AllOf` | Saturating sum of children |
| `AnyOf` | Minimum of children (1 when empty) |
| `Once` | 0 once latched, otherwise the child's distance |
| Every other leaf, including `Not` | 0 when true, `ASSERTION_PROXIMITY_UNIT` (1) otherwise |

A memory place that cannot be resolved, or has no sample at the evaluation
point, contributes `u128::MAX`. The per-assertion value is the minimum observed
along the run's checked prefixes, including `Eventually` deadline points; ties
prefer the earlier time, then the smaller event-log offset. Because the distance
is a pure function of the log, online equals offline. The event log records
these distances as observational `assertion_proximity` entries and derives a
per-checkpoint fingerprint from them; see
[event-log.md](event-log.md#assertion-proximity-projection).

## Determinism and fingerprint neutrality

- The fold contains no host wall-clock read, thread RNG, or unordered-map
  iteration on an outcome-significant path; host and guest outcomes merge in
  stable-id order.
- The same log and property set yield the same outcomes, violation sites,
  ordering, proximities, and verdict on every evaluation, on every host, online
  or offline.
- Properties enter the scenario hash through `properties_ref`, but evaluation
  only reads the already recorded log, and guest markers are observational
  entries excluded from the causal comparison. Declaring, removing, or amending
  a property therefore leaves the schedule, the instruction stream, and every
  backend fingerprint unchanged, which the fingerprint-neutrality check proves
  against the simulated backend with negative controls.

## Formal trace export

`ExternalFormalTraceExporter::export_event_log` validates a retained entry slice
as a dense, hash-valid prefix and returns `ExternalFormalTraceExport { bytes,
content_hash, entry_count }`. It only serializes; it never loads, interprets,
or evaluates a specification, and it does not change the event-log encoding.
The bytes are UTF-8 lines:

```text
format=crucible.external-formal-trace.v1
scheduler_event_log_previous_prefix=<hex of the empty-log prefix hash>
entries=<n>
entry_begin
entry.sequence=<seq>
entry.at_ticks=<virtual-time ticks>
entry.class=causal|observational
entry.hash=<entry content hash hex>
entry.payload_begin
<typed payload material>
entry.payload_end
entry_end
...
```

`content_hash` is the BLAKE3 hash of `bytes`. External tooling consumes this
export; conformance against an external specification is never part of the
runtime.

## Black-box-first guarantee

Host-side checking is the floor and white-box markers are an additive
enhancement:

- All five quantifiers work with `BlackBoxHostOracle` on an unmodified guest,
  over network, console, coverage, memory, I/O, lifecycle, and quiescence facts.
- A `GuestMarker` predicate is rejected at validation unless some node opts into
  white-box mode, and markers from nodes without an enabled policy are ignored.
- The absence of guest markers never degrades host-side checking; a scenario may
  mix both sources, and both report through one outcome set.

## Tests

| Check | Covers |
|-------|--------|
| `checks.crucible.phase4.propertyVocabulary` | Closed quantifier set, tags, TOML/binary round trips, shared `Condition` |
| `checks.crucible.phase4.propertyConfiguration` | Ids, messages, deadlines, dispositions, wall-clock rejection |
| `checks.crucible.phase4.propertyFingerprintNeutrality` | `properties_ref` in scenario identity, fingerprint neutrality |
| `checks.crucible.phase4.observedStateMaterialization` | `ObservedState` prefix cutoff and exclusions |
| `checks.crucible.phase4.hostSideAssertions` | All quantifiers in black-box mode |
| `checks.crucible.phase4.guestMarkerAssertions` | Marker payloads, finalization, policy gating |
| `checks.crucible.phase4.offlineAssertionChecker` | Online/offline report equality, amended re-grading |
| `checks.crucible.phase4.assertionLogFold` | One fold path, edge-disposition taxonomy |
| `checks.crucible.phase4.assertionEvaluationTiming` | Deadline points, terminal-only `AfterQuiescence` |
| `checks.crucible.phase4.assertionEvaluationOrder` | Stable-id order, leaf cache |
| `checks.crucible.phase4.assertionLifecycle` | Lifecycle transitions, outcome set, verdict |
| `checks.crucible.phase4.assertionDeterminismNonPerturbation` | Determinism, read-only view, harness lint |
| `checks.crucible.phase4.assertionViolationRecords` | Violation site attribution |
| `checks.crucible.phase4.assertionViolationReproduction` | Artifact-bound replay and divergence |
| `checks.crucible.phase4.assertionProximityGradient` | Distance computation and neutrality |
| `checks.crucible.phase4.formalTraceExport` | Deterministic export, no in-runtime evaluator |

Gate-level coverage by `checks.crucible.phase4.gates.e2eDeterminism` and
`checks.crucible.phase4.gates.replayOracle`, together with
`checks.crucible.phase1.gates.harnessLint` and
`checks.crucible.phase1.gates.singleVmFingerprint`, is described in
[testing-and-gates.md](testing-and-gates.md).
