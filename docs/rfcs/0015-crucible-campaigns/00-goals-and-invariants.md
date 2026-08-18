# 00 — Scope, vocabulary, and determinism boundary

This file establishes the concepts used throughout RFC-0015 and separates the
three kinds of state that are otherwise easy to conflate: modeled execution,
campaign knowledge, and operational placement.

## 00.1 Vocabulary

| Term | Meaning |
| --- | --- |
| **Scenario** | Immutable `World`, fault/signal plan, properties, measurements, seed, and selectable declarations defining legal modeled behavior. |
| **Configuration** | One temporal-graph node, identified by `(ScenarioDef, Schedule)`. |
| **Choice point** | A stable opportunity at which one value from a typed domain may be selected. |
| **Selection** | The concrete value chosen at one choice point and recorded in the schedule. |
| **Campaign** | A named, persistent adaptive exploration of one scenario lineage. |
| **Policy** | Immutable rules for proposing candidates, prioritizing paths, ranking outcomes, fairness, and retention. |
| **Proposal** | A campaign request to try one legal value at one choice point. |
| **Attempt** | An idempotent executable unit: instantiate a parent, apply a proposal, and run to a stop condition. |
| **Observation** | Canonical outcome of a completed attempt: child configuration, measurements, properties, coverage, and discovered choice points. |
| **Expansion** | All proposals and observations associated with one `(parent, choice point)`. |
| **Continuation** | A resumable projection describing whether an expansion can yield another proposal and how. |
| **Frontier** | The set of ready, waiting, and open continuations plus admitted attempts not yet completed. |
| **Finding** | A stable failure signature with a self-contained reproduction artifact and optional retained exact checkpoint. |
| **Materialization** | A hot process, exact durable closure, or cached replay state that makes one configuration cheap to instantiate. |
| **Lineage** | Scenario/genesis/provenance boundary within which graph and checkpoint reuse is valid. |

## 00.2 Three planes

```text
MODELED EXECUTION PLANE
  scenario + recorded schedule -> configuration/state
  deterministic, replayable, content-addressed

CAMPAIGN KNOWLEDGE PLANE
  proposals + observations + policy -> future work
  adaptive and persistent, never part of configuration identity

OPERATIONAL PLACEMENT PLANE
  workers + leases + CPU/RAM + cache locality -> where/when work runs
  opportunistic, host-dependent, never part of modeled state
```

- **[CMOD-1]** Data from the campaign or placement plane MUST affect modeled
  execution only through a validated `Selection` recorded in the schedule.
- **[CMOD-2]** Host wall time, worker identity, process ID, lease state, fleet
  size, completion arrival order, local cache inventory, and S3 location MUST
  NOT enter a `ScenarioDef`, `Decision`, `ConfigurationId`, checkpoint identity,
  event-log canonical projection, or reproduction artifact.
- **[CMOD-3]** Guidance MAY choose which proposal to issue next and which
  configuration to realize, but MUST NOT mutate a previously realized
  configuration or retroactively change an edge.

## 00.3 Model probability, proposal probability, and recorded fact

The word “probability” has three distinct uses:

1. **Model probability `P`** belongs to the scenario and describes the modeled
   environment, such as a one-percent per-frame loss process.
2. **Proposal probability `Q`** belongs to the campaign and describes how a
   finite exploration budget is allocated, such as oversampling high loss rates
   or boundary values.
3. **Recorded selection** belongs to the schedule and states exactly what
   occurred on one branch.

`P` and `Q` may be different. A bug-hunting campaign will often deliberately
make them different. Such a campaign may report that it found a bug but may not
claim that its observed frequency estimates real-world probability. Statistical
estimation rules appear in §03.

- **[CMOD-4]** Every probabilistic proposal MUST name both the model-prior
  identity, when present, and the proposal-policy identity. A realized branch
  MUST record the concrete selection and never depend on re-rolling either
  distribution during replay.
- **[CMOD-5]** Campaign reports MUST label probability estimates as descriptive,
  guidance-biased, or statistically weighted. Guidance-biased sample frequency
  MUST NOT be presented as modeled failure probability.

## 00.4 Canonical and non-canonical activity

The following are canonical when their inputs are declared and recorded:

- scheduler selection among a typed choice domain;
- signal-fault outcome or parameter selection at a stable opportunity;
- guest application selection through the white-box choice protocol;
- workload input selection declared by the scenario;
- preemption or interrupt-timing selection admitted by the scheduler;
- a campaign proposal converted into one of the preceding selections.

The following create non-canonical debugger branches or a new lineage:

- changing guest memory or registers manually;
- editing a device model or signal program already consumed by the prefix;
- using host sensor or network state not captured as scenario input;
- changing guest binaries, topology, QEMU build, or protocol implementation;
- returning a value outside the declared choice domain.

- **[CMOD-6]** A campaign MAY reuse a checkpoint across policy revisions because
  policy is not modeled state. It MUST NOT reuse a checkpoint across scenario or
  provenance changes unless a separately specified prefix-equivalence proof
  authenticates that reuse. The initial implementation provides no such proof
  and therefore forks a fresh lineage.

## 00.5 Correctness and exploration completeness

Crucible remains an execution and exploration system, not a model checker.
Except for a finite domain explicitly exhausted under a bounded horizon, a
campaign makes no completeness claim. Progressive widening, probabilistic
sampling, coverage guidance, beam selection, and corpus mutation all trade
completeness for reach.

- **[CMOD-7]** Every campaign result MUST report the admitted choice points,
  explored values, stop conditions, budgets consumed, reductions applied, and
  whether any domain was actually exhausted.
- **[CMOD-8]** “No finding” means no finding in the recorded explored set. The
  CLI and structured API MUST NOT render it as proof that no failing branch
  exists unless all relevant finite domains and horizons were exhausted.

## 00.6 Local-first execution and future distribution

The initial implementation is deliberately local-first:

- one daemon owns campaign planning;
- workers are local QEMU worlds;
- hot branching uses on-host copy-on-write;
- durable closures use a local filesystem content store;
- an S3-compatible object API is an allowed next backend;
- worker-host distribution is deferred.

The data plane nevertheless uses location-independent attempt and observation
objects. A future worker host can fetch a parent closure, restore it once, and
perform local hot fanout without changing campaign semantics.

- **[CMOD-9]** No initial local implementation API may require a native process
  handle, host path, or in-memory Rust object in a durable `Attempt` or
  `Observation`. Local acceleration is attached through optional cache handles
  outside canonical encoding.
