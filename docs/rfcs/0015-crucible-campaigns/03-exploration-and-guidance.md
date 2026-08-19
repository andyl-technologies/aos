# 03 — Candidate generation, guidance, and adaptive exploration

Exhaustive search is usually impossible. This file specifies how a campaign
selects a small, useful, replayable subset of a vast mixed discrete and integral
space while preserving a clear account of what was and was not explored.

## 03.1 Two nested decisions

Campaign planning has two levels:

1. **Frontier selection:** which open branch point and candidate-source
   continuation should receive the next unit of work?
2. **Candidate generation:** which previously unadmitted value should that
   branch point try?

The existing breadth-first, depth-first, priority, coverage, novelty, assertion
proximity, and deterministic-bandit mechanisms are frontier policies. The new
candidate-generator abstraction handles typed domains.

```rust,illustrative
pub trait CandidateGenerator {
    fn poll(
        &self,
        opportunity: &ChoiceOpportunity,
        view: &ExpansionStateView,
        seed: Seed,
    ) -> CandidatePoll;
}

pub enum CandidatePoll {
    Yield(ChoiceValue),
    WaitForFeedback { completed_visits: u64 },
    Exhausted,
}
```

This is an illustrative interface, not permission to store trait objects. The
durable representation is a closed, versioned `CandidateGeneratorSpec` plus
canonical facts from which its cursor and statistics are derived.

The initial canonical specification is a closed tagged union covering `all`,
weighted categorical, stratified/boundary/log/permuted/progressive integer,
corpus mutation, and an ordered positive-integer-weight mixture of other
specifications. It records an implementation-protocol version, bounds every
map/list before allocation, and exposes mixture children in the generic object
envelope. Arbitrary class names, native closures, serialized functors, and
unversioned parameter maps are not admitted. Recursive mixture references are
authenticated as ordinary content children and must form a complete reachable
closure before policy or campaign-ref publication.

- **[GUIDE-1]** Candidate generation MUST be a pure function of the named
  planner engine/artifact and state, choice opportunity, branch point, branch
  request, policy, campaign seed, explicit planning budget, and canonical
  bounded `CampaignPlanningView`. Direct and RPC planner adapters receive the
  same logical view.
- **[GUIDE-2]** Generator implementation version and parameters MUST be included
  in `CampaignPolicyId` and every resulting proposal's provenance.

### Candidate sources and explicit branches

Every `BranchRequest` supplies one of two source forms:

```rust,illustrative
pub enum CandidateSource {
    Finite { values: CanonicalSet<ChoiceValue> },
    Generated { generator: CandidateGeneratorSpecId },
}
```

A finite source is an explicit bounded set, not a statement about the
cardinality of the underlying domain. An operator can therefore branch a huge
integer opportunity at three deliberately chosen values. `--all` is shorthand
for a finite source only when validation proves that the complete domain fits
the policy's explicit exhaustive-cardinality ceiling.

A generated source is a suspended deterministic computation: sampling,
mutation, exhaustive iteration, or progressive widening. Finite and generated
sources share validation, proposal, attempt, observation, credit, and replay
machinery. Issuing a finite request is additive; it does not close or replace a
policy generator already attached to the same branch point. Replacing the
exploration policy requires an explicit policy activation, or deriving a new
campaign when the operator wants an independent future history.

## 03.2 Built-in generators

The initial implementation provides:

| Generator | Domain | Behavior |
| --- | --- | --- |
| `all` | Small Boolean/discrete | Admits every alternative in stable ID order. |
| `weighted_categorical` | Discrete | Keyed sampling without replacement using exact integer weights. |
| `stratified_integer` | Integer | Admits values from deterministic strata across the full range. |
| `boundary_integer` | Integer | Prioritizes min, max, default, landmarks, adjacent values, and powers of two. |
| `log_integer` | Positive integer | Samples exact integer logarithmic buckets with declared rounding. |
| `permuted_integer` | Finite integer | Walks a keyed permutation without materializing the domain. |
| `progressive_integer` | Integer | Starts with landmarks/strata and refines intervals from feedback. |
| `mutate_near_corpus` | Any supported domain | Deterministically mutates retained successful, novel, or failing values. |

Generators compose as a fixed ordered mixture with integer weights. Duplicate
values deduplicate by `(BranchPointId, ChoiceDomainId, ChoiceValue)`; the
generator advances until it yields a new value or proves exhaustion. Distinct
request/proposal facts that produce the duplicate remain visible as provenance.

- **[GUIDE-3]** Every finite generator MUST eventually exhaust its domain if
  polled without a budget limit. Sampling generators over huge domains MUST
  report admitted cardinality and may report `Open` rather than `Exhausted`.
- **[GUIDE-4]** Boundaries, defaults, producer landmarks, and values immediately
  adjacent by one legal step SHOULD receive an initial fairness allocation
  before purely adaptive exploitation.

## 03.3 Progressive widening

For a branch point with `N` completed descendant visits and `M` admitted
distinct children, a widening policy permits another child when:

```text
M < ceil(k * N^alpha)
```

`k` and `alpha` are exact nonnegative rationals with a specified integer
rounding algorithm. The implementation does not evaluate a floating-point power.
The first version supports a closed set of rational exponents with exact integer
root/power implementations, including `1/2` and `1`. A policy may additionally
declare minimum initial children, maximum children, minimum completed visits per
child, and domain-exhaustion behavior.

For integer domains, the generator maintains a derived interval partition:

```text
[minimum ................................ maximum]
     | landmarks and initial strata |

observations reveal a transition in [a, b]
                         |
                         +-> split [a, b], sample midpoint/adjacent values
```

Intervals receive deterministic scores from:

- reward improvement or regression;
- coverage or semantic novelty at their endpoints;
- property-verdict disagreement;
- measurement discontinuity;
- uncertainty from low visit count;
- producer landmarks contained in the interval.

The partition is derived from proposals and observations and can be rebuilt.
Splits use exact integer midpoint and rounding rules. Empty or duplicate splits
are discarded.

- **[GUIDE-5]** Progressive widening MUST feed descendant observations back to
  the expansion state at every branch point on the recorded branch-edge path.
  It MUST NOT mutate ancestor configurations.
- **[GUIDE-6]** Widening eligibility and interval selection MUST be explainable
  from stored visit counts, rewards, proposal values, policy parameters, and
  observation IDs.
- **[GUIDE-7]** A widening branch point MAY remain dormant indefinitely without
  a live QEMU process. Polling its expansion state again realizes its parent
  from the cheapest correct cache tier.

## 03.4 Tree policy: deterministic MCTS/PUCT

The default adaptive tree policy is a deterministic fixed-point PUCT variant.
For an edge `e` from parent `s`:

```text
score(s, e) =
    mean_reward(e)
  + exploration_weight * prior(e) * sqrt(visits(s)) / (1 + visits(e))
  + novelty_bonus(e)
  + fairness_bonus(e)
```

All terms use saturating checked integer or fixed-point arithmetic. Square roots
use a specified integer algorithm. Scores are accumulated in a fixed field
order. Ties break by `SelectionId`, then `ConfigurationId`.

The prior may come from the scenario's model distribution, an explicit campaign
proposal prior, or a uniform default. Using a model prior for PUCT does not make
the resulting visit frequency a statistical estimate; it is still guidance.

Rewards propagate from a completed observation along its recorded branch-edge
path. Confirmed correctness failures dominate ordinary optimization rewards in
bug-finding mode. Optimization mode may instead reject failures and optimize the
remaining metric vector.

- **[GUIDE-8]** PUCT statistics MUST be keyed by stable branch-point and branch-
  edge identity. Results from different `ChoiceClassId`s MUST NOT be pooled
  unless the policy explicitly declares a shared class.
- **[GUIDE-9]** Duplicate attempts and duplicate observations MUST receive
  credit exactly once.

## 03.5 Guidance signals and objectives

Built-in observation signals include:

- basic-block and semantic coverage gain;
- inverse-frequency novelty/rarity;
- assertion-proximity progress;
- property failure or recovery;
- metric improvement relative to a declared baseline;
- new choice-opportunity discovery;
- failure-signature novelty;
- state or event-log novelty under a declared projection.

Signals are readers of canonical observation data. A campaign policy combines
them with fixed-point weights or uses them as a Pareto vector.

Measurements remain separate from properties:

- properties are correctness constraints and hard filters or findings;
- measurements provide exact observations;
- objectives map measurements to minimize/maximize directions;
- guidance decides how objectives and novelty affect future work.

- **[GUIDE-10]** Adaptive normalization MUST NOT depend on executor completion
  arrival order. Strict mode folds observations in deterministic attempt order;
  streaming mode records the exact observation basis used by each planner step.
- **[GUIDE-11]** Host CPU time, wall-clock duration, executor queue delay, and
  checkpoint-restore latency MUST NOT be scenario-performance objectives. They
  may appear only in operational telemetry.

## 03.6 Beam and Pareto survival

At named measurement barriers, a campaign may select survivors for deeper fault
paths:

1. reject branches with disqualifying property failures, crashes, or missing
   required measurements;
2. compute a canonical metric vector;
3. retain a Pareto frontier or lexicographic/top-`K` order;
4. reserve configured capacity for coverage novelty, rare states, or
   underexplored choice classes;
5. retain or materialize survivor checkpoints according to policy.

Canonical ties break by configuration ID. A survivor decision is stored as a
planner fact naming all considered observations and the selection rule.

- **[GUIDE-12]** A “best-performing” campaign SHOULD reserve explicit
  exploration capacity when bug discovery is also a goal. Pure top-`K`
  optimization may systematically discard slow or pathological branches where
  bugs concentrate.
- **[GUIDE-13]** A campaign report MUST distinguish property filtering, Pareto
  domination, budget pruning, retention eviction, and true domain exhaustion.

## 03.7 Hierarchical fault exploration

Branching on every packet loss, I/O completion, or memory access is usually
intractable. Campaigns explore event-heavy models hierarchically:

1. choose coarse parameters such as rate, duration, target, spatial window, or
   signal transition;
2. sample individual outcomes from the selected keyed model process;
3. retain branches with interesting measurements, coverage, or failures;
4. locally expose and mutate exact event outcomes near the interesting suffix;
5. minimize the resulting schedule while preserving the finding signature.

This uses RFC-0014's selected outcome, transition, parameter, trace-window, and
mapping mutation seams without turning every signal sample into a branch.

- **[GUIDE-14]** Per-event branching MUST be opt-in and bounded. The default for
  high-rate opportunities is to select model parameters and sample keyed
  outcomes, then promote a bounded interesting window for exact branching.

## 03.8 Probabilistic exploration and statistical validity

Three modes are explicit:

### Bug-hunting mode

The proposal distribution may oversample boundaries, rare faults, and known
dangerous interactions. Reports make no frequency claim.

### Optimization mode

Adaptive search seeks good metric vectors. Probability is a proposal mechanism,
not an estimate of how often a configuration occurs naturally.

### Statistical mode

Samples are drawn from modeled distribution `P`, or the campaign records both
`P(path)` and proposal distribution `Q(path)` as exact rational/log-weight
material sufficient for declared importance weighting. Adaptive resampling uses
predeclared sequential Monte Carlo rules and reports effective sample size and
weight concentration. Paths with `Q = 0` where `P > 0` invalidate the estimate.

An operator or debugger proposal used as an attempt's `ExecutionBasis` is an
intervention, not a draw from the campaign's proposal distribution. Its
observation remains useful for finding bugs, comparing outcomes, and—when
policy explicitly opts in—updating adaptive guidance. It is excluded from
frequency and importance-weighted estimators unless the statistical policy
modeled that intervention in advance and records the correct `P/Q` evidence. An
operator proposal later attached as an `AdditionalCause` does not retroactively
taint or legitimize the original execution basis. A manually requested
pathological value must never silently change a population claim.

- **[GUIDE-15]** Statistical mode MUST reject any proposal policy that cannot
  provide the declared support and weight accounting. It MUST NOT silently fall
  back to guidance-biased frequency.
- **[GUIDE-16]** Model and proposal distributions use integer masses, reduced
  rationals, or canonical fixed-point log weights with explicit rounding. They
  MUST NOT use platform-native floating-point ordering.

## 03.9 Strict and streaming planning

Strict mode commits observations in deterministic attempt order before issuing
dependent proposals. It may buffer out-of-order results and can suffer
head-of-line blocking, but the campaign proposal sequence is reproducible from
the initial snapshot, policy, seed, and budget grants.

Streaming mode incorporates any completed canonical observation immediately.
Every proposal records its observation basis, so its reason remains
reproducible, but a rerun with different completion order may discover branches
in a different order and may spend a finite budget differently. Every individual
branch and finding remains bit-replayable.

- **[GUIDE-17]** The selected campaign mode MUST be visible in status, exports,
  and reports. Strict and streaming claims MUST never be conflated.
- **[GUIDE-18]** Switching mode is a policy revision recorded before subsequent
  proposals. It does not rewrite earlier planner steps.

## 03.10 Search reduction and minimization

Content-address deduplication, conservative partial-order reduction, and proven
symmetry reduction remain valid before guidance. Guidance orders or samples the
remaining graph; it does not weaken reduction soundness.

On finding, minimization may remove selections, reduce integer values toward
landmarks/boundaries, simplify discrete choice paths, narrow fault windows, and
shorten stop horizons while preserving the stable failure signature and replay
oracle.

- **[GUIDE-19]** Reduction MUST explore when equivalence or independence is
  uncertain. Guidance score similarity is not proof of semantic equivalence.
- **[GUIDE-20]** A minimized artifact MUST retain the original finding,
  minimization policy, candidate history, and proof that the final artifact
  reproduces the same signature.

## 03.11 Branch-source rules

- **[GUIDE-21]** A finite candidate request MUST be additive to existing
  expansion state, canonically ordered, lazily consumed, and bounded by both
  request cardinality and campaign budget. Duplicate values MUST reuse the same
  semantic branch edge, and attempts MUST deduplicate when all of their semantic
  inputs match.
- **[GUIDE-22]** `branch --all` MUST fail before request publication when the
  validated finite domain exceeds the configured exhaustive-cardinality ceiling
  or cannot provide a finite cardinality proof.
- **[GUIDE-23]** An operator or debugger `ExecutionBasis` MUST be excluded from
  statistical estimators unless the pinned statistical policy admitted its
  selection mechanism and records valid support and weighting evidence. An
  `AdditionalCause` MUST NOT reclassify the attempt.
- **[GUIDE-24]** A policy MAY learn from intervention observations only through
  an explicit policy rule visible in proposal explanations and campaign claims.
