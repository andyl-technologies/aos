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

The closed specification vocabulary provides:

| Generator | Domain | Behavior |
| --- | --- | --- |
| `all` | Small Boolean/discrete | Admits every alternative in stable ID order. |
| `weighted_categorical` | Discrete | Keyed sampling without replacement using exact integer weights. |
| `stratified_integer` | Integer | Admits values from deterministic strata across the full range. |
| `boundary_integer` | Integer | Prioritizes min, max, default, landmarks, adjacent values, and powers of two. |
| `log_integer` | Positive integer | Samples integral base powers with exact upward step rounding. |
| `permuted_integer` | Finite integer | Walks a keyed permutation without materializing the domain. |
| `progressive_integer` | Integer | Starts with landmarks/strata and refines intervals from feedback. |
| `mutate_near_corpus` | Integer | Deterministically mutates completed selections whose children remain in the retained corpus. |

The current repository-owned executable checkpoint implements generator
implementation-version 2 `all` for Boolean and discrete domains. It derives
`false`, then `true`, or the discrete alternatives in stable `AlternativeId`
order without storing a cursor.

Generator implementation-version 3 defines static `boundary_integer` order.
It emits the inclusive minimum, inclusive maximum, opportunity default, and
declared landmarks in canonical numeric order. It then visits those deduplicated
anchors in that order and emits each legal one-step lower and upper neighbor.
Finally it emits legal powers of two by ascending exponent; unsigned domains use
positive powers, while signed domains try the positive value before the negative
value at each exponent and include `i64::MIN` as the negative `2^63`. Every
candidate is filtered through the exact stepped domain and first occurrence
wins. This implementation accepts at most 64 declared landmarks and derives at
most 512 candidates, keeping proposal and restart owner validation bounded. It
needs no stored cursor or feedback.

Generator implementation-version 4 defines static `stratified_integer` order.
Let `C` be the exact stepped-domain cardinality and `E = min(strata, C)`. For
`E > 1`, zero-based candidate ordinal `j` uses legal-value offset
`floor(j * (C - 1) / (E - 1))` and value `minimum + offset * step`; this
includes both endpoints. For `E = 1`, the offset is `floor((C - 1) / 2)`, the
lower of the two middle legal values when the cardinality is even. If the
requested strata exceed the cardinality, every legal value is emitted. The
implementation admits at most 4,096 strata and reconstructs each ordinal with
checked 128-bit arithmetic in constant space.

Generator implementation-version 5 defines static `log_integer` order over a
strictly positive stepped domain. It emits the inclusive minimum, then integral
powers `base^e` for ascending `e` beginning at zero. Each power is rounded
upward to the least legal domain value `minimum + ceil((base^e - minimum) /
step) * step`; powers at or below the minimum select the minimum, and rounded
values above the maximum are omitted. It then emits the inclusive maximum.
First occurrence wins throughout. Base two over the full unsigned 64-bit range
is the largest sequence: 64 powers plus a distinct maximum, or 65 candidates.
The owner uses checked 128-bit arithmetic and constant bounded space.

Generator implementation-version 6 defines `permuted_integer` for stepped
domains with cardinality `C <= 2^64 - 1`. Its key is
`H("crucible.campaign.generator.permuted-integer.v6",
BranchRequestId.digest)`, so policy activation cannot reinterpret an existing
request. Split the 32-byte key into four big-endian `u64` words. Let `N` be the
least power of two at least `C`, `M = N - 1`, and begin with zero-based ordinal
offset `x`. For rounds zero through three, compute `y = x XOR (word & M)` on
even rounds and `y = (word - x) mod N` on odd rounds. Replace `x` with `y` only
when `y < C`; otherwise leave it unchanged. Each restricted round is an
involution of `[0, C)`, so their composition is a bijection. The candidate is
`minimum + x * step`. This walks every legal value exactly once with four
bounded rounds and no domain materialization. Cardinality `2^64` fails closed
because its last value has no one-based `u64` proposal ordinal.

Generator implementation-version 7 defines `weighted_categorical` over at
most 256 alternatives named by a discrete domain. The weight map is nonempty,
contains only positive `u64` weights, and every key must name an alternative in
that exact domain. At zero-based draw `j`, let `W` be the checked `u128` sum of
the remaining weights. Derive a big-endian `u128` sample from the first 16 bytes
of
`H("crucible.campaign.generator.weighted-categorical.v7",
BranchRequestId.digest || be64(j) || be64(nonce))`. Let `T = (-W) mod W` in
unsigned 128-bit arithmetic. Starting with nonce zero, reject samples below `T`
and increment the nonce; the first accepted sample selects position
`sample mod W` in the cumulative positive-weight intervals of the remaining
alternatives in canonical `AlternativeId` order. Remove the selected
alternative and repeat. At most 256 rejection attempts are admitted per draw;
exhausting that bound fails closed. This is exact integer-weight sampling
without replacement, contains no floating-point arithmetic, and reconstructs
the same complete order from the immutable request after restart.

Generator implementation-version 8 defines `ordered_mixture` over one through
256 ordered positive-weight child specifications. Every child must itself have
an executable finite owner for the request's exact domain; a suspended child
suspends the complete mixture. Resolve each child's complete candidate order,
then maintain its zero-based consumed count `e_i` and weight `w_i`. At each
step choose the nonexhausted component with the least exact virtual finish time
`(e_i + 1) / w_i`, comparing fractions by checked `u128` cross multiplication
and breaking ties by original component ordinal. Advance that component even
when its value has already been emitted, and emit a value only on its first
occurrence in canonical `ChoiceValue` equality. Recursive materialization and
each scheduler advance consume one of 8,192 work units; nesting is limited to
64 mixtures and output to 512 distinct values. Exceeding any bound fails closed.
This preserves exact integer weights without expanding them into repeated
entries, makes duplicate suppression independent of map insertion order, and
reconstructs the same mixture after restart.

Generator implementation-version 9 defines feedback-gated
`progressive_integer` over a stepped integer domain. Let `C` be the exact
domain cardinality, `S = min(initial_strata, C)`, and
`L = min(C, request.maximum_proposals)`. The first `min(S, L)` candidates use
the version-4 stratified offsets for exactly `S` strata, including both domain
endpoints when `S > 1` and the lower midpoint when `S = 1`. After all `S`
initial candidates, form every maximal interval of still-unselected legal
offsets, including exterior intervals. Select the interval with greatest
cardinality, breaking equal-cardinality ties by lower offset, emit its lower
midpoint `lower + floor((length - 1) / 2)`, split around that offset, and
repeat. This completely determines the candidate order without reward or
arrival-order input.

Initial candidates are immediately available. One-based refinement `r`
becomes available only when the branch point has at least
`r * feedback_interval` distinct authenticated descendant-observation credits.
After an admitted refinement, the continuation reports
`WaitingForFeedback(completed, required)` until the next threshold is met.
Version 9 admits at most 4,096 initial strata and at most 4,096 proposals, and
the maximum feedback threshold must fit `u64`. Reaching `L` is `Exhausted`
only when `C <= request.maximum_proposals`; otherwise it is budget-limited
`Closed`. The interval heap and every threshold are owner-recomputed during
local acceptance, import, and restart.

Generator implementation-version 10 defines view-dependent
`mutate_near_corpus` over a stepped integer domain. For the request's exact
branch point, the owner scans at most 4,096 authenticated completed-observation
credits. A credit contributes an anchor only when its branch attempt names the
request's exact opportunity and domain and its observation child remains in the
exact snapshot corpus. Anchors deduplicate in canonical integer order. For each
anchor in that order, the owner tries the legal one-step lower value and then
the legal one-step upper value, followed by distance two in the same lower-then-
upper order, through the declared `maximum_distance`. Out-of-domain values and
every repeated value are omitted; the anchor itself is not emitted.

Version 10 does not assign a permanent positional meaning to the mutable corpus.
Its portable continuation is the exact set of values already proposed by the
immutable request. At proposal ordinal `n`, the owner recomputes the candidates
from the exact current snapshot and chooses the first candidate not among
ordinals `1..n-1`. Corpus growth may therefore introduce a newly preferred
candidate without reinterpreting an earlier proposal. When no unproposed
candidate exists, the continuation waits for the next completed branch-point
credit rather than claiming domain exhaustion. It closes only at the request's
proposal budget.

The owner admits at most 4,096 legal-step distance, 4,096 proposals, and 65,536
anchor-distance work units per recomputation. It charges at most 128 MiB of
canonical credit, observation, and attempt bodies, in addition to the shared
selection resolver's existing 4,096-ID and 128-MiB unique-record budget. Every
limit and the exact proposal-set continuation are recomputed during local
acceptance, import, and restart.

Other algorithms remain valid suspended specifications but fail closed at
proposal issuance and expansion projection until their versioned cursor and
feedback owners are implemented. Earlier and unknown implementation versions
remain suspended rather than being reinterpreted as versions 2 through 10; this
preserves owner validation of histories created before executable enumeration
landed.

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

For reduced `k = a / b`, completed visits `N`, admitted children `M`, initial
allocation `I`, hard ceiling `H`, and per-child visit floor `V`, the first
version derives the power-law allowance `R` as follows:

```text
alpha = 0:   R = ceil(a / b)
alpha = 1:   R = ceil(a * N / b)
alpha = 1/2: R = least nonnegative r such that (r * b)^2 >= a^2 * N
L = min(H, max(I, R))
```

The square-root comparison uses exact unsigned 256-bit limb products and a
bounded binary search over `[0, H]`; it does not approximate the irrational
root. Products for the linear case use unsigned 128-bit arithmetic. Values
above `H` saturate to `H` before they can affect admission.

One more child is eligible exactly when `M < L` and either `M < I` or
`N >= M * V`. The initial allocation therefore cannot deadlock waiting for
feedback from children that do not yet exist. The visit threshold is computed
in unsigned 128-bit arithmetic; a threshold above `u64::MAX` is valid but
unreachable by the canonical visit counter. `M > H` is an integrity error.
These rules are implemented and conformance-tested as a pure owner primitive;
using them to issue generated candidates still requires the complete
branch-point projection and a new planner/generator implementation version.

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
are discarded. Version 9 is the bounded feedback-gated interval owner described
in §03.2: its visit count gates refinement, while its largest-gap choice does
not yet consume reward, novelty, finding, or measurement scores. A later
implementation version is required before those signals may change interval
selection.

- **[GUIDE-5]** Progressive widening MUST feed descendant observations back to
  the expansion state at every branch point on the recorded branch-edge path.
  It MUST NOT mutate ancestor configurations.
- **[GUIDE-6]** Widening eligibility and interval selection MUST be explainable
  from stored visit counts, rewards, proposal values, policy parameters, and
  observation IDs.
- **[GUIDE-7]** A widening branch point MAY remain dormant indefinitely without
  a live QEMU process. Polling its expansion state again realizes its parent
  from the cheapest correct cache tier.
- **[GUIDE-25]** Progressive-integer implementation-version 9 MUST reproduce the
  exact stratified-prefix and largest-gap/lower-midpoint order in §03.2, unlock
  refinement `r` only at the exact authenticated `r * feedback_interval`
  completed-visit threshold, and enforce its 4,096-strata, 4,096-proposal, and
  checked-`u64` threshold bounds during local acceptance, import, and restart.
  Earlier and unknown progressive versions MUST remain suspended.
- **[GUIDE-26]** Corpus-mutation implementation-version 10 MUST derive anchors
  only from exact completed branch selections whose children remain in the
  snapshot corpus, reproduce the canonical anchor and lower-then-upper distance
  order in §03.2, and use the exact previously proposed value set as its
  portable continuation. It MUST enforce the 4,096-credit, 4,096-distance,
  4,096-proposal, 65,536-work-unit, and two 128-MiB input-resolution bounds
  during local acceptance, import, and restart. Earlier and unknown corpus-
  mutation versions MUST remain suspended.

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

The exact arithmetic profile uses `S = 1_000_000`. A prior is an integer in
`[0, S]`; reward sums, means, and score terms are expressed in millionths. For
parent visits `N`, edge visits `n`, exploration weight `c`, and prior `p`, the
first fixed-point scorer computes:

```text
sqrt_N = floor(sqrt(N * S * S))
weighted_prior = floor(c * p / S)
exploration = floor(floor(weighted_prior * sqrt_N / S) / (1 + n))
mean_reward = trunc_toward_zero(reward_sum / n), or 0 when n = 0
```

An unvisited edge MUST have a zero reward sum. An edge prior above `S` or edge
visits above parent visits is invalid. The configured novelty bonus is added
once when the owner-derived novelty predicate is true, and the configured
fairness bonus is added once when the edge owns the current fairness
reservation. Each nonnegative bonus saturates at `i64::MAX`; the ordered sum
`mean_reward`, exploration, novelty, fairness saturates to the signed `i64`
range. The integer square root is the unique greatest integer whose square does
not exceed its input. These staged divisions and saturation points are part of
the language-neutral contract.

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

The repository now rebuilds the completed-visit portion of those statistics
from the exact snapshot's idempotent branch-point credit index. Every credited
observation must name one and only one matching scoped path segment; the result
partitions parent visits by `BranchEdgeId`, so convergence and duplicate causes
cannot add credit. One projection admits at most 65,536 credits and 128 MiB of
canonical credit, observation, attempt, and path bodies. It is identical after
restart and fails closed for legacy unscoped paths.

The repository also derives a policy-bound PUCT projection from that partition.
For `K > 0` completed edges, it assigns `floor(S / K)` prior
micros to every edge and assigns the `S mod K` remainder one micro at a time in
ascending `BranchEdgeId` order. The prior mass therefore sums to exactly `S`.
Exactly one least-visited edge owns the fairness reservation, with
`BranchEdgeId` breaking visit-count ties.

Coverage novelty is owner-recomputed from the exact snapshot. The owner takes
the union of coverage identities named by canonical observations credited to
the requested branch point, then counts each target identity across every
canonical observation in that snapshot. An identity is a novelty event only
when its global occurrence count is exactly one. Each such event is credited
once to the semantic edge of its credited observation; an edge's Boolean PUCT
novelty predicate is true when its event count is nonzero. Shared identities,
duplicate causes, and conflicting observations therefore add no novelty. The
fold scans at most 1,000,000 observation-root entries and 65,536 canonical
observations, visits at most 1,000,000 coverage identities, retains at most
65,536 branch-relevant identities, and charges at most 128 MiB of unique
canonical observation and coverage bodies. It is read-only and identical after
restart/import.

Owner-verified findings contribute a policy-weighted positive reward. The
closed signal names are `finding.property-violation`, `finding.divergence`, and
`finding.timeout`. For each configured signal, the owner scans the exact
snapshot's current finding clusters and credits each authenticated occurrence
whose canonical observation is credited to the requested branch point. One
cluster occurrence contributes its signal weight once to that observation's
semantic edge and therefore backpropagates through every branch point on the
recorded path. Unconfigured classes contribute nothing. Per-edge event counts
are retained in the projection for explanation; the weighted sum saturates at
signed `i64::MAX` before entering PUCT. One fold scans at most 65,536 finding-
root entries, 1,000,000 aggregate occurrence entries, and 128 MiB of canonical
finding bodies. Complete snapshot authentication precedes the shallow bounded
fold, so large reproduction bodies are not reparsed per projection.

Objective reward remains zero. The active tree-search policy produces the exact
decomposed fixed-point score for every edge. Empty branch points receive no
synthetic edge, prior, novelty, reward, or fairness reservation. This projection
is not yet consumed by canonical planner ordering. Model/explicit priors,
objective reward, and the path-ranking planner integration remain open.

The first executable closed-planner checkpoint deliberately establishes the
pure paged frontier loop before adaptive scoring. Engine
`crucible-canonical-frontier` implementation version 1 receives the
coordinator's exact authenticated continuation state and next legal candidate
for every served source, considers only `Ready` sources, and chooses the least
canonical `PlanningScanPosition`. It carries that offer across pages and issues
only at EOF. This ordering is deterministic fairness bootstrap behavior, not a
claim that PUCT is complete. Introducing objective reward, prior, or edge-visit
terms requires the complete owner-built projections and exact arithmetic above
and a new engine implementation version. The exact scorer, edge-visit
partition, coverage-novelty fold, finding-reward fold, uniform-prior fallback,
and fairness owner are now implemented and conformance-tested independently of
ranking; the remaining owner-built inputs and ranking engine remain the gate
that prevents them from changing campaign behavior prematurely.

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
2. compute the canonical objective vector and exact weighted reward;
3. compute the declared Pareto-top-`K`, lexicographic, or weighted-top-`K`
   primary order;
4. reserve breadth-first capacity first and novelty capacity second, then fill
   remaining capacity from the primary order;
5. retain or materialize survivor checkpoints according to policy.

The breadth-first reserve orders admissible candidates by
`(breadth_ordinal, ConfigurationId)`. The novelty reserve orders them by
descending `(novelty_score, ConfigurationId)`, with configuration identity as
the ascending tie-break. A candidate already selected by an earlier reserve
does not consume a later reserve slot. Filtered candidates never consume a
reserve. Reserves deliberately consider every admissible candidate, including
a Pareto-dominated candidate, because exploration capacity is independent of
the primary exploitation order.

Lexicographic comparison follows objective-name order. Each component applies
its minimize or maximize direction before the next component is considered.
Weighted comparison uses the exact sum of signed objective values multiplied by
their millionth-denominated policy weights; minimize terms are negated. Pareto
dominance requires one component to be strictly better and none worse. The
nondominated Pareto set is ordered by exact weighted reward when it exceeds the
remaining capacity. Every remaining tie breaks by `ConfigurationId`; input,
map, and executor-arrival order are irrelevant.

One decision admits at most 16,384 distinct configurations. Pareto evaluation
preflights `candidate_count * (candidate_count - 1) * max(objective_count, 1)`
and rejects more than 4,000,000 pair-by-component visits before comparison.
Lexicographic ranking conservatively charges
`candidate_count^2 * max(objective_count, 1)` against the same 4,000,000-visit
ceiling. Weighted ordering conservatively charges
`candidate_count^2 * maximum_reward_operand_bytes` and rejects more than
512 MiB of operand-byte visits. Exact weighted arithmetic permits at most
8 KiB in either reduced reward magnitude and at most 64 MiB of accumulated
arithmetic work. Evaluation and explanation records are each at most 4 MiB; the
survivor-selection record is at most 32 MiB. One decision admits at most 128 MiB
of aggregate canonical evaluation and explanation bodies, charged while
records are loaded or built.

A survivor decision is a content-addressed fact naming the exact policy,
selection rule, every considered objective evaluation, selected configuration
set, and one explanation per considered configuration. Explanations distinguish
objective selection, breadth-first selection, novelty selection, property or
measurement filtering, Pareto domination with a canonical dominator, and rank
pruning.

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

The implemented deterministic schedule minimizer admits a shortest-first
lexicographic window, then orders that bounded window with seeded
content-address tie-breaks. One run considers at most 4,096 candidates and
admits at most 128 MiB of conservative candidate-copy work, including the kept
schedule, complementary removed decisions, and removed-index vector. The
effective candidate count is the lesser of those two compiled bounds. Campaign
reproduction schema v2 retains the seed plus both compiled bounds as the exact
policy, every attempted candidate's artifact/schedule/replayed-state identities
and observed fingerprint, and the final replayed state. Candidate generation
stops at the policy bound; it does not allocate the complete combinatorial
candidate space.

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
  or cannot provide a finite cardinality proof. The first executable porcelain
  derives implementation-version 2 `all` and an exact-cardinality proposal
  budget for Boolean and discrete domains, and binds both to the active
  exhaustive policy selected at the request's authenticated snapshot.
- **[GUIDE-23]** An operator or debugger `ExecutionBasis` MUST be excluded from
  statistical estimators unless the pinned statistical policy admitted its
  selection mechanism and records valid support and weighting evidence. An
  `AdditionalCause` MUST NOT reclassify the attempt.
- **[GUIDE-24]** A policy MAY learn from intervention observations only through
  an explicit policy rule visible in proposal explanations and campaign claims.
