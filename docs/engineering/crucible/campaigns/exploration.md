# Exploration and guidance

Exhaustive search is usually impossible. A campaign selects a small, useful,
replayable subset of a very large mixed discrete and integral space while
keeping an exact account of what was and was not explored. The policy and
generator vocabulary lives in `crucible_campaign::policy`; the pure planner in
`crucible_campaign::planner_service` and `crucible_campaign::exploration`.

## Two nested decisions

1. **Frontier selection:** which open branch point and candidate-source
   continuation receives the next unit of work?
2. **Candidate generation:** which previously unadmitted value does that
   source try next?

The durable representation of a generator is never a trait object. It is a
closed, versioned `CandidateGeneratorSpec` (an algorithm plus an
implementation version) whose cursor and statistics are re-derived from
campaign facts. Arbitrary class names, closures, and unversioned parameter maps
are not admitted. Generation is a pure function of the planner engine and
state, the opportunity, branch point, branch request, policy, campaign seed,
planning budget, and the bounded planning view; direct and RPC planner adapters
receive the same view. Generator implementation versions and parameters are
part of the policy identity and every proposal's provenance.

## Candidate sources

Every branch request carries exactly one source:

| Source | Meaning |
| --- | --- |
| `Finite` | An explicit bounded value set, optionally with positive raw `u64` prior weights (missing weights mean weight one) |
| `ModeledFinite` | Finite values whose exact positive masses were resolved from the opportunity's probability model |
| `ModeledGenerated` | A deterministic generator resolved from the opportunity's model (currently uniform app randomness) |
| `Generated` | A versioned deterministic generator interpreted from campaign facts |
| `StatisticalFinite` | One categorical statistical draw with exact target and proposal masses |
| `StatisticalSmc` | One sequential Monte Carlo transition for an authenticated generation slot |

A finite source is a statement about the request, not the domain: an operator
can branch a 64-bit integer opportunity at three chosen values. `branch --all`
is a finite source only when validation proves the complete domain fits the
policy's exhaustive-cardinality ceiling; otherwise it fails before request
publication. Finite mass maps contain at most 4,096 entries and name exactly the
value set. A modeled source's model ID must equal the opportunity's
`model_prior`.

Finite and generated sources share validation, proposal, attempt, observation,
credit, and replay machinery. A finite request is additive: it does not close
or replace a generator already attached to the same branch point. Replacing the
exploration policy requires an explicit policy activation, or a derived
campaign. Weights affect proposal ranking only; they never change canonical
value order, legality, budgets, deduplication, or attempt identity.

## Built-in generators

| Algorithm | Domain | Order |
| --- | --- | --- |
| `All` | Boolean, discrete | `false` then `true`, or alternatives in stable `AlternativeId` order |
| `BoundaryInteger` | Integer | Minimum, maximum, default, and landmarks in numeric order; then each anchor's legal one-step lower and upper neighbours; then legal powers of two by ascending exponent. At most 64 landmarks and 512 candidates. |
| `StratifiedInteger { strata }` | Integer | For cardinality `C` and `E = min(strata, C)`, ordinal `j` uses offset `floor(j * (C - 1) / (E - 1))`, including both endpoints; `E = 1` uses the lower midpoint. At most 4,096 strata. |
| `LogInteger { base }` | Positive integer | Minimum, then `base^e` for ascending `e` rounded up to the next legal value, then maximum. |
| `PermutedInteger` | Power-of-two cardinality, through `2^64` | A four-round keyed permutation of domain offsets, keyed by the branch request digest; emits `min(C, maximum_proposals)` values. |
| `WeightedCategorical { weights }` | Discrete (at most 256 alternatives) | Exact integer-weight sampling without replacement, with rejection sampling over 128-bit keyed hashes. |
| `OrderedMixture { components }` | Any | 1 to 256 weighted child generators interleaved by least virtual finish time `(e_i + 1) / w_i`, compared by cross multiplication, first occurrence wins. At most 64 levels, 512 distinct outputs, and 8,192 work units. |
| `ProgressiveInteger { initial_strata, feedback_interval }` | Integer | Stratified prefix, then feedback-gated interval refinement (below). |
| `MutateNearCorpus { maximum_distance }` | Integer | Legal-step neighbours of completed selections whose children remain in the corpus. |
| `GroupProgressive { maximum_proposals }` | Group | Complete, constraint-valid group tuples from bounded semantic anchors; at most 4,096 tuples. |

Every algorithm accepts only its own implementation version; unknown versions
fail closed. All arithmetic is checked integer arithmetic in constant space,
and every bound is enforced at local acceptance, restart, and import, so a
proposal is always recomputable from the immutable request and snapshot.

**Progressive integer.** The first `min(S, L)` candidates use the stratified
offsets, where `S = min(initial_strata, C)` and
`L = min(C, maximum_proposals)`. Refinement `r` becomes available only when the
branch point has at least `r * feedback_interval` distinct descendant credits,
and between thresholds the continuation reports
`WaitingForFeedback(completed, required)`. Each refinement chooses one maximal
interval of unselected legal offsets. Intervals are ranked by the exact-mean
discontinuity between their two selected endpoints in coverage rarity, then
finding reward, then novelty, then objective reward, then by the number of
producer landmarks inside the interval, the endpoint PUCT score difference,
interval length, and finally the lower offset. The chosen interval emits the
landmark closest to its lower midpoint, or the midpoint itself when it holds no
landmark. Reaching `L` is `Exhausted` only when the domain fits in the
proposal budget; otherwise it is a budget-limited `Closed`.

**Corpus mutation.** For the request's branch point the owner scans at most
4,096 completed credits whose attempt names the same opportunity and domain and
whose child is still in the corpus. For each anchor in canonical order it tries
distance one below, then above, then distance two, up to `maximum_distance`.
The continuation is the exact set of values the request already proposed, so
corpus growth can introduce a new preferred candidate without reinterpreting an
earlier one. With no unproposed candidate it waits for the next credit rather
than claiming exhaustion.

### Progressive widening

For a branch point with `N` completed descendant visits and `M` admitted
children, a `ProgressiveWideningPolicy` with exact rational `k = a / b`,
exponent `alpha` in `{0, 1/2, 1}`, initial allocation `I`, hard ceiling `H`, and
per-child visit floor `V` computes:

```text
alpha = 0:   R = ceil(a / b)
alpha = 1:   R = ceil(a * N / b)
alpha = 1/2: R = least r >= 0 such that (r * b)^2 >= a^2 * N
L = min(H, max(I, R))
```

One more child is eligible exactly when `M < L` and either `M < I` or
`N >= M * V`. The square-root case uses exact wide-integer products and a
bounded binary search; no floating-point power is evaluated. A widening branch
point may remain dormant indefinitely without consuming execution resources.

## Tree policy: deterministic PUCT

`ExplorerPolicy` is `TreeSearch { puct, widening }`, `Beam { width,
novelty_reserve }`, or `Exhaustive { maximum_cardinality }`. Tree search uses a
fixed-point PUCT score with `S = 1_000_000`. For parent visits `N`, edge
visits `n`, exploration weight `c`, and normalized prior `p` in `[0, S]`:

```text
sqrt_N         = floor(sqrt(N * S * S))
weighted_prior = floor(c * p / S)
exploration    = floor(floor(weighted_prior * sqrt_N / S) / (1 + n))
mean_reward    = trunc_toward_zero(reward_sum / n), or 0 when n = 0
score          = mean_reward + exploration + novelty_bonus + fairness_bonus
```

The novelty bonus is added once when the edge has a coverage-novelty event, and
the fairness bonus once when the edge holds the current fairness reservation
(the least-visited edge, ties broken by `BranchEdgeId`). Bonuses and the
ordered sum saturate at the signed 64-bit range. The staged divisions and
saturation points are part of the language-neutral contract.

Edge statistics are rebuilt from the snapshot's idempotent credit index and
keyed by stable branch-point and edge identity, so convergent paths and
duplicate causes are credited once. The inputs are:

- **Prior.** Each completed edge takes the raw source weight of the proposal
  with the lowest admission ordinal among its credited observations. For total
  weight `W`, every edge gets `floor(S * w / W)` micros and the remainder is
  distributed one micro at a time in ascending `BranchEdgeId` order, so priors
  sum to exactly `S`.
- **Coverage novelty and rarity.** An identity covered by exactly one canonical
  observation in the snapshot is a novelty event for that observation's edge.
  Inverse-frequency rarity adds `floor(65_536 / f(i))` for each identity.
- **Findings.** The closed signals `finding.property-violation`,
  `finding.divergence`, and `finding.timeout` add a policy-weighted positive
  reward once per authenticated cluster occurrence credited to the branch
  point.
- **Objectives.** Owner-published objective evaluations contribute a signed
  scalar reward converted to millionths.

An unseen offered edge is scored as one prospective addition with zero visits
and reward and the fairness reservation. Higher totals win; equal totals pick
the lower `BranchEdgeId`, then the lower scan position.

The planner never reads the repository. The coordinator supplies a
snapshot-bound `PlannerCandidateGuidance` record beside every ready offer and
recomputes it at acceptance, restart, and import, so a substituted score,
domain, or reward fails closed. One served page is one bounded projection batch
(at most 65,536 credited observations and 128 MiB of bodies per input class).

## Guidance signals and objectives

Signals read canonical observation data: coverage gain, rarity, assertion
proximity, property failure, metric improvement, newly discovered
opportunities, and failure-signature novelty. A policy combines them with
fixed-point weights or a Pareto vector.

- Properties are correctness constraints and produce findings.
- Measurements provide exact observations.
- Objectives map measurements to minimize or maximize directions.
- Guidance decides how objectives and novelty affect future work.

Host CPU time, wall-clock duration, queue delay, and restore latency are never
scenario objectives; they appear only in operational telemetry. Adaptive
normalization never depends on executor completion order.

## Beam and Pareto survival

At named measurement barriers a campaign may select survivors for deeper
paths:

1. reject branches with disqualifying property failures, crashes, or missing
   required measurements;
2. compute the canonical objective vector and exact weighted reward;
3. order by Pareto-top-`K`, lexicographic, or weighted-top-`K` rule;
4. reserve breadth-first capacity first and novelty capacity second, then fill
   the remainder from the primary order;
5. retain or materialize survivor checkpoints according to policy.

Reserves consider every admissible candidate, including Pareto-dominated ones,
because exploration capacity is independent of exploitation. Every remaining
tie breaks by `ConfigurationId`. One decision admits at most 16,384
configurations, with explicit preflight limits on pairwise comparison work and
on exact weighted arithmetic. A survivor decision is a content-addressed fact
naming the policy, rule, every considered evaluation, the selected set, and one
explanation per configuration (objective, breadth, novelty, filtered,
dominated with a canonical dominator, or rank-pruned).

Pure top-`K` optimization can systematically discard slow or pathological
branches where bugs concentrate, so a campaign that also hunts bugs should
reserve exploration capacity.

## Hierarchical fault exploration

Branching on every packet loss, I/O completion, or memory access is usually
intractable. Event-heavy models are explored hierarchically: choose coarse
parameters (rate, duration, target, window), sample individual outcomes from
the keyed model process, retain interesting branches, then expose and mutate
exact outcomes near the interesting suffix, and finally minimize. Per-event
branching is opt-in and bounded.

The promotion boundary converts at most 4,095 exact signal-fault candidates
from one search frontier into one campaign opportunity under the
`crucible.signal-fault-search.v1` adapter. Outcome searches use a Boolean
domain; transition and parameter searches use stable discrete identities plus
one final alternative for the unmodified model result, staying within the
4,096-alternative cap. The coordinate retains the exact parent and
candidate-set digest; the instance retains the frontier time.

Live promotion is attempt-scoped and enabled only for `NextChoice` stops after
the start configuration has been materialized exactly. Only a frontier first
recorded during the current scheduler quantum whose parent and virtual time
equal the current boundary is eligible; retrospective frontiers are never
reported as discoveries at a later child. One configuration may contain at most
4,096 promoted signal-fault events. Replay installs all finite overrides before
launch and requires each candidate to have actually been consumed by the signal
runtime at the exact parent and time. Pending promoted branches are not
exact-checkpoint-ready, and restart reconstructs the plan from immutable
records rather than process-local state.

## Probabilistic exploration

- **Bug-hunting:** the proposal distribution may oversample boundaries and
  rare faults. Reports make no frequency claim.
- **Optimization:** probability is a proposal mechanism, not an estimate.
- **Statistical:** described below.

### Statistical mode

A statistical policy records exact integer-mass target `P` and proposal `Q`
distributions so estimates can be importance weighted. A path with `Q = 0`
where `P > 0` invalidates the estimate, and a policy that cannot provide the
declared support and weight accounting is rejected; it never silently falls
back to biased frequency.

- The **static finite design** pins complete distributions for coordinates
  `0..N`, each with a predeclared opportunity, parent coordinate, model, and
  stop condition, and runs with the exhaustive planner.
- The **sequential Monte Carlo design** keeps that finite flight as stage zero,
  fixes the particle count, and predeclares every later stage's distribution and
  selector. A selector binds declaration, domain, producer instance, model, and
  stop before the parent observation exists. The owner issues one request per
  particle slot, waits for every observation in a stage, and derives the next
  generation. The systematic resampler draws one exact offset from the campaign
  seed, next-stage coordinate, and nonce; observation content never enters it.
  When the exact effective sample size falls to the declared threshold, the
  generation records the normalization factor and parent multiplicities and
  resets carried weights.

A report is available only after every declared coordinate has a canonical
observation. The ordinary importance estimate divides the endpoint weight sum
by the fixed endpoint count. A separately labelled self-normalized estimate
uses the realized weight sum and carries finite-sample bias. Effective sample
size and weight concentration are descriptive; shared genealogy precludes an
IID interval.

An operator or debugger proposal used as an execution basis is an
intervention, not a draw. Its observation can find bugs and, when the policy sets
`InterventionLearningPolicy::IncludeInGuidance`, update guidance, but it is excluded
from estimators unless the statistical design modeled it. A later
`AdditionalCause` neither taints nor legitimizes the original basis. Once
activated, the statistical policy identity is immutable for the lineage.

## Strict and streaming planning

Strict mode commits observations in deterministic admission order before
issuing dependent proposals; it may buffer out-of-order results and suffer
head-of-line blocking, but the proposal sequence is reproducible from the
initial snapshot, policy, seed, and grants. Streaming mode incorporates any
completed observation immediately and records the exact observation basis of
every proposal. Status, exports, and reports always show the mode.

Changing mode derives a new campaign. A streaming-to-strict derivation
reconstructs the authenticated contiguous completion prefix, preserves
completed ordinals beyond any hole, and resumes strict publication at the first
incomplete ordinal.

## Reduction and minimization

Content-address deduplication, conservative partial-order reduction, and proven
symmetry reduction run before guidance; guidance orders what remains and never
weakens reduction soundness. Reduction explores whenever equivalence is
uncertain.

The deterministic schedule minimizer admits a shortest-first lexicographic
window, orders it with seeded content-address tie-breaks, and considers at most
4,096 candidates and 128 MiB of conservative candidate-copy work. The minimized
reproduction retains the seed and both bounds as its policy, every attempted
candidate's identities and observed fingerprint, and the final replayed state.
