# Exploration

Exploration turns one deterministic run into a systematic walk of the schedule
space around it: fork, save and restore, state-space search, coverage feedback,
coverage-guided fuzzing, guided and adaptive frontier ordering, preemption and
app-randomness branching, reproduction artifacts, and minimization. None of
these features owns a private state representation or execution path. Each one
is an operation on the content-addressed temporal graph
(`crates/crucible/crucible-engine/src/model/temporal_graph/`) and every
realization goes through the single `instantiate` function in
`crates/crucible/crucible-engine/src/model/runtime.rs`.

```text
  fork      = instantiate a recorded Configuration, append Decisions, record a thin node
  save      = materialize a fat checkpoint keyed by config.id(), replay-oracle checked
  resume    = instantiate the tip
  replay    = rebuild a cached fat checkpoint by thin replay and compare identities
  search    = enumerate genuine choices at a frontier, step each, dedup by id,
              cover provably redundant children (symmetry, partial order)
  fuzz      = seeded, coverage-biased sampling of ScenarioFamily points into
              pinned scenarios; corpus entries are reproduction artifacts in a DagStore
  reproduce = (scenario form, schedule) artifact; minimize = failure-preserving shrink
```

The order in which these capabilities were built, and the gates that guard each
rung, is recorded in the dependency ladder in
[testing-and-gates.md](testing-and-gates.md). Execution-model vocabulary
(`Configuration`, `Schedule`, `Decision`, `reduce`, `instantiate`) is defined in
[execution-model.md](execution-model.md), and the checkpoint DAG itself in
[execution-graph.md](execution-graph.md). Operator usage of `search`, `fuzz`, and
`triage` is in [the user exploration guide](../../users/crucible/exploration.md).

## Where the code lives

| Area | Path | Key items |
|------|------|-----------|
| Fork, resume, replay, unified check | `crucible-engine/src/model/temporal_graph/core.rs` | `TemporalGraph::{resume, fork, replay, search, search_with_strategy, branch_preemptions, validate_unified_operation}` |
| Checkpoint cache and restore | `crucible-engine/src/model/temporal_graph/core/checkpoint_cache.rs`, `search_storage.rs` | `materialize_checkpoint`, `materialize_hot_checkpoint`, `evict_fat_checkpoint_to_thin`, `replay_oracle_admit_cached_snapshot`, `replay_checkpoint` |
| Search vocabulary | `crucible-engine/src/model/exploration.rs` | `SearchStrategy`, `SearchBudget`, `FrontierReductionPolicy`, `FrontierReductionReport` |
| Frontier ordering, oracles | `crucible-engine/src/model/runtime/search.rs` | `compare_search_frontier_candidates`, `is_genuine_search_frontier_decision` |
| Reductions | `crucible-engine/src/model/runtime.rs` | `SymmetryReductionClasses`, `PartialOrderReductionPolicy` |
| Guidance and bandit | `crucible-engine/src/model/exploration/guidance.rs`, `guidance_search.rs`, `adaptive_campaign.rs` | `GuidanceSignal`, `GuidanceSignalComposition`, `AdaptiveStrategyConfig` |
| Fuzzing and corpus | `crucible-engine/src/model/family/instances.rs`, `runtime/coverage_guidance.rs` | `ScenarioFamily::{fuzz_coverage_guided, fuzz_coverage_guided_corpus}` |
| App-random branching | `crucible-engine/src/model/app_random_branching.rs` | `TemporalGraph::branch_app_random` |
| Reproduction, minimization | `crucible-engine/src/model/family/instances.rs`, `failure/model.rs`, `reproduction.rs`, `engine.rs` | `ReproductionArtifact`, `FindingReproductionArtifact::minimize`, `MinimizationConfig` |
| Lifecycle and session fork | `crucible-session/src/session/exploration.rs`, `session/engine.rs` | `ExplorationLifecycleDriver`, `fork_child` |

All paths are relative to `crates/crucible/`.

## Determinism rules shared by every feature

- Exploration never weakens the run contract. Any choice that influences state
  is a recorded `Decision` drawn from the seeded decision source; no exploration
  path reads host wall-clock time or a thread RNG.
- Every ordering is a total order over content addresses. Frontier ties break
  by configuration id, clusters and corpus entries live in `BTreeMap`s, and
  seeded scores are BLAKE3 or FNV digests of explicit material.
- Feedback (coverage, rarity, assertion proximity, bandit rewards) is read-only.
  It changes which configurations are expanded and in which order, never what a
  configuration denotes, and never enters configuration, checkpoint, or
  reproduction-artifact identity.
- Scores and weights are integers in micro-units (`GUIDANCE_SCORE_ONE_MICRO` =
  `1_000_000`). Floating-point summation is not associative across hosts, so it
  is banned on ordering paths; `lint_guidance_determinism_source` in
  `model/runtime.rs` is the comment- and string-aware token scan that
  `gate:harness-lint` runs over the guidance, UCB, reward, and frontier-ordering
  sources.

## Lifecycle control for exploration drivers

Search and fuzz drivers pause, resume, and stop branches only through session
commands. `ExplorationLifecycleDriver` owns nothing but an `mpsc::Sender` for the
session actor mailbox and an `Arc<LiveSnapshot>`; it has no handle on the
engine, scheduler, or backend. `pause`, `resume`, and `stop` send
`SessionCommand::{Pause, Continue, Stop}` and poll the live snapshot until the
expected state appears.

| Constant | Value | Meaning |
|----------|-------|---------|
| `EXPLORATION_LIFECYCLE_RESPONSE_BOUND_QUANTA` | `1` | Maximum scheduler quanta between request and acknowledgement |
| `EXPLORATION_LIFECYCLE_MAX_ACTOR_YIELDS` | `128` | Actor yields spent polling before `AcknowledgementTimeout` |

An acknowledgement (`ExplorationLifecycleAcknowledgement`) records the live
state, quantum count, and canonical event-log length before and after the
command, so a caller can prove the command did not append to the canonical
log. A late acknowledgement fails with `AcknowledgementExceededBound` rather
than being accepted. Pause only changes whether the actor steps; scheduler and
RNG state live in the configuration, so pause followed by continue is
bit-identical to an uninterrupted run. See [session.md](session.md) for the
actor and its quantum-boundary command servicing.

## Fork

`TemporalGraph::fork(base, decisions)` realizes `base` through `resume` (which
calls `instantiate`), appends each decision with `try_step`, and records the
branch with `record_thin_checkpoint`. The returned `TemporalGraphFork` carries
the base runtime, the branch `Configuration`, and its thin `Checkpoint`. There
is no fork-specific realization path: the branch is an ordinary DAG node and a
later save or search materializes it through the same replay-oracle-checked
path as any other node. The fork point may be any recorded configuration, not
only the tip. `try_step` also enforces the per-scenario app-random draw cap, so
a fork cannot smuggle in an over-cap schedule.

At the session layer, the session `Engine` (`crucible-session/src/session/engine.rs`)
exposes `fork_child(base, decisions, loop)` and
`fork_child_from_checkpoint(from, loop)`, which call `TemporalGraph::fork` and return a
new paused `SessionActor` with its own mailbox and live snapshot. Both reject a
parent that is loaded or running with `SessionError::InvalidEngineState`; a
running parent must first pause at a quantum boundary. Because the child is a
distinct actor over a distinct configuration, mutating it cannot affect the
parent.

Fork and save never hand a checkpoint to a free-running, wall-clock QEMU
instance. Doing so would abandon determinism for that instance and create a
second execution path. The interactive debugger's mutable branches are a
separate, explicitly non-canonical construct described in
[time-travel-debugging.md](time-travel-debugging.md).

## Save and restore strategies

A configuration can be realized two ways, and the relationship between them is
what makes cached snapshots trustworthy:

```text
  thin replay   : nearest cached ancestor (or baked genesis) + replay the
                  schedule suffix. Depends only on determinism and the recorded
                  schedule; correct by construction. (instantiate_thin_replay)
  exact restore : load the cached fat checkpoint for config.id(). Fast, but it
                  is a cache of reduce() and can be incomplete or corrupt.

  replay oracle : identity(fat checkpoint) == identity(thin replay)
                  mismatch => EngineError::ReplayOracleMismatch
```

The rules the code enforces:

- The thin checkpoint is the source-of-truth DAG node. `materialize_checkpoint`
  records the thin node first, realizes the configuration, builds the fat
  checkpoint, runs `replay_checkpoint` against the thin derivation, and only
  then inserts it into the exact-snapshot cache. `save_checkpoint` and
  `save(store, configuration)` are this operation plus closure persistence, and
  saving the same configuration twice returns the existing checkpoint.
- `instantiate` checks a cached snapshot with `replay_checkpoint` before loading
  it whenever an independent thin path exists. A mismatch is returned as an
  error; `instantiate` never silently switches to replay.
- `replay_oracle_admit_cached_snapshot` validates a cache entry (and its cached
  ancestors) and, when the oracle rejects it, evicts the entry back to its thin
  node with `evict_fat_checkpoint_to_thin` before returning the error. Eviction
  changes neither checkpoint identity nor the denoted configuration.
- `validate_cached_snapshots_with_replay_oracle` admits every cached entry from
  shortest schedule to longest, so a corrupt ancestor is rejected before any
  descendant can be restored from it.
- `TemporalGraph::replay(configuration)` is the on-demand oracle check for a
  stored fat checkpoint and returns a `ReplayOracleCheck` naming the
  configuration, fat checkpoint, and thin checkpoint identities.

A replay-oracle mismatch is localized to the first differing decision by the
bisection helper `localize_replay_oracle_mismatch`
(`crucible-test-support/src/replay_oracle.rs`) rather than repaired. The exact QEMU
snapshot descriptors behind fat checkpoints, and how incomplete captures fail
closed, are described in [execution-graph.md](execution-graph.md).

## State-space search

### Frontier expansion

The schedule space is a tree of decisions made into a DAG by content
addressing: nodes are recorded configurations and edges are decisions.
`TemporalGraph::search(frontier, reduction_policy, materialization_policy,
trigger)` expands one frontier:

1. Realize the frontier with `resume`, the same `instantiate` path used by
   user-facing resume and fork.
2. Read the runtime's `scheduler.search_frontier` choices. Only genuine choices
   branch: `is_genuine_search_frontier_decision` accepts a
   `Decision::Selection` whose `is_campaign_branch()` is set. Delivery orders
   that the scheduler's total order already resolves, raw RNG draws, and
   control-plane decisions are replay material, not branches.
3. `try_step` each choice into a child and pass the children to
   `enumerate_frontier_reduced`, which deduplicates by configuration id and
   applies the reduction policy.
4. Pass each explored child to `materialize_hot_checkpoint`. Hot nodes within
   the `MaterializationPolicy` budget become replay-oracle-checked fat
   checkpoints; cold or over-budget nodes stay thin. Covered children are
   reported in `FrontierReductionReport::covered` and never materialized.

`search_with_replay_oracle_sampling` additionally samples returned fat
checkpoints deterministically (`SearchReplayOracleSamplingReport`) and fails
with `EngineError::SearchReplayOracleMismatch` if a sampled checkpoint differs
from its thin reconstruction.

### Strategies

`search_with_strategy(root, strategy, budget, ...)` repeatedly selects a pending
frontier and calls the single-frontier expansion above. `SearchBudget` caps the
number of frontier expansions; the bounded-depth variants skip candidates whose
depth is not below `max_depth`. The strategy only orders the work-list, so with
a budget that exhausts the frontier every strategy reaches the same graph.

| `SearchStrategy` | Ordering key (smallest expands first) | Tie-break |
|------------------|----------------------------------------|-----------|
| `BreadthFirst` | schedule depth | configuration id |
| `DepthFirst` | reverse schedule depth | configuration id |
| `Priority { seed }` | `search_priority_score`: FNV-1a over `crucible.search.strategy.priority.v1`, the seed bytes, and the depth | configuration id |
| `CoverageGuided` | `(coverage unknown, coverage fingerprint)` from the candidate's checkpoint | configuration id |

`select_strategy_frontier` exposes the same ordering read-only so a concrete
backend driver can keep ownership of runtime realization while matching graph
search exactly. The CLI maps `crucible search --strategy bfs|dfs|guided` to
`BreadthFirst`, `DepthFirst`, and `CoverageGuided`; see [cli.md](cli.md) for the
remaining flags (`--max-depth`, `--max-states`, `--on-violation stop|collect`,
`--findings-out`).

`search_with_strategy_and_failure_oracle` attaches a `SearchFailureOracle`. The
oracle is a read-only reporter: when a reached configuration fails, the search
records a `SearchDiscoveredFailure` holding the configuration id, the failure
fingerprint, and a `FindingReproductionArtifact` captured with discovery path
`StateSpaceSearch`. It never changes which nodes are explored.

Fleet work stealing (`search_with_work_stealing_fleet`) is described in
[distributed-exploration.md](distributed-exploration.md).

### Reductions

Symmetry and partial-order reduction keep the graph tractable. They are sound
graph-level node-deduplication over the content-addressed DAG: they skip
generating a child only when an explored representative provably covers it,
and they never rewrite a child configuration. Crucible contains no model
checker and no specification-language evaluator; when the proof material is
missing, the candidate is explored.

`FrontierReductionPolicy` carries both inputs, and `FrontierReductionPolicy::none()`
explores every candidate:

- **Symmetry.** `SymmetryReductionClasses` maps nodes to caller-supplied
  interchangeable classes (`SymmetryClassId`). `symmetry_reduction_key` returns
  a `SymmetryReductionKey` hashed from a checkpoint's coverage plus node-local
  state under canonical class relabeling. It returns `None` (explore) unless the
  checkpoint has explicit coverage, a loadable materialized state, and an
  unambiguous relabeling. Representatives are searched at graph scope, not only
  among the current candidates.
- **Partial order.** `PartialOrderReductionPolicy` holds explicit
  `PartialOrderIndependenceProof` pairs. `Decision::is_independent_from`
  requires an explicit proof for the unordered pair, known disjoint node sets,
  and no shared ordered decision resource; unknown or global decision kinds are
  dependent. Among proven-independent orderings, the representative is chosen by
  `Decision::reduction_order_key`, which is not part of configuration identity.

A covered child is reported as `FrontierCoveredChild` with the representative's
configuration id, a `FrontierReductionReason` (`Symmetry` or `PartialOrder`),
and a content-addressed reduction key. `search_with_strategy_reduced` schedules
the canonical representative whenever it covers a non-canonical ordering, so
the reduced graph does not depend on which strategy reaches an ordering first.

## Guided and adaptive exploration

### Guidance signals

A guidance signal is a deterministic, read-only scoring function over a
realized frontier candidate. `GuidanceSignal::score` takes a
`GuidanceSignalInput` (coverage fingerprint, rarity count, optional
assertion-proximity distance) and returns a `GuidanceScore { micros: u64 }`.

| `GuidanceSignalKind` | Built-in | Score |
|----------------------|----------|-------|
| `Coverage` | `CoverageGuidanceSignal` | `0` for unknown coverage, else `u64::MAX - low64(fingerprint)` |
| `NoveltyRarity` | `NoveltyRarityGuidanceSignal` | `1_000_000 / (rarity_count + 1)` |
| `AssertionProximity` | `AssertionProximityGuidanceSignal` | `0` if unknown, else `1_000_000 / (distance + 1)` |

`GuidanceSignalComposition::new` sorts its `GuidanceSignalWeight`s by signal
identity so authoring order cannot change accumulation order. `score`
accumulates `score * weight_micros` in `u128` and divides by one million.
`GuidanceSignalComposition::coverage_only()` is the default; when the
composition is exactly coverage-only, `compare_guided_search_frontier_candidates`
uses the `CoverageGuided` ordering key directly, so the default reproduces
`SearchStrategy::CoverageGuided` exactly. Otherwise higher composite scores
expand first, with ties broken by configuration id.

`GuidanceSearchState` deliberately lives outside `TemporalGraph`. It holds
per-configuration `GuidanceObservation`s (coverage fingerprint and minimum
assertion-proximity distance, both derived from the unified event log by
`record_event_log_observation`) and a `GuidanceRarityTable` counting admitted
configurations per coverage fingerprint. Because observations cannot enter
graph, checkpoint, or artifact identity, guidance can reorder expansion without
affecting what any node denotes. `TemporalGraph::search_with_guidance` runs the
shared expansion path with a `GuidanceSearchConfig`. The assertion-proximity
distance metric is owned by the assertion layer; see
[assertions.md](assertions.md).

### Adaptive strategy selection

Adaptive selection is optional and off by default
(`AdaptiveStrategyConfig::disabled` always selects `BreadthFirst`). When
enabled, `TemporalGraph::search_adaptive_campaign` runs a deterministic integer
UCB bandit over a sorted, deduplicated set of `AdaptiveStrategyArm`s
(`BreadthFirst`, `CoverageGuided`, `Priority`), each mapped to the
corresponding `SearchStrategy`:

- Fairness floor: when `breadth_first_floor_interval` is nonzero and the arm set
  contains `BreadthFirst`, every expansion whose sequence is a multiple of the
  interval is forced breadth-first, so the frontier cannot starve.
- Arm selection: an unpulled arm scores `u64::MAX`; otherwise the arm with the
  highest fixed-point UCB score wins, ties broken by a seeded hash of the graph
  fingerprint and then by arm order.
- Rewards: realized nodes are credited in content-address order with new
  coverage, novelty gain (`1_000_000 / rarity`), assertion-proximity progress,
  and a confirmed-failure flag that dominates
  (`ADAPTIVE_CONFIRMED_FAILURE_REWARD` = `1_000_000_000_000`).

The run is campaign-adaptive but run-deterministic. `AdaptiveCampaignConfig::campaign_identity`
hashes the bandit configuration and guidance weights, and
`AdaptiveCampaignRun` records every selection and credit, so repeating the
campaign with the same root, budget, and configuration reproduces the same arm
choices, graph, and failures as a unit. Each discovered failure still carries a
bare scenario-and-schedule reproduction artifact with no reference to the
campaign, signals, or bandit.

## Coverage feedback

Coverage is black-box basic-block coverage collected by the QEMU plugin's
TCG-execution hook, so it needs no guest source, symbols, or in-guest agent.
`BasicBlockCoverageConfig` (`crucible-engine/src/trigger/observability.rs`) is a
registration-time switch: `BasicBlockCoverageMode::Off` produces
`BasicBlockCoverageRegistrationPlan::Disabled` and no engine consumer, while
`On` registers the TCG-exec callback with a power-of-two map of
`DEFAULT_BASIC_BLOCK_COVERAGE_MAP_ENTRIES` (`65_536`) entries. The config is not
part of `World` or `ScenarioDef`, and `affects_execution_fingerprint()` is
`false`: turning coverage on or off cannot change scenario, configuration, or
checkpoint identity, or the execution fingerprint. The plugin side is described
in [qemu-plugin.md](qemu-plugin.md).

Coverage observations are observational event-log entries, excluded from the
determinism comparison (see [event-log.md](event-log.md)). Search and fuzzing
read the coverage projection of the log as their feedback signal, and there is
no parallel coverage record:

- `event_log_coverage_projection` collects coverage entries and hashes the
  sorted set of unique observation materials under
  `crucible.scheduler.event-log.coverage-projection.v1`. Duplicate block hits
  and interleaving do not perturb the fingerprint; an empty projection hashes
  to `ContentHash::default()`, which every consumer treats as unknown coverage.
- `coverage_fingerprint_from_event_log` is the per-checkpoint
  `coverage_fingerprint` used by `CoverageGuided` ordering and symmetry keys.
- `EventLogCoverageFeedback::fingerprint_for` returns the same digest for both
  consumers (`EventLogCoverageFeedbackConsumer::Search` and
  `CoverageGuidedFuzzing`).

Coverage feeds the search and fuzzer as feedback only; recording or reading it
has no effect on `reduce`.

## Coverage-guided fuzzing

### Sampling

Fuzzing samples the parameter space of a `ScenarioFamily` rather than
enumerating decisions. A family never runs directly: every iteration pins one
concrete `PinnedScenario` (and therefore one `ScenarioDef` with a fixed id) and
runs that instance. Fault-plan variation comes from the family's fault-density
axis, which selects a prefix of the family plan's fault-signal bindings.

`ScenarioFamily::fuzz_coverage_guided(config, feedback)` runs
`CoverageGuidedFuzzConfig { meta_seed, iterations }` iterations. For iteration
`sequence`:

1. Read the feedback fingerprint `feedback[sequence % feedback.len()]` (or
   unknown coverage when no feedback was supplied).
2. Choose `sample_index = (low64(H(meta_seed, coverage)) + sequence) % cardinality`
   under `crucible.coverage-guided-fuzz.sample.v1` and pin that family point.
3. Assign energy `1 + low64(H(meta_seed, sequence, coverage)) % 1024`.
4. Append one typed campaign `Decision::Selection`
   (`coverage-guided-fuzz-mutation`, producer hashed under
   `crucible.coverage-guided-fuzz.selection.v1`) to the pinned genesis
   configuration with `try_step`.
5. Mark the iteration `new_coverage` the first time its fingerprint is seen.

`CoverageGuidedFuzzRun::coverage_biased_order` lists candidate configuration ids
in coverage-guided priority. Each `CoverageGuidedFuzzIteration` can emit a
`FindingReproductionArtifact` with discovery path `CoverageGuidedFuzzing`.
Identical `(family, meta_seed, feedback, iterations)` inputs reproduce the same
sampled points, energies, and candidates.

### Durable corpus

`ScenarioFamily::fuzz_coverage_guided_corpus(store, config, corpus_config,
feedback)` runs the same sampler against a content-addressed corpus held in a
`DagStore`:

- The seed entry is family sample `0` with an empty schedule. Every candidate
  is captured as a `ReproductionArtifact` and replayed before admission, so
  every corpus entry, not only a failure, is a self-contained reproduction.
- Admission is coverage-driven. A candidate whose artifact id is already
  retained is `DuplicateArtifact`; one whose coverage fingerprint already has an
  owner is `PrunedSubsumedCoverage`; otherwise it is `AdmittedNewCoverage` and
  stored. `CoverageGuidedCorpus` keeps a coverage-to-owner index for this check.
- Each admitted entry stores two objects: the artifact's compact canonical
  bytes (the store key must equal the artifact id, or
  `ArtifactStoreKeyMismatch` is returned) and a corpus-entry descriptor.
- Parent selection (`coverage_guided_corpus_select_parent`) draws a seeded
  ticket modulo the total energy and walks entries in artifact-id order,
  weighting each by `max(energy, 1)`.
- Energy is `floor + low64(H(seed, sequence, coverage, artifact)) % 1_000_000`,
  where `floor` is `1_000_000` for known coverage and `1` for unknown coverage.

The descriptor format (`coverage_guided_corpus_entry_descriptor_bytes`):

```text
crucible.coverage-guided-corpus.entry.v1
artifact=<hex>
artifact_store=<hex>
scenario=<hex>
schedule=<hex>
replayed_state=<hex>
coverage=<hex>
energy=<u64>
parent=<hex>|none
origin=seed|fuzz-iteration:<sequence>
```

The recorded parent is provenance and drives seeded selection; the candidate
itself is the sampled family instance plus its selection decision.

`CoverageGuidedFuzzThroughputReport` measures throughput in deterministic work
units rather than wall-clock time. `meets_target()` requires at least
`min_generated_mutants` generated mutants
(`DEFAULT_COVERAGE_GUIDED_FUZZ_THROUGHPUT_TARGET` = `25`), one work unit per
mutant, and replay validation of every mutant plus the seed entry; throughput
is never bought by skipping replay validation. Scaling a corpus across hosts is
covered in [distributed-exploration.md](distributed-exploration.md), and the
campaign service's live exploration of typed fault choices is owned by the
campaign crate.

## Preemption branching

`Decision::Preemption` carries a `PreemptionDecision { node, at, kind }` where
`kind` is `PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu }` or
`PreemptionKind::InterruptAt { target_vcpu, irq }`. Varying when the timer
interrupt lands gives single-vCPU guests an interleaving axis too.

`TemporalGraph::branch_preemptions(frontier, config, reduction_policy)` expands
a `PreemptionBranchConfig` (`node`, `deadline`, `horizon`, positive `step`,
switch vCPUs, interrupt target and vector). Each exact tick in
`[deadline, horizon]` at `step` stride yields one switch and one interrupt
alternative. A domain with `step == 0` or more than 2,048 tick slots (4,096
alternatives) is rejected. Each alternative is a campaign-branch
`Decision::Selection` paired with the `Decision::Preemption` it selects, and the
selection retains the bounded producer domain so replay and artifact import can
authenticate the preemption at its recorded parent
(`validate_preemption_branch_schedule`). A preemption whose producer evidence
was stripped is rejected.

Children go through `enumerate_frontier_choices_reduced`, so partial-order
reduction can collapse commuting preemptions on distinct nodes. Every explored
child and each unique representative of a covered child is materialized through
`materialize_checkpoint`, so each branch is a content-addressed, replay-oracle
validated node.

## App-controlled randomness

A guest that opts into app-requested randomness records each request as an
exact `Decision::RngDraw` followed by a model-sample `Decision::Selection`.
`TemporalGraph::branch_app_random(parent, observed, discovery, config)` treats
the served value as a branch dimension:

- `parent` must end with the `RngDraw` paired with the observed selection
  (`MissingParentDraw`, `ParentDrawMismatch` otherwise), and the discovery must
  match the standardized app-random producer contract.
- `AppRandomBranchConfig` holds a seed and an `AppRandomSampleBudget` of at most
  `MAX_APP_RANDOM_SAMPLES_PER_DRAW` (`64`) alternatives. A zero budget records
  no graph mutation.
- Alternatives replace only the observed selection and keep the draw in the
  immutable prefix, so the schedule's draw count and the scenario's draw cap
  are unchanged. Branching is lazy: one caller-chosen site per call, never an
  eager scan of every draw.

A scenario without app-random draws produces no branches and leaves the graph
unchanged. The doorbell transport is described in
[guest-host-channel.md](guest-host-channel.md).

## Reproduction artifacts

Every interesting finding (a property violation, a divergence, a concrete
execution timeout, or a retained corpus entry) is captured as a self-contained
artifact that reproduces it bit-identically by replay alone, regardless of how
the finding was reached (campaign branching, state-space search, or
coverage-guided fuzzing).

The engine form is `ReproductionArtifact` in
`crucible-engine/src/model/family/instances.rs`. It carries only the complete
`ScenarioDefForm` (whose embedded seed is the run seed) and the recorded
`Schedule`; it has no reference to a family, campaign, or host path. Its compact
canonical bytes are:

```text
magic   "crucible.reproduction-artifact.v9\0"
blob    ScenarioDefForm compact binary (must start with
        "crucible.scenario-def-form.v9\0")
blob    Schedule compact binary
```

The artifact id is the BLAKE3 hash of these bytes, so the `DagStore` key for a
stored artifact equals its id. `ReproductionArtifact::capture` replays before
returning, and `replay()` validates retained preemption producer evidence and
then calls `reduce`. Stored checkpoints are never required for correctness.

`FindingReproductionArtifact` wraps the artifact with its
`FindingDiscoveryPath` (`CampaignFork`, `StateSpaceSearch`,
`CoverageGuidedFuzzing`, `RetainedCorpusEntry`), the discovering oracle's
`finding_fingerprint`, the configuration id, and the `ReproductionReplay`
evidence. `capture` rejects a scenario form whose id differs from the
configuration's (`ReproductionScenarioMismatch`) and verifies the replayed
state; `load_from_store` decodes and replays stored bytes. The same
configuration yields the same artifact id whichever path discovered it.

The CLI's portable text form (`crucible.reproduction-artifact.v4`, defined in
`crucible-test-support/src/reproduction.rs` and `crucible-cli`) adds pinned
producer identities and content-addressed component references for transport;
it is documented with the CLI in [cli.md](cli.md) and for operators in
[the artifacts guide](../../users/crucible/artifacts.md).

## Minimization

`FindingReproductionArtifact::minimize(config, failure_fingerprint)` shrinks a
finding's schedule while preserving the same failure. The caller's oracle maps
a candidate to `Option<ContentHash>`; a candidate is accepted only when it
returns the original `finding_fingerprint`.

1. Validate the public value against its embedded artifact and replay evidence
   (`ReproductionArtifactReplayMismatch`, `ReplayTargetMismatch`) and require the
   original to reproduce its own fingerprint.
2. Enumerate candidates with `minimization_candidates`: subsequences of the
   recorded schedule ordered shortest first, then by
   `minimization_candidate_key` (a hash of seed, artifact, kept schedule, and
   removed indices under `crucible.minimization.candidate.v1`), then by removed
   indices. A campaign-branch selection authenticates its complete prefix, so
   any candidate that keeps one must keep every earlier decision; exact branch
   prefixes that drop a trailing suffix are always offered first.
3. Capture each candidate as a self-contained artifact, replay it, then consult
   the oracle. Each attempt is recorded as a `MinimizationAttempt`; the first
   accepted candidate is the result.

Enumeration is bounded by `MAX_MINIMIZATION_CANDIDATES` (`4_096`) and by
`MAX_MINIMIZATION_CANDIDATE_WORK_BYTES` (128 MiB of conservative candidate-copy
work). `MinimizationConfig::automatic_interesting_suffix` restricts removal to a
terminal window of at most `MAX_AUTOMATIC_INTERESTING_WINDOW_DECISIONS` (`64`)
decisions starting at the latest campaign branch in that bound; the earlier
prefix stays authenticated. Because ordering and limits are fixed functions of
the seed and content addresses, repeated runs produce the same minimal artifact.
`MinimizationRun` records the seed, window, target fingerprint, original,
minimized artifact, and every attempt. Triage strengthens the accept predicate
to signature equality; see [failure-triage.md](failure-triage.md).

## The unifying check

`TemporalGraph::validate_unified_operation(evidence)` validates the output of
any advanced operation through one path. `UnifiedGraphOperationEvidence` has one
variant per `UnifiedGraphOperationKind`: `Resume`, `Fork`, `Save`, `Replay`,
`StateSpaceSearch`, `CoverageGuidedFuzzing`, `ReproductionArtifact`, and
`Minimization`. The check:

1. reduces the typed evidence to one configuration and rejects internally
   inconsistent or forged evidence;
2. records the configuration in the graph and realizes it with `instantiate`;
3. compares the runtime state with `reduce(def, schedule)`
   (`ReplayTargetMismatch` on disagreement);
4. materializes a checkpoint and checks it with `replay_checkpoint`.

The resulting `UnifiedGraphOperationReport` names the graph, configuration,
schedule, checkpoint, reduced and runtime states, the single-VM fingerprint
(the runtime state identity), and the `ReplayOracleCheck`. Because every
advanced feature is the same operation on the same graph, this one replay-oracle
plus fingerprint check covers all of them.
