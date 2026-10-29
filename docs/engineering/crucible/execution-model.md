# Execution model

The execution model is the small algebra the rest of Crucible implements: one
state type, one function that extends it, one function that realizes it, and
one function that produces the root it realizes from. Start, resume, fork,
replay, save, and search are all expressed in these terms, so they share one
code path and one correctness check.

The model lives in `crates/crucible/crucible-engine/src/model/`. The live,
controllable driver around it lives in `crates/crucible/crucible-session/`.

```text
  ScenarioDef                 immutable definition     (scenario-model.md)
  Decision                    one resolved choice
  Schedule = [Decision]       totally ordered decisions
  Configuration = (ScenarioDef, Schedule)    the only identity-bearing state

  try_step:    &Configuration x Decision   -> Result<Configuration>
  reduce:      &ScenarioDef x &Schedule    -> Result<State>
  instantiate: &TemporalGraph x &Configuration -> Result<RuntimeState>
  bake:        &World                      -> Result<GenesisCheckpoint>
```

`reduce` is the meaning of a configuration; `instantiate` realizes that meaning
as a runtime backed by the temporal-graph cache. The replay oracle ties them
together: realizing one configuration two different ways must produce the same
state.

## `Configuration`: the only state type

```rust
pub struct Configuration {
    pub def: ScenarioDef,
    pub schedule: Schedule,
}
```

`Configuration` is defined in `model/configuration.rs`. Its identity is a pure
function of the scenario and the schedule:

- `Configuration::id()` (an alias of `content_hash()`) hashes the domain tag
  `crucible.configuration.v2`, the `ScenarioDef` id, the seed, and every
  decision of the schedule in order (`configuration_hash` in
  `model/canonical.rs`).
- `Configuration::genesis(def)` is `(def, [])`. Genesis is not a special
  object; it is the configuration with the empty schedule, and
  `is_genesis()` tests exactly that.
- Constructing, cloning, and hashing a configuration never boots a VM,
  allocates guest memory, or touches the temporal graph.

The materialized QEMU runtime, device overlays, and scheduler queues are a
cache of `reduce(def, schedule)`. They never contribute to identity, so a
configuration can be stored as a thin parent edge plus schedule delta and
reconstructed on demand, and "the cache must agree with recomputation" is a
checkable statement.

Scheduler state and every decision-stream position are functions of
`(def, schedule)`. Stopping at decision `t`, persisting the configuration, and
continuing later therefore cannot diverge from never stopping: there is no
live-only state to lose. The reduction is also prefix-closed. `State(t)`
depends only on `Schedule[0..t]`, so every prefix of a recorded schedule is a
valid configuration and a valid fork point.

## `Decision` and `Schedule`: recorded nondeterminism

Intra-VM execution between scheduling points is deterministic at the source,
so the only nondeterminism left is cross-node ordering, probabilistic choice,
and explicit exploration choices. Each resolved choice is a `Decision`; the
`Schedule` is the totally ordered list of decisions in the order the scheduler
resolved them.

| Variant | Payload | Records |
| --- | --- | --- |
| `Decision::DeliveryOrder` | `DeliveryOrderDecision { at, order: Vec<EventKey> }` | The order of events resolved at one virtual time |
| `Decision::RngDraw` | `RngDecision { stream: RngStreamId, value }` | One raw `u64` draw from a named seeded stream |
| `Decision::Override` | `OverrideDecision { point: SchedulingPoint, choice: ChoiceTag }` | A search or fuzzing override at a scheduling point |
| `Decision::Preemption` | `PreemptionDecision { node, at: SimInstant, kind }` | A vCPU switch or interrupt at an exact tick |
| `Decision::Selection` | `SelectionDecision` | A typed campaign selection whose producer evidence is validated on replay |

`PreemptionKind` is `VcpuSwitch { from_vcpu, to_vcpu }` or
`InterruptAt { target_vcpu, irq }`. An `InterruptAt` on a single-vCPU node
varies when the periodic timer or an external interrupt preempts that vCPU.

The canonical hash writes a fixed variant tag before each payload
(`DeliveryOrder` 0, `RngDraw` 1, `Override` 2, `Preemption` 3, `Selection` 5)
so payloads of different variants never collide. `EventKey` carries the full
ordering key `(virtual_time, consumer, producer, sequence)`.

`Schedule` (in `model/configuration.rs`) is append-only and value-like:

| Method | Behavior |
| --- | --- |
| `Schedule::empty()`, `from_decisions` | Build a schedule in recorded order |
| `prefix(len)`, `suffix_from(len)` | Split at a decision index; `ScheduleError::PrefixTooLong` past the end |
| `appended(decision)` | Return a new schedule; never mutates |
| `content_hash()` | Domain `crucible.schedule.v2` |
| `to_compact_binary()` / `from_compact_binary()` | Magic `crucible.schedule.v4\0` |

### What is recorded and what is recomputed

Only information that cannot be recomputed from the definition and the
preceding schedule must be stored. The code applies that rule per decision
source:

- **Seeded draws.** `DecisionRecorder::draw_u64` (in
  `crates/crucible/crucible-engine/src/decision.rs`) forks a stream from the
  scenario `Seed`, draws, and appends `Decision::RngDraw`. A
  `Decision::RngDraw` records its `RngStreamId` (a domain plus a name), and
  streams are forked by name-hash in per-entity domains, so adding, removing,
  or renaming an unrelated node never perturbs another stream's draws. A new
  recorder hydrates stream positions from the existing schedule, so a resumed
  run never repeats a draw.
- **Default preemptions.** `DecisionRecorder::default_rr_preemption` derives
  the round-robin vCPU switch at a nonzero multiple of `rr_switch_quantum` from
  the node, the icount, the quantum, and the vCPU count. It returns a
  `PreemptionDecision` without appending it: default preemptions are
  deterministic engine behavior, not search decisions.
- **Explorer preemptions.** A non-default preemption is recorded as a
  `Decision::Selection` immediately followed by the `Decision::Preemption` it
  selects. `preemption_branch_choices` generates the bounded domain (at most
  4096 alternatives) at an exact parent, and `validate_preemption_branch_schedule`
  regenerates it at every recorded parent during `instantiate`, replay, and
  reproduction. Missing or non-reproducing producer evidence is an error.
- **App-requested randomness.** A guest that opted into the white-box channel
  can request random values. The plugin reports each served value as
  `BackendRngEvidence { node, stream, request_id, width, value }`.
  `DecisionRecorder::admit_backend_rng_evidence` re-derives the raw draw from
  the named seeded stream, requires the served value to match the modeled
  sample, and appends a `Decision::RngDraw` followed by a
  `Decision::Selection`. Replay serves the recorded value; it never re-rolls.

The scenario's `app_random_draw_cap` bounds app-random decisions per run.
`try_step` and `reduce` both count them and fail with
`EngineError::AppRandomDrawCapExceeded` past the cap. The default cap,
`DEFAULT_APP_RANDOM_DRAW_CAP`, is `u64::MAX`.

## `try_step`: constructing identity

```rust
pub fn try_step(config: &Configuration, decision: Decision)
    -> Result<Configuration, EngineError>;
```

`try_step` (in `model/runtime.rs`) returns `(config.def, config.schedule ++
[decision])` after checking the app-random cap. It executes nothing, boots
nothing, and touches no cache. It is the temporal-graph edge constructor, which
is why the graph can be built, hashed, deduplicated, and traversed without
running a guest.

## `reduce`: the pure meaning

```rust
pub fn reduce(def: &ScenarioDef, schedule: &Schedule)
    -> Result<State, EngineError>;
```

At the model level, `reduce` returns `State { id }`, where `id` hashes the
domain `crucible.reduce.state.v2`, the scenario id, the seed, and the schedule.
Every model `RuntimeState` produced by `instantiate` carries
`id == reduce(def, schedule).id`, and `ReproductionArtifact::replay` uses
`reduce` directly. The concrete guest state is produced by the backend that
realizes the configuration; its equality across realization paths is what the
replay oracle checks.

`reduce` is a pure function of its arguments. No wall clock, host scheduling
order, or host entropy may influence it; any residual nondeterminism must be
eliminated or routed through the seeded decision source.

## `instantiate`: one recursive function

```rust
pub fn instantiate(graph: &TemporalGraph, config: &Configuration)
    -> Result<RuntimeState, EngineError>;
```

`instantiate` (in `model/runtime.rs`) is the only function that turns a
configuration into a `RuntimeState`. It first runs
`validate_preemption_branch_schedule`, then recurses:

```text
instantiate(graph, config):
    if config is genesis:
        load the baked genesis checkpoint for config.def
        (EngineError::MissingBakedGenesis if absent)
    elif graph has an exact cached snapshot of config.id():
        if an independent replay path exists:
            graph.replay_checkpoint(config, snapshot)   # replay oracle
        load the snapshot
    elif graph.nearest_cached_ancestor(config) = ancestor:
        rt = instantiate(graph, ancestor)
        replay_suffix(rt, ancestor, config.schedule[ancestor.len..], config)
    else:
        rt = instantiate(graph, genesis(config.def))
        replay_suffix(rt, genesis, config.schedule, config)
```

- `nearest_cached_ancestor` scans prefixes from longest to shortest and never
  returns the configuration itself.
- `replay_suffix` requires the starting runtime to name the starting
  configuration, steps every suffix decision with `try_step`, and fails with
  `EngineError::ReplayTargetMismatch` if the result is not the requested
  configuration.
- The recursion terminates at the baked genesis checkpoint. Cold boot is not a
  branch of `instantiate`; it happens only while baking.

The branch taken is a performance decision and must not be observable in the
result: every branch yields a content-equal `RuntimeState` for the same
configuration.

`RuntimeState` carries the runtime id, the configuration id, per-node
`NodeBlobRef`s and icounts, the reconstructed `SchedulerState`, and the
`EventLogOffset` from which a resumed run continues appending.

### Start, resume, and fork are the same call

```text
  start  = instantiate((def, []))              genesis
  resume = instantiate((def, schedule))        the tip
  fork   = instantiate((def, schedule[0..k]))  a non-tip prefix,
           then try_step with different decisions
```

`TemporalGraph::resume` records the configuration's thin checkpoint closure and
then calls `instantiate`. `TemporalGraph::fork` resumes the base, applies the
new decisions with `try_step`, and records the branch as a thin checkpoint.
There is no separate boot, restore, or fork realization path, so "it resumes
correctly" and "it forks correctly" are the same property, tested once.

## `bake`: genesis as a checkpoint

Booting a guest (firmware, kernel, init, userspace reaching steady state) is
the slowest and least interesting phase of a run, and the one most exposed to
nondeterminism. Crucible runs it once, to a declared ready point, and turns the
result into the genesis checkpoint. After that, even the first run of a
scenario is a restore.

```rust
pub fn bake(world: &World) -> Result<GenesisCheckpoint, EngineError>;
```

The model `bake` (in `model/runtime.rs`):

1. Calls `World::validate_ready_point_policies`, which runs the full world
   topology validation.
2. Builds `Configuration::genesis(world.scenario_def())`.
3. Records a `CheckpointKind::Fat` checkpoint with
   `Checkpoint::from_recorded_configuration`, using
   - per-node baked blobs: `NodeBlobRef::Baked(hash)` where the hash covers the
     world identity and the node's canonical material (domain
     `crucible.model.node-baked-blob.v1`), and
   - per-node icounts: the target count for `ReadyPoint::FixedIcount`, zero for
     the other policies.

A genesis checkpoint is registered per scenario with
`TemporalGraph::with_baked_genesis` or `cache_baked_genesis`, which require a
fat checkpoint whose id is exactly `Configuration::genesis(def).id()`. Because
the scenario id covers the Plan, Properties, and Seed, each scenario has its own
genesis node; the per-node baked blob references depend only on the World, so
scenarios over the same World name the same baked VM blobs.

Production baking is done by `crucible-daemon`: a guarded fresh lifecycle boots
each World VM to its ready boundary and captures an authenticated snapshot set
(`ProductionBakedGenesisCheckpoint` in
`crates/crucible/crucible-daemon/src/qemu_baked_genesis.rs`). The production
baked-genesis catalog is keyed by World plus scenario. The QEMU side of bake is
the only place a guest is cold-booted.

### The ready point

The ready point decides where `t = 0` sits; it does not affect determinism
after `t = 0`. Each VM node declares one `ReadyPoint`:

| Policy | Snapshot when | Trade-off |
| --- | --- | --- |
| `FixedIcount { icount }` | The node has retired exactly `icount` instructions | Simplest and black-box; brittle when the image changes |
| `NetworkIdle { window }` | The first network-idle span of `window` | Black-box and robust to small image changes; needs incident links |
| `ConsoleMarker { marker }` | `marker` appears on the guest console | Black-box; depends on stable boot output |
| `AgentSignal` | An in-guest agent signals ready | Highest fidelity; requires `WhiteBoxPolicy::Enabled` |

Validation rules for these policies are listed in
[scenario-model.md](scenario-model.md#validation).

## Homogeneous VM state references

A VM's state in any checkpoint is a `NodeBlobRef`:

```rust
pub enum NodeBlobRef {
    Baked(ContentHash),
    CowDelta { parent: ContentHash, delta: ContentHash, resolved: ContentHash },
}
```

Genesis references the baked blob; later checkpoints reference a
copy-on-write delta over a parent blob. `NodeBlobRef::content_hash()` returns
the resolved state hash for both shapes, so no code path distinguishes an
"initial" VM state from a "materialized" one, and the replay oracle compares
the two realizations by hash. `cow_delta_ref()` exposes the delta as a
`CowDeltaKind::VmMemory` object for storage accounting.

## The replay oracle

The fat-checkpoint cache is validated structurally, not by convention. For any
configuration, materializing its stored fat checkpoint must equal re-deriving
it thin from an ancestor or genesis:

```text
  load(fat checkpoint of config)  ==  replay(instantiate(ancestor), suffix)
```

`TemporalGraph::replay_checkpoint` (in
`model/temporal_graph/search_storage.rs`) implements the check. It rebuilds the
configuration through `instantiate_thin_replay`, which never uses the target's
own snapshot, and compares the checkpoint id, per-node blob references,
per-node icounts, event-log offset, and `MaterializedState` id. Any difference
is `EngineError::ReplayOracleMismatch`; a fat checkpoint without state is
`EngineError::CheckpointMaterializedStateIncomplete`.

The oracle runs at every point where a fat cache would be trusted:

- `instantiate` checks an exact cached snapshot before loading it whenever an
  independent replay path exists.
- `replay_oracle_admit_cached_snapshot` admits cached ancestors from genesis
  outward before checking the target, so a corrupt ancestor cannot make a
  matching corrupt descendant look valid. A rejected entry is evicted back to
  its thin checkpoint and the error is returned.
- `validate_cached_snapshots_with_replay_oracle` admits every cached snapshot
  in order of schedule length.
- `TemporalGraph::replay` is the on-demand form.

Because save, resume, and fork are all `instantiate`, this one equality
validates all of them plus snapshot completeness: a fat checkpoint that omits
state fails the oracle instead of producing a wrong resume.

A mismatch is never repaired. The graph has no path that reconciles a fat/thin
disagreement by overwriting one with the other, and a failed exact
realization never falls back to replay automatically; replay is a separate,
explicitly requested operation. During active search, the strict sampled
replay-oracle path in
`crates/crucible/crucible-test-support/src/replay_oracle.rs` calls
`localize_replay_oracle_mismatch`, which bisects the fat and thin fingerprint
streams to the first differing schedule decision and exact icount. Sampling is
deterministic (`SearchReplayOracleSamplingConfig`). See
[failure-triage.md](failure-triage.md).

## Operations as model expressions

| Operation | Model expression | Entry point |
| --- | --- | --- |
| start | `instantiate(genesis(def))` | `TemporalGraph::resume` on genesis |
| resume | `instantiate((def, schedule))` at the tip | `TemporalGraph::resume` |
| fork | `instantiate` of a prefix, then `try_step` with different decisions | `TemporalGraph::fork` |
| replay | thin re-derivation compared with a stored fat checkpoint | `TemporalGraph::replay` |
| save | materialize a fat checkpoint keyed by `Configuration::id()` | `TemporalGraph::save_checkpoint`, `TemporalGraph::save` |
| search | enumerate decisions at a frontier, `try_step` each, dedupe by id | `TemporalGraph::enumerate_frontier`, `TemporalGraph::search` |

A configuration reached by two decision paths that denote the same
`(def, schedule)` is one graph node, so search deduplicates instead of
re-materializing. `TemporalGraph::validate_unified_operation` checks any
operation's output through the same path: record the closure, `instantiate`,
compare with `reduce`, materialize, and run the replay oracle. The graph-side
detail is in [execution-graph.md](execution-graph.md).

## Production realization routes

The model `instantiate` defines the semantics. Production QEMU realization in
`crucible-daemon` uses operation-specific lifecycle routes that implement the
same three cases with authenticated inputs:

- **Fresh execution** owns its baked ready boundary and captures genesis.
- **Exact resume** consumes one atomic restore request for an authenticated
  exact-checkpoint closure (`PRODUCTION_EXACT_CLOSURE_SCHEMA_VERSION` 9, at
  most `MAX_EXACT_CHECKPOINT_RAM_LAYERS` RAM layers, see
  `crates/crucible/crucible-engine/src/exact_checkpoint.rs`).
- **Baked replay** consumes a replay-only admission from the baked-genesis
  catalog and replays the schedule.

Exact restore authenticates the complete closure (root, target manifest,
snapshot, artifacts, and ordered RAM chain) before launch and fails if any part
is missing or does not authenticate. It never silently changes realization
mechanism. See [qemu-integration.md](qemu-integration.md).

## The host-side driver

The pure model is driven by an explicit state machine in `crucible-session`.
`Engine` (in `crates/crucible/crucible-session/src/session/engine.rs`) owns the
source-of-truth `Configuration`, an optional `RuntimeState` cache, the
`TemporalGraph`, and the single `QuantumLoop`. Its run state is the closed
`EngineState` set: `Loaded`, `Running`, `Paused { reason }`, and
`Stopped { outcome }`.

- `Engine::instantiate_runtime` realizes the configuration through
  `TemporalGraph::resume` and moves `Loaded` to `Paused`.
- `Engine::step_quantum` drives exactly one scheduler quantum.
- `SessionActor` services pending mailbox commands before stepping while
  `Running`, steps one quantum, publishes its `LiveSnapshot`, and calls
  `tokio::task::yield_now().await`. While `Loaded` or `Paused` it does not step;
  it waits on the mailbox (and polls debugger run control). Control therefore
  takes effect only at quantum boundaries.
- `LiveSnapshot` mirrors state kind, virtual time, event-log length, and quanta
  counters in atomics, so observers never take the engine lock.

The runtime is a rebuildable cache. `Engine::evict_runtime_cache` drops it
without changing the boundary snapshot, configuration, frontier, event-log
length, or quantum count; `reinstantiate_runtime_cache` rebuilds it from the
configuration and graph; `refresh_runtime_cache` rebuilds before replacing, so
a failed rebuild leaves the old runtime in place. This is what makes
pause, fork, and resume safe and lets memory pressure evict warm runtimes. The
actor and control surface are described in [session.md](session.md).

## Verification

Instantiating the same configuration twice, by any combination of branches,
must produce identical fingerprints. Because start, resume, fork, and snapshot
completeness are the same operation, that one comparison covers all four.

| Check | Covers |
| --- | --- |
| `checks.crucible.phase1.executionModelCore` | Core type spine and identities |
| `checks.crucible.phase1.executionDecisionTaxonomy` | Closed `Decision` set |
| `checks.crucible.phase1.decisionRecording` | Seeded recorder, name-hash stream forks, schedule hydration |
| `checks.crucible.phase1.executionStepPurity` | `try_step` performs no realization |
| `checks.crucible.phase1.executionResumeFingerprint` | Resume equals an uninterrupted run |
| `checks.crucible.phase1.executionInstantiate` | Exact, ancestor-replay, and baked-genesis branches |
| `checks.crucible.phase1.executionLifecycleRoutes` | Production exact-resume and baked-replay routes |
| `checks.crucible.phase1.executionBake` | Model bake and baked catalog basis |
| `checks.crucible.phase1.executionReadyPoint` | Ready-point policies and white-box opt-in |
| `checks.crucible.phase1.executionNodeBlobRef` | Baked and CoW blob references |
| `checks.crucible.phase1.executionGraphOperations` | Save, replay, and frontier enumeration |
| `checks.crucible.phase1.executionEngineStateMachine` | `Engine` run states and actor loop |
| `checks.crucible.phase1.executionLiveSnapshot` | Lock-free live mirror |
| `checks.crucible.phase1.executionCacheEviction` | Runtime cache eviction safety |
| `checks.crucible.phase1.gates.replayOracle` | Fat/thin equality, model and QEMU |
| `checks.crucible.phase1.gates.divergenceBisect` | First-difference localization |

See [testing-and-gates.md](testing-and-gates.md) for how gates are run.
