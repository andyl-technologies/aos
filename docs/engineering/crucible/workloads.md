# Workloads and worked examples

Crucible's only first-class participants are QEMU guests and I/O sub-nodes.
This page explains where the load in a scenario comes from (the guest
itself), how workload parameters become part of scenario identity, how
classic load shapes are expressed without a load-generation subsystem, and
which worked example scenarios ship in
`crates/crucible/crucible-engine/src/example_corpus.rs`.

The workload vocabulary lives in
`crates/crucible/crucible-engine/src/model/workload.rs`, its validation in
`crates/crucible/crucible-engine/src/model/validation.rs`, and the builder
helpers on `NodeTemplate` in `crates/crucible/crucible-engine/src/model/family.rs`.
For authoring guidance see [the user examples](../../users/crucible/examples.md)
and [the fault cookbook](../../users/crucible/cookbook.md).

## The workload model

Application traffic is produced inside guests: an HTTP daemon serves, a
client loop requests, a benchmark drives a store. Crucible observes the effects
black-box (frames on links, I/O at sub-nodes, console output, lifecycle state)
and steers the run around them (faults, node start and stop, timers,
properties). It never originates application records itself.

A host-side traffic generator, common in in-process simulators, is deliberately
absent for three reasons:

- **There is nothing in-process to feed.** A Crucible node is a guest VM.
  Injecting synthetic records would need a new host-to-guest data path, which
  either requires guest cooperation or adds a bespoke device, a new
  nondeterminism surface that breaks the unmodified-guest contract.
- **It would reintroduce host nondeterminism.** A generator paced by a host
  clock or fed by host entropy brings host time into the run. Even seeded, its
  timing would depend on when the host loop ran rather than on virtual time.
- **In-guest load is already deterministic.** Load inside the guest is just
  more guest instructions, covered by intra-VM hermeticity and the seeded
  entropy boundary (see [determinism.md](determinism.md)). It needs no new
  machinery.

The model states this as code:

| Item | Value |
| --- | --- |
| `APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST` | `true` |
| `WORKLOAD_ENGINE_ROLE` | `WorkloadEngineRole::ObservationAndSteeringOnly` |
| `WorkloadEngineRole::originates_application_traffic` | `false` |
| `WorkloadEngineRole::permits_host_side_traffic_injector` | `false` |

`checks.crucible.phase4.workloadModel` also scans the engine model, backend,
device, and crate-root sources and fails if a declaration such as
`struct WorkloadGenerator`, `struct HostTrafficInjector`, or
`fn inject_application_traffic` appears. No application-traffic origination
path exists in the engine.

Link-level perturbation (latency, bandwidth, loss, partitions) is the only
layer at which Crucible shapes traffic, and it does so through the fault model
(see [the signal-driven fault guide](../../users/crucible/signal-driven-faults.md)).

## Scenario parameters on the command line

A workload is selected and configured by plain tokens on the guest kernel
command line, `WorldNode::cmdline`. The command line is part of the world's
canonical material, so every workload parameter is part of the scenario's
content address: changing a parameter produces a different `ScenarioDef::id`
and therefore a different, individually reproducible scenario (see
[scenario-model.md](scenario-model.md)). Parameters are never delivered by a
host-side poke after boot.

| Key | Type | Values |
| --- | --- | --- |
| `crucible.workload` (`WORKLOAD_SCENARIO_PARAMETER`) | `GuestWorkloadBinary` | `httpd` (`Httpd`), `httpget` (`ClientLoop`), `bench` (`Benchmark`) |
| `wseed` (`WORKLOAD_SEED_SCENARIO_PARAMETER`) | `GuestWorkloadSeed` | `0x` followed by 64 lowercase hex digits (a 256-bit `Seed`) |
| `load_pattern` | `GuestWorkloadPattern` | `steady`, `spike`, `cardinality_growth`, `correlated_failure` |
| `spike_mode` | `GuestWorkloadSpikeMode` | `virtual_time_rate`, `start_node_burst` |
| `load_time_source` | `GuestWorkloadTimeSource` | `virtual_time` (the only value) |
| `wcfg` | `GuestWorkloadConfigTreeRef` | `<delivery>,export=<blob ref>,mount=<path>` |
| scalar keys | `GuestWorkloadScalarParameter` | see below |

`GuestWorkloadBinary` is a closed set (`GuestWorkloadBinary::SUPPORTED`). The
binary itself is ordinary guest content in the kernel, root image, or initrd;
the parameter only tells the guest program what to run. Each type has a
`selected_cmdline` method that replaces any existing token for its key, so a
command line carries exactly one value per key. The matching
`NodeTemplate` builders are `guest_workload`, `guest_workload_seed`,
`guest_workload_config_tree`, `guest_workload_pattern`,
`guest_workload_spike_mode`, and `guest_workload_time_source`.

### Scalar parameters

`GuestWorkloadParameterKey::SUPPORTED` lists twelve scalar keys:

| Key | Meaning |
| --- | --- |
| `target` | Request target, such as `server:8080`. |
| `rate`, `rate_per_sec` | Request or operation rate. |
| `base_rate_per_sec`, `peak_rate_per_sec`, `burst_rate_per_sec` | Rates for time-varying shapes. |
| `count` | Total request or operation count. |
| `payload_size`, `payload_size_bytes` | Payload size in bytes. |
| `initial_keys`, `key_growth_per_sec`, `key_cap` | Key-cardinality policy. |

`GuestWorkloadScalarParameter::new` rejects an empty value or one containing
whitespace (`EngineError::WorkloadParameterInvalidValue`).

### Structured configuration

Larger configuration, such as a request schedule or a key-distribution table,
is delivered as a content-addressed tree rather than on the command line.
`GuestWorkloadConfigTreeRef` names a `GuestWorkloadConfigTreeDelivery`:

- `readonly_rootfs` (`ReadOnlyRootfs`): the tree is the node's read-only
  `root_image`. `NodeTemplate::guest_workload_config_tree` sets the root image
  to the export, so the config is represented in both the delivery token and
  the world's canonical material.
- `readonly_9p` (`ReadOnlyNineP`): the tree is served by the read-only 9p
  sub-node, whose QIDs are path-hashed and whose directory enumeration is sorted
  (see [io-subnodes.md](io-subnodes.md)).

Both channels are read-only (`GuestWorkloadConfigTreeDelivery::is_read_only`
is always true). The export is a `ContentAddressedBlobRef`, and the mount must
be an absolute, portable guest path: no whitespace or commas, no trailing
slash except `/`, and no empty, `.`, or `..` components.
`World::workload_config_trees` returns the validated `(node, config)` bindings.

The model exports its policy as constants that the parameterization check
forbids flipping: `WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG`,
`WORKLOAD_CONFIG_TREES_ARE_READ_ONLY`,
`WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS`, and
`WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION` are `true`;
`WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED` is `false`.

### Validation

World construction runs the `validate_world_node_workload*` functions on every
VM node and rejects:

| Condition | Error |
| --- | --- |
| Unknown or repeated `crucible.workload` | `WorldNodeUnsupportedWorkload`, `WorldNodeDuplicateWorkload` |
| Malformed or repeated `wseed` | `WorldNodeInvalidWorkloadSeed`, `WorldNodeDuplicateWorkloadSeed` |
| Repeated or invalid scalar parameter | `WorldNodeDuplicateWorkloadParameter`, `WorldNodeInvalidWorkloadParameterValue` |
| Unparsable or repeated `wcfg` | `WorldNodeUnsupportedWorkloadConfigTree`, `WorldNodeDuplicateWorkloadConfigTree` |
| `readonly_rootfs` without a root image, or with a different one | `WorldNodeWorkloadConfigTreeRootfsMissingRootImage`, `WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage` |
| Unknown or repeated `load_pattern` / `spike_mode` / `load_time_source` | `WorldNodeUnsupportedWorkload{Pattern,SpikeMode,TimeSource}`, `WorldNodeDuplicateWorkload{Pattern,SpikeMode,TimeSource}` |
| `spike` without a `spike_mode` | `WorldNodeWorkloadSpikePatternMissingMode` |
| `spike_mode` without the `spike` pattern | `WorldNodeWorkloadSpikeModeWithoutSpikePattern` |
| `spike` or `cardinality_growth` without `load_time_source=virtual_time` | `WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource` |
| `load_time_source` on a pattern that does not vary over time | `WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern` |

## Seeding in-guest randomness

A workload that draws random targets, payloads, or think times is
reproducible without any guest change. The scenario seed reaches the guest
through the `fw_cfg` entry `opt/crucible/seed` and QEMU's seeded RNG device,
host entropy sources are rejected before QEMU starts, and RDRAND/RDSEED are
masked (see [determinism.md](determinism.md)). A guest reading
`/dev/urandom` or seeding a PRNG from the kernel pool therefore draws a pure
function of `(ScenarioDef, Seed, Schedule)`.

The rule is that a workload must not open a new entropy source: no RNG seeded
from host time, no host entropy, no clock read that escapes virtual time.
Randomness must come through the boundary the run already seals. Anything else
is a determinism defect that the run-twice gates surface as a divergence.

A guest that wants a workload seed independent of the scenario `Seed`, so two
scenarios can differ only in load pattern, receives one as plain configuration:
`GuestWorkloadSeed` renders `wseed=0x...` on the command line. Because the
command line is world material, changing the workload seed changes scenario
identity without touching the global seed. `WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES`
is `true` and `WORKLOAD_SEED_REQUIRES_WHITE_BOX` is `false`: the white-box
path is never required for this delivery mode.

## Load patterns

The classic load shapes are properties of the guest program plus scenario
parameters, expressed with existing plan primitives:

```text
  classic pattern        Crucible mechanism (no host-side generator)
  ---------------------  ------------------------------------------------------
  steady                 in-guest loop at a configured rate (rate_per_sec=...)
  spike                  virtual_time_rate: the guest's rate is a function of
                           virtual time (base/peak rates, spike window)
                         start_node_burst: StartNode a baked load-node at a
                           chosen virtual time; the burst is a lifecycle event
  cardinality growth     in-guest key policy (initial_keys, key_growth_per_sec,
                           key_cap) on the guest's virtual-time clock;
                           Crucible observes the I/O and network effects
  correlated failure     a fault plan that perturbs several nodes together over
                           a virtual-time window; the system's failures are a
                           consequence of real perturbation, not stamped records
```

Time-varying shapes must derive their variation from virtual time, the guest's
icount-derived clock or an event scheduled in virtual time, never from host
wall-clock. `GuestWorkloadTimeSource` has a single variant, `VirtualTime`;
`WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME` is `true` and
`WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED` is `false`. The
virtual-time-shapes check also forbids `Instant::now` and `SystemTime::now`
in the engine model. `WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES` is
`true`: no load pattern needs the white-box channel.

### Fixtures

`GuestWorkloadLoadPatternFixture` provides one small, fully validated world and
plan per shape. `scenario_def(seed)` wraps it with empty properties.

| Constructor | World | Plan |
| --- | --- | --- |
| `steady` | `client`: `rate_per_sec=100 load_pattern=steady` | empty |
| `spike_virtual_time_rate` | `client`: `base_rate_per_sec=10 peak_rate_per_sec=500 spike_at_ticks=50 spike_duration_ticks=10`, `spike_mode=virtual_time_rate`, `load_time_source=virtual_time` | empty |
| `spike_start_node_burst` | `client-steady` (`base_rate_per_sec=10`) and `client-burst` (`burst_rate_per_sec=500`), both `spike_mode=start_node_burst` | event graph: `start-burst-at-vt` fires once at virtual time 50 and runs `Action::start_node(client-burst)` |
| `cardinality_growth` | `client`: `initial_keys=8 key_growth_per_sec=4 key_cap=1024`, `load_time_source=virtual_time` | empty |
| `correlated_failure_campaign` | linked `client-a` and `client-b` at `rate_per_sec=50` | a fault-signal plan: one event signal at virtual time 50 drives an impulse binding per node that crashes it with 1 s downtime and immediate reboot |

The correlated-failure fixture uses the signal-driven fault model; that model
is described in the [signal-driven fault guide](../../users/crucible/signal-driven-faults.md).
`crates/crucible/crucible-engine/tests/workload_load_patterns.rs` checks that
independent fixture construction yields byte-identical world, plan,
compact-binary, and canonical-TOML material and the same `ScenarioDef::id`.

## Worked example corpus

`crates/crucible/crucible-engine/src/example_corpus.rs` ships the worked
examples as regular content-addressed scenarios. The developer-facing examples
and the determinism fixtures are therefore the same artifacts: an example that
stops reproducing fails a check instead of going stale.

| Item | Value |
| --- | --- |
| `BUILT_IN_EXAMPLE_CORPUS_VERSION` | `crucible.example-corpus.v2` |
| `built_in_example_corpus()` | happy path, partition recovery, crash and restart |
| `HAPPY_PATH_SCENARIO_NAME` | `happy-path.scn` |
| `PARTITION_RECOVERY_SCENARIO_NAME` | `partition-recovery.scn` |
| `CRASH_RESTART_SCENARIO_NAME` | `crash-restart.scn` |
| `FAULT_CAMPAIGN_FAMILY_NAME` | `fault-campaign.fam` |

Each `ExampleScenarioFixture` carries a `ScenarioDefForm`, the flags
`zero_guest_components` and `requires_white_box`, the black-box observations
for a double-backed run, and replay steps. Application semantics use
structured guest assertions; host facts (lifecycle, faults, timers,
quiescence) are evaluated host-side (see [assertions.md](assertions.md)). The
corpus as a whole sets `EXAMPLE_CORPUS_REQUIRES_GUEST_COMPONENTS` and
`EXAMPLE_CORPUS_WHITE_BOX_REQUIRED` to `true` because the store examples use
guest assertions. The happy path alone runs with zero guest-side components.

Durations below are in ticks; one tick is one picosecond (see
[virtual-time.md](virtual-time.md)).

### Happy path (`happy-path.scn`)

Two x86_64 nodes with 256 MiB each, white-box disabled, joined by one link
(latency 5,000,000 ticks, jitter 1,000,000, no loss); seed 42:

- `server`: `crucible.workload=httpd`, `port=8080`; ready at the console
  marker `listening on 0.0.0.0:8080`.
- `client`: `crucible.workload=httpget target=server:8080 count=100`; ready at
  `client ready`.

Properties: `no-crashes` (`Always` neither node is `Crashed`) and
`all-requests-succeed`. The latter is `Eventually`, triggered by the client's
`CLIENT_STARTED` console line, requiring the console line
`CLIENT_RESULT requests=100 successful=100 failed=0` and the client reaching
`Exited` within 60,000,000,000 ticks. The plan fires `Action::pass()` once
`all-requests-succeed` is satisfied and the world is quiescent.

This example needs no in-guest agent, marker emission, image change, or
kernel patch. Success is judged from the application's own console output.
The same reasoning holds for encrypted protocols: wire observations can
diagnose connectivity, but only the application's own result proves the client
accepted a response.

### Partition recovery (`partition-recovery.scn`)

Three replicas `db-0`, `db-1`, `db-2` (512 MiB, white-box enabled,
`store.role=replica cluster=crucible-a2`) in a triangle of the same link
shape; seed 99. Properties are guest assertions `no-split-brain`
(unreachable) and `replicas-reconciled` (sometimes), plus
`converges-after-heal`: once `db-0` has started, `replicas-reconciled` must be
satisfied within 30,000,000,000 ticks.

The plan's `wait-ready` event waits for all three `ready to accept
connections` console lines and a coverage point in `db-0`, then arms a heal
timer of 10,000,000,000 ticks. The `heal` event logs the end of the recovery
interval, and `pass-on-converge` passes once replicas reconcile and the world
is quiescent. The fixture does not bind a network fault; its replay steps
supply the recovery observations.

### Crash and restart (`crash-restart.scn`)

The same three-replica world (`cluster=crucible-a3`); seed 7. The plan:

1. `crash-after-commit`: when `db-1` has started and has performed one block
   write, observed black-box as an `IoPattern`, stop `db-1`. The write proves
   the replica was committing before it is killed.
2. `restart`: 5,000,000,000 ticks after `crash-after-commit`, start `db-1`.
3. `pass-on-reconverge`: after `db-1` restarts and the guest assertions
   `committed-write-survived` and `replicas-reconciled` are satisfied, pass at
   quiescence.

Properties add `data-not-lost` (unreachable) and `reconverges`, which must
hold within 40,000,000,000 ticks of `db-1` reaching `Crashed`.

### Fault campaign (`fault-campaign.fam`)

`fault_campaign_family` is a `ScenarioFamily` over eight generated seeds, 3 to
5 nodes, and ring or mesh topologies. Its template node is white-box enabled with a
fixed-icount ready point at 100 retired instructions, and the family carries
the shared `no-split-brain` guest assertion.
`run_fault_campaign_example` drives the full reproduce-then-explore loop in
process:

1. Coverage-guided fuzzing (`fuzz_coverage_guided`) over the family with
   deterministic event-log coverage feedback (default
   `CoverageGuidedFuzzConfig::new(Seed::from_u64(0x33a4_f00d), 4)`).
2. A planted no-split-brain violation on the first iteration with new
   coverage, evaluated by the host assertion evaluator.
3. A reduced `FindingReproductionArtifact`, replayed to confirm it reproduces
   the same violation.
4. Save of the pre-failure configuration to a `MemoryDagStore`, resume from
   that checkpoint, and fork with an alternate decision.

Every step is checked with `TemporalGraph::validate_unified_operation`, and the
outcome is a `FaultCampaignExampleReport` (see
[exploration.md](exploration.md) and [execution-graph.md](execution-graph.md)).

### Running and verifying the corpus

`run_example_scenario` reduces a fixture through the double-backed path,
captures a `ReproductionArtifact`, replays it, and fails with `ReplayDiverged`
unless the canonical event log, fingerprint stream, assertion report, event
firings, and topology-change applications all match.
`verify_example_scenario_runs` repeats that `runs` times and requires
byte-identical logs, fingerprint streams, assertion reports, replay results,
and scenario ids across runs (`VerifyRunsZero` for zero runs, `VerifyDiverged`
otherwise). The `verify_*_default_runs` helpers use five runs.

The CLI exposes the corpus in two ways:

- `builtin:<name>` scenario references resolve through
  `resolve_builtin_example_scenario` in
  `crates/crucible/crucible-cli/src/cli/planning/verify_seed_render.rs` to
  `RunScenarioRef::BuiltInExample`.
- `crucible selftest`, in builds with the test-only backend, verifies the
  built-in corpus (or a corpus manifest given with `--corpus`) with
  `DEFAULT_SELFTEST_RUNS = 5`. The installed CLI omits this path.

`crucible verify --runs N --adversarial` multiplies each run across the
hostile host profiles in `VERIFY_HOSTILE_PROFILES` (`loaded-single-core`,
`reordered-two-core`, `loaded-many-core`, plus the baseline). Each profile
varies executor workers, logical cores, priority pressure, wall-clock skew and
backsteps, I/O stalls, and poll order. `--bisect` runs divergence-bisection on
a mismatch (see [testing-and-gates.md](testing-and-gates.md)).
`checks.crucible.phase7.adversarialExampleVerify` exercises this over the
built-in corpus, including the fault-campaign family.

## Checks

| Check | Covers |
| --- | --- |
| `checks.crucible.phase4.workloadModel` | `GuestWorkloadBinary`, the engine role constants, and the forbidden origination APIs. |
| `checks.crucible.phase4.workloadSeed` | `GuestWorkloadSeed`, the `wseed` parameter, and the black-box-only delivery constants. |
| `checks.crucible.phase4.workloadLoadPatterns` | Pattern and spike-mode vocabularies, the fixtures, and `cargo test -p crucible-engine --test workload_load_patterns`. |
| `checks.crucible.phase4.workloadVirtualTimeShapes` | The time-source vocabulary, consistency validation, and the ban on wall-clock APIs. |
| `checks.crucible.phase4.workloadParameterization` | Scalar keys, config trees, read-only delivery, and identity changes for parameter changes. |
| `checks.crucible.phase1.guestEntropyLaunch` | An RNG-backed guest workload reproduces from the scenario-derived `fw_cfg` seed and the seeded `rng-builtin`/`virtio-rng` device; enabled RDRAND/RDSEED and host entropy sources are rejected. |
| `checks.crucible.phase7.adversarialExampleVerify` | Adversarial verify and bisection over the built-in corpus. |
