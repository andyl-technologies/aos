# Scenario model

A scenario is the immutable, content-addressed definition of a run: which
machines exist and how they are wired, what happens to them, what must be true,
and how every residual choice is resolved. It is the spatial half of the
execution model: the genesis configuration of a run is exactly
`Configuration::genesis(def)`, and every later state is a reduction of this
definition under a schedule (see [execution-model.md](execution-model.md)).

The code lives in `crates/crucible/crucible-engine/src/model/`. The operator
view of the same format is in
[../../users/crucible/scenarios.md](../../users/crucible/scenarios.md) and
[../../users/crucible/topology.md](../../users/crucible/topology.md).

## A value, not a program

A scenario contains no live handles, wall-clock values, mutable state, or
host-varying paths. Images and kernels are referenced only by content hash.
Two scenarios with equal content are the same scenario on every host, and a
change produces a new scenario with a new identity.

The model has two representations:

| Type | Defined in | Role |
| --- | --- | --- |
| `ScenarioDef` | `model/scenario/definition.rs` | The identity-bearing execution handle: the scenario id, the `Seed`, and the app-random draw cap. Fields are private; the id covers the seed and cap, so equal ids mean equal handles. |
| `ScenarioDefForm` | `model/configuration.rs` | The materialized form for storage, exchange, and reproduction. It holds the validated components and rebuilds the `ScenarioDef` with `scenario_def()`. |

`ScenarioDefForm` is the materialized `(World, Plan, Properties, Seed)` tuple
plus three further identity-bearing components:

| Component | Type | Says |
| --- | --- | --- |
| World | `World` | What machines and devices exist and how they are wired |
| Plan | `Plan` | Event choreography and the signal-driven fault program |
| Properties | `Properties` | Which assertions must hold |
| Measurements | `MeasurementDefinitions` | Which guest measurements are declared |
| Selectables | `ScenarioSelectables` | The guest choice catalog and its limits |
| Seed | `Seed` | The 256-bit root of every seeded decision stream |
| App-random cap | `u64` | The maximum app-random decisions in one run |

`ScenarioDefForm` exposes only immutable accessors. `with_plan` and
`with_selectables` return a rebuilt, revalidated form rather than mutating.
Measurements are documented with [assertions.md](assertions.md); selectables
and app-random requests with [guest-host-channel.md](guest-host-channel.md).

## Orthogonal layers

World, Plan, Properties, and Seed are independent layers, and none is folded
into another:

- Links are topology, so they belong to the World.
- Faults and timed actions are perturbations, so they belong to the Plan.
- Assertions are observations, so they belong to the Properties.
- Root entropy is the Seed.

The separation is structural. Each layer is independently content-addressed and
reusable: one World can be shared by many scenarios, and one Plan or Properties
bundle can be applied to any World that declares the nodes it references.

The alternative this rules out is a scenario as a flat list of events whose
first, triggerless "boot" event creates links, registers assertions, and starts
nodes. That form parses and runs, but it loses three properties:

- **Reuse.** The topology is no longer a value that can be hashed and shared
  with a different fault campaign.
- **Analyzability.** The scheduler's lookahead graph, visualization, and
  property scoping would have to interpret events to recover the graph.
- **Identity over meaning.** The hash would depend on action order inside the
  boot event, so equivalent scenarios authored slightly differently would hash
  differently.

A Plan may still contain triggerless events that fire at virtual time zero; it
may not express topology or assertions as events. `ScenarioBuilder` has no
boot-event entry point.

## Content addressing

### Identity hashes

Model identities are computed by `ContentHash::from_canonical_material(domain,
material)`. The material is a canonical line-oriented `key=value` text, and the
domain tag versions each material stream independently:

| Identity | Domain |
| --- | --- |
| `World::id` | `crucible.model.world.v6` |
| `Plan::content_hash` | `crucible.model.plan.v6` |
| `Properties::content_hash` | `crucible.model.properties.v2` (`PROPERTY_SCHEMA_DOMAIN`) |
| `ScenarioDef::id` | `crucible.model.world-plan-properties-seed-scenario.v2` |
| Selectables reference | `crucible.model.scenario-selectables.v1` |
| Baked VM blob per node | `crucible.model.node-baked-blob.v1` |
| Seed decision-RNG root | `crucible.model.seed-decision-rng-root.v1` |

The scenario id hashes references to the components, not their folded
material:

```text
world_ref=<World id hex>
plan_ref=<Plan hash hex>
properties_ref=<Properties hash hex>
measurements_ref=<hex>          (only when measurements are declared)
selectables_ref=<hex>           (only when selectables are declared)
seed_bytes=<64 lowercase hex>
app_random_draw_cap=<u64>
```

Changing any component, the seed, or the cap changes the scenario id; changing
nothing but authoring order changes nothing.

The engine's canonical-material hasher (`MaterialHasher` in
`model/canonical.rs`) is a fixed, host-independent 256-bit mixing function with
domain separation and length-prefixed writes. It is not BLAKE3 and not
cryptographic. BLAKE3 is used where raw bytes are addressed:
`ContentHash::from_bytes` keys DAG-store objects and computes
`ReproductionArtifact::id`, and image, kernel, initrd, block, and 9p artifacts
are referenced by the BLAKE3 hash of their bytes. Serialized forms render every
`ContentHash` as `blake3:<64 lowercase hex>`; `ContentAddressedBlobRef::parse`
accepts only that shape.

### Canonicalization rules

Content addressing is over meaning, not spelling. Component constructors
canonicalize before hashing or serializing:

| Rule | Implementation |
| --- | --- |
| Nodes sorted by `NodeId` | `canonical_world_node_defs` |
| Links sorted by endpoint pair, then latency, jitter, loss, bandwidth | `canonical_world_links` |
| Link endpoints ordered so `(a, b)` and `(b, a)` are equal | `LinkDef::with_transport`: `let (endpoint_a, endpoint_b) = if left <= right` |
| Assertions sorted by id, then material | `canonical_assertions` |
| Compound predicate sets sorted by material | `canonical_predicate_set` |
| Signal programs and fault bindings sorted by id | `programs.sort_by_key(SignalProgram::id)`, `bindings.sort_by(...)` |
| Strings length-prefixed | `node_id_len=`, `cmdline_len=`, `message_len=` |
| Durations in exact ticks | `link_latency_ticks=`, `link_jitter_ticks=` |
| Probabilities in fixed point | `link_loss_millionths=` |
| Clock scale bound into identity | `min_link_latency_ticks=` heads the World material |
| Artifacts by content hash | `kernel_ref=`, `root_image_ref=`, `initrd_ref=` as `blake3:` refs or `none` |

No probability or density that enters a hash is a host-printed float. Ticks are
exact simulation ticks at the fixed scale `SIM_TICKS_PER_NS = 1_000`; see
[virtual-time.md](virtual-time.md).

The compact binary codec (`ScenarioBinaryWriter` in `model/binary_state.rs`)
writes fixed-width little-endian integers (`fn write_u64(&mut self, value:
u64)`) and length-prefixed UTF-8 (`fn write_string(&mut self, value: &str)`).
Every binary form starts with a NUL-terminated magic:

| Form | Magic |
| --- | --- |
| Scenario | `crucible.scenario-def-form.v9\0` |
| World | `crucible.world.v6\0` |
| Plan | `crucible.plan.v6\0` |
| Properties | `crucible.properties.v2\0` |
| Seed | `crucible.seed.v1\0` |
| Schedule | `crucible.schedule.v4\0` |
| Reproduction artifact | `crucible.reproduction-artifact.v9\0` |

## World

```rust
pub struct World {
    pub id: ContentHash,
    // canonical nodes, links, and fault topology; private
}
```

`World` stores nodes and links behind immutable accessors and carries
canonical `nodes` and `links`; `World::from_nodes_and_links` (and the
heterogeneous `World::from_node_defs_and_links`) sorts both collections and
validates them before hashing. `World::nodes` is the one heterogeneous logical
VM/block/9p collection: every entry is a `WorldNodeDef`, either
`WorldNodeDef::Vm(WorldNode)` or `WorldNodeDef::Io(WorldIoNode)`, and node ids
are unique across both kinds. `World::vm_nodes` projects the VMs and
`World::links` returns the logical links.

### VM nodes

`WorldNode` carries only launch-time inputs, so its hash is portable and no
guest modification is implied:

| Field | Meaning |
| --- | --- |
| `id: NodeId` | Stable identity; key for links, faults, properties, and stream forking |
| `arch: VmArchitecture` | `X86_64` or `Aarch64`; selects the QEMU system binary |
| `memory_mib: u32` | Guest RAM; at least 1 MiB |
| `cmdline: String` | Kernel command line, hashed verbatim |
| `ready_point: ReadyPoint` | Where `t = 0` sits for this node |
| `white_box: WhiteBoxPolicy` | `Disabled` (default) or `Enabled` |
| `smp_vcpus: u16` | Fixed vCPU count. `N >= 1` |
| `kernel`, `root_image`, `initrd` | Optional `ContentAddressedBlobRef`s |

`WorldNode` carries fixed `smp_vcpus`, and the count is part of the hashed
configuration, so changing it is a different scenario. A multi-vCPU node runs
under single-threaded round-robin TCG, never MTTCG: `crucible-qemu-host`
rejects `thread=multi` and requires a pinned round-robin switch quantum before
spawning QEMU. There is no per-node clock shift; the fixed tick scale enters
World identity through `min_link_latency_ticks`.

Absent by design: host paths, an authored genesis-snapshot path (genesis is
produced by bake), participant counts, shared-memory geometry, and scratch
directories.

### Ready points

The `ReadyPoint` enum includes `FixedIcount`, `NetworkIdle`, `ConsoleMarker`,
and `AgentSignal`. Ready-point material is part of the World hash and of the
baked blob hash. The policy semantics and trade-offs are in
[execution-model.md](execution-model.md#the-ready-point).
`World::validate_ready_point_policies` rejects `AgentSignal` unless
`WhiteBoxPolicy::Enabled` is set, so the white-box ready point is never a
default.

### I/O nodes

A `WorldIoNode` is a block or 9p sub-node owned by a declared VM:

| Kind | Configuration |
| --- | --- |
| `WorldIoNodeKind::Block` | `base_image` (BLAKE3 of the exact bytes), `base_length`, `WorldBlockLatency` (read, write, flush, get-length, per-byte nanoseconds) |
| `WorldIoNodeKind::NineP` | `tree` (BLAKE3 of the canonical `FsTree` bytes), `WorldNinePLatency` (control, data, per-byte nanoseconds) |

The base artifact is read-only; guests write only copy-on-write overlays. I/O
nodes participate in scheduling but are not baked. See
[io-subnodes.md](io-subnodes.md).

### Logical topology only

The World encodes the logical topology and nothing about the physical
transport. Completion-order source numbers and request and response ring
capacities live in `WorldIoInstantiationLayout`, derived from canonical node
order plus a `WorldIoLayoutPolicy` when a session resolves concrete artifacts.
Shared-memory region layout, queue sizing, and host memory geometry are
likewise computed at instantiation.

This keeps identity portable (a host laying out memory differently does not
change the hash), lets any transport revision consume the same World, and gives
topology readers the logical graph instead of a memory map. The model is
logical; the layout is derived; the derivation is not identity.

The World also carries a fault topology (fault domains, network interfaces,
segments, media, forwarders, queues, paths, and attachments) whose identity is
folded into the World hash. Its vocabulary belongs to the signal-driven fault
model; see [../../users/crucible/topology.md](../../users/crucible/topology.md).

### Links and the latency floor

`LinkDef` is a symmetric logical edge between two declared nodes:

| Field | Meaning |
| --- | --- |
| endpoints | Canonical pair; `LinkDef::new` canonicalizes endpoint order and rejects self-loops |
| `latency: SimDuration` | One-way base latency, at least `MIN_LINK_LATENCY` |
| `jitter: SimDuration` | Maximum subtractive jitter; `latency - jitter` must stay at or above the floor |
| `loss: LinkLossProbability` | Frame-loss probability in millionths |
| `bandwidth_bps: Option<u64>` | Optional bits-per-virtual-second cap |

```rust
pub const MIN_LINK_LATENCY: SimDuration = SimDuration {
    ticks: SIM_TICKS_PER_NS,
};
```

`MIN_LINK_LATENCY` is exported as the one-nanosecond floor. A link MUST have a
strictly positive latency. Link latency is the scheduler's conservative
lookahead bound: the minimum inbound latency to a node is the soonest any peer
can deliver to it. A zero-latency link collapses that horizon to the node's
current time, forces lock-step execution, and admits same-time delivery cycles
that the total order cannot break. Requiring a positive floor even after jitter
keeps every lookahead strictly positive. See [scheduling.md](scheduling.md).

The floor is a liveness minimum, not a recommended operating point. One
nanosecond is the smallest value that keeps lookahead positive while
restricting fidelity as little as possible; links well above the floor give
more parallelism. Two cases are treated differently:

- A statically declared base latency below the floor is a modeling error and is
  rejected at construction (`EngineError::WorldLinkLatencyBelowFloor`).
- A latency-reducing fault that would push a valid link below the floor at run
  time is clamped up to the floor in the network-link sub-node, so a fault can
  never break scheduler liveness.

`LinkLossProbability` stores loss as fixed-point millionths and rejects values
above `1_000_000` (`EngineError::LinkLossProbabilityOutOfRange`). Unsigned
`SimDuration` makes negative latency unrepresentable.

### Static topology

The node set and link set are fixed for the life of a scenario. There is no
operation that adds or removes a node or changes the link set mid-run.
`World::static_topology()` derives a `WorldStaticTopology` from the World alone:

| Field | Contents |
| --- | --- |
| `participants` | The VM participants |
| `scheduling_nodes` | Every VM, block/9p node, and logical link as a `SchedulerNodeId` |
| `rng_streams` | The per-entity decision-RNG streams |
| `lookahead_graph` | Directed scheduler-lookahead edges |
| `bake_nodes` | The VM nodes `bake` boots to a ready point |

None of these takes a `Schedule`, so none can vary with a schedule prefix.
Membership dynamics (crash, restart, partition, heal, isolation, a node that
has not joined yet) are modeled as signal-driven fault bindings over declared
nodes and links, never as topology edits; see
[../../users/crucible/signal-driven-faults.md](../../users/crucible/signal-driven-faults.md).

Dynamic membership would make the participant set, the stream set, the
lookahead graph, and the bake set functions of decision time. Bake could no
longer run once per World, a new participant would shift stream allocation,
and the conservative scheduling argument would have to handle a time-varying
graph. Every membership scenario that matters is expressible as a fault over a
static world.

## Plan

`Plan` carries one event graph plus one canonical `FaultSignalPlan`. The event
graph holds triggered control actions (arm and cancel timers, start and stop
nodes, create savepoints, fork, log, pass, and fail); see
[conditions-and-triggers.md](conditions-and-triggers.md). The fault signal plan
holds signal programs, typed bindings, and resource limits; fault effects are
bindings driven by signals, not event actions.

Plans are validated against the World they layer over
(`Plan::validate_for_world`): every node, link, and fault target must be
declared. Fault-plan admission rejects missing programs, duplicate identities,
invalid selectors, undeclared targets, malformed effect parameters, and
exceeded resource ceilings before hashing or execution. Typed signal
coordinates prevent negative time from entering the runtime. Plans evaluate
against virtual time and stable opportunities, never host wall clock. The
current TOML schema requires `fault_model = "signal_bindings_v2"`.

## Properties

`Properties` carries an independent content hash over canonical `AssertionDef`
material. Each assertion has an id, a message, and a `Property` whose
`PropertyKind` is one of `Always`, `Sometimes`, `Eventually`,
`AfterQuiescence`, or `Reachable`. `Properties::from_assertions_for_world`
validates every predicate node reference against the World and rejects empty
compound predicates (`PropertyPredicateEmptyCompound`). Semantics are in
[assertions.md](assertions.md).

## Seed

`Seed` carries the 256-bit root entropy (`[u8; 32]`). `Seed::from_u64` writes
the integer little-endian into the first eight bytes. The seed is part of
scenario identity, and all of its bytes feed the decision RNG:

- `Seed::decision_rng_root_seed` hashes the seed material in domain
  `crucible.model.seed-decision-rng-root.v1` and takes the first eight bytes
  as the `u64` root of `DecisionRng`.
- `Seed::fork_stream` and `Seed::stream_seed` fork a `DecisionStream` by
  name-hash within the stream's domain. Node, link, and device streams use
  separate domains (`crucible.decision-rng.node-stream.v1`,
  `crucible.decision-rng.link-stream.v1`,
  `crucible.decision-rng.device-stream.v1`), so a device named `disk` and a
  node named `disk` never collide.
- `World::seeded_rng_streams` projects the static stream set into seeded
  stream roots.

Forking by name-hash rather than allocation order is what keeps unrelated
World edits from perturbing other streams' draws. See
[determinism.md](determinism.md).

## Authoring

`ScenarioBuilder` (in `model/family.rs`) is the code-first front door. It
exposes distinct entry points per layer:

| Layer | Entry points |
| --- | --- |
| World | `world`, `node`, `node_like`, `link` |
| Plan | `plan` |
| Properties | `properties`, `property` |
| Seed | `seed` |

`NodeTemplate` holds reusable node settings (`fixed_icount`, `network_idle`,
`console_marker`, `agent_signal` constructors plus `arch`, `memory_mib`,
`cmdline`, `smp_vcpus`, `kernel`, `root_image`, `initrd`, `white_box`).
`node_like` copies another declared node's settings at build time. `link` adds
a default link at `MIN_LINK_LATENCY`, lossless, with no jitter or bandwidth cap;
`world` copies a complete World with its concrete links.

```rust
let def = ScenarioBuilder::new()
    .node(
        "db-0",
        NodeTemplate::console_marker("crucible-ready")
            .memory_mib(512)
            .cmdline("console=ttyS0 quiet"),
    )
    .node_like("db-1", "db-0")
    .link("db-0", "db-1")
    .property(no_split_brain)
    .seed(Seed::from_u64(42))
    .build()?; // validates, canonicalizes, content-addresses
```

`build` composes through `World::from_nodes_and_links` and
`World::scenario_def_with_plan_properties_and_seed`, the same path as manual
composition, so builder and manual construction produce equal ids.
`World::scenario_def_with_plan_and_properties` is the default-seed variant.

### Serialized form

`ScenarioDefForm` and each component have a deterministic TOML form and a
compact binary form. Both round-trip: serialize then parse yields an equal
form with the same id. The TOML schema tag is `crucible.scenario.v9`. An
excerpt of `tests/crucible/fixtures/happy-path.scenario.toml`:

```toml
schema = "crucible.scenario.v9"

[scenario]
id = "blake3:8d1aa4263532d8bfb1b51d80f854fd2a4bd98b40e5ea81efa2f763c1d016d944"
seed = "0x2a00000000000000000000000000000000000000000000000000000000000000"
app_random_draw_cap = 10

[world]
id = "blake3:47cad13f2dcf8cefe071433a343c478180a2ec53e35dbaac31110bbfb1b8be63"

[[world.node]]
id = "client"
arch = "x86_64"
memory_mib = 256
cmdline = "console=ttyS0 quiet crucible.workload=httpget target=server:8080 count=100"
smp_vcpus = 1
kernel = "blake3:fe37bad9b18652cadbc50fae4c118fa5e741731c4cf55176d48826ecad85d104"
root_image = "blake3:1a0a45c8a824f9e4358d5430617567384ae4c499ad5ce81e42508aa945a9236d"
white_box = "disabled"

[world.node.ready_point]
kind = "console_marker"
marker = "client ready"

# ... the "server" node is elided ...

[[world.link]]
endpoint_a = "client"
endpoint_b = "server"
latency_nanos = 5000000
jitter_nanos = 1000000
loss_millionths = 0

[plan]
id = "blake3:5eb4dc45c0e8000c187ecb483b8df894b3173a13e46eb7f908a5d91e8dfba09f"
fault_model = "signal_bindings_v2"
fault_signal_semantic_version = 2

[properties]
id = "blake3:7982a620d7e9488ab7c32f426a00909b6db549ea169e5e2e802e14eb89cc2ab7"
```

`ScenarioDefForm::from_canonical_toml` checks, in order: the 256 MiB TOML size
limit, that no image field holds a host path, that the plan uses the current
fault schema, strict deserialization (unknown fields are errors), component
validation, and finally that every serialized `id` equals the recomputed one
(`EngineError::ScenarioSerializedIdMismatch`). `from_compact_binary` applies
the same validation. A parsed form is therefore already well formed.

## Scenario families

A `ScenarioFamily` (in `model/family/instances.rs`) is a deterministic
generator over a finite parameter space, used for fuzzing and search. A run
never executes a family; it pins one concrete instance.

| Axis | Type | Bound |
| --- | --- | --- |
| Seeds | `SeedSpace::explicit` or `SeedSpace::generated(meta_seed, count)` | 1 to 1,000,000 seeds, no duplicates |
| Topology size | `TopologySizeRange::new(min, max)` | `1 <= min <= max <= 256` |
| Topology shape | `TopologyShape` | `Ring`, `Star`, `Mesh`, `Random` (seed-derived, connected) |
| Fault density | `FamilySpace::with_fault_densities` | Bindings retained from the family fault plan |

`FamilySpace::sample(index)` enumerates points without wrapping, and shapes and
densities are sorted and deduplicated so sampling is independent of authoring
order. `ScenarioFamily::instantiate(params)` builds a concrete World, Plan, and
Properties through the same validating constructors as the builder and returns
a `PinnedScenario` carrying only the `ScenarioDefForm` and its parameter point.
`PinnedScenario::genesis_configuration` pairs the executable `Configuration`
with that form. Nothing refers back to the family.

## Reproduction artifacts

A failure reproduces from the self-contained `(seed, scenario, schedule)`
tuple. `ReproductionArtifact` stores the complete validated `ScenarioDefForm`
and the recorded `Schedule`; the seed is the form's own seed, not a separate
field that could drift.

- `ReproductionArtifact::id` is BLAKE3 over the canonical bytes: the magic
  `crucible.reproduction-artifact.v9\0`, then the scenario form's compact
  binary as a length-prefixed blob, then the schedule's compact binary.
- `capture` builds an artifact and replays it once before returning.
- `from_compact_binary` decodes a transported artifact with no family handle,
  requiring the inner scenario version to match the outer one.
- `replay` validates retained preemption producer evidence and reduces the
  embedded scenario and schedule; `verify_replay` fails with
  `EngineError::ReproductionArtifactReplayMismatch` when the reduced state is
  not the expected one.

Images are referenced by content hash, so an artifact is portable across hosts
and replays offline when its artifacts are available. The DAG-store form of
the same closure is `DagStoreReproductionArtifact`; see
[execution-graph.md](execution-graph.md#the-dag-store).

## Validation

Every well-formedness rule runs at build or parse time, before hashing or
execution. A scenario that reaches the scheduler is already known well formed,
so the runtime never defends against a malformed definition.

| Check | Error |
| --- | --- |
| Node ids unique across VM and I/O nodes | `DuplicateWorldNodeId` |
| `AgentSignal` requires white-box opt-in | `WhiteBoxReadyPointWithoutOptIn` |
| Network-idle window nonzero, with incident links | `ReadyPointNetworkIdleWindowZero`, `ReadyPointNetworkIdleWithoutLinks` |
| Console marker nonempty | `ReadyPointConsoleMarkerEmpty` |
| `smp_vcpus >= 1` | `WorldNodeSmpVcpuCountZero` |
| `memory_mib >= 1` | `WorldNodeMemoryMibZero` |
| Workload command-line parameters well formed | `WorldNodeUnsupportedWorkload` and related |
| I/O node owner is a declared VM | `WorldIoNodeUnknownOwner` |
| Link endpoints declared and distinct | `WorldLinkUnknownNode`, `WorldLinkSelfLoop` |
| Canonical link pair unique | `DuplicateWorldLink` |
| `latency >= MIN_LINK_LATENCY` | `WorldLinkLatencyBelowFloor` |
| `latency - jitter >= MIN_LINK_LATENCY` | `WorldLinkJitterBelowLatencyFloor` |
| Loss at most 1,000,000 millionths | `LinkLossProbabilityOutOfRange` |
| Plan and fault-plan references and parameters valid | Plan and fault-signal admission errors |
| Predicate node references declared | Properties validation errors |
| Image refs are `blake3:` content hashes | `ScenarioImageReferenceNotContentAddressed` |
| Serialized ids match recomputed ids | `ScenarioSerializedIdMismatch` |

All errors are `EngineError` variants. `crucible-qemu-host` launch-profile
validation mirrors the launch rows (vCPU count, round-robin TCG, fixed icount)
before it spawns QEMU.

## Verification

| Test | Check |
| --- | --- |
| `scenario_def_form_is_immutable_pure_four_tuple_value` | `checks.crucible.phase1.spatialScenarioDefValue` |
| `scenario_layers_stay_structurally_orthogonal` | `checks.crucible.phase1.spatialLayerOrthogonality` |
| `spatial_components_have_independent_content_addresses_and_cross_reuse` | `checks.crucible.phase1.spatialComponentAddressing` |
| `world_topology_rejects_invalid_links` | `checks.crucible.phase1.spatialWorldTopology` |
| `world_node_launch_inputs_are_portable_and_identity_bearing` | `checks.crucible.phase1.spatialNodeLaunchInputs` |
| Ready-point policy tests | `checks.crucible.phase1.executionReadyPoint` |
| Link floor, jitter, and loss tests | `checks.crucible.phase1.spatialLinkTransport`, `checks.crucible.phase3.schedulerLinkLatencyFloor` |
| Layout-invariance tests | `checks.crucible.phase1.spatialLogicalTopology` |
| `world_static_topology_is_derived_from_world_only` | `checks.crucible.phase1.spatialStaticTopology` |
| Plan component and admission tests | `checks.crucible.phase1.spatialPlanComponent`, `checks.crucible.phase1.spatialPlanValidation` |
| `properties_content_address_is_orthogonal_and_validated` | `checks.crucible.phase1.spatialPropertiesComponent` |
| `seed_is_scenario_identity_and_name_hashed_stream_root` | `checks.crucible.phase1.spatialSeedComponent` |
| `scenario_builder_keeps_authoring_layers_structurally_orthogonal` | `checks.crucible.phase1.spatialScenarioBuilder` |
| `serializable_scenario_form_round_trips_and_rejects_host_paths` | `checks.crucible.phase1.spatialSerializableForm` |
| `scenario_family_pins_concrete_validated_instances` | `checks.crucible.phase1.spatialScenarioFamily` |
| `reproduction_artifact_is_self_contained_and_replay_checked` | `checks.crucible.phase1.spatialReproductionArtifact` |
| `world_topology_hashes_nodes_and_links_canonically`, `authored_order_does_not_change_identity` | `checks.crucible.phase1.spatialCanonicalization` |
| `scenario_def_form_rejects_well_formedness_matrix_before_hashing` | `checks.crucible.phase1.spatialValidationPass` |

The complete signal-driven fault admission and adapter path is gated by
`checks.crucible.phase7.gates.signalFaultSystem`.
