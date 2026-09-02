# Authoring fault scenarios

Crucible scenarios should be generated through the public Rust model API and
then serialized as canonical TOML. This is the complete authoring path for a
fault experiment; the CLI consumes the result but does not provide imperative
commands such as “disconnect link now.”

## Authoring pipeline

```text
declare World
  + admit WorldFaultTopology
  + build SignalProgram and FaultBinding values
  + resolve them into a Plan for that World
  + declare Properties
  + choose Seed
  = ScenarioDefForm -> canonical TOML -> crucible run
```

Each step fails before guest launch when identities, types, phases,
capabilities, or references disagree.

## 1. Declare the executable world

A `World` contains VM nodes, deterministic logical links, and optional block or
9p I/O nodes. A node's kernel, root image, and initrd may be supplied by the
production lifecycle configuration when the scenario leaves those artifact
references empty.

Use `World::from_nodes_and_links` for VM-only worlds and
`World::from_node_defs_and_links` when adding I/O sub-nodes. Logical
`LinkDef` values establish guest frame transport and its baseline latency,
jitter, loss, and bandwidth.

The complete two-VM lifecycle construction in
[`crucible-qemu-live-world-network.rs`](../../../crates/crucible-api/examples/crucible-qemu-live-world-network.rs)
is the smallest production example. It deliberately has no signal-driven
faults; use it to separate basic transport failures from fault-plan failures.

## 2. Declare fault-addressable topology

`WorldFaultTopology` is the immutable registry that selectors and adapters use.
It can contain:

- fault domains;
- network interfaces, segments, media, forwarders, queues, paths,
  attachments, contact plans, policy artifacts, and mobile endpoints;
- storage devices, controllers, paths, arrays, media/durability contracts, and
  policy artifacts; and
- per-node CPU, register, memory, interrupt, clock, and accelerator capability
  contracts.

Attach it with `World::with_fault_topology`. Admission canonicalizes unordered
registries, expands valid direct-segment paths, resolves references, and rejects
duplicates, dangling objects, invalid geometry, unsupported device concepts,
and limits exceeded by authored material.

The topology does not create runtime hardware. A network segment must
correspond to declared endpoints, a block target must correspond to a world I/O
node, and a QEMU hardware target must match a capability the backend can
realize.

The production shared-cause example shows a complete network, block-storage,
and node topology in
[`topology()`](../../../crates/crucible-api/examples/crucible-qemu-signal-shared-cause.rs).

## 3. Build the signal program

A `SignalProgram` is a typed directed acyclic graph. Every `SignalNode` has a
stable `SignalId`, coordinate domain, output `SignalShape`, input list, and
`SignalNodeKind`. Its declared outputs are the only nodes a binding may read.

Choose the coordinate domain first:

| Domain | Typical use |
|---|---|
| `VirtualTime` | Scheduled outages, environmental changes, maintenance windows. |
| `NodeCounter` | Effects tied to one VM's retired-instruction progress. |
| `Operation` | Per-frame, per-I/O, instruction, or access choices. |
| `Spatial` | Trajectories, zones, distance, attenuation, interference. |
| `Event` | Exact impulses and recorded discrete events. |
| `State` | Feedback-delayed state machines and accumulated exposure. |

Sources include constants, steps, pulses, periodic signals, normalized traces,
spatial fields, event sequences, and keyed stochastic processes. Pure
operators transform values without memory; stateful operators carry declared,
checkpointed state. [Signal programs](signals.md) explains every family and the
[reference](reference.md#plans-signals-bindings-and-faults) lists exact fields.

For a one-time outage, prefer an event or pulse. For a fault that stays active
until a later transition, use a Boolean step/pulse with a persistent binding.
For a shared cause, expose one signal output and bind it independently to each
affected target.

## 4. Bind signals to typed effects

`FaultBinding::new` connects one or more signal outputs to:

- a sampling rule;
- a mapping such as `ActiveWhenTrue`, `ImpulseOnEvent`, or a numeric map;
- an exact, fault-domain, or query selector;
- one or more legal `FaultPhase` opportunities;
- an `EffectRequest` containing semantic version, lifetime, and typed effect;
- search and observability policy; and
- the signal program used to validate the connection.

These fields are a contract, not optional metadata. For example, a persistent
network outage sampled at a boundary is different from an impulse that drops
one frame at admission. A storage completion error at resolve is different
from persistence loss at flush.

Use [Fault bindings](bindings.md) for the complete bridge contract, then the
effect selection tables in [Network faults](network-faults.md) and
[Storage, node, and hardware faults](storage-node-faults.md). The
[reference effect registry](reference.md#exhaustive-effect-registry) gives the exact legal
target kinds, phases, lifetimes, and operations for every effect.

## 5. Resolve the plan against the world

Create a `FaultSignalPlan` from programs, bindings, and explicit resource
limits. Then attach it with:

```rust
let plan = Plan::empty().with_fault_signals_for_world(&world, faults)?;
```

This is the important authoring boundary. It materializes selectors against the
immutable topology and lowers the signal plan into the world's event graph.
Do not attach a pre-resolved target set copied from another world: content
identity and target contracts are world-specific.

The complete implementation-backed pattern is in
[`shared_cause_plan()` and `build_source()`](../../../crates/crucible-api/examples/crucible-qemu-signal-shared-cause.rs).

## 6. Declare application properties

Fault application is not a test verdict. Add properties for the behavior the
guest or modeled topology must satisfy:

- use a typed guest marker for application-level success or failure;
- use console matching for a stable, opaque prebuilt workload;
- use network observations for transport/topology claims; and
- choose `Always`, `Eventually`, `Sometimes`, `AfterQuiescence`, or
  `Reachable` according to the intended temporal claim.

Include a bounded terminal condition when running. A fault that successfully
makes an application wait forever is otherwise indistinguishable from an
unbounded test. See [Properties, observations, and verdicts](properties-and-evidence.md)
for the full predicate and evidence model.

## 7. Serialize, inspect, and run

Build the complete form and write canonical TOML:

```rust
let source = ScenarioDefForm::from_components(
    &world,
    &plan,
    &properties,
    Seed::from_u64(0x5eed),
)?;
let toml = source.to_canonical_toml()?;
```

The generated IDs cover nested world, plan, property, and artifact material.
Never hand-update one hash after editing a structural sketch; regenerate the
whole document.

Run the result with explicit bounds and retain a canonical trace:

```sh
./result/bin/crucible \
  --seed 0x5eed \
  --format jsonl \
  --trace run.jsonl \
  run scenario.toml \
  --until virtual-time \
  --max-virtual-time 30s \
  --max-quanta 10000 \
  --save-on fail
```

## 8. Supply external artifacts

World artifacts and normalized signal traces live in a content-addressed
`DagStore`. A direct Rust lifecycle integration supplies them with
`ProductionVmLifecycleConfig::with_world_artifacts` and
`with_signal_artifacts`. Exact checkpoints copy their transitive signal
dependencies into the authenticated execution closure, so restore does not
silently depend on the original import location.

See [Recorded signal inputs](recorded-signals.md) for importing and storing a
trace. There is currently no CLI command that imports raw CSV, JSONL, PCAP, or
PCAPNG, and ordinary packaged `run`/`verify` do not attach `--store` as the
lifecycle signal store. Trace-driven direct runs therefore use the Rust
lifecycle API; bounded search and replay have their separately documented
artifact-store paths. [Stores and artifacts](artifacts.md) defines each object
and its retention/portability contract.

## Common admission failures

| Failure | Correction |
|---|---|
| Selector resolves to no targets | Declare the object in `WorldFaultTopology` and resolve the plan for the same world. |
| Effect/target or effect/phase mismatch | Use the registry row for that effect; do not approximate with a nearby phase. |
| Persistent/impulse mismatch | Match `EffectLifetime` to the effect registry and signal mapping. |
| Backend capability mismatch | Declare the exact realized QEMU CPU/device capability or choose a supported target. |
| Trace object missing | Persist raw provenance, chunks, and manifest, then supply the same DAG store. |
| Stale content ID in TOML | Regenerate with `ScenarioDefForm::to_canonical_toml`. |
| Test never terminates | Add a property terminal condition, virtual-time ceiling, and scheduler-quantum bound. |
