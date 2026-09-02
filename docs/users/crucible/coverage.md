# Feature coverage

This page is the inventory for Crucible's user-visible functionality. It maps
each shipped surface to its implementation authority, operational status, user
documentation, and production evidence. A feature is not considered documented
merely because its Rust type appears in generated API documentation.

Use the status vocabulary from [Support boundaries](support.md): **packaged**,
**public API**, **certified**, **model only**, and **rejected**. Several rows
carry more than one status because the model, direct Rust integration, and
packaged CLI expose different portions of the same feature.

## Coverage contract

Complete user coverage requires all applicable columns below:

| Requirement | Required content |
|---|---|
| Purpose | What the feature models and when an operator should use it. |
| Status | Exact packaged/API/certification boundary, including architecture and backend restrictions. |
| Configuration | Fields, closed variants, units, bounds, defaults, and reference rules. |
| Admission | Cross-field validation and backend capability requirements. |
| Execution | Sampling point, phase, state transitions, composition, and deterministic ordering. |
| Evidence | Canonical events, adapter evidence, property observations, and terminal verdict behavior. |
| Continuation | Checkpoint, resume, fork, search, and replay semantics. |
| Example | A complete recipe or implementation-backed executable when the feature benefits from one. |

The [canonical reference](reference.md) remains the exhaustive CLI and scenario
exchange vocabulary. Task guides explain how those fields form an experiment.

## Packaged command inventory

All thirteen shipped subcommands are packaged on the local CLI. A command can
still have narrower daemon or backend behavior, which its guide must state.

| Command | Primary behavior | User documentation | Boundary |
|---|---|---|---|
| `run` | Execute one canonical scenario to a bounded terminal condition. | [Running Crucible](running.md), [Reference](reference.md#run) | Local packaged-QEMU is primary; ordinary run does not attach the DAG store as a signal-artifact store. |
| `verify` | Compare independent reductions or retained artifacts. | [Reproduction](reproduction.md#verify-repeated-execution), [Reference](reference.md#verify) | Live verification uses fresh matched-QEMU execution; ordinary verify has the same signal-store boundary as run. |
| `selftest` | Exercise the small packaged live-QEMU gate subset. | [Running Crucible](running.md#self-test) | Repository certification contains many gates that are not selectable here. |
| `save` | Materialize an exact savepoint at an admitted boundary. | [Reproduction](reproduction.md#savepoints), [Reference](reference.md#save) | Requires a durable DAG store and a supported boundary. |
| `resume` | Continue an exact retained world. | [Reproduction](reproduction.md#resume), [Reference](reference.md#resume) | Fails closed when the closure, scenario, scheduler identity, or backend identity differs. |
| `fork` | Continue a retained prefix with an explicit branch choice. | [Reproduction](reproduction.md#fork), [Reference](reference.md#fork) | Branch points must be admitted choices; mutation creates a non-canonical descendant. |
| `replay` | Reproduce an artifact and optionally compare or bisect evidence. | [Reproduction](reproduction.md#replay), [Reference](reference.md#replay) | Reproduction artifacts may carry authenticated signal objects and resolved-effect traces. |
| `search` | Explore bounded alternate schedules and fault choices. | [Exploration](exploration.md#state-space-search), [Reference](reference.md#search) | Local search attaches `--store` for signal search material; budgets are mandatory for useful exploration. |
| `fuzz` | Instantiate and explore a bounded scenario family. | [Exploration](exploration.md#coverage-guided-fuzzing), [Reference](reference.md#fuzz) | Packaged local campaigns exist; fleet campaign orchestration remains an API/certification surface. |
| `triage` | Cluster, compare, and minimize retained findings. | [Exploration](exploration.md#findings-and-triage), [Reference](reference.md#triage) | Operates on signed findings ledgers, not arbitrary log files. |
| `debug` | Inspect a retained or running execution. | [Debugging](debugging.md#debug-command), [Reference](reference.md#debug) | Some actions require a daemon session, debug gateway, guest agent, or explicit mutable fork. |
| `serve` | Run the cleartext HTTP/2 lifecycle control plane. | [Daemon operation](daemon.md), [Reference](reference.md#serve) | Not a distributed scheduler and not equivalent to every local CLI workflow. |
| `completions` | Emit an offline shell completion definition. | [Running Crucible](running.md#shell-completions), [Reference](reference.md#completions) | Reads only command schema and does not discover a backend. |

Global options, environment variables, input resolution, output formats,
terminal conditions, and exit codes are cataloged in
[Running Crucible](running.md) and the [command-line reference](reference.md#command-line-interface).

## Scenario model inventory

| Surface | Authority | Status | Documentation |
|---|---|---|---|
| `ScenarioDef = World + Plan + Properties + Seed` | `crucible::model` | Packaged and public API | [Operating Crucible](README.md#the-model), [Scenarios](scenarios.md) |
| Canonical TOML and derived content IDs | `ScenarioDefForm` and TOML model | Packaged and public API | [Scenarios](scenarios.md#authoring-surfaces), [Reference](reference.md#canonical-scenario-document) |
| VM nodes and logical links | `World`, `WorldNode`, `LinkDef` | Packaged and public API | [Scenarios](scenarios.md#world), [Reference](reference.md#worldnode-vm-fields) |
| Block and 9p I/O sub-nodes | `WorldIoNode` | Public API and certified live adapter | [Scenarios](scenarios.md), [Storage and hardware faults](storage-node-faults.md) |
| Fault-addressable topology | `WorldFaultTopology` | Public API and certified adapters | [Fault topology reference](topology.md), [Authoring](authoring.md#2-declare-fault-addressable-topology) |
| Signal-driven plan | `FaultSignalPlan`, `SignalProgram`, `FaultBinding` | Public API and certified adapters | [Signal-driven faults](signal-driven-faults.md), [Authoring](authoring.md) |
| Event/control graph | `Plan` event graph | Packaged and public API | [Scenarios](scenarios.md#plan), [Reference](reference.md#planevent-fields-and-actions) |
| Temporal properties | `Properties`, `Property`, `Predicate` | Packaged and public API | [Scenarios](scenarios.md#properties), [Reference](reference.md#properties-and-predicates) |
| Deterministic seed and keyed choices | `Seed`, RNG stream identities | Packaged and public API | [Scenarios](scenarios.md#seed), [Running Crucible](running.md#seed-resolution) |

## Fault-topology inventory

The world topology contains sixteen canonical collections. Every referenced ID
must resolve within the same admitted world.

| Collection | Declares | Execution status |
|---|---|---|
| `fault_domains` | Named, finite sets of typed targets for shared causes. | Public API; used by production adapters. |
| `network_interfaces` | VM or forwarder endpoints, technology, addresses, and domain membership. | Live network adapter. |
| `network_segments` | Point-to-point or logical transmission segments. | Live network adapter. |
| `network_media` | Shared or point-to-point media and bounded resources. | Live network adapter/model. |
| `network_forwarders` | Switches, routers, gateways, and other forwarding elements. | Live network adapter/model. |
| `network_queues` | Bounded interface/media/forwarder queues. | Live network adapter/model. |
| `network_paths` | Ordered directed routes through segments and forwarders. | Live network adapter/model. |
| `network_attachments` | Endpoint association and candidate state. | Network model and certified fault runtime. |
| `network_contact_plans` | Scheduled disrupted-link contacts. | Network model and certified fault runtime. |
| `network_policy_artifacts` | Closed network lookup and policy tables. | Public API; content-addressed validation. |
| `mobile_endpoints` | Endpoints driven by an admitted truth trajectory. | Model truth; not a guest sensor device. |
| `storage_devices` | Block/9p durability, cache, discard, completion, and media contracts. | Live storage and 9p adapters. |
| `storage_controllers` | Namespaces, access paths, and controller identity. | Live storage model/adapter. |
| `storage_arrays` | Member/path layout, quorum, selection, and rebuild topology. | Storage model and certified fault runtime. |
| `storage_policy_artifacts` | Closed storage and 9p policy tables. | Public API; content-addressed validation. |
| `node_capabilities` | Exact CPU, register, memory, interrupt, clock, error, and accelerator contracts. | Matched patched-QEMU capability adapters. |

Detailed fields, variants, validation, and cross-reference rules are in the
[fault topology reference](topology.md). Public struct definitions remain
supplementary implementation authority rather than a user-facing substitute.

## Signal inventory

The closed signal registry currently contains:

- 21 source kinds;
- 36 pure operator kinds;
- 9 stateful operator kinds;
- 6 coordinate domains;
- typed scalar, vector, enum, event, and byte values;
- explicit units, decimal scale, overflow, rounding, interpolation, missing
  data, and boundary policies; and
- resource limits for authored graphs and runtime state.

| Family | Examples | Status | Current guide |
|---|---|---|---|
| Analytic | constant, step, pulse, periodic pulse, ramp, triangle, sawtooth | Public API and certified evaluator | [Signal-driven faults](signal-driven-faults.md) |
| Recorded | event sequence and normalized trace | Public API; search/replay integrations; ordinary run limitation | [Recorded signal inputs](recorded-signals.md) |
| Spatial | point set, grids, zones, path profiles, fields, transmitters | Host model; may drive supported adapters | [Signal-driven faults](signal-driven-faults.md) |
| Stochastic | Bernoulli, uniform integer, exponential wait, Weibull wait | Public API and certified evaluator/search | [Signal-driven faults](signal-driven-faults.md) |
| Telemetry | One-boundary-delayed adapter state | Public API and certified evaluator | [Signal-driven faults](signal-driven-faults.md) |
| Pure transforms | Arithmetic, comparison, Boolean, selection, lookup, geometry, events | Public API and certified evaluator | [Reference](reference.md#plans-signals-bindings-and-faults) |
| Stateful transforms | Hysteresis, debounce, integrators, FSM, Markov, burst, counter, queue | Public API; checkpointed evaluator state | [Signal-driven faults](signal-driven-faults.md) |

## Binding and opportunity inventory

Bindings cover boundary, coordinate, opportunity, and event sampling; typed
mappings; exact/domain/query selectors; phase sets; impulse, persistent, and
state-machine lifetimes; search policy; observability policy; and optional
opportunity filters. The closed registries include every fault operation and
target kind listed in the [reference](reference.md#fault-opportunity-operation-values).

Admission resolves selectors, verifies signal shapes, and validates the
effect/target/phase/lifetime/operation tuple before boot. Runtime composition is
adapter-owned; bindings do not overwrite one another by declaration order.

## Executable effect inventory

There are 71 executable effect kinds:

| Adapter family | Effect count | Execution boundary | Guide |
|---|---:|---|---|
| Network | 31 | Host-side deterministic network route and adapter state. | [Network faults](network-faults.md) |
| Storage | 18 | Deterministic block request, service, completion, persistence, media, and controller state. | [Storage and hardware faults](storage-node-faults.md) |
| 9p | 2 | Deterministic 9p result and visibility state. | [Storage and hardware faults](storage-node-faults.md) |
| Node | 2 | Production VM lifecycle and progress state. | [Storage and hardware faults](storage-node-faults.md) |
| CPU | 5 | Matched QEMU CPU/vCPU/register/instruction/exception capability. | [Storage and hardware faults](storage-node-faults.md) |
| Interrupt | 2 | Matched QEMU interrupt route capability. | [Storage and hardware faults](storage-node-faults.md) |
| Memory | 5 | Matched QEMU address-space, access, ECC, region, and service capability. | [Storage and hardware faults](storage-node-faults.md) |
| Clock | 2 | Matched guest-visible QEMU clock-source capability. | [Storage and hardware faults](storage-node-faults.md) |
| Accelerator | 4 | Declared deterministic Crucible accelerator fault device. | [Storage and hardware faults](storage-node-faults.md) |

The [exhaustive effect registry](reference.md#exhaustive-effect-registry)
currently enforces one row for every effect. The expanded domain references
will add every effect's complete parameters, legal tuple, composition,
capability, evidence, continuation state, and authoring pattern.

## Assertions and evidence inventory

| Surface | Purpose | Status |
|---|---|---|
| Temporal quantifiers | Express invariants, reachability, eventuality, and quiescent verdicts. | Packaged and public API. |
| Deterministic predicates | Observe lifecycle, network, console, guest marker, timer, I/O, and named truth state. | Packaged and public API; exact set is closed. |
| Guest markers | Report application semantics at an exact guest coordinate. | Packaged static guest emitter and live QEMU doorbell. |
| Adapter evidence | Record contributors, preconditions, application, capability, and result. | Production fault adapters. |
| Event log | Canonical scheduler, decision, observation, property, and evidence history. | Packaged output and artifact input. |
| Fingerprints | Compare deterministic machine and modeled state at admitted boundaries. | Packaged verification and certification gates. |
| Resolved-effect trace | Preserve authoritative effect work for locked replay and diagnosis. | Public API and reproduction/search artifact paths. |

## Continuation and exploration inventory

| Surface | Preserved identity/state | Status |
|---|---|---|
| Thin checkpoint | Scenario and schedule position without a complete live execution closure. | Model/API surface; not sufficient for arbitrary production restore. |
| Fat checkpoint | Whole-world QEMU state, adapter state, scheduler state, signal state, and authenticated dependencies. | Packaged save/resume/fork and public API. |
| Reproduction artifact | Scenario, schedule, evidence, backend identity, critical payloads, and optional effect/signal material. | Packaged replay and triage. |
| Search frontier | Stable alternate choices reachable from an execution prefix. | Packaged bounded search and public API. |
| Scenario family/corpus | Deterministic campaign inputs, coverage, findings, and lineage. | Packaged local fuzzing; fleet orchestration is API/certification-only. |
| Debug branch | Read-only canonical inspection or explicit non-canonical mutable descendant. | Packaged with gateway/guest/session limitations. |

## Rejected and non-guaranteed surfaces

The following are not inferred as supported from nearby schema concepts:

- guest sensor, battery, power-supply, or cooling-device adapters;
- arbitrary host QEMU, KVM, passthrough devices, or host GPU fault injection;
- host `tc`, `netem`, namespaces, or load generators as deterministic inputs;
- heterogeneous per-node guest images through the packaged CLI;
- packaged AArch64 operator support merely because architecture types exist;
- a raw-trace import CLI command;
- ordinary `run`/`verify` automatic signal-store attachment;
- every local workflow over the daemon; or
- a general packaged distributed/fleet campaign operator.

Admission must fail closed when a scenario requests a rejected target or an
unavailable backend capability.

## Maintenance rule

When a user-visible registry or command changes, update this inventory, the
appropriate complete reference, at least one task guide where behavior changes,
and the documentation coverage tests in the same change. A new enum variant
that appears only in Rust source is incomplete feature work.
