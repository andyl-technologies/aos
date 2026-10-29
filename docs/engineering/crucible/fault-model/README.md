# Signal-driven fault model

Crucible represents every injected fault as a deterministic **cause** connected
to a typed **effect** at a stable hardware **opportunity**. The same machinery
drives a constant link outage, a recorded radio trace, rack vibration that
corrupts disk reads and flaps a connector, or an exact-boundary CPU register
mutation inside patched QEMU. There is no second fault path: the signal/binding
plan is the only representation the scenario schema, scheduler, adapters,
checkpoints, and replay accept.

This directory describes the implementation and its design rationale. The user
guides cover authoring:
[signal-driven faults](../../../users/crucible/signal-driven-faults.md),
[signals](../../../users/crucible/signals.md),
[bindings](../../../users/crucible/bindings.md),
[network faults](../../../users/crucible/network-faults.md),
[storage and node faults](../../../users/crucible/storage-node-faults.md), and
[recorded signals](../../../users/crucible/recorded-signals.md). The
[reference](../../../users/crucible/reference.md) is the exhaustive field
catalog.

## Architecture

```text
recorded traces   generated sources   spatial fields   adapter telemetry
       \                 |                  |                 /
        +----------------+------------------+----------------+
                                 |
                  SignalProgram (closed, typed DAG)
                                 |
              BindingMapping / hazard / state transition
                                 |
                FaultBinding: selector + sampling + effect
                                 |
            +--------------------+--------------------+
            |                    |                    |
     network adapter      storage/9p adapter     node adapter
     (crucible-daemon)    (daemon + qemu-host)   (patched QEMU)
            |                    |                    |
            +--------------------+--------------------+
                                 |
       resolved effect records + event log + checkpoint state
                                 |
         recomputed-cause, locked-effect, or outcome-only replay
```

The four concepts are deliberately separate:

1. A **signal** is a typed value or event stream over an explicit domain
   (virtual time, node counter, operation, space, event, or state). It knows
   nothing about frames, blocks, or registers.
2. A **fault opportunity** is the canonical, content-addressed context of one
   point where an adapter may act: a frame admission, a block persist, a memory
   load, an interrupt delivery.
3. A **binding** samples signals, maps their value into the parameters of one
   closed effect kind, and selects targets. Its ID is a decision-domain
   separator, an event-log identity, and the composition tie-breaker.
4. A **domain adapter** validates, composes, and applies effects with the
   physical semantics of its domain, and records evidence for replay.

## Invariants

- **No host nondeterminism.** Evaluation never consults host time, scheduling,
  files, unrecorded network input, or host entropy. Live host sensors are never
  canonical inputs; recordings are imported and normalized first.
- **Exact arithmetic.** Canonical values are integers, exact rationals, enums,
  and bytes with declared units and decimal scale. Overflow and rounding are
  explicit node policies. Floats are rejected in scenario material.
- **Keyed, not sequenced, randomness.** Every stochastic choice is a BLAKE3
  digest of the scenario seed, signal node, consumer, and stable
  opportunity/transition/coordinate identity. Adding an unrelated fault never
  shifts another fault's draws.
- **Explicit state.** Hysteresis, burst state, queues, wear, association, and
  other memory live in bounded, canonically encoded checkpoint state.
- **Typed application.** A signal reaches hardware only through a validated
  binding and an adapter; there is no untyped mutation API.
- **Causal scheduling.** A dynamic effect cannot move delivery into a
  consumer's past or lower an admitted scheduler bound without a boundary
  transition.
- **Deterministic composition.** Overlapping effects combine by a per-effect
  algebra in canonical binding-ID order, never container or callback order.
- **Fail closed.** Unknown fields, unknown variants, unsupported phases,
  missing backend capabilities, exceeded limits, and replay mismatches are
  errors before or at the responsible coordinate, never silent substitutions.

## Scope

Executable effects cover three adapter families: **network** (wired, logical,
radio, mobile, shared-medium, satellite, and contact links), **storage**
(block, flash, controller, array, and 9p), and **node** (lifecycle, vCPU,
register, instruction, interrupt, memory, clock, and the deterministic
accelerator device). The closed set is the `EffectKind` registry described in
[effects and taxonomy](effects-and-taxonomy.md).

Sensors, IoT buses and actuators, batteries, power supplies, and cooling
devices are not modeled as targets. Environmental, power, thermal, movement,
and vibration values may still be signal sources that drive the supported
effects, for example a temperature trace driving `cpu.service`. Any target or
effect outside the registry is rejected as unknown.

## Pages

| Page | Contents |
| --- | --- |
| [Signal programs](signal-program.md) | Value types, units, domains, sources, operators, stochastic keys, identity. |
| [Bindings and runtime](bindings-and-runtime.md) | Opportunities, targets, sampling, mappings, lifetimes, composition, capabilities, search. |
| [Effects and taxonomy](effects-and-taxonomy.md) | Closed effect registry, phases, composition algebras, taxonomy ledger. |
| [Network adapter](network.md) | Directed segments, paths, service models, media, routing, association, contacts. |
| [Storage adapter](storage.md) | Durability layers, service queues, caches, write dispositions, flush, media, arrays, 9p. |
| [Node faults and QEMU](node-and-qemu.md) | Node adapter, fault command ABI, safe boundaries, capabilities, inertness. |
| [Replay and observability](replay-and-observability.md) | Normalized traces, resolved-effect traces, replay modes, event log, checkpoints. |
| [Resource limits](resource-limits.md) | Scenario-owned limits, compiled ceilings, and failure behavior. |

## Source map

All model types live in
[`crucible-engine/src/model/fault_signal/`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/):

| Module | Owns |
| --- | --- |
| `mod.rs`, `canonical/`, `validation.rs` | `SignalProgram`, value/unit/domain enums, canonical material. |
| `evaluator.rs`, `evaluator/` | Deterministic evaluation, keyed choices, evaluator checkpoint. |
| `trace.rs`, `trace_import.rs`, `spatial.rs`, `sampler.rs` | Normalized traces, importers, spatial fields, inverse-CDF tables. |
| `binding.rs`, `binding/` | `FaultBinding`, selectors, sampling, mappings, search policy. |
| `binding_runtime.rs`, `binding_runtime/` | Evaluating bindings into `ResolvedBindingAction` batches. |
| `opportunity.rs` | Targets, operations, `FaultCoordinate`, `FaultOpportunity` identity. |
| `effect_registry.rs`, `effect_registry/` | `EffectKind` descriptors, phases, lifetimes, composition algebras. |
| `network_effect.rs`, `storage_effect.rs`, `node_effect.rs` | Closed per-domain effect parameters. |
| `effect_implementation.rs` | Production implementation records from which capability manifests derive. |
| `adapter_runtime.rs`, `adapter_runtime/` | `TransactionalFaultAdapters`: atomic prepare/commit across the three families. |
| `execution_runtime.rs` | `FaultExecutionRuntime`: one checkpoint surface for evaluator plus adapters. |
| `runtime.rs`, `runtime/` | Contribution tables, replay modes, resolved-effect traces, observations. |
| `search_materialization.rs` | Turning bounded mutation policies into fixed scenarios. |
| `plan.rs` | `FaultSignalPlan`, the sole admitted fault-program container. |
| `resource_limits.rs` | `FaultResourceLimits` registry. |

Production adapters:
[network](../../../../crates/crucible/crucible-daemon/src/vm_lifecycle/network_faults.rs),
[storage coordination](../../../../crates/crucible/crucible-daemon/src/vm_lifecycle/storage_faults.rs),
[block directive resolution](../../../../crates/crucible/crucible-qemu-host/src/storage_fault_resolver.rs),
[node/QEMU actions](../../../../crates/crucible/crucible-qemu-host/src/fault_action_sink.rs), and the
[owning production runtime](../../../../crates/crucible/crucible-qemu-host/src/production_fault_runtime.rs).
