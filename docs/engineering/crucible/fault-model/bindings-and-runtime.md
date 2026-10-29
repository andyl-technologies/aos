# Bindings, opportunities, and runtime state

Signals describe causes. This page describes how causes reach modeled hardware
at stable points without turning the signal language into an untyped mutation
API.

Source: [`binding.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/binding.rs),
[`binding/`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/binding/),
[`binding_runtime.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/binding_runtime.rs),
[`opportunity.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/opportunity.rs), and
[`runtime.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/runtime.rs).

## Opportunities

Network frames, block requests, memory accesses, interrupts, and clock reads
share an abstract lifecycle:

```text
produce -> admit -> queue -> resolve -> deliver
```

Storage refines it with `persist` and `visibility`, and the node adapter uses
architecture- and device-specific phases (`before_instruction`, `load`,
`raise`, `clock_read`, `execute`, and so on). `boundary` is an exact
scheduler/QEMU safe boundary with affected vCPUs quiescent. The complete
`FaultPhase` enum lives in the
[effect vocabulary](../../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_registry/vocabulary.rs).

An adapter constructs a `FaultOpportunity` before evaluating bindings:

```text
FaultOpportunity {
  adapter     network | storage | node (derived from the target kind)
  target      ResolvedFaultTarget
  operation   adapter-owned closed FaultOperation
  phase       FaultPhase
  coordinate  FaultCoordinate { virtual_ticks, retired_instructions? }
  sequence    adapter-owned stable operation sequence
  direction   optional FaultDirection
  payload     bounded OpportunityPayload metadata, never host pointers
  id          content hash of all of the above
}
```

The ID excludes host thread order, allocation addresses, hash-map order, and
callback order, so replaying the same schedule reconstructs the same ID before
any effect is evaluated. The adapter-owned sequence distinguishes otherwise
equal operations at the same coordinate. A search-injected or locked outcome
names the opportunity it replaces and fails if replay meets a different one.

`retired_instructions` is optional. Idle jumps may advance virtual time without
retiring instructions, so the instruction count is never inferred from logical
ticks. A node backend may *refine* a virtual-time-only coordinate with an
authentic retirement sample (`FaultCoordinate::accepts_backend_refinement`);
virtual time and any authored instruction count are immutable.

## Targets and selectors

Targets are typed identities from the world, not strings interpreted by an
effect. `FaultTargetKind` is closed (network interface, segment, medium, queue,
forwarder, path, attachment, contact; block device and range, storage
controller and array, 9p device; node, vCPU, register, memory range,
interrupt, clock source, accelerator). Identifiers are 1 to 96 ASCII bytes:
lowercase letter first, lowercase alphanumerics and single hyphens, ending
alphanumeric.

`TargetSelector` is one of:

| Selector | Resolution |
| --- | --- |
| `exact` | Exactly one target. |
| `target_set` | A canonical explicit set within one adapter domain. |
| `fault_domain` | A static common-cause domain resolved during admission. |
| `dynamic_path` | Network-only path membership with a versioned membership state machine. |

Selectors resolve to finite, canonically sorted sets during validation; only
dynamic path membership changes at runtime, through deterministic recorded
transitions. Empty results require an explicit, identity-bearing
`allow_empty`. Symbolic register and memory targets are resolved and
capability-checked before their first opportunity, and the resolution enters
the effect record.

An `OpportunityFilter` names the adapter, a nonempty operation set, phases, and
optional target kinds. Admission rejects any phase or target kind absent from
the effect's registry descriptor; an adapter never moves an effect to a nearby
phase.

## Binding shape

```text
FaultBinding {
  id, selector, input signals, sampling, mapping,
  typed effect specification, search policy, observability policy
}
```

One signal may feed many bindings, which is how correlated common-cause faults
are expressed. One binding may read several signals. Validation proves that
signal shapes match the mapping and effect parameters.

`BindingSampling`:

| Kind | Coordinate |
| --- | --- |
| `at_boundary` | Current global virtual-time boundary. |
| `at_opportunity` | Current adapter opportunity (requires a filter). |
| `at_change` | Exact discovered input change. |
| `cadence_nanos` | Exact positive multiples of the cadence. |
| `at_event` | Event coordinate projected from a declared parent. |

The event parent is `virtual_time`, `opportunity_operation`,
`opportunity_state`, or `node_counter` with an explicit node. Opportunity
parents require the matching filter. The parent is binding identity, so replay
never guesses an event's coordinate domain.

`BindingMapping`:

| Kind | Meaning |
| --- | --- |
| `active_when_true` | Boolean (optionally inverted) activates a persistent effect. |
| `active_when_equal` | Enum equality activates an effect. |
| `threshold` | Comparison with optional clear threshold and residence time. |
| `map_parameter` | A signal quantity becomes one effect parameter. |
| `piecewise_parameter` | Exact transfer function with explicit rounding and overflow. |
| `hazard` | A probability evaluated per opportunity by keyed choice. |
| `impulse_on_event` | Each input event produces one impulse. |
| `state_transition` | Input requests a transition from a declared transition table. |
| `service_profile` | Signals drive a time-varying capacity or service model. |

A `service_profile` pairs each input with a stable role ID and exact
`SignalShape` (for example a `distance` or `range` input in millimetres). The
ordered role/shape list participates in action identity and is revalidated on
checkpoint restore; unknown, duplicate, missing, or wrong-shaped roles fail
admission. A mapping result is either canonical effect parameters or an
explicit inactive result; clamping happens only when declared.

## Lifetimes

Every effect descriptor declares one or more `EffectLifetime` values:

- **persistent** transforms are active while their binding is active (bandwidth
  cap, read-only disk, clock drift). Deactivation removes only that binding's
  contribution; the rest are recombined.
- **opportunity** outcomes are resolved separately per operation (frame loss,
  I/O error, ECC event).
- **impulse** mutations happen once at a coordinate (memory bit flip, reset).
  They cannot be "healed"; a later binding may apply a distinct reversing
  effect, and replay keeps both.
- **state-machine** effects drive a declared transition system (flap,
  association, controller lifecycle).

There is no separate interval, permanent, or activate/heal fault form. A finite
interval is a Boolean pulse bound to a persistent effect; a permanent change is
a step; explicit activation is an event-sequence state transition; per-operation
probability is a hazard mapping at an opportunity. Scenarios using any other
fault schema are rejected before their fault contents are parsed.

## Composition and transactions

Applicable binding results are ordered by adapter, target, phase, effect, and
binding ID, and each effect family composes by its registry
`CompositionAlgebra` (see [effects and taxonomy](effects-and-taxonomy.md)).
Composition output that can affect later operations is part of the execution
fingerprint.

`TransactionalFaultAdapters` gives the network, storage, and node families one
atomic prepare/commit step. Binding evaluation produces a complete
`PreparedActionBatch` of `ResolvedBindingAction` values; a batch either commits
in every affected adapter or is rejected as a whole, and committed contribution
groups are the sole input to opportunity resolution. Host-owned network and
storage devices read typed actions from a `HostFaultActionSink`, so effects
retain their target, phase, mapping output, and binding identity all the way to
the device.

## Capabilities

Each effect descriptor names a versioned capability ID such as
`network.service-curve.v1`, `storage.volatile-cache-loss.v1`, or
`qemu.memory.mutate.v1`. A backend advertises a `FaultCapabilityManifest`
(backend ID, capability set, numeric bounds). Host manifests are derived from
the concrete adapters' implementation registries
([`effect_implementation.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_implementation.rs)),
so vocabulary membership alone never advertises support. Admission resolves
every binding to its required capabilities and fails closed when one is
missing. A lower-fidelity substitute would need its own explicit effect kind;
there is no implicit fallback. Locked replay requires the same capability
semantic version.

## Runtime and checkpoint state

`FaultRuntimeCheckpoint` carries the semantic version, signal-plan content
hash, resource limits, binding runtime (evaluator state, mapping state,
consumed opportunities, dynamic membership, scheduler cursor, active
contribution table, keyed search overrides), per-adapter checkpoint state, replay cursor and recorded
work items, retained effect hashes, and branch parent. `FaultExecutionRuntime`
owns evaluator and adapter state behind one checkpoint surface so neither can
be persisted without the other.

A fat checkpoint contains all mutable signal, binding, and adapter state
needed to resume without pre-checkpoint event-log history, except immutable
content-addressed artifacts. Trace chunks and lookup artifacts referenced by
state remain explicit store dependencies of exported savepoints.

## Search and fuzzing

Bindings declare a `BindingSearchPolicy`:

| Policy | Branches over |
| --- | --- |
| `fixed` | Nothing; the model result is used. |
| `branch_outcome` | Fired/not fired at selected opportunities, bounded by `maximum_branches`. |
| `branch_transition` | A finite list of state-machine transitions. |
| `branch_parameter` | A finite list of concrete parameter values. |
| `mutate_trace_window` | Finite concrete sample-replacement schedules within one bounded trace interval. |
| `mutate_mapping` | Finite concrete transfer-function point replacements. |

Search never branches over unbounded numeric ranges and never asks the runtime
to invent values. Mutation policies are materialized before guest start
([`search_materialization.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/search_materialization.rs))
into ordinary fixed-policy programs and bindings, bounded by
`search_choices_per_state`; exceeding the bound is an admission error. A
changed trace changes program identity, so every binding on that graph is
readmitted. Materialization provenance and generated artifact hashes stay with
the child scenario, which replays without the explorer.
