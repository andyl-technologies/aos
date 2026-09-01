# Migrating to signal-driven faults

Crucible accepts one fault schema: `signal_bindings_v2`. Earlier fault entries,
imperative activation/healing calls, tagged active-fault state, and launch-time
clock-skew declarations are not compatibility paths. Parsing stops before typed
lowering when `fault_model = "signal_bindings_v2"` is absent or different.

There is deliberately no field-by-field translator. A translation that guessed
signal identity, interpolation, sampling keys, effect lifetime, or opportunity
phase could produce a different experiment while appearing to preserve it.
Re-author the behavior as a signal graph and binding, regenerate canonical TOML,
and treat the resulting scenario, program, binding, and artifact IDs as new
content identities.

See the [exhaustive reference](reference.md#plans-signals-bindings-and-faults)
for every accepted field and value. The implementation contracts are the
[signal schema](../../../crates/crucible/src/model/fault_signal/plan.rs),
[binding schema](../../../crates/crucible/src/model/fault_signal/binding.rs), and
[closed effect registry](../../../crates/crucible/src/model/fault_signal/effect_registry.rs).

## Required plan marker

Every standalone plan uses the marker at its root:

```toml
fault_model = "signal_bindings_v2"
```

A scenario envelope places the same marker below `[plan]`:

```toml
[plan]
fault_model = "signal_bindings_v2"
```

Unknown fields, older marker values, missing markers, and mixed old/new forms are
errors. The control RPC is version 5; clients and servers with a different ABI
version reject one another during admission.

## Behavior mapping

| Earlier intent | Signal-driven representation | Important choices to make explicit |
| --- | --- | --- |
| Fault active for a fixed interval | Pulse or piecewise signal plus a persistent binding | Coordinate axis, inclusive boundaries, unit, and value outside the interval |
| Fault starts and remains active | Step or piecewise signal plus a persistent binding | Initial value, transition coordinate, and effect removal behavior |
| Explicit activate/deactivate commands | Event-sequence source or state-transition operator | Event identity, total ordering at equal coordinates, and complete transition table |
| Independent probability on each operation | Opportunity binding with a hazard mapping | Opportunity phase, deterministic key domains, exact probability, and retry identity |
| Random duration or rate | Counter-based stochastic signal/operator | Distribution, finite bounds, sampling cadence, and scenario-owned key domains |
| Named fault tag used by a predicate | Observe the binding/effect evidence or a named signal output | Exact binding ID, target, effect kind, and assertion semantics |
| Static guest clock offset or drift | `clock.transform` effect bound to a clock-source target | Offset/drift fields, clock source, lifetime, rounding, and transition coordinate |
| Crash followed by restart policy | `node.lifecycle` state-machine effect | Stop/reset/start states, exact transitions, persistence, and restart coordinate |
| Network delay/loss/corruption entry | Network effect bound to the appropriate interface, segment, medium, queue, path, attachment, contact, or forwarder | Physical target, packet/opportunity key, composition, queue/in-flight policy, and effect phase |
| Block or 9p fault entry | Storage effect bound to a device, byte range, controller, array, or 9p target | Operation class, byte/range selector, persistence opportunity, recovery event, and result policy |

## Migration procedure

1. Inventory the experiment's intended physical cause separately from its
   observable effect. Encode reusable causes as signals and hardware behavior as
   bindings to closed effect kinds.
2. Declare every signal value type, unit, coordinate basis, boundary policy,
   interpolation rule, missing-data rule, rounding rule, and overflow rule.
3. For stochastic behavior, select the documented deterministic key domains.
   Do not reuse an old random seed as an implicit per-operation stream.
4. Resolve targets through the World model. Do not copy cached target hashes;
   canonical lowering derives them from the current World.
5. Select the binding lifetime and exact phase. Persistent, state-machine, and
   opportunity effects have different checkpoint and replay behavior.
6. Configure all resource limits needed by the graph, trace, binding, replay,
   adapter, and event-retention state. Admission fails before execution if a
   declared or restored object exceeds them.
7. Generate canonical TOML with the public builder/codec, validate it against
   the current World and live capability manifests, then record new golden IDs.
8. Run the scenario once in recording mode and replay the resolved-effect trace.
   Require complete trace consumption and byte-identical terminal evidence.

## What does not migrate

- Old checkpoint bytes and RPC payloads are not decoded as the new runtime
  state. Start from a newly admitted signal-driven scenario.
- Old scenario IDs, binding IDs, random decision identities, and reproduction
  artifacts do not retain identity across the schema replacement.
- Sensor targets remain specification-only until QEMU exposes real sensor
  devices. Plans that request a sensor adapter are rejected rather than ignored
  or simulated by a test double.
- There is no fallback that approximates node timing, CPU, memory, network, or
  storage effects in the scheduler. Production effects must be admitted and
  applied by their live adapter.

If admission reports an unsupported pre-signal schema, add the current marker
only after the plan has actually been re-authored. Adding the marker to old
fields does not make them valid and unknown-field rejection will identify the
remaining obsolete content.
