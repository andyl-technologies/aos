# Fault bindings

A fault binding is the only bridge from signal values to production adapter
mutations. It says when inputs are sampled, which concrete targets and
opportunities are eligible, how values become effect parameters, how concurrent
effects compose, and what evidence is retained.

Read [Signal programs](signals.md) first when designing causes. Use the
[effect guides](README.md#effect-guides) to select an executable effect and the
[reference](reference.md#plan-signals-bindings-and-faults) for exact TOML shapes.

## Binding contract

Each `[[plan.fault_binding]]` contains:

| Field | Contract |
| --- | --- |
| `id` | Unique stable binding identity. |
| `signals` | Ordered, nonempty exported signal IDs; maximum 128. |
| `sampling` | Boundary, opportunity, change, cadence, or typed event sampling. |
| `selector` | A finite, homogeneous target set resolved against the declared World. |
| `mapping` | Closed typed transfer from signal inputs to effect parameters. |
| `effect` | One effect kind, parameter payload, phase, and lifetime contract. |
| `opportunity_filter` | Required where opportunity sampling cannot be inferred; adapter, operations, phases, optional target kinds. |
| `composition` | Effect-family algebra used when multiple active bindings overlap. |
| `search` | Fixed policy or a finite, declared branch/mutation space. |
| `observability` | Sample and mapped-value retention policy. |

Admission validates all of these together. A mapping that produces a valid
parameter type can still be rejected if its selected target, phase, lifetime,
operation, capability, or composition algebra is illegal for that effect.

## Sampling

| Sampling kind | Coordinate and behavior | Typical use |
| --- | --- | --- |
| `at_boundary` | Once at each deterministic scheduler boundary | Global modes and slowly changing state. |
| `at_opportunity` | Once for each matching typed adapter opportunity | Per-packet, per-I/O, per-instruction, and similar effects. |
| `at_change` | Whenever an input changes | Analytic transitions without polling. |
| `cadence_nanos` | At a positive exact virtual-time cadence | Periodic control or sampling. |
| `at_event` | At one typed event with explicit parent coordinate | Event-triggered effects that preserve causality. |

`at_event` parents are `virtual_time`, `node_counter { node }`,
`opportunity_operation`, or `opportunity_state`. Opportunity parents require a
matching opportunity filter. Event ordering and the parent coordinate become
replay evidence.

Do not use a cadence to approximate an opportunity-level probability. Sample a
keyed stochastic signal at the opportunity so retries, filtering, and replay
retain stable identities.

## Target selectors

Selectors are resolved and canonicalized at admission:

- `exact` contains exactly one concrete target.
- `target_set` contains an explicit finite set.
- `fault_domain` names a static topology domain and retains its resolved set.
- `dynamic_path` names a versioned network path, an initial set, and membership
  semantic version `1`; it is network-only.

A resolved set is empty only when `allow_empty` explicitly permits it. It may
contain at most 65,536 targets, no duplicates, and targets from only one adapter.
Dynamic membership changes are deterministic state transitions, not ad hoc host
queries.

The complete target-kind vocabulary is:

| Adapter | Target kinds |
| --- | --- |
| Network | `network_interface`, `network_segment`, `network_medium`, `network_queue`, `network_forwarder`, `network_path`, `network_attachment`, `network_contact` |
| Storage | `block_device`, `block_range`, `storage_controller`, `storage_array`, `ninep_device` |
| Node | `node`, `vcpu`, `register`, `memory_range`, `interrupt`, `clock_source`, `accelerator` |

Sensor targets are not executable in the current schema. See
[Topology](topology.md) for the objects from which targets are resolved.

## Opportunity filters

An opportunity filter has one adapter, a nonempty operation set, a nonempty
phase set, and optionally a target-kind restriction. Every operation must
belong to the adapter. Every phase and target kind must be legal for the chosen
effect.

```toml
[plan.fault_binding.opportunity_filter]
adapter = "network"
operations = ["network_transmit", "network_receive"]
phases = ["admit"]
target_kinds = ["network_interface"]
```

The closed operation vocabulary has 22 network operations, 13 storage
operations, and 27 node/CPU/memory/interrupt/clock/accelerator operations. Use
the [operation table](reference.md#fault-opportunity-operation-values) rather
than inventing names. Filters are predicates over opportunities already
declared by an adapter; they do not create new observation points.

## Mapping signal values

Mappings are closed, typed functions. They cannot call arbitrary code or mutate
an adapter directly.

| Mapping kind | Input-to-output rule | Authoring constraints |
| --- | --- | --- |
| `direct` | One input is already the complete effect parameter value | Exact type, unit, and lifetime shape match. |
| `boolean_gate` | Boolean selects inactive/active payload | Both payloads are complete and equal-shaped. |
| `threshold` | Ordered input selects below/at-or-above payload | Threshold shares input shape and unit. |
| `piecewise_constant` | Ordered breakpoints select a payload | Strict ordering and explicit before/after coverage. |
| `piecewise_linear` | Ordered points interpolate numeric parameters | Exact rounding/overflow; bounded, compatible shapes. |
| `enum_map` | Enum variant selects a payload | Exhaustive over the declared enum schema. |
| `parameter_set` | Inputs fill named fields of a parameter record | Names and arity match the effect's closed schema. |
| `state_transition` | Value selects a registered transition table entry | Table is declared, finite, and compatible. |
| `service_profile` | Value selects a named physical-input service profile | Profile exists in the policy registry and matches the effect. |

Mapping declarations and candidate sets are capped at 4,096. Piecewise tables
must cover their domain explicitly; out-of-range behavior is not inferred.
Mapped parameters are validated again by the effect implementation before an
adapter command is emitted.

## Phases and lifetimes

Phases locate an effect within a typed operation:

| Phase | Meaning |
| --- | --- |
| `admit` | Before an operation is accepted. |
| `resolve` | While a target, route, result, or physical outcome is resolved. |
| `enqueue` | When work enters a modeled queue. |
| `service` | While bounded work consumes a service resource. |
| `deliver` | At completion or delivery to the consumer. |
| `transition` | At a topology, device, or state transition. |
| `observe` | At a read-only observation boundary. |

Not every adapter exposes every phase, and every effect descriptor lists its
legal subset. Choosing an earlier phase can change whether in-flight work is
affected, so phase is part of the effect's semantic identity.

Lifetimes state how long mapped parameters remain active:

| Lifetime | Behavior |
| --- | --- |
| `opportunity` | Applies only to the sampled operation. |
| `until_change` | Persists until the binding maps a different value. |
| `duration_nanos` | Persists for an exact positive virtual duration. |
| `count` | Applies to a bounded number of matching opportunities. |
| `state` | Persists as declared adapter state until a transition replaces it. |

Deactivation restores the declared baseline or the composition result of other
active bindings. Stateful effects and duration/count lifetimes are checkpointed.

## Composition

Overlapping active bindings must use the effect family's declared algebra.
Crucible rejects ambiguous mixtures instead of relying on activation order.

| Algebra | Combination rule | Common family |
| --- | --- | --- |
| `exclusive` | At most one active value | State machines and complete policy replacements. |
| `latest_by_coordinate` | Greatest canonical activation coordinate wins | Versioned state transition. |
| `minimum` | Smallest value wins | Capacity/rate ceilings. |
| `maximum` | Largest value wins | Delay or severity floors. |
| `sum_saturating` | Sum with declared saturation | Additive delays or load. |
| `product_probability` | Independent probabilities combine exactly | Loss/failure probability. |
| `boolean_any` | Active if any contributor is true | Gating or availability conditions. |
| `ordered_pipeline` | Apply transformations in canonical binding order | Payload/result transformations. |
| `set_union` | Canonical union of selections | Recipient or candidate sets. |
| `service_intersection` | Most restrictive compatible service constraints | Rate/IOPS/token/queue service. |

Canonical order is based on stable identities and coordinates, never host thread
timing. The effect registry is authoritative for which algebra an effect accepts.

## Search policy

Search never invents fault values. A binding declares a finite policy that is
materialized before QEMU starts:

| Policy | Search dimension |
| --- | --- |
| `fixed` | No binding variation. |
| `branch_outcome` | Up to `maximum_branches` mapped outcomes. |
| `branch_transition` | One of the declared transition candidates. |
| `branch_parameter` | One named parameter takes one declared typed candidate. |
| `mutate_trace_window` | Declared trace samples in a fixed time window take declared replacements, under `maximum_mutations`. |
| `mutate_mapping` | Declared mapping point indices take complete replacement points, under `maximum_mutations`. |

The bounded Cartesian product consumes the same global `--max-states` budget as
schedule-frontier expansion. Each materialized scenario root costs one state.
Findings retain the exact ordered mutation recipe and authenticated signal
object closure, so replay does not depend on the campaign's working store.

## Observability and evidence

`observability.samples` is `every_sample`, `changes_and_effects`, or
`every_nth { stride }`. A binding can also retain inactive opportunities and
complete mapped values. The default retains changes/effect-relevant samples,
omits inactive opportunities, and retains mapped values.

More retention improves diagnosis but increases trace and artifact size. Even
when a value is omitted, canonical digests and effect application evidence
preserve replay validation. Evidence identifies binding, sample coordinate,
input digest, mapping result digest, target, opportunity, phase, lifetime,
composition result, capability decision, adapter command/result, and search
mutation provenance where applicable.

## Admission checklist

Before running a campaign, verify:

1. Every input is exported, acyclic, and shape/unit compatible with the mapping.
2. The selector resolves to the intended homogeneous targets and empty matches
   are intentional.
3. Sampling uses the causal coordinate that should make replay identities stable.
4. Opportunity adapter, operations, phases, and target kinds agree.
5. Effect parameters, phase, lifetime, and composition are legal in the
   [effect registry](reference.md#exhaustive-effect-registry).
6. Required topology policy objects and packaged capabilities exist.
7. Search candidates and all history/work limits are finite and campaign-sized.
8. Observability retains enough information to explain failures.

Admission and capability negotiation happen before guest execution. Unsupported
or internally inconsistent bindings fail closed rather than becoming no-ops.

