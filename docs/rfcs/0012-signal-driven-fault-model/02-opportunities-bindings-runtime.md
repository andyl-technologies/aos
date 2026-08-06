# 02 — Fault opportunities, bindings, effects, and runtime state

Signals describe causes. This file defines how causes reach modeled hardware at
stable points without turning the signal language into an untyped mutation API.

## 2.1 The common operation lifecycle

Network frames, block requests, sensor samples, memory accesses, interrupts, and
clock reads differ in payload and hardware semantics but share a useful abstract
lifecycle:

```text
produce -> admit -> queue -> resolve -> deliver
```

Not every adapter exposes every phase. A clock read may produce and resolve in
one boundary; a network frame may queue for a time-varying service model; a
sensor may autonomously produce samples before a guest reads them.

An effect attaches only at a phase declared by its adapter:

| Phase | Representative effects |
| --- | --- |
| `produce` | Sensor bias/noise, source timestamp error, generated interrupt. |
| `admit` | Immediate rejection, link outage, read-only disk, bus arbitration loss. |
| `queue` | Capacity restriction, priority starvation, congestion, service stall. |
| `resolve` | Loss, error status, timeout, corruption, stale data, machine check. |
| `deliver` | Added delay, duplication, reordering, interrupt drop, late completion. |
| `transition` | Reset, handoff, power loss, reconnect, calibration loss. |

- **[OPP-1]** Every effect kind MUST declare the adapter, lifecycle phase, target
  kinds, opportunity context, and output mutation it is permitted to use.
- **[OPP-2]** An adapter MUST reject a binding whose effect is attached to an
  unsupported phase; it MUST NOT silently move the effect to a nearby phase.

## 2.2 Stable opportunity identity

A `FaultOpportunity` is canonical context for one possible application:

```text
FaultOpportunity {
  domain:       network | block | sensor | clock | memory | cpu | interrupt | ...
  target:       stable target identity
  operation:    adapter-defined closed enum
  phase:        lifecycle phase
  coordinate:   virtual time and optional node counter
  sequence:     adapter-owned stable operation sequence
  direction:    optional typed direction
  subtarget:    optional address/range/channel/vector/cell/register selector
  payload_meta: bounded canonical metadata, never ambient pointers
}
```

The opportunity ID is a content digest of canonical context. Payload bytes are
not necessarily duplicated into the ID; an adapter declares the immutable
payload digest or stable producer/sequence identity required to distinguish
operations.

- **[OPP-3]** Opportunity identity MUST be independent of host thread scheduling,
  allocation address, hash-map order, and callback order.
- **[OPP-4]** Replaying the same schedule to the same operation MUST reconstruct
  the same opportunity ID before evaluating effects.
- **[OPP-5]** An adapter MUST use a monotonically recorded sequence or another
  proven stable identity when two otherwise equal operations can occur at the
  same coordinate.
- **[OPP-6]** Search-injected opportunity outcomes MUST name the opportunity ID
  they replace and MUST fail if replay encounters a different opportunity.

## 2.3 Targets and selectors

Targets are typed scenario identities, not free-form strings interpreted by an
effect. Initial target classes are:

- node, vCPU, register, interrupt vector, clock source;
- physical or virtual memory range and named symbol resolved before execution;
- network endpoint, interface, directed link, segment, path, queue, switch,
  router, shared medium, cell/sector, beam, gateway, or failure domain;
- block/flash device, namespace/LUN, queue, sector/range, erase block, or cache;
- filesystem/9p device and operation class;
- sensor device, channel, axis, sample stream, calibration, or timestamp source;
- actuator, bus/controller, address, message class, or peripheral function;
- power source, rail, PSU, PDU, UPS, battery, charger, thermal zone, fan, or
  cooling loop;
- environment field or enclosure.

Selectors may name one object, an explicit set, or a closed query over static
world metadata. Dynamic query results are sorted by canonical target identity.

- **[OPP-7]** A selector MUST resolve to a finite typed target set during scenario
  validation, except selectors intentionally bound to dynamic path members or
  associations; those MUST define deterministic membership transitions.
- **[OPP-8]** Empty selectors MUST be rejected unless `allow_empty = true` is
  explicit and identity-bearing.
- **[OPP-9]** Symbolic memory/register/device targets MUST be resolved and
  capability-checked before their first opportunity; resolution output belongs
  to reproduction metadata.

## 2.4 Binding shape

A binding consists of:

```text
FaultBinding {
  id
  selector
  input signal output(s)
  sampling rule
  mapping/activation rule
  typed effect specification
  composition group, if the adapter defines one
  search policy
  observability policy
}
```

One signal output may feed many bindings. One binding may use several signal
outputs, for example temperature plus fan state, or position plus interference
plus cell load.

- **[BIND-1]** Binding IDs MUST be unique and stable. They are decision-domain
  separators, event-log identities, and deterministic composition tie-breakers.
- **[BIND-2]** Binding validation MUST prove that signal types and units match the
  mapping and effect parameters.
- **[BIND-3]** A binding MUST NOT call arbitrary adapter code. It selects one
  closed effect kind whose schema and application contract are versioned.

## 2.5 Mapping and activation rules

Bindings use one closed sampling vocabulary:

| `sampling` | Required fields | Deterministic coordinate |
| --- | --- | --- |
| `at_boundary` | none | Current global virtual-time boundary. |
| `at_opportunity` | opportunity filter | Current adapter opportunity coordinate. |
| `at_change` | none | Exact discovered input-change boundary. |
| `cadence_nanos` | positive cadence | Exact multiples of the cadence. |
| `at_event` | `event_parent` | Typed event coordinate projected from the declared parent. |

`event_parent` is exactly `virtual_time`, `opportunity_operation`,
`opportunity_state`, or `node_counter` with an explicit node signal ID. Event
bindings accept only event-domain inputs. Opportunity parents require and
inherit the matching opportunity filter; node-counter parents require an exact
retired-instruction coordinate. The parent kind and node ID are canonical
binding identity, so replay never guesses an event's coordinate domain.

Bindings use a closed mapping vocabulary:

| `kind` | Meaning |
| --- | --- |
| `active_when_true` | Boolean signal activates a stateful effect. |
| `active_when_equal` | Enum/state equality activates an effect. |
| `threshold` | Comparison with optional hysteresis and residence time. |
| `map_parameter` | Convert a signal quantity into one effect parameter. |
| `piecewise_parameter` | Exact lookup/piecewise-linear transfer function. |
| `hazard` | Signal controls a probability evaluated per opportunity. |
| `impulse_on_event` | Each typed input event produces one impulse effect. |
| `state_transition` | Input event/state requests an adapter state transition. |
| `service_profile` | Signal controls a time-varying capacity/service model. |

Every `service_profile` declaration pairs each canonical signal input with an
effect-specific role and an exact `SignalShape`. Roles are stable identifiers,
not inferred from signal names or vector position. For example, the RF channel
contract uses `distance`, `orientation`, aggregate `interference`, and `fading`;
the contact contract uses `range`. The ordered role/shape vector crosses the adapter seam,
participates in action identity, and is revalidated during checkpoint restore.
Unknown, duplicate, missing, or wrong-shaped roles fail admission.

Mappings may clamp only when the clamp is explicit. A loss probability above
one, negative bandwidth, nonexistent error code, or invalid target address is a
validation/runtime error according to whether it can be detected before
evaluation.

- **[BIND-4]** The mapping result MUST be canonical typed effect parameters or an
  explicit inactive result.
- **[BIND-5]** A probabilistic hazard MUST use a keyed opportunity decision as
  specified by [SIG-20]/[SIG-21], not an evaluator-global RNG cursor.
- **[BIND-6]** A signal transition that activates a persistent transform and an
  opportunity that samples that transform at the same coordinate MUST have an
  adapter-declared total order.

The default boundary order is:

```text
heal expired state
-> apply signal transitions
-> apply adapter lifecycle transitions
-> construct opportunity
-> evaluate bindings
-> combine effects
-> resolve operation
-> record outcomes
```

Adapters may refine this order but cannot contradict scheduler causality.

## 2.6 Persistent transforms versus impulses

Effects have one of three lifetime classes:

1. **Persistent transform:** active while a binding state is active, such as
   bandwidth restriction, sensor bias, stuck bit, clock drift, or read-only disk.
2. **Opportunity outcome:** resolved separately for each operation, such as
   packet loss, I/O error, delayed sample, or corrected ECC event.
3. **Impulse mutation/transition:** occurs once at a coordinate, such as a memory
   bit flip, reset, handoff start, interrupt injection, or power transient.

An impulse is not an active boolean fault and cannot be healed. A later binding
may reverse it through a distinct modeled effect, but replay retains both
transitions.

- **[BIND-7]** Every effect schema MUST declare its lifetime class.
- **[BIND-8]** An impulse MUST record whether application succeeded, the resolved
  concrete target, and enough before/after evidence to detect incompatible locked
  replay.
- **[BIND-9]** Healing a persistent transform MUST remove only the named binding
  contribution; remaining overlapping effects are recombined deterministically.

## 2.7 Composition algebra

The generic evaluator orders applicable binding results by adapter, target,
phase, effect family, and binding ID. Each effect family declares an algebra,
for example:

| Effect family | Representative composition |
| --- | --- |
| Availability/outage | Logical OR of outage causes; all causes must clear. |
| Added latency | Saturating or checked sum, declared by adapter. |
| Capacity caps | Minimum cap, or simultaneous service constraints if semantically distinct. |
| Loss hazards | Independent keyed hazards with deterministic any-fires evaluation. |
| Burst state | Shared state source, not independent probabilities. |
| Clock offset | Checked sum. |
| Clock rate | Exact rational multiplication with bounds. |
| Sensor bias | Checked sum by unit. |
| Sensor gain | Exact rational multiplication. |
| Data transforms | Stable binding-ID order with each before/after digest recorded. |
| Fatal outcomes | Adapter-defined severity precedence or explicit conflict rejection. |
| Reset policies | Strongest declared lifecycle effect, with deterministic tie-breaking. |

- **[BIND-10]** Composition MUST be associative and commutative where the physical
  semantics permit it. Where order matters, the adapter MUST define stable order
  and record intermediate evidence.
- **[BIND-11]** Incompatible simultaneous effects MUST be rejected or resolved by
  a documented severity/precedence lattice. Container iteration order is never a
  resolution policy.
- **[BIND-12]** Composition output MUST be included in the execution fingerprint
  whenever it can affect future operations.

## 2.8 Adapter contract

Each domain adapter provides:

```text
DomainAdapter {
  target schemas
  operation and phase enums
  opportunity constructor
  effect schemas
  validation and capability requirements
  combination algebra
  apply(effect_set, operation, state)
  event-log projection
  checkpoint codec
  locked-replay verifier
}
```

Adapters are ordinary hermetically built Crucible code, not runtime plugins
loaded from scenario-controlled paths. A future extension mechanism requires a
separate RFC and a deterministic ABI.

- **[BIND-13]** Adapter application MUST be a pure state transition over modeled
  state, operation, combined effects, and recorded/keyed decisions.
- **[BIND-14]** Adapter state that can influence later behavior MUST be bounded,
  canonically serialized, hashed, checkpointed, and restored.
- **[BIND-15]** Accepted effects MUST be tested through their real production
  backend. Tests MAY invoke an adapter's pure state transition directly for
  algebra and state-machine coverage, but MUST NOT introduce a mock, fake, or
  test-double backend or count direct invocation as application evidence.

## 2.9 Capability negotiation and fidelity

Capabilities are fine-grained, versioned identifiers such as:

```text
network.link.profile.v1
network.path.route-transition.v1
block.torn-write.v1
block.volatile-cache-loss.v1
qemu.memory.bit-flip.physical.v1
qemu.cpu.machine-check.x86_64.v1
qemu.interrupt.drop.v1
qemu.clock.drift.v1
```

A backend returns supported capabilities plus bounds such as maximum trace
channels, memory mutation width, address spaces, supported clock sources, and
maximum signal-state bytes.

- **[BIND-16]** Scenario admission MUST resolve every binding to required
  capabilities and fail closed when the selected backend does not provide them.
- **[BIND-17]** A lower-fidelity substitute MUST have a different explicit effect
  kind or fidelity mode included in scenario identity, and that mode MUST itself
  be completely implemented and documented. Missing functionality is not a
  fidelity mode.
- **[BIND-18]** Locked replay MUST verify the same capability semantic version or
  reject the replay before applying resolved effects. The implementation PR does
  not include capability-version compatibility mappings.

## 2.10 Runtime and checkpoint state

The scheduler/checkpoint state gains:

- signal-program content address and evaluator version;
- state for every stateful signal node;
- last evaluated coordinates and trace chunk cursors;
- active persistent binding contributions;
- adapter-combined effective tables/profiles;
- per-binding transition sequence;
- keyed search overrides;
- path association, route, medium, service-queue, thermal, battery, wear, and
  other adapter states as applicable;
- retained hashes of resolved effect records required by the replay oracle.

- **[BIND-19]** A fat checkpoint MUST contain all mutable signal, binding, and
  adapter state needed to resume without reading pre-checkpoint event-log
  history, except immutable content-addressed source artifacts.
- **[BIND-20]** A thin checkpoint MUST reconstruct the same state by reducing the
  recorded schedule from an ancestor and verify the same materialized-state ID.
- **[BIND-21]** Trace chunks and lookup artifacts referenced by checkpoint state
  MUST remain explicit store dependencies and GC roots of exported savepoints.

## 2.11 Search and fuzzing

Not every signal sample is a useful branch. Bindings declare search policy:

- `fixed`: never branch; use model result;
- `branch_outcome`: branch fired/not-fired at selected opportunities;
- `branch_transition`: branch a state-machine transition;
- `branch_parameter`: choose among a finite declared parameter set;
- `mutate_trace_window`: fuzz a bounded normalized trace interval;
- `mutate_mapping`: fuzz declared transfer-function points within bounds.

Search choice identity includes signal program, binding, opportunity, and
candidate set. State-space reduction may treat independent opportunity choices
as commutative only when adapter dependency analysis proves disjoint targets and
state.

- **[BIND-22]** Search MUST NOT branch continuously over unbounded numeric signal
  ranges. Candidate sets and mutation bounds MUST be finite and explicit.
- **[BIND-23]** A search result MUST export the concrete signal/binding choices
  needed for ordinary locked replay without rerunning the explorer.
- **[BIND-24]** Minimization MAY remove signal nodes, trace intervals, bindings,
  or opportunity outcomes only while preserving schema validity, source
  provenance, and the selected failure signature.

## 2.12 Single execution path and schema replacement

Finite, permanent, activate, and heal behavior remains expressible, but only in
the signal/binding language:

| Required behavior | Sole representation |
| --- | --- |
| finite interval | Boolean pulse plus a persistent binding |
| permanent transition | Boolean step plus a persistent binding |
| explicit activation/deactivation | Event-sequence state transition consumed by a binding |
| per-operation probability | Probability signal sampled by a hazard mapping at a stable opportunity |

These are examples for rewriting scenarios, not an internal lowering table. The
old `FaultPlanEntry`, `inject_fault`, `heal_fault`, fault-tag activation events,
and their parser/builder/runtime variants are removed in the implementation PR.
Old scenario schema versions fail admission with a versioned migration error;
Crucible does not parse and reinterpret their fault contents.

- **[BIND-25]** The implementation MUST expose exactly one authoring schema,
  canonical representation, scheduler path, active-contribution representation,
  and adapter-application path for faults. No compatibility translator, shadow
  evaluator, or old-schema feature flag may remain.
- **[BIND-26]** Removal MUST include public builders, CLI options, codecs,
  random generators, examples, tests, event variants, search actions, state
  fields, and documentation for the old path. Repository-wide guards MUST fail
  if the retired type or variant names are reintroduced outside a migration
  guide or historical RFC text.
