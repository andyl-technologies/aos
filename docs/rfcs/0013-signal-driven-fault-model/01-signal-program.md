# 01 — Typed deterministic signal programs

This file defines the reusable cause model. A `SignalProgram` turns immutable
sources and checkpointed state into typed values or events. It does not know how
to drop a frame, corrupt a disk read, bias a sensor, or reset a machine; those
semantics belong to bindings and adapters.

## 1.1 Signal values and units

A canonical signal value is one of:

```text
bool
i64 / u64
ratio(numerator: i64, denominator: u64)
duration_nanos(u64)
rate_per_second(u64)
probability_millionths(u32)
enum(schema_id, variant_id)
event(schema_id, canonical_payload)
vector2(quantity, quantity)
vector3(quantity, quantity, quantity)
```

A scalar or vector quantity has a declared unit and decimal scale. Initial
standard units include virtual nanoseconds, millimetres, millimetres per second,
millidegrees, millidegrees Celsius, microvolts, microamps, microwatts,
millidecibels, millidecibel-milliwatts, bits per second, operations per second,
parts per million, and probability millionths.

- **[SIG-1]** Every signal output MUST have a statically known type, unit, and
  scale. Graph validation MUST reject incompatible operator inputs and implicit
  unit conversion.
- **[SIG-2]** Canonical values and intermediate arithmetic MUST use integers or
  exact rationals with specified overflow and rounding behavior. A scenario
  serializer MUST NOT emit native floating-point signal values.
- **[SIG-3]** Unit conversion MUST be an explicit graph node whose source unit,
  destination unit, rational scale, offset, rounding direction, and overflow
  policy participate in scenario identity.

The implementation MUST use checked `i128`/`u128` intermediates and
validated `i64`/`u64` stored values. Saturation is never implicit: a node chooses
`error`, `saturate`, or a validated proof that overflow is impossible.

## 1.2 Evaluation domains

Signals do not all advance on one implicit clock. Each source and stateful node
declares an evaluation domain:

| Domain | Coordinate | Typical uses |
| --- | --- | --- |
| `virtual_time` | global virtual nanoseconds | power, weather, load, scheduled outages |
| `node_counter` | node ID and retired-instruction coordinate | CPU exposure, instruction-triggered events |
| `operation` | stable opportunity ID and ordinal | packet, block, sensor, memory, clock, or interrupt choices |
| `spatial` | position plus optional orientation | path loss, obstruction, vibration zone, temperature field |
| `event` | typed event sequence | handoff, reset, alarm, recorded discrete failures |
| `state` | prior checkpointed model state | thermal, battery, wear, queue, filter, Markov, hysteresis |

One graph may combine domains only through explicit sampling nodes. For example,
`sample_spatial(position_at(virtual_time), attenuation_field)` converts a
spatial field into a virtual-time signal. A disk error hazard samples a
virtual-time vibration signal at a disk-operation opportunity.

- **[SIG-4]** Every evaluation MUST carry an explicit domain coordinate. A node
  MUST NOT read a coordinate outside its domain except through a typed sampling
  or projection operator.
- **[SIG-5]** Guest-visible clocks MUST NOT implicitly drive canonical signal
  evaluation because a clock fault could create a causal cycle. A scenario MAY
  explicitly sample a guest clock only through a delayed observation edge whose
  prior value is checkpointed.
- **[SIG-6]** Live host time, live host sensors, ambient host network input, and
  unrecorded external callbacks MUST NOT be canonical signal domains.

## 1.3 Source nodes

### Constant and analytic sources

| `kind` | Parameters | Output |
| --- | --- | --- |
| `constant` | typed value | Same value everywhere. |
| `step` | ordered `(coordinate, value)` points | Piecewise-constant value. |
| `pulse` | start, duration, inactive and active values | One exact interval. |
| `periodic_pulse` | epoch, period, width, phase, values | Repeating interval. |
| `ramp` | start/end coordinates and values | Exact linear ramp. |
| `triangle` | epoch, period, minimum, maximum | Periodic triangle wave. |
| `sawtooth` | epoch, period, minimum, maximum | Periodic exact ramp/reset. |
| `event_sequence` | ordered coordinates and payloads | Discrete typed events. |

Sine waves are not a primitive because a portable transcendental implementation
is unnecessary for the core contract. A sampled lookup table can represent a
calibrated periodic waveform when needed.

### Trace sources

A trace source selects one channel from a normalized trace artifact and declares:

- trace object content address;
- channel ID and expected unit/type;
- source-time to simulation-time affine mapping;
- interpolation (`exact`, `hold_previous`, `nearest`, or `linear`);
- behavior before the first and after the last sample (`error`, `hold`,
  `constant`, `repeat`, or `inactive`);
- missing-sample behavior (`error`, `hold`, `interpolate`, or `inactive`);
- optional quality/validity channel and rejection threshold.

- **[SIG-7]** Trace interpolation and extrapolation MUST be explicit and
  content-addressed. Missing samples MUST NOT silently become zero.
- **[SIG-8]** Linear interpolation MUST use exact multiply/divide arithmetic and
  a declared rounding direction. Duplicate timestamps are invalid unless the
  channel is explicitly an ordered event channel.
- **[SIG-9]** A trace source MUST identify both the canonical normalized trace
  and retained raw provenance as specified in
  [`05-recording-replay-observability.md`](05-recording-replay-observability.md).

### Spatial sources

Spatial signals represent a quantity over position, orientation, frequency,
time, or a subset of those axes:

| `kind` | Meaning |
| --- | --- |
| `point_set` | Samples at named points with nearest or validated interpolation. |
| `regular_grid` | Dense 2D/3D fixed-cell field. |
| `tiled_grid` | Content-addressed field chunks for a large city/facility. |
| `zone_map` | Polygon/polyhedron membership with priority and boundary rules. |
| `path_profile` | Quantity indexed by distance along a declared path. |
| `seeded_field` | Counter-based deterministic value keyed by quantized coordinate. |
| `transmitter_field` | Derived path-loss/antenna contribution from a transmitter. |

Coordinates use a declared reference frame. Geographic input is normalized into
a local integer Cartesian frame before canonical evaluation. The normalized
artifact records the geographic origin and projection metadata for provenance,
but evaluation uses integer millimetres.

- **[SIG-10]** Spatial boundary inclusion, grid quantization, interpolation,
  orientation convention, and coordinate frame MUST be explicit.
- **[SIG-11]** Seeded spatial fields MUST be keyed by stable field ID, scenario
  seed, quantized coordinates, and declared correlation scale. They MUST NOT
  consume a traversal-order RNG cursor.

### State and telemetry sources

Domain adapters may expose read-only typed telemetry such as queue depth,
temperature, battery charge, wear counter, serving cell, link utilization,
sensor validity, or node lifecycle. Telemetry edges are evaluated from the state
at the start of the current deterministic boundary. An effect applied at that
boundary cannot feed back into its own signal until a later boundary.

- **[SIG-12]** A telemetry dependency graph MUST be acyclic within one boundary.
  Feedback MUST include an explicit one-boundary delay or state node.
- **[SIG-13]** Every telemetry value used by a canonical signal MUST be included
  in materialized state or be a pure derivation of state already included there.

## 1.4 Pure operators

The closed initial operator set is:

| Family | Operators |
| --- | --- |
| Arithmetic | `add`, `subtract`, `multiply_ratio`, `divide_ratio`, `absolute`, `negate` |
| Bounds | `min`, `max`, `clamp` |
| Comparison | `equal`, `not_equal`, `less`, `less_equal`, `greater`, `greater_equal` |
| Logic | `all`, `any`, `not`, `select` |
| Mapping | `lookup_step`, `piecewise_linear`, `enum_map`, `unit_convert` |
| Time | `delay`, `sample_hold`, `window_min`, `window_max`, `window_mean` |
| Space | `distance`, `zone_contains`, `field_sample`, `orientation_delta` |
| Events | `edge_rising`, `edge_falling`, `merge_events`, `gate_events` |

Window operations specify an exact discrete sample cadence or operate over
source change points; they do not sample at an implementation-selected cadence.

- **[SIG-14]** The operator vocabulary MUST be closed and versioned. Unknown
  operators or fields MUST be rejected.
- **[SIG-15]** Graph validation MUST detect cycles, duplicate node IDs, missing
  inputs, type/unit mismatches, invalid ranges, impossible denominator values,
  unbounded retained state, and unsupported backend telemetry before execution.
- **[SIG-16]** Pure-node output MUST be a pure function of canonical inputs and
  coordinates and MAY be memoized by content address plus coordinate.

## 1.5 Stateful operators

Some physical behavior requires memory. Initial stateful nodes are:

| `kind` | State and behavior |
| --- | --- |
| `hysteresis` | Boolean state, high/low thresholds, optional minimum residence. |
| `debounce` | Candidate value and duration before committing a change. |
| `integrator` | Exact accumulated value over declared change intervals. |
| `leaky_integrator` | Integer recurrence with rational decay at fixed cadence. |
| `finite_state_machine` | Closed state/event transition table. |
| `markov_chain` | Closed states and exact transition probabilities at fixed opportunities. |
| `burst_process` | Good/bad state with deterministic transition opportunities. |
| `counter` | Count of typed input events with optional bounded reset. |
| `queue_model` | Bounded service/backlog state for an adapter-declared service curve. |

State machines cannot execute actions. Their output is state or events consumed
by bindings.

- **[SIG-17]** Every stateful node MUST declare its initial state, transition
  domain, state-size bound, and canonical serialization.
- **[SIG-18]** Stateful-node state and the coordinate through which it has been
  evaluated MUST be captured in checkpoints and execution fingerprints.
- **[SIG-19]** Restoring a checkpoint and advancing a stateful signal to a
  coordinate MUST produce the same transitions and values as uninterrupted
  execution.

## 1.6 Stochastic sources and hazards

Stochastic behavior is deterministic under the scenario seed. The initial
portable mechanisms are:

- independent probability at a stable opportunity;
- probability driven by another signal;
- a fixed-cadence finite Markov chain;
- a good/bad burst process;
- deterministic spatial noise fields;
- event-time sequences imported as traces.

Exponential and Weibull waiting-time samplers are required stochastic source
variants. They use the versioned exact integer lookup/interpolation algorithm in
[`09-normative-schema.md`](09-normative-schema.md), including its conformance
vectors and rounding rules. Implementations must not call a platform math
library and round the result.

- **[SIG-20]** A stochastic choice MUST be keyed by scenario seed, signal node
  ID, binding or consumer domain, and stable opportunity/transition identity.
- **[SIG-21]** A choice MUST consume no shared mutable RNG position. Repeating
  the same keyed choice MUST return the same result without depending on which
  other signals were evaluated.
- **[SIG-22]** Search MAY replace selected stochastic keyed results with explicit
  branch decisions, but the selected result and continuation identity MUST enter
  the schedule.

## 1.7 Change discovery and scheduler interaction

A virtual-time signal reports one of:

- its exact next change coordinate;
- a conservative lower bound on the next possible change;
- `opportunity_only`, meaning it changes only when sampled at a hardware
  opportunity;
- `end`, meaning it cannot change again.

Analytic steps, pulses, trace samples, event sequences, and finite-state timers
can report exact changes. Piecewise-linear values need not schedule every value;
bindings request exact threshold crossings or sample at opportunities. A
threshold mapper over a piecewise-linear input calculates its next exact crossing
with rational arithmetic.

- **[SIG-23]** Any signal transition that changes topology, availability, a
  conservative latency bound, or another scheduler-visible readiness condition
  MUST be admitted as an exact scheduler boundary event before it takes effect.
- **[SIG-24]** A continuously varying signal MUST NOT force scheduler work at
  arbitrary host-selected polling intervals. It is sampled at declared cadences,
  exact crossings, or stable hardware opportunities.
- **[SIG-25]** Signal evaluation MUST fail loudly rather than apply a transition
  retroactively when its required coordinate is already in a consumer's past.

## 1.8 Canonicalization and identity

`SignalProgram` identity covers:

- schema and evaluator semantic version;
- canonical topological node order;
- every node kind, type, unit, parameter, and input edge;
- every source artifact content address and channel selection;
- coordinate frames and time mappings;
- arithmetic, rounding, interpolation, extrapolation, and overflow policies;
- stochastic domain separators;
- declared state-machine tables and initial state;
- capability requirements.

Presentation order does not matter. IDs are normalized and nodes are serialized
in dependency order with stable ID tie-breaking. Unreferenced nodes are either
rejected or included by an explicit exported-output declaration; they are never
silently ignored.

- **[SIG-26]** Semantically equal programs MUST have equal canonical material
  regardless of TOML row order.
- **[SIG-27]** Any change that can alter evaluation MUST change program identity.
- **[SIG-28]** Evaluator semantic changes MUST use a new version and MUST NOT
  reinterpret an existing content address.

## 1.9 Deliberate exclusions from the core language

The following are not signal nodes:

- shell commands, WASM modules, Python, Lua, or arbitrary bytecode;
- host filesystem or URL reads;
- native floating-point functions;
- unbounded loops, recursion, collections, or dynamically created nodes;
- mutation of device or guest state;
- property assertions or workload actions;
- implicit live data subscriptions.

Calibrated complex models in this implementation are represented as normalized
trace artifacts, lookup tables, or spatial fields. A later hermetic model adapter
requires a separate RFC and complete conformance implementation; this PR adds no
extension slot, placeholder ABI, or unknown-model passthrough.
