# Signal programs

A `SignalProgram` turns immutable sources and checkpointed state into typed
values or events. It is a finite, closed, declarative DAG, not a script
runtime: there are no shell commands, WASM, bytecode, host file or URL reads,
native floating point, unbounded loops, recursion, dynamically created nodes,
or device/guest mutation. Calibrated complex models enter as normalized traces,
lookup tables, or spatial fields.

Source: [`fault_signal/mod.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/mod.rs)
and [`evaluator.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/evaluator.rs).
The current evaluator semantics are `SIGNAL_EVALUATOR_VERSION`.

## Values and units

Every node output has a static `SignalShape`: value type, `SignalUnit`, and an
`i8` decimal scale exponent. Validation rejects mismatched operator inputs and
implicit unit conversion; conversion is an explicit `unit_convert` node whose
scale, offset, rounding, and overflow participate in identity.

| `SignalValueType` | Canonical representation |
| --- | --- |
| `bool`, `i64`, `u64` | Integers. |
| `ratio` | `i64` numerator over positive `u64` denominator, in lowest terms. |
| `duration_nanos`, `rate_per_second` | `u64`. |
| `probability_millionths` | `u32` no greater than 1,000,000. |
| `enum(schema)`, `event(schema)` | Schema and variant IDs; events carry a bounded payload. |
| `vector2`, `vector3` | Homogeneous numeric, non-ratio components. |
| `bytes` | Bounded opaque bytes. |

Units are a closed enum: dimensionless, virtual nanoseconds, millimetres,
square millimetres, millimetres per second, millidegrees, millicelsius,
microvolts, microamps, microwatts, femtowatts, microjoules, millidecibels,
millidecibel-milliwatts, kilohertz, bits/bytes/operations per second, parts per
million, probability millionths, micrometres per second squared, and
micrometres per hour.

Arithmetic uses checked 128-bit intermediates over 64-bit stored values.
`SignalOverflow` is `error` or `saturate`; `SignalRounding` is `floor`,
`ceiling`, `toward_zero`, `away_from_zero`, or `nearest_ties_to_even`.
Saturation is never implicit.

## Evaluation domains

Signals do not share one implicit clock. Each source and stateful node declares
a `SignalDomain`:

| Domain | Coordinate | Typical use |
| --- | --- | --- |
| `virtual_time` | Global virtual time | Weather, load, power, scheduled outages. |
| `node_counter` | Node plus retired instructions | Instruction-exposure effects. |
| `operation` | Adapter, target, operation, producer sequence | Per-frame, per-I/O, per-access choices. |
| `spatial` | Position and optional orientation | Path loss, zones, interference. |
| `event` | Typed event sequence | Resets, alarms, recorded discrete failures. |
| `state` | Prior checkpointed state | Thermal, wear, queue, Markov, hysteresis. |

Domains combine only through explicit sampling or projection operators.
Guest-visible clocks never implicitly drive evaluation, because a clock fault
could then form a causal cycle.

Adapter telemetry (queue depth, association, lifecycle, and so on) is read from
the state at the start of the current deterministic boundary through a
`SignalBoundarySnapshot`. An effect applied at a boundary cannot feed back into
its own signal until a later boundary, so telemetry dependencies are acyclic
within one boundary.

## Sources

`SignalSourceKind` is closed:

| Family | Kinds |
| --- | --- |
| Analytic | `constant`, `step`, `pulse`, `periodic_pulse`, `ramp`, `triangle`, `sawtooth` |
| Events | `event_sequence` |
| Recorded | `trace` (one channel of a normalized trace artifact) |
| Adapter state | `telemetry` |
| Spatial | `point_set`, `regular_grid`, `tiled_grid`, `zone_map`, `path_profile`, `seeded_field`, `transmitter_field` |
| Stochastic | `bernoulli`, `uniform_integer`, `exponential_wait`, `weibull_wait` |

There is no sine primitive; a sampled lookup table represents a calibrated
periodic waveform without a portable transcendental implementation.

A trace source declares the artifact content address, channel, expected shape,
source-to-virtual time mapping, `SignalInterpolation` (`exact`,
`hold_previous`, `nearest`, or `linear` with explicit rounding and overflow),
`SignalBoundaryBehavior` before and after the data (`error`, `hold`,
`constant`, `repeat`, `inactive`), and `MissingSampleBehavior` (`error`,
`hold`, `interpolate`, `inactive`). Missing samples never silently become zero.

Spatial sources evaluate over integer millimetre Cartesian coordinates.
Geographic input is normalized into a local frame before admission; the
artifact retains origin and projection metadata for provenance only. Seeded
fields are keyed by field ID, seed, and quantized coordinates, so revisiting a
location reproduces the same value regardless of traversal order.

Exponential and Weibull waits sample a content-addressed
[`InverseCdfTable`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/sampler.rs):
a monotone partition of the keyed `u64` quantile domain whose distribution
parameters are exact rationals. Sampling is one binary search; no platform math
library is called.

## Operators

`PureSignalOperator` is closed and versioned:

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

Window operators use an exact declared cadence or the source's change points,
never an implementation-chosen sampling rate. Pure-node output is a function
of canonical inputs and coordinate, so it may be memoized by content address
and coordinate.

`StatefulSignalOperator` covers `hysteresis`, `debounce`, `integrator`,
`leaky_integrator`, `finite_state_machine`, `markov_chain`, `burst_process`,
`counter`, and `queue_model`. Each declares initial state, transition domain,
and a bounded canonical encoding. State machines emit state or events; they
cannot execute actions. Restoring a checkpoint and advancing to a coordinate
produces the same transitions as uninterrupted execution.

## Keyed stochastic choices

Every random draw is derived, not consumed from a cursor. The evaluator hashes
(BLAKE3) the scenario seed, signal node ID, consumer identity, a
`StochasticKeyDomain` tag, and the domain's stable identity:

| Key domain | Identity material |
| --- | --- |
| `opportunity` | The `FaultOpportunity` content ID. |
| `transition` | The binding transition sequence. |
| `coordinate` | The evaluation coordinate plus same-coordinate sequence. |

Repeating a keyed choice returns the same value regardless of which other
signals were evaluated. Search may replace a keyed result with an explicit
branch decision, which then enters the schedule.

## Change discovery

A virtual-time signal reports its exact next change, a conservative lower
bound, that it changes only at opportunities, or that it ends. Analytic steps,
traces, event sequences, and state-machine timers report exact changes;
threshold crossings over piecewise-linear inputs are computed with rational
arithmetic. A transition that changes topology, availability, or a
scheduler-visible bound is admitted as an exact scheduler boundary before it
takes effect. Continuous signals are never polled at host-chosen intervals, and
a transition whose coordinate is already in a consumer's past fails loudly.

## Identity and limits

Program identity covers the evaluator version, canonical topological node
order (stable ID tie-break), every node kind, shape, parameter and edge, source
artifact addresses and channels, coordinate frames and time mappings, every
arithmetic/interpolation/overflow policy, stochastic domain separators,
state-machine tables, and capability requirements. Authored row order does not
matter; any change that can alter evaluation changes the identity, and an
evaluator semantic change bumps the version rather than reinterpreting an
existing address.

Admission validates cycles, duplicate IDs, missing inputs, type and unit
mismatches, ranges, denominators, retained-state bounds, and telemetry support
before execution. Evaluation is iterative in topological order. Graph size
limits (`SignalResourceLimits`) derive from the scenario
[resource limits](resource-limits.md), bounded by compiled `HARD_SIGNAL_*`
ceilings; graph depth is fixed at 4,096.
