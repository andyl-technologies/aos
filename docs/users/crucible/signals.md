# Signal programs

Crucible signal programs describe deterministic causes. A signal is a typed,
versioned node in a directed acyclic graph; a binding samples one or more
exported nodes and maps their values into a typed fault effect. The same model
covers constants, time-varying waveforms, recorded measurements, spatial
fields, stochastic processes, and checkpointed state machines.

This guide explains how to choose and compose signals. The exact TOML field
catalog remains in the [reference](reference.md#plans-signals-bindings-and-faults),
and [bindings](bindings.md) covers the cause-to-effect bridge.

## Evaluation model

Each `[[plan.signal]]` row declares:

| Field | Contract |
| --- | --- |
| `id` | Unique stable identity used by downstream `inputs` and bindings. |
| `semantic_version` | Must be `1`; it fixes evaluator and canonicalization semantics. |
| `domain` | Coordinate on which the node changes: `virtual_time`, `node_counter`, `operation`, `spatial`, `event`, or `state`. |
| `value_type` | Exact shape, including enum schema, event payload, vector scalar, or byte schema where applicable. |
| `unit` | Physical unit carried through validation and arithmetic. |
| `scale_decimal_exponent` | Exact decimal scale in `-18..=18`; default `0`. |
| `inputs` | Ordered upstream IDs. Ordering matters for subtraction, selection, and other noncommutative operators. |
| `node` | One source, pure specification, or stateful specification. |

Admission rejects missing inputs, cycles, incompatible domains, shapes, units,
or operator arity. Evaluation is integer/rational and explicit about rounding
and overflow. It does not depend on host floating-point behavior.

Only exported outputs may be consumed by bindings. State, history, stochastic
draw positions, and telemetry delay state become part of checkpoints and replay
evidence; restoring a checkpoint does not restart a process from its initial
state.

## Values, units, and arithmetic policy

The closed value types are `bool`, `i64`, `u64`, `ratio`, `duration_nanos`,
`rate_per_second`, `probability_millionths`, `enum`, `event`, `vector2`,
`vector3`, and `bytes`. Parameterized shapes must carry the same schema on both
sides of an operator. Probability values are integers from 0 through 1,000,000.

Units prevent accidental comparisons such as time against temperature. The
catalog includes dimensionless, virtual time, distance/area/velocity,
orientation, temperature, electrical power and energy, RF quantities,
frequency, rates, ratios, acceleration, and precipitation. See the
[unit table](reference.md#plans-signals-bindings-and-faults) for canonical names.
Use `unit_convert` for an explicit compatible affine conversion.

Every operation that can discard precision or exceed its representation names
its policy:

- `rounding`: `floor`, `ceiling`, `toward_zero`, `away_from_zero`, or
  `nearest_ties_to_even`.
- `overflow`: `error` or `saturate`. `error` fails the evaluation rather than
  silently wrapping.
- interpolation: `exact`, `hold_previous`, `nearest`, or `linear`; linear
  carries rounding and overflow policy.
- boundary behavior: `error`, `hold`, `constant`, `repeat`, or `inactive`.
- missing-sample behavior: `error`, `hold`, `interpolate`, or `inactive`.

## Source catalog

The 21 source kinds below are the complete version-1 vocabulary.

### Analytic and event sources

| Kind | Required configuration | Use |
| --- | --- | --- |
| `constant` | `value` | An immutable typed literal. |
| `step` | ordered `points`, `before` | A piecewise-constant schedule. Points must be canonical and strictly ordered. |
| `pulse` | `start`, `duration`, `inactive`, `active` | One exact half-open active interval. Duration is positive. |
| `periodic_pulse` | `epoch`, positive `period`, `width`, `phase`, inactive/active values | Repeating exact intervals; width and phase must fit the period. |
| `ramp` | start/end coordinates and values, `rounding` | One exact linear transition. |
| `triangle` | epoch, period, phase, min/max, `rounding` | A repeating rise-and-fall waveform. |
| `sawtooth` | epoch, period, phase, min/max, `rounding` | A repeating ramp with an exact reset boundary. |
| `event_sequence` | ordered `events` | Typed events. Same-coordinate ordering is retained and stable. |

Use analytic sources when the cause is part of the experiment definition. They
are easiest to minimize because every transition is declared directly in the
scenario.

### Recorded and telemetry sources

| Kind | Required configuration | Use and constraints |
| --- | --- | --- |
| `trace` | normalized `artifact`, `raw_provenance`, `channel`, interpolation/boundary/missing policies; optional quality and time mapping | Replays an imported channel. The normalized object and raw provenance are both retained. |
| `telemetry` | `adapter`, `target`, `field`, `boundary_delay = 1` | Reads production adapter telemetry one boundary late, preventing an instantaneous feedback loop. |

Import recorded data before authoring a trace source. The importer validates
ordering, units, quality, interpolation policy, and time mapping and writes a
content-addressed normalized artifact. Follow [Recorded signals](recorded-signals.md)
for that workflow. Telemetry fields are adapter-defined and must be supported by
the selected target and packaged capability contract.

### Spatial sources

| Kind | Required configuration | Use and constraints |
| --- | --- | --- |
| `point_set` | artifact, coordinate frame, interpolation, outside policy | Irregular named samples. |
| `regular_grid` | artifact, frame, origin, positive cell size, dimensions, interpolation, outside policy | Dense three-dimensional grid. |
| `tiled_grid` | manifest, frame, tile size, interpolation, outside policy | Bounded content-addressed tiles loaded through a manifest. |
| `zone_map` | artifact, frame, boundary and overlap policies | Polygon or polyhedron membership. |
| `path_profile` | artifact, path, interpolation, before/after policies | Quantity indexed by distance along a declared path. |
| `seeded_field` | seed domain, frame, quantization, correlation, distribution and parameters | Deterministic correlated field keyed by quantized coordinates. |
| `transmitter_field` | transmitter, frame, position signal, model, lookup and environment signals; optional orientation | Calibrated path loss plus antenna and environmental contributions. |

Coordinate frames must match, or be connected by an explicitly declared
transform. Outside, boundary, and overlap behavior are never inferred. Spatial
artifacts are part of the transitive object closure retained for replay.

### Stochastic sources

| Kind | Required configuration | Result |
| --- | --- | --- |
| `bernoulli` | probability, key domain, optional opportunity filter | Stable keyed Boolean draw. |
| `uniform_integer` | inclusive minimum/maximum, key domain, optional filter | Unbiased stable keyed integer. |
| `exponential_wait` | rate, sampler version/table, key domain, optional maximum | Exact integer inverse-CDF wait. |
| `weibull_wait` | shape, scale, sampler version/table, key domain, optional maximum | Exact integer inverse-CDF wait. |

The key domain is `opportunity`, `transition`, or `coordinate`. Choose it by the
identity that should keep a draw stable: a concrete adapter opportunity, a
state transition, or a signal coordinate. Adding an unrelated opportunity must
not renumber prior draws. Sampler version and table identities are replay
contracts, not tuning hints.

## Pure operators

Pure nodes derive an output only from inputs and coordinates. They have no
hidden mutable state. The 36 operators are grouped below by authoring purpose.

| Family | Operators | Important rules |
| --- | --- | --- |
| Arithmetic | `add`, `subtract`, `multiply_ratio`, `divide_ratio`, `absolute`, `negate`, `min`, `max`, `clamp` | Inputs must have compatible shape/unit. Ratio arithmetic declares exact ratio, rounding, and overflow. |
| Comparison | `equal`, `not_equal`, `less`, `less_equal`, `greater`, `greater_equal` | Ordered comparisons require compatible ordered values and produce Boolean. |
| Boolean/selection | `all`, `any`, `not`, `select` | `select` uses a Boolean condition and equal-shaped branches. |
| Transfer | `lookup_step`, `piecewise_linear`, `enum_map`, `unit_convert` | Breakpoints are strictly ordered; enum mapping is exhaustive; conversions are explicit. |
| History | `delay`, `sample_hold`, `window_min`, `window_max`, `window_mean` | Declare positive cadence/window and a finite retained-sample limit. Mean declares rounding/overflow. |
| Spatial | `distance`, `zone_contains`, `field_sample`, `orientation_delta` | Inputs share a coordinate frame; metric/convention is explicit. |
| Events | `edge_rising`, `edge_falling`, `merge_events`, `gate_events` | Edge operators consume Boolean; merge has a positive source-sequence limit; gating preserves event identity. |

The wire specification kind is sometimes broader than the operator name:
parameter-free operators use `simple`; multiplication/division use
`ratio_arithmetic`; all three windows use `window`. Exact specification fields
are in the [pure specification table](reference.md#plans-signals-bindings-and-faults).

## Stateful operators

Stateful nodes own checkpointed state and have explicit bounded work/history.

| Kind | State and behavior | Required bounds or policy |
| --- | --- | --- |
| `hysteresis` | Boolean latch with separate set/clear predicates | Initial value and minimum residence. |
| `debounce` | Commits an input only after it remains stable | Initial value and residence interval. |
| `integrator` | Exact accumulated input over time | Initial value, cadence or change-driven mode, time unit, rounding, overflow. |
| `leaky_integrator` | Fixed-cadence integration with rational decay | Positive cadence/time unit, catch-up limit, decay, rounding, overflow. |
| `finite_state_machine` | Closed states with event, guard, and timer transitions | Nonempty states, valid initial state, exhaustive transition policy, unmatched-event policy. |
| `markov_chain` | Exact-probability state transitions | States, initial state, opportunity identity, rows summing exactly to the probability scale. |
| `burst_process` | Correlated two-state good/bad process | Initial state, exact transition probabilities, opportunity identity. |
| `counter` | Bounded typed-event count | Initial/min/max, overflow behavior, optional reset event. |
| `queue_model` | Bounded backlog and service evolution | Capacity, service profile, overflow behavior, positive catch-up/work limits. |

Finite-state timers use an explicit arm/cancel operation and are represented in
checkpoint state. On restore, pending timers retain their declared deadlines and
stable ordering.

## Resource limits and admission

Signal resource limits are scenario-owned values capped by compiled hard
ceilings. They cover node count, graph edges, depth, exported outputs, state
bytes, retained samples/events, spatial artifacts, stochastic tables, and
per-evaluation work. Admission computes the complete graph and object closure
before a VM starts. A scenario that exceeds a limit fails closed; it is not
silently truncated.

Practical authoring rules:

1. Give every cause a physical type and unit before choosing operators.
2. Keep source coordinates in the domain that supplies their stable identity.
3. Declare rounding, overflow, missing, and boundary behavior at every lossy
   boundary.
4. Bound history, catch-up, queues, event merges, and search candidates.
5. Export only nodes that bindings consume or that evidence must retain.
6. Run admission before a campaign and retain the canonical scenario hash.

## Checkpoints, replay, and evidence

The evaluator checkpoint includes semantic versions, stateful node payloads,
retained histories, pending timers, stochastic position/key state, and imported
object identities. Restore validates these against the admitted program. A
shape, version, graph, object, or state mismatch is a hard error.

The canonical trace records sampled coordinates and digests according to each
binding's observability policy. Reproduction artifacts authenticate the
transitive signal-object closure, including normalized traces, sampler tables,
spatial data, and search mutations. Use [Reproduction](reproduction.md) to
resume or replay and [Debugging](debugging.md) to inspect evaluation evidence.
