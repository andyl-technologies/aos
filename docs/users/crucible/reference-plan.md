# Crucible plan and property reference

This page lists every `[plan]` and `[properties]` field of the canonical
scenario TOML, including the closed signal, binding, operation, target,
effect, and predicate vocabularies. It is part of the
[Crucible reference](reference.md), which also defines the value
notation used in the tables.

## Plans, signals, bindings, and faults

There is one fault authoring and execution model. A plan combines an ordinary
event graph with signal programs and typed bindings. Static, finite, periodic,
stochastic, trace-replayed, and stateful behavior all use this same path; there
is no separate imperative activation API.

Implementation sources:

- [plan wire shape](../../../crates/crucible/crucible-engine/src/model/toml.rs)
- [signal value, source, operator, and state schemas](../../../crates/crucible/crucible-engine/src/model/fault_signal/mod.rs)
- [binding, selector, mapping, sampling, and search schemas](../../../crates/crucible/crucible-engine/src/model/fault_signal/binding.rs)
- [closed effect registry](../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_registry.rs)
- [network effect parameters](../../../crates/crucible/crucible-engine/src/model/fault_signal/network_effect.rs)
- [storage and 9p effect parameters](../../../crates/crucible/crucible-engine/src/model/fault_signal/storage_effect.rs)
- [node, CPU, memory, interrupt, clock, and accelerator parameters](../../../crates/crucible/crucible-engine/src/model/fault_signal/node_effect.rs)
- [resource-limit registry](../../../crates/crucible/crucible-engine/src/model/fault_signal/resource_limits.rs)

### Fault-topology canonical locations

Fault-topology arrays are direct children of `[world]`. The complete canonical
row set is `[[world.fault_domain]]`, `[[world.network_interface]]`,
`[[world.network_segment]]`, `[[world.network_medium]]`,
`[[world.network_forwarder]]`, `[[world.network_queue]]`,
`[[world.network_path]]`, `[[world.network_attachment]]`,
`[[world.network_contact_plan]]`, `[[world.network_policy_artifact]]`,
`[[world.mobile_endpoint]]`, `[[world.storage_device]]`,
`[[world.storage_controller]]`, `[[world.storage_array]]`,
`[[world.storage_policy_artifact]]`, and
`[[world.node_fault_capabilities]]`. See the
[fault topology reference](topology.md#canonical-toml-locations) for every
top-level and nested field, closed policy payload, constraint, and continuation
rule.

#### Storage-array declarations

Every `[[world.storage_array]]` row is a complete logical-device
contract. All fields below are required; there are no inferred RAID defaults or
legacy fallbacks.

| Field | Accepted value | Meaning |
| --- | --- | --- |
| `id` | Unique object ID | Stable array identity used by `storage_array` targets. |
| `device` | Block storage-device ID | Guest-visible logical block node. It must not be a member. |
| `semantic_version` | `1` | Exact layout, parity, and rebuild semantics. |
| `layout` | `mirror`, `stripe`, `single_parity`, or `dual_parity` | Closed physical layout. Single parity requires at least three members; dual parity requires at least four. |
| `chunk_bytes` | Positive power of two | Data chunk and parity-stripe unit. |
| `read_quorum` | Positive integer no greater than member count | Minimum online member paths before reads are admitted. |
| `write_quorum` | Positive integer no greater than member count | Minimum online members before non-atomic writes are admitted. |
| `members` | Canonical nonempty member table | Each row has unique `id`, unique block `device`, and contiguous `ordinal` beginning at zero. |
| `paths` | Canonical path table | Each row has `id`, positive `queue_depth`, and a `policy` reference. |
| `member_path_state` | `array_state` artifact ID | Complete baseline online state for every declared member and path. |
| `selection_policy` | `array_selection` artifact ID | Baseline mirror read selection: lowest healthy, stable hash, or least loaded. |
| `rebuild_service` | `rebuild` artifact ID | Baseline positive rebuild chunk, queue depth, and byte rate. |
| `consistency_policy` | `array_consistency` artifact ID | Baseline quorum, degraded-commit, or atomic-stripe behavior. |
| `failure_result` | Non-success block `typed_result` artifact ID | Exact result returned when no legal quorum exists. |
| `fault_domains` | Canonical fault-domain ID list | Shared-cause domains containing the array. |

The smallest member capacity, rounded down to `chunk_bytes`, must cover the
logical device after mirror/stripe/parity overhead. The baseline policy always
routes logical I/O through the declared members. An active
`storage.array_state` binding replaces all five baseline policy references as
one state transition; when it deactivates, the declaration baseline resumes.

### `[plan]` fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required generated content address | Identity of the event graph and complete signal-driven fault layer. |
| `fault_model` | Required; only `signal_bindings_v2` | Selects the sole accepted fault schema. Earlier forms fail before typed lowering. |
| `fault_signal_semantic_version` | Required; only `2` | Locks signal/binding semantics for canonicalization and replay. |
| `signal` | Empty array by default | Closed signal-program rows described below. |
| `fault_binding` | Empty array by default | Typed bridges from signal outputs to effects. |
| `resource_limits` | All compiled defaults | Scenario-owned limits; every value must be positive and no greater than its compiled ceiling. |
| `event` | Empty array by default | Non-fault event-graph rows. |

### `[[plan.event]]` fields and actions

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required string | Unique event identity. |
| `trigger` | Optional | Predicate table or DSL string. Omission is unconditional. |
| `action` | Required | One closed action table. |
| `policy` | `once` by default; `repeatable` | Fire once or on later false-to-true transitions. |

| Action `kind` | Fields | Effect |
| --- | --- | --- |
| `arm_timer` | `name`, `after_ticks` | Arm or replace a relative timer using exact picosecond ticks. |
| `cancel_timer` | `name` | Cancel the timer. |
| `start_node` | `node` | Start a declared stopped node. |
| `stop_node` | `node` | Stop a declared node. |
| `create_savepoint` | optional `label` | Record a labeled savepoint request at the firing boundary in the trigger action state and event log. The run does not materialize a checkpoint from it; use `save` or a debugger session for that. |
| `fork` | optional `label` | Record a labeled fork request at the firing boundary in the trigger action state and event log. The run does not start a child execution from it; use `campaign branch` for an alternate execution. |
| `pass` | none | Produce an explicit passing terminal verdict. |
| `fail` | `reason` | Produce an explicit failing terminal verdict. |
| `log` | `level`, `message` | Emit deterministic text; level is `debug`, `info`, `warn`, or `error`. |
| `group` | `actions` | Apply nested actions in declared order as one group. |

### `[[plan.signal]]` common fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required | Stable signal identity. |
| `domain` | Required | `virtual_time`, `node_counter`, `operation`, `spatial`, `event`, or `state`. |
| `exported` | Default `true` | Whether the node is available as a binding input. |
| `value_type` | Required | `bool`, `i64`, `u64`, `ratio`, `duration_nanos`, `rate_per_second`, `probability_millionths`, `enum`, `event`, `vector2`, `vector3`, or `bytes`; parameterized types also carry their schema/scalar type. |
| `unit` | Required | One unit from the table below. |
| `scale_decimal_exponent` | Default `0`; `-18..=18` | Exact decimal scaling carried in signal shape. |
| `inputs` | Empty unless required by an operator | IDs of upstream nodes; order is semantic for noncommutative operators. |
| `kind` and kind-specific fields | Required | Flattened closed source, pure operator, or stateful operator specification. |

Every stateful signal additionally requires positive `state_bytes`, the exact
bounded checkpoint allocation for that node. Source and pure nodes reject that
field.

Signal units are exhaustive:

| Unit | Stored quantity |
| --- | --- |
| `dimensionless` | Integer or rational without a physical unit. |
| `virtual_nanoseconds` | Virtual duration or coordinate. |
| `millimetres`, `square_millimetres`, `millimetres_per_second` | Position, squared distance, or velocity. |
| `millidegrees` | Orientation. |
| `millicelsius` | Temperature. |
| `microvolts`, `microamps`, `microwatts`, `microjoules` | Voltage, current, power, or energy. |
| `femtowatts`, `millidecibels`, `millidecibel_milliwatts` | Exact linear or logarithmic RF/optical quantity. |
| `kilohertz` | Frequency. |
| `bits_per_second`, `bytes_per_second`, `operations_per_second` | Service rate. |
| `parts_per_million`, `probability_millionths` | Ratio or probability; probability is `0..=1_000_000`. |
| `micrometres_per_second_squared`, `micrometres_per_hour` | Acceleration or precipitation rate. |

Signal source, pure, and stateful kinds below are defined by the
[signal schema](../../../crates/crucible/crucible-engine/src/model/fault_signal/mod.rs).

Signal source kinds are exhaustive:

| `kind` | Required fields | Purpose |
| --- | --- | --- |
| `constant` | `value` | Emit one immutable typed literal. |
| `step` | ordered `points`, `before` | Emit piecewise-constant values. |
| `pulse` | `start`, `duration`, `inactive`, `active` | Emit one finite active interval. |
| `periodic_pulse` | `epoch`, `period`, `width`, `phase`, `inactive`, `active` | Emit repeating exact active intervals. |
| `ramp` | `start`, `end`, `start_value`, `end_value`, `rounding` | Emit one exact linear transition. |
| `triangle` | `epoch`, `period`, `phase`, `minimum`, `maximum`, `rounding` | Emit a periodic triangle wave. |
| `sawtooth` | `epoch`, `period`, `phase`, `minimum`, `maximum`, `rounding` | Emit a periodic sawtooth wave. |
| `event_sequence` | ordered `events` | Emit typed events with stable same-coordinate order. |
| `trace` | `artifact`, `raw_provenance`, `channel`, `interpolation`, `before`, `after`, `missing`; optional quality channel/threshold and time mapping | Replay a normalized recorded channel while retaining its raw provenance. |
| `telemetry` | `adapter`, `target`, `field`, `boundary_delay=1` | Read delayed production telemetry without a feedback loop. |
| `point_set` | `artifact`, `coordinate_frame`, `interpolation`, `outside` | Sample irregular spatial data. |
| `regular_grid` | `artifact`, `coordinate_frame`, `origin_mm`, `cell_size_mm`, `dimensions`, `interpolation`, `outside` | Sample a dense 3-D grid. |
| `tiled_grid` | `manifest`, `coordinate_frame`, `tile_size_mm`, `interpolation`, `outside` | Sample a bounded tiled grid. |
| `zone_map` | `artifact`, `coordinate_frame`, `boundary`, `overlap` | Resolve polygon/polyhedron membership. |
| `path_profile` | `artifact`, `path`, `interpolation`, `before`, `after` | Sample a quantity by distance along a path. |
| `seeded_field` | `field_seed_domain`, `coordinate_frame`, `quantization_mm`, `correlation_mm`, `distribution`, `distribution_parameters` | Generate a deterministic correlated field. |
| `transmitter_field` | `transmitter`, `coordinate_frame`, `position_signal`, optional `orientation_signal`, `model`, `lookup`, `environment_signals` | Apply calibrated path-loss, antenna, and environment transfer. |
| `bernoulli` | `probability_millionths`, `key_domain`, optional `opportunity_filter` | Make a stable-key Boolean draw. |
| `uniform_integer` | `minimum`, `maximum`, `key_domain`, optional `opportunity_filter` | Make an unbiased stable-key inclusive integer draw. |
| `exponential_wait` | `rate`, `sampler_version`, `sampler_table`, `key_domain`, optional `maximum_nanos` | Sample an exact integer inverse-CDF exponential wait. |
| `weibull_wait` | `shape`, `scale_nanos`, `sampler_version`, `sampler_table`, `key_domain`, optional `maximum_nanos` | Sample an exact integer inverse-CDF Weibull wait. |

Interpolation is `exact`, `hold_previous`, `nearest`, or `linear`; linear also
declares `rounding` and `overflow`. Boundary behavior is `error`, `hold`,
`constant`, `repeat`, or `inactive`. Missing-sample behavior is `error`, `hold`,
`interpolate`, or `inactive`. Rounding is `floor`, `ceiling`, `toward_zero`,
`away_from_zero`, or `nearest_ties_to_even`; overflow is `error` or `saturate`.
Stochastic `key_domain` is `opportunity`, `transition`, or `coordinate`.

Pure specification kinds select the parameter shape:

| `kind` | Required fields | Purpose |
| --- | --- | --- |
| `simple` | `operator`, `overflow` | Configure a parameter-free arithmetic, comparison, Boolean, selection, or edge operator. |
| `ratio_arithmetic` | `operator`, `ratio`, `rounding`, `overflow` | Multiply or divide by an exact reduced ratio. |
| `clamp` | `minimum`, `maximum`, `overflow` | Clamp a value to inclusive typed bounds. |
| `lookup_step` | ordered `points`, `before`, `after` | Apply a piecewise-constant lookup. |
| `piecewise_linear` | ordered `points`, `rounding`, `overflow` | Apply exact linear interpolation between lookup points. |
| `enum_map` | exhaustive `entries` | Map every accepted enum input to a typed output. |
| `unit_convert` | `from_unit`, `to_unit`, `ratio`, `offset`, `rounding`, `overflow` | Convert compatible units with exact affine arithmetic. |
| `delay` | positive `delay`, positive `retained_samples` | Delay values in their declared domain with a hard history bound. |
| `sample_hold` | positive `cadence`, `epoch`, positive `retained_samples` | Sample and hold at exact domain coordinates. |
| `window` | `operator`, positive `window`, `sampling_cadence`, positive `retained_samples`, `rounding`, `overflow` | Compute a bounded window minimum, maximum, or mean. |
| `distance` | `metric`, `rounding` | Compute spatial distance in one coordinate frame. |
| `zone_contains` | `zone` | Test declared zone membership. |
| `field_sample` | none | Sample a declared spatial field using the input coordinate. |
| `orientation_delta` | `convention` | Compute orientation difference using a closed convention. |
| `merge_events` | positive `source_sequence_limit` | Merge typed event streams with bounded stable ordering. |
| `gate_events` | none | Pass typed events only while the Boolean gate input is true. |

The `operator` field is exhaustive:

| Operator | Valid pure specification | Result |
| --- | --- | --- |
| `add` | `simple` | Add equal-shaped inputs. |
| `subtract` | `simple` | Subtract the second input from the first. |
| `multiply_ratio` | `ratio_arithmetic` | Multiply by the declared exact ratio. |
| `divide_ratio` | `ratio_arithmetic` | Divide by the declared exact ratio. |
| `absolute` | `simple` | Produce a signed value's absolute magnitude. |
| `negate` | `simple` | Negate a signed value. |
| `min` | `simple` | Select the minimum input. |
| `max` | `simple` | Select the maximum input. |
| `clamp` | `clamp` | Clamp to explicit inclusive bounds. |
| `equal` | `simple` | Test equality. |
| `not_equal` | `simple` | Test inequality. |
| `less` | `simple` | Test strict less-than ordering. |
| `less_equal` | `simple` | Test less-than-or-equal ordering. |
| `greater` | `simple` | Test strict greater-than ordering. |
| `greater_equal` | `simple` | Test greater-than-or-equal ordering. |
| `all` | `simple` | Compute Boolean conjunction. |
| `any` | `simple` | Compute Boolean disjunction. |
| `not` | `simple` | Compute Boolean negation. |
| `select` | `simple` | Select between equal-shaped branches with a Boolean condition. |
| `lookup_step` | `lookup_step` | Apply the declared piecewise-constant lookup. |
| `piecewise_linear` | `piecewise_linear` | Apply the declared interpolating lookup. |
| `enum_map` | `enum_map` | Apply the exhaustive enum mapping. |
| `unit_convert` | `unit_convert` | Apply the exact compatible-unit conversion. |
| `delay` | `delay` | Read the bounded delayed value. |
| `sample_hold` | `sample_hold` | Read the fixed-cadence held value. |
| `window_min` | `window` | Compute the bounded window minimum. |
| `window_max` | `window` | Compute the bounded window maximum. |
| `window_mean` | `window` | Compute the exactly rounded bounded window mean. |
| `distance` | `distance` | Compute spatial distance. |
| `zone_contains` | `zone_contains` | Test zone membership. |
| `field_sample` | `field_sample` | Sample a spatial field. |
| `orientation_delta` | `orientation_delta` | Compute orientation difference. |
| `edge_rising` | `simple` | Emit an event on a Boolean rising edge. |
| `edge_falling` | `simple` | Emit an event on a Boolean falling edge. |
| `merge_events` | `merge_events` | Merge typed events in stable order. |
| `gate_events` | `gate_events` | Gate a typed event stream. |

Stateful specification kinds are exhaustive:

| `kind` | Required fields | Purpose |
| --- | --- | --- |
| `hysteresis` | `initial`, `set_when`, `clear_when`, `minimum_residence_nanos` | Apply Boolean hysteresis with an optional residence interval. |
| `debounce` | `initial`, `residence_nanos` | Commit an input only after it remains stable for the residence interval. |
| `integrator` | `initial`, `cadence_nanos`, positive `time_unit_nanos`, `rounding`, `overflow` | Integrate exactly at source changes or a declared cadence. |
| `leaky_integrator` | `initial`, positive `cadence_nanos`, positive `time_unit_nanos`, `decay_ratio`, positive `maximum_catch_up_steps`, `rounding`, `overflow` | Integrate at fixed cadence while applying exact rational decay. |
| `finite_state_machine` | nonempty `states`, `initial`, exhaustive `transitions`, `unmatched_event` | Run a closed event/guard/timer transition table. |
| `markov_chain` | nonempty `states`, `initial`, `opportunity`, `probability_rows` | Run an exact-probability finite Markov chain. |
| `burst_process` | `initial_bad`, transition probabilities, `opportunity` | Run a two-state correlated good/bad process. |
| `counter` | `initial`, `maximum`, `overflow`, optional `reset_event` | Count bounded typed events with explicit overflow/reset behavior. |
| `queue_model` | positive `capacity`, `discipline`, `overflow` | Model bounded checkpointed service backlog. |

Unknown variants or fields in any table are rejected.

### `[[plan.fault_binding]]` fields

| Field | Required/default | Meaning |
| --- | --- | --- |
| `id` | Required | Stable binding identity. |
| `signals` | Required nonempty list | Canonical input signals. |
| `sampling` | Default `at_boundary` | String value `at_boundary`, `at_opportunity`, `at_change`, `cadence_nanos`, or `at_event`; the latter two use adjacent parameter fields. |
| `mapping` | Required | Closed signal-to-effect transfer below. |
| `selector` | Required | `exact`, `target_set`, `fault_domain`, or version-1 `dynamic_path`. |
| `phases` | Default: every phase in the effect descriptor | Nonempty exact application-phase set; canonical output always emits it. |
| `effect` | Required | One typed effect specification; `semantic_version=1`. |
| `opportunity_filter` | Required when opportunity sampling cannot be inferred | Adapter, operation set, phase set, and optional target-kind constraints. |
| `search` | Default `fixed` | String selecting bounded search behavior; non-fixed parameters use adjacent `[plan.fault_binding.search_policy]`. |
| `observability` | Default policy | Sample retention, inactive-opportunity retention, and mapped-value retention; canonical output always emits it. |
| `transition_declaration` | Required only by `state_transition` mapping | Versioned exhaustive transition-table declaration retained in the binding. |
| `service_declaration` | Required only by `service_profile` mapping | Versioned named physical-input service-profile declaration retained in the binding. |

`transition_declaration` has exact fields `id`, `semantic_version = 1`,
`input`, `effect`, singular `transition = [{ request, transition }]`, and
`default_transition`. The input is an event or enum value type; each request is
a typed signal value and each transition is a registered adapter-transition ID.

`service_declaration` has exact fields `id`, `semantic_version = 1`, `effect`,
`inputs = [{ role, shape }]`, and `parameters`. A shape contains value type,
unit, and decimal exponent. Parameters are `probability`, `duration_nanos`,
`bits_per_second`, `bytes_per_second`, `operations_per_second`,
`capacity_ratio`, `signed_offset`, or `unsigned_count` and must belong to the
declared effect.

| Mapping `kind` | Fields | Result |
| --- | --- | --- |
| `active_when_true` | `invert` | Persistent activation from Boolean input. |
| `active_when_equal` | `value` | Persistent activation for one enum value. |
| `threshold` | `comparison`, `threshold`, optional `clear_threshold`, `residence_nanos` | Stateful threshold/hysteresis activation. |
| `map_parameter` | `parameter` | Map one signal to one registered effect field. |
| `piecewise_parameter` | `parameter`, ordered `points`, `rounding`, `overflow` | Exact finite transfer function. |
| `hazard` | none | Keyed probability outcome at matching opportunities. |
| `impulse_on_event` | none | One impulse per typed event identity. |
| `state_transition` | `transition_table` | Exhaustively registered adapter transition. |
| `service_profile` | `service_profile` | Registered named physical-input service model. |

Search policy kinds are `fixed`, `branch_outcome { maximum_branches }`,
`branch_transition { candidates }`, `branch_parameter { parameter, candidates }`,
`mutate_trace_window { start_nanos, end_nanos, candidates,
maximum_mutations }`, and `mutate_mapping { point_indices, candidates,
maximum_mutations }`. Mutation candidates are concrete, finite replacement
schedules. A trace candidate names `trace_node` and exact existing sample
coordinates with typed replacement values. A mapping candidate names exact
point indices and complete typed replacement points. Crucible materializes the
bounded Cartesian product into fixed-policy scenarios before starting QEMU; it
never guesses mutation values. `--max-states` is one global budget for that
product: every materialized scenario root consumes one state, and every graph
frontier expansion consumes another. It is not reset for each candidate.
Finding artifacts embed the authenticated transitive signal-object closure and
the exact ordered mutation recipe, so replay does not require the search
store that produced the candidate.

### Fault opportunity operation values

`opportunity_filter.operations` is a required, nonempty list when a binding
declares an opportunity filter. Every value in one list must belong to the
filter's `adapter`; mixed-adapter lists are rejected. `phases` is also required
and nonempty, while `target_kinds` may be empty to avoid further restriction.
For example:

```toml
[plan.fault_binding.opportunity_filter]
adapter = "network"
operations = ["network_transmit", "network_receive"]
phases = ["admit"]
target_kinds = ["network_interface"]
```

The following table is the complete closed operation vocabulary. The
[operation enum and adapter mapping](../../../crates/crucible/crucible-engine/src/model/fault_signal/opportunity.rs)
and the [filter schema and validation](../../../crates/crucible/crucible-engine/src/model/fault_signal/binding.rs)
are the corresponding code contracts.

| Operation value | Adapter | Opportunity represented |
| --- | --- | --- |
| `network_transmit` | `network` | A frame leaves a producer or forwarding interface. |
| `network_receive` | `network` | A frame arrives at a selected recipient interface. |
| `network_contend` | `network` | Participants contend for a shared-medium resource. |
| `network_allocate` | `network` | A shared medium allocates service, a slot, or another bounded resource. |
| `network_enqueue` | `network` | A frame is admitted to a bounded network queue. |
| `network_serve` | `network` | A queued frame consumes modeled link or forwarder service. |
| `network_dequeue` | `network` | A frame leaves a queue for delivery, forwarding, or disposal. |
| `network_learn` | `network` | A forwarder updates learned forwarding state. |
| `network_lookup` | `network` | A forwarder consults routing, switching, firewall, or related state. |
| `network_route` | `network` | A route is selected or transitions between versioned paths. |
| `network_translate` | `network` | An address, port, protocol, or control result is translated. |
| `network_encapsulate` | `network` | A frame or bundle is encapsulated or decapsulated. |
| `network_select` | `network` | A path, backend, beam, gateway, channel, or candidate is selected. |
| `network_traverse` | `network` | Traffic traverses one segment, medium, path, or scheduled contact. |
| `network_change` | `network` | A versioned topology, path, profile, or attachment changes. |
| `network_discover` | `network` | A network, peer, access point, cell, service, or contact is discovered. |
| `network_authenticate` | `network` | Network access or peer identity is authenticated. |
| `network_associate` | `network` | An interface establishes an attachment or association. |
| `network_handoff` | `network` | An attachment moves between access resources or paths. |
| `network_acquire` | `network` | A scheduled contact, channel, beam, or link is acquired. |
| `network_custody` | `network` | Delay-tolerant traffic changes custody or durable queue ownership. |
| `network_teardown` | `network` | A contact, association, tunnel, or attachment is torn down. |
| `storage_read` | `storage` | A block or 9p read request is resolved. |
| `storage_write` | `storage` | A block or 9p write request is resolved. |
| `storage_flush` | `storage` | A guest requests a durability or ordering barrier. |
| `storage_discard` | `storage` | A block range is discarded or deallocated. |
| `storage_get_length` | `storage` | Guest-visible device capacity is queried. |
| `storage_reset` | `storage` | A storage device, controller, namespace, or path is reset. |
| `storage_erase` | `storage` | A flash erase block is erased. |
| `storage_refresh` | `storage` | Media is refreshed to restore or retain readable state. |
| `storage_admit` | `storage` | A controller decides whether to admit an operation. |
| `storage_submit` | `storage` | An admitted operation is submitted to controller service. |
| `storage_complete` | `storage` | A block, controller, array, or 9p operation completes. |
| `storage_enumerate` | `storage` | A controller, namespace, path, or 9p device is enumerated. |
| `storage_rebuild` | `storage` | An array performs bounded rebuild work. |
| `node_boot` | `node` | A node enters its boot transition. |
| `node_run` | `node` | A node or vCPU performs scheduled execution. |
| `node_pause` | `node` | A node enters a paused state. |
| `node_reset` | `node` | A node performs an architectural reset. |
| `node_stop` | `node` | A node stops or powers off. |
| `node_resume` | `node` | A stopped or paused node resumes execution. |
| `cpu_instruction` | `node` | A vCPU reaches an instruction execution opportunity. |
| `cpu_exception` | `node` | A vCPU reaches an architecture exception transition. |
| `cpu_halt` | `node` | A vCPU enters or leaves a halted service state. |
| `register_access` | `node` | An architecture-resolved register is read or written. |
| `memory_fetch` | `node` | A vCPU fetches instruction bytes. |
| `memory_load` | `node` | A vCPU loads data from memory. |
| `memory_store` | `node` | A vCPU stores data to memory. |
| `memory_dma_read` | `node` | A device reads guest memory through DMA. |
| `memory_dma_write` | `node` | A device writes guest memory through DMA. |
| `memory_page_table_walk` | `node` | A vCPU MMU reads a page-table descriptor. |
| `memory_refresh` | `node` | Modeled main memory performs a refresh operation. |
| `interrupt_raise` | `node` | An interrupt source raises an interrupt. |
| `interrupt_route` | `node` | An interrupt controller resolves a route and target. |
| `interrupt_acknowledge` | `node` | A target acknowledges an interrupt. |
| `interrupt_deliver` | `node` | An interrupt is delivered to a target vCPU. |
| `interrupt_return` | `node` | A vCPU completes an interrupt-return transition. |
| `clock_read` | `node` | Guest software reads a registered clock source. |
| `clock_arm` | `node` | A guest-visible timer is armed. |
| `clock_fire` | `node` | A guest-visible timer reaches its fire boundary. |
| `clock_synchronize` | `node` | A clock synchronization update is applied. |
| `clock_source_switch` | `node` | Guest-visible timekeeping switches clock sources. |
| `accelerator_submit` | `node` | A job is submitted to an accelerator queue. |
| `accelerator_execute` | `node` | An accelerator performs modeled job work. |
| `accelerator_complete` | `node` | An accelerator job produces a completion. |
| `accelerator_memory_access` | `node` | An accelerator accesses device or guest memory. |
| `accelerator_reset` | `node` | An accelerator performs a reset transition. |

### Target selector values

| Target kind | Adapter | What it selects |
| --- | --- | --- |
| `network_interface` | network | One endpoint interface. |
| `network_segment` | network | One directed physical or logical segment. |
| `network_medium` | network | One shared medium/channel resource. |
| `network_queue` | network | One bounded queue. |
| `network_forwarder` | network | Switch, router, modem, repeater, or gateway. |
| `network_path` | network | Versioned directed path. |
| `network_attachment` | network | Interface association/attachment. |
| `network_contact` | network | Scheduled or acquired contact. |
| `block_device` | storage | One whole block or flash device. |
| `block_range` | storage | One byte-addressed range of a block or flash device. |
| `storage_controller` | storage | One controller namespace or access path. |
| `storage_array` | storage | One declared array member or path. |
| `ninep_device` | storage | One 9p device. |
| `node` | node | One whole emulated node. |
| `vcpu` | node | One virtual CPU. |
| `register` | node | One architecture-resolved register bit range. |
| `memory_range` | node | One physical or resolved virtual memory range. |
| `interrupt` | node | One exact source, route, target vCPU, and vector/type. |
| `clock_source` | node | One registered guest-visible clock source. |
| `accelerator` | node | Declared accelerator device. |

Sensor targets are specification-only and are rejected by this schema.

### Exhaustive effect registry

Every row below is executable. `Parameters` names the primary closed table or
fields; nested enum fields are defined in the network, storage, and node
parameter sources listed at the start of
[Plans, signals, bindings, and faults](#plans-signals-bindings-and-faults).
Legal targets,
phases, lifetimes, composition, capabilities, and replay-evidence keys are
enforced by the [effect registry](../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_registry.rs).

| Effect `kind` | Parameters and purpose |
| --- | --- |
| `network.availability` | Directional `state` and queued/in-flight policies; make an interface, segment, path, or contact up, down, receive-only, or transmit-only. |
| `network.flap` | Down, training, and recovery durations; model timed link transitions. |
| `network.negotiated_mode` | Rate, duplex, lanes, FEC, and training duration. |
| `network.profile_delta` | Optional latency/rate/error/technology profile components. |
| `network.propagation_delay` | Exact delay or a distance/velocity lookup; adds propagation time above the immutable scheduler floor. |
| `network.access_delay` | Per-opportunity arbitration or retry delay in virtual nanoseconds. |
| `network.jitter` | Keyed bounded delay variation with a closed distribution. |
| `network.service_curve` | Ordered piecewise-constant rate segments integrated over virtual time. |
| `network.token_bucket` | Rate, burst size, and initial tokens for a checkpointed service constraint. |
| `network.queue_policy` | Byte/frame capacity, discipline/classes, and overflow response. |
| `network.frame_loss` | Explicit or millionths-probability frame loss keyed to stable frame identity. |
| `network.burst_error_state` | Correlated good/bad loss and corruption process with checkpointed transition state. |
| `network.duplicate` | Probability, copy count, and inter-copy gap for bounded additional deliveries. |
| `network.reorder` | Bounded reorder window and keyed selection rule. |
| `network.payload_transform` | Bit flip, field mutation, truncation, or undetected corruption. |
| `network.detected_frame_error` | CRC/FCS/framing/FEC class and corrected/retry/drop/reset receiver action. |
| `network.mtu` | MTU plus drop, fragment, or typed-error oversize policy. |
| `network.pause_backpressure` | Class-scoped pause state with an optional exact resume boundary. |
| `network.recipient_subset` | Versioned multicast/broadcast candidate filtering by declared membership. |
| `network.forwarder_lifecycle` | Restart/reset/power-loss transition, downtime, and queue/table retention. |
| `network.forwarding_mutation` | Wrong-port, flood, blackhole, loop, or stale-age lookup mutation. |
| `network.route_transition` | Old/new paths, convergence events, and in-flight policy. |
| `network.control_plane_service` | Bounded control queue, service curve, work size, and overflow. |
| `network.firewall_disposition` | Selector/state machine plus accept, reject, or drop. |
| `network.connection_state` | NAT, conntrack, load-balancer, tunnel, or DNS table and overflow state. |
| `network.shared_medium` | Resources, arbitration, contention/collision/capture, and duty cycle. |
| `network.rf_channel` | Carrier/bandwidth, signal/noise/gain/attenuation/fading, SINR transfer, and retry outcomes. |
| `network.association` | Candidate set, authentication, selection, hysteresis, timers, handoff, and traffic policy. |
| `network.control_result_transform` | Technology operation plus drop, stale, bias, replace, or typed error result. |
| `network.contact` | Contact intervals, range delay, and beam/gateway candidates. |
| `network.custody_queue` | Bundle/byte capacity, priority, expiry, route/contact plan, hop bound, and overflow. |
| `storage.availability` | Online/offline/read-only/degraded state. |
| `storage.reported_capacity` | Guest-visible length and affected-range policy. |
| `storage.latency` | Operation-filtered base delay and keyed jitter at resolve or delivery. |
| `storage.service` | Integrated bandwidth, IOPS, queue, class, and token service constraints. |
| `storage.operation_failure` | Operation set, keyed probability, and referenced typed failure result. |
| `storage.stall_timeout` | Stall, recovery, and modeled timeout coordinates with explicit completion behavior. |
| `storage.completion_reorder` | Bounded keyed completion ordering within the declared window. |
| `storage.duplicate_completion` | Protocol-valid additional completions and guest duplicate disposition. |
| `storage.read_transform` | Bit corruption, stale-version read, or cross-range/device misdirection. |
| `storage.write_disposition` | Applied, lost, torn, or misdirected persistence. |
| `storage.persistence_order` | Declared durable partial order and violation behavior. |
| `storage.volatile_cache` | Bounded cache admission, eviction, dirty-eviction, and power-loss-protection policy. |
| `storage.volatile_cache_loss` | Boundary impulse selecting the exact eligible cached-write set to lose. |
| `storage.flush_disposition` | Honest, erroring, lying, or stalled flush result. |
| `storage.media_range` | Persistent bad, latent, poisoned, or read-only byte range with count/time thresholds. |
| `storage.flash_state` | Per-erase-block wear, program/erase failure, retention, and read-disturb state. |
| `storage.controller_lifecycle` | Reset/reconnect/enumeration/namespace/path transition and pending-I/O treatment. |
| `storage.array_state` | Array member/path state, selection, quorum, rebuild, and partial-update consistency. |
| `ninep.result` | Typed errno, stale object, or misdirected 9p result. |
| `ninep.visibility` | Checkpointed committed-versus-visible frontier and lookup behavior. |
| `node.lifecycle` | Boot, crash, reset, power-cycle, stop, and recovery transition with explicit state loss. |
| `node.hang` | Node, vCPU-set, or accelerator progress outage with watchdog/recovery policy. |
| `cpu.service` | Exact rational execution capacity, thermal throttling, and vCPU service schedule. |
| `cpu.vcpu_state` | Online, offline, or stalled vCPU transition with round-robin topology state. |
| `cpu.register_transform` | Architecture-resolved bit flip, stuck mask/value, or replacement. |
| `cpu.instruction_transform` | Instruction result corruption, skip, or replay at an exact instruction opportunity. |
| `cpu.exception` | Architecture-specific machine check, hardware error, or injected exception. |
| `interrupt.disposition` | Drop, delay, duplicate, or replace one exact interrupt delivery. |
| `interrupt.storm` | Bounded generated interrupt sequence with exact acknowledgements. |
| `memory.mutation` | Atomic GPA/GVA bit flip or byte replacement at a safe boundary. |
| `memory.access_transform` | Stuck/read-corrupt/lost-write/torn-write/poison transform by access class. |
| `memory.ecc_event` | Corrected or uncorrectable ECC event with a platform error record and acknowledgement. |
| `memory.region_state` | Persistent failure, retention decay, or rowhammer disturbance with range counters. |
| `memory.service` | Shared memory-access latency, bandwidth, and page-table-walk service constraints. |
| `clock.transform` | Guest-visible offset, rational drift, jump, freeze, jitter, or wander. |
| `clock.source_state` | Clock-source failure, fallback, selection, or synchronization state. |
| `accelerator.lifecycle` | Device disappearance, reset, reconnect, enumeration, and queue treatment. |
| `accelerator.result_transform` | Ordered accelerator job-field or result-buffer corruption. |
| `accelerator.memory_event` | Corrected, uncorrectable, or transformed device-memory event. |
| `accelerator.service` | Compute, memory, thermal, or power service cap with queue/job ledgers. |

The registry has 71 distinct keys and exactly one row above for each key. A
reference-integrity gate compares this document with the closed
registry so a new executable kind cannot ship undocumented.

## Properties and predicates

### `[properties]` and assertions

| Location | Required fields | Meaning |
| --- | --- | --- |
| `[properties]` | `id` | Generated content address for the property bundle. |
| `[[properties.assertion]]` | `id`, `message`, `property` | Stable assertion name, user-facing failure message, and nested temporal property. |

### Property kinds

`[properties.assertion.property]` is tagged by `kind`. Supplying a field not
listed for that kind is an error.

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `always` | `predicate` | Invariant: the predicate must hold at every relevant evaluation point. |
| `sometimes` | `predicate` | Liveness witness: the predicate must hold at least once. |
| `eventually` | `trigger`, `property`, `deadline_ticks` | After `trigger` holds, `property` must hold within this many virtual-time ticks from the trigger instant. |
| `after_quiescence` | `predicate` | Check the predicate once when the run quiesces or reaches its run limit. |
| `reachable` | `predicate`, `expectation` | Coverage-style reachability or unreachability expectation. |

Reachability expectation tables:

| `kind` | Fields/default | Meaning |
| --- | --- | --- |
| `reachable` | `on_unreached: warn\|fail`, default `warn` | Expect at least one witness; warn or fail if none is observed. |
| `unreachable` | None | Fail if a witness is observed. |

### Predicate kinds

A predicate may be a DSL string or a structured table tagged by `kind`. The
same vocabulary is accepted for assertion predicates and event triggers.

| `kind` | Required/optional fields | True when |
| --- | --- | --- |
| `at` | `at_ticks` | Virtual time equals the exact coordinate. |
| `after` | `duration_ticks`, `of` | The exact picosecond duration has elapsed since event ID `of` last fired. |
| `timer` | `name` | The named relative timer fires. |
| `network_match` | `predicate`, `link?` | A delivered frame, optionally restricted to a link ID, matches the nested frame predicate. |
| `console_match` | `node`, `regex` | The node's captured serial output matches the regex program. |
| `coverage_point` | `node`, `point` | The node executes the nested address or symbol code point. |
| `memory_predicate` | `node`, `place`, `cmp`, `value` | The sampled memory/register value satisfies the comparison. |
| `io_pattern` | `node`, `io_kind` | An I/O event of the selected kind is observed for the node. |
| `node_state` | `node`, `state` | The node has the selected lifecycle state. |
| `assertion_state` | `name`, `state` | The named assertion is satisfied or violated. |
| `quiescent` | None | The scheduler has settled with no immediately runnable work. |
| `named` | `name`, `nodes?` | The named predicate DSL entry resolves in the current world/plan context. |
| `guest_marker` | `marker` | The white-box-enabled guest emits the named bare marker or declared assertion marker as applicable. |
| `all_of` | `predicates` array | Every nested predicate is true. |
| `any_of` | `predicates` array | At least one nested predicate is true. |
| `once` | `predicate` | The nested predicate has become true at least once. |
| `not` | `predicate` | The nested predicate is false. |

### Named predicate DSL strings

These strings may appear directly where a predicate is expected. Structured
`kind = "named"` form also accepts `name` plus an optional `nodes` array.

| DSL value | Expansion |
| --- | --- |
| `no_crashed_nodes` | `not(any_of(node_state(node, crashed) for every VM))` |
| `quiescent` | `quiescent` |
| `node_alive:<node>` | `not(node_state(<node>, crashed))` |
| `node_crashed:<node>` | `once(node_state(<node>, crashed))` |

### Nested predicate value tables

Frame predicates used by `network_match`:

| `kind` | Required fields | Match |
| --- | --- | --- |
| `any` | None | Any delivered frame. |
| `exact` | `bytes_hex` | Complete frame bytes equal the hexadecimal sequence. |
| `contains` | `needle_hex` | Frame contains the hexadecimal byte sequence. |
| `prefix` | `prefix_hex` | Frame begins with the hexadecimal byte sequence. |

Code points used by `coverage_point`:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `guest_address` | `address` | Exact guest virtual address. |
| `symbol` | `name` | Symbol resolved by the configured observation backend. |

Places used by `memory_predicate`:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `physical_address` | `address`, `width` | Read a guest physical address. |
| `virtual_address` | `address`, `width` | Read a guest virtual address. |
| `symbol` | `name`, `width` | Read memory at a symbol. |
| `register` | `name`, `width` | Read a guest register. |

Memory widths:

| `width` | Read size |
| --- | ---: |
| `u8` | 8 bits |
| `u16` | 16 bits |
| `u32` | 32 bits |
| `u64` | 64 bits |

Unsigned memory comparisons:

| `cmp` | Operation |
| --- | --- |
| `eq` | Equal to `value`. |
| `ne` | Not equal to `value`. |
| `lt` | Less than `value`. |
| `le` | Less than or equal to `value`. |
| `gt` | Greater than `value`. |
| `ge` | Greater than or equal to `value`. |

`io_pattern.io_kind` values:

| Value | Matches |
| --- | --- |
| `any` | Any modeled I/O event. |
| `block_read` | Block read. |
| `block_write` | Block write. |
| `fsync` | Flush/fsync event. |
| `nine_p` | 9p filesystem event. |
| `network` | Network event. |

Node lifecycle states:

| `node_state.state` | Meaning |
| --- | --- |
| `started` | The declared node is running. |
| `crashed` | The node entered its modeled crash state. |
| `hung` | The node is running but no longer making modeled progress. |
| `exited` | The guest/runtime exited. |

Assertion phases:

| `assertion_state.state` | Meaning |
| --- | --- |
| `satisfied` | The named assertion reached its satisfied terminal phase. |
| `violated` | The named assertion reached its violated terminal phase. |
