# 09 — Normative scenario schema

This file replaces the illustrative status of §6 with the normative fault-system
schema. It specifies logical TOML fields and validation; the Rust model and
binary codecs use the same closed registry. Examples in §6 must parse under this
schema unless explicitly marked `specification-only`.

## 9.1 Strictness, versions, and common values

Every scenario using this system declares:

```toml
schema = "crucible.scenario.v5"

[plan]
kind = "event_graph"
fault_model = "signal_bindings_v2"
seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

- All tables are closed. Unknown or duplicate keys, duplicate IDs, implicit
  numeric conversions, TOML floats, datetimes, and heterogeneous arrays fail.
- IDs match `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`, are 1–96 ASCII bytes, and are
  unique in their namespace. User-supplied IDs are never hashes.
- Content references use `blake3:` plus exactly 64 lowercase hexadecimal digits.
- Hex payloads are lowercase, even length, and contain no prefix or separators.
- Required fields have no default. The only defaults are listed explicitly in
  this file and enter canonical material as their expanded values.
- `u32`, `i64`, and `u64` values through `i64::MAX` use TOML integers. Because
  TOML has no unsigned integer type, `u64` values from `i64::MAX + 1` through
  `u64::MAX` use the reserved canonical string `"u64:<unsigned-decimal>"`.
  Leading signs, leading zeroes, malformed decimals, using that string below
  the threshold, and using it for a non-`u64` field are rejected. A value
  outside the field's type or semantic bounds is rejected while parsing.
- Rational tables contain `numerator: i64` and `denominator: u64`; denominator
  is positive and the pair must already be in lowest terms with a positive
  denominator.
- Quantities never carry free-form unit strings. `unit` is one closed enum value
  from §9.2 and `scale_decimal_exponent` is an `i8` from -18 through 18.

- **[SCHEMA-1]** The TOML parser, public Rust builders, canonical material, binary
  codec, generated reference, and JSON projection MUST be derived from or checked
  against one closed registry.
- **[SCHEMA-2]** Omitted defaults MUST canonicalize identically to their explicit
  values, and serializers MUST emit the explicit canonical form.
- **[SCHEMA-3]** Specification-only sensor/IoT/power-device kinds MUST be rejected
  as unknown by v2 even though this RFC documents their future schema.

## 9.2 Value types and units

`value_type` is one of:

```text
bool
i64
u64
ratio
duration_nanos
rate_per_second
probability_millionths
enum:<schema-id>
event:<schema-id>
vector2:<scalar-type>
vector3:<scalar-type>
bytes
```

Initial unit enum:

| Unit | Stored type | Scale/range rule |
| --- | --- | --- |
| `dimensionless` | i64/u64/ratio | Explicit decimal scale allowed. |
| `virtual_nanoseconds` | u64/i64 | Scale must be zero. |
| `millimetres` | i64 | Local coordinates; no implicit geographic conversion. |
| `square_millimetres` | i64 | Squared Cartesian distance; no implicit conversion to length. |
| `millimetres_per_second` | i64 | Local velocity. |
| `millidegrees` | i64 | Normalize angles by operator-specific closed interval. |
| `millicelsius` | i64 | Absolute temperature; conversions explicit. |
| `microvolts` | i64/u64 | Electrical potential. |
| `microamps` | i64/u64 | Current. |
| `microwatts` | i64/u64 | Power. |
| `femtowatts` | u64 | Canonical linear RF/optical power; maximum is approximately 18.4 kW. |
| `microjoules` | i64/u64 | Energy. |
| `millidecibels` | i64 | Ratio in dB. |
| `millidecibel_milliwatts` | i64 | Absolute RF power. |
| `kilohertz` | u64 | Frequency. |
| `bits_per_second` | u64 | Positive where used as service. |
| `bytes_per_second` | u64 | Positive where used as service. |
| `operations_per_second` | u64 | Positive where used as service. |
| `parts_per_million` | i64/u64 | Signed only when the modeled quantity permits. |
| `probability_millionths` | u32 | 0–1,000,000. |
| `micrometres_per_second_squared` | i64/u64 | Acceleration. |
| `micrometres_per_hour` | u64 | Precipitation rate. |

Adding a unit changes the schema minor version and requires conversion,
canonicalization, boundary, and overflow vectors.

## 9.3 Signal tables

Every signal is an array element:

```toml
[[plan.signal]]
id = "signal-id"
kind = "constant"
domain = "virtual_time"
value_type = "u64"
unit = "dimensionless"
scale_decimal_exponent = 0
```

Common required fields are `id`, `kind`, `domain`, `value_type`, and `unit`.
`scale_decimal_exponent` defaults to `0`. `domain` is `virtual_time`,
`node_counter`, `operation`, `spatial`, `event`, or `state`. Domain-specific
coordinates use the tables in §9.4.

### Source-node fields

| `kind` | Additional required fields | Optional fields and defaults |
| --- | --- | --- |
| `constant` | `value` | None. |
| `step` | `points = [{coordinate, sequence, value}]` | `before = error`; equal coordinates require increasing sequence. |
| `pulse` | `start`, `duration`, `inactive`, `active` | None; duration positive. |
| `periodic_pulse` | `epoch`, `period`, `width`, `inactive`, `active` | `phase = 0`; period positive; width no greater than period. |
| `ramp` | `start`, `end`, `start_value`, `end_value`, `rounding` | None; end greater than start. |
| `triangle` | `epoch`, `period`, `minimum`, `maximum`, `rounding` | `phase = 0`. |
| `sawtooth` | `epoch`, `period`, `minimum`, `maximum`, `rounding` | `phase = 0`. |
| `event_sequence` | `events = [{coordinate, sequence, payload}]` | None. |
| `trace` | `artifact`, `raw_provenance`, `channel`, `interpolation`, `before`, `after`, `missing` | `quality_channel`; `quality_accept`; time mapping required for timestamped trace. |
| `telemetry` | `adapter`, `target`, `field` | `boundary_delay = 1`; only value 1 is accepted in v1. |
| `point_set` | `artifact`, `coordinate_frame`, `interpolation`, `outside` | Linear interpolation requires the artifact's canonical line/triangle/tetrahedron simplex mesh. |
| `regular_grid` | `artifact`, `coordinate_frame`, `origin`, `cell_size`, `dimensions`, `interpolation`, `outside` | None. |
| `tiled_grid` | `manifest`, `coordinate_frame`, `tile_size`, `interpolation`, `outside` | None. |
| `zone_map` | `artifact`, `coordinate_frame`, `boundary`, `overlap` | None. |
| `path_profile` | `artifact`, `path`, `interpolation`, `before`, `after` | None. |
| `seeded_field` | `field_seed_domain`, `coordinate_frame`, `quantization`, `correlation`, `distribution` | Distribution parameters. |
| `transmitter_field` | `transmitter`, `coordinate_frame`, `position_signal`, `model`, `lookup` | `orientation_signal`, `environment_signals`; all inputs share the output domain. |
| `bernoulli` | `probability_millionths`, `key_domain` | `opportunity_filter`; Boolean output. |
| `uniform_integer` | `minimum`, `maximum`, `key_domain` | `opportunity_filter`; inclusive bounds. |
| `exponential_wait` | `rate` rational, `sampler_version`, `sampler_table`, `key_domain` | `maximum_nanos`; duration output. |
| `weibull_wait` | `shape` rational, `scale_nanos`, `sampler_version`, `sampler_table`, `key_domain` | `maximum_nanos`; duration output. |

`interpolation` is `exact`, `hold_previous`, `nearest`, or `linear`. Every
`linear` source also requires `rounding` and `overflow`; these fields are part
of canonical identity. Boundary
behavior is `error`, `hold`, `constant`, `repeat`, or `inactive`; `constant`
requires `boundary_value`. Missing behavior is `error`, `hold`, `interpolate`,
or `inactive`. `rounding` is `floor`, `ceiling`, `toward_zero`,
`away_from_zero`, or `nearest_ties_to_even`.

`repeat` is admitted for ordered time/counter/operation/state step and trace
sources with a positive extent. Spatial outside policies reject `repeat`
because a point set, grid, zone, or path has no unique periodic continuation.

Normalized point-set artifacts store samples in lexicographic coordinate order
and an optional canonical list of simplices. A simplex contains two, three, or
four strictly increasing sample indexes and represents a line, triangle, or
tetrahedron. Degenerate cells fail import. Linear sampling evaluates exact
barycentric weights, chooses the first containing simplex on a shared boundary,
and applies the declared rounding and overflow policy once to the weighted sum.

Every tile referenced by a tiled-grid manifest is a regular grid in the same
coordinate frame. Its origin equals the tile's inclusive minimum, its final
sample coordinate equals the tile's exclusive maximum, and that final sample is
the interpolation halo shared with the adjacent tile. The declared tile extent
must equal `cell_size * (dimensions - 1)` on every axis; mismatches fail loudly.

Transmitter lookup artifacts contain the transmitter position, a strictly
ordered distance/value curve, an optional canonical receiver-orientation
correction table, and one exact additive coefficient per environment signal.
An authored `orientation_signal` requires a nonempty orientation table and an
omitted orientation signal requires the table to be empty. Orientation rows are
ordered yaw/pitch/roll millidegrees and nearest-row ties use row order.

### Pure operator fields

Pure operators use `kind`, `inputs`, and the fields below. Input order is
semantic for subtraction, division, select, distance, and event merge; otherwise
canonicalization sorts by input ID only when the operator is mathematically
commutative.

| Family/kinds | Required fields | Validation |
| --- | --- | --- |
| `add`, `subtract`, `min`, `max` | `inputs` | Same scalar/vector type and unit. |
| `multiply_ratio`, `divide_ratio` | `input`, `ratio` | Denominator positive; output unit declared. |
| `absolute`, `negate` | `input` | Signed numeric only; minimum signed value follows overflow policy. |
| `clamp` | `input`, `minimum`, `maximum` | Same type/unit; minimum no greater than maximum. |
| comparisons | `left`, `right` | Same comparable type/unit; Boolean output. |
| `all`, `any` | `inputs` | At least one Boolean input. |
| `not` | `input` | Boolean. |
| `select` | `condition`, `when_true`, `when_false` | Branch types/units equal. |
| `lookup_step` | `input`, ordered `points`, `before`, `after` | Strict input keys. |
| `piecewise_linear` | `input`, ordered `points`, `rounding`, `overflow` | Strict keys; numeric output. |
| `enum_map` | `input`, exhaustive `entries` | Every input variant exactly once. |
| `unit_convert` | `input`, `from_unit`, `to_unit`, `ratio`, `offset`, `rounding`, `overflow` | Registered compatible dimension. |
| `delay` | `input`, `delay`, `retained_samples` | Positive domain coordinate delay and positive hard history bound. |
| `sample_hold` | `input`, `cadence`, `epoch`, `retained_samples` | Positive cadence and positive hard history bound. |
| window operators | `input`, `window`, `sampling`, `retained_samples` | Bounded retained sample/change count. |
| `distance` | `left`, `right`, `metric`, `rounding` | Same coordinate frame; metric `euclidean`, `euclidean-squared`, or `manhattan`; squared output uses `square_millimetres`. |
| `zone_contains` | `position`, `zone_map`, `zone` | Matching frame. |
| `field_sample` | `field`, `position` | Matching dimensions/frame. |
| `orientation_delta` | `left`, `right`, `convention` | Convention is `yaw-pitch-roll-millidegrees`; each component uses the signed shortest arc. |
| edge operators | `input` | Boolean; emit typed edge event. |
| `merge_events` | `inputs`, `source_sequence_limit` | Inputs canonicalize by source ID; merged sequence is `source_index * source_sequence_limit + source_sequence`. |
| `gate_events` | `events`, `gate` | Typed events plus Boolean gate. |

Every arithmetic/operator table requires `overflow = error/saturate`; default is
`error`. Saturation limits are the declared output type bounds and become
canonical material.

### Stateful operator fields

| `kind` | Required fields and state |
| --- | --- |
| `hysteresis` | `input`, `initial`, `set_when`, `clear_when`, `minimum_residence_nanos`; stores Boolean and last transition. |
| `debounce` | `input`, `initial`, `residence_nanos`; stores committed/candidate values and candidate coordinate. |
| `integrator` | `input`, `initial`, `cadence_nanos`, `time_unit_nanos`, `rounding`, `overflow`; zero cadence selects source change points; stores accumulator and last coordinate/value. |
| `leaky_integrator` | `input`, `initial`, `cadence_nanos`, `time_unit_nanos`, `decay_ratio`, `maximum_catch_up_steps`, `rounding`, `overflow`; stores accumulator, latest observed input, and cadence coordinate. Evaluation fails before mutation when the required catch-up exceeds the positive authored ceiling. |
| `finite_state_machine` | `input_events`, `states`, `initial`, exhaustive transition table, unmatched-event policy; stores state and timers. |
| `markov_chain` | `states`, `initial`, `opportunity`, exact probability rows; stores state and transition ordinal. |
| `burst_process` | `initial`, good/bad transition probabilities, transition opportunity; stores state and ordinal. |
| `counter` | `events`, `initial`, `maximum`, `overflow`, optional reset event; stores count. |
| `queue_model` | arrival events, service signal, capacity, discipline, overflow; stores bounded ordered entries and service remainder. |

State-machine transitions contain `from`, `event`, optional Boolean `guard`,
`to`, emitted event, and timer operations. Duplicate `(from,event,guard)` rows
are rejected. State machines cannot invoke effects.

### Exact stochastic samplers

`bernoulli` compares a keyed uniform `u32` in `[0,999999]` with
`probability_millionths`. `uniform_integer` uses rejection sampling over a keyed
counter stream to avoid modulo bias. `exponential_wait` and `weibull_wait` use
versioned integer inverse-CDF lookup artifacts supplied by the schema registry;
their tables cover the full keyed `u64` quantile domain, use monotone `u64`
durations, and are checked against committed golden vectors. No platform math
function participates in canonical evaluation. `key_domain` is
`opportunity`, `transition`, or `coordinate`; it fixes the stable identity tuple
defined in §1.6. A finite `maximum_nanos` clips only after inverse-CDF rounding
and is canonical material.

## 9.4 Coordinates and trace mapping

| Domain | Required coordinate table |
| --- | --- |
| virtual time | `{ nanos = u64 }` |
| node counter | `{ node = id, retired_instructions = u64 }` |
| operation | `{ adapter, target, operation, producer_sequence, suboperation }` |
| spatial | `{ frame, x_mm, y_mm, z_mm, yaw_mdeg, pitch_mdeg, roll_mdeg }` |
| event | `{ coordinate, sequence }` in the event source's parent domain |
| state | `{ adapter, target, boundary_sequence }` |

Trace time mapping is:

```toml
[plan.signal.time_mapping]
source_epoch = 0
virtual_epoch_nanos = 0
numerator = 1
denominator = 1
rounding = "floor"
```

The mapped coordinate is `virtual_epoch + round((source-source_epoch) *
numerator / denominator)`. Overflow, non-monotone output, and two samples mapping
to the same coordinate are errors unless the channel is an ordered event channel.

## 9.5 Binding tables

```toml
[[plan.fault_binding]]
id = "binding-id"
signals = ["signal-a"]
sampling = "at_opportunity"
search = "fixed"

[plan.fault_binding.mapping]
kind = "active_when_true"

[plan.fault_binding.selector]
kind = "network_segment"
segment = "segment-id"
direction = "a_to_b"

[plan.fault_binding.effect]
kind = "network.availability"
semantic_version = 1
state = "down"
```

`signal = "id"` is accepted only as canonical input syntax for exactly one
signal and serializes as `signals = ["id"]`. `sampling` is `at_boundary`,
`at_opportunity`, `at_change`, an explicit positive `cadence_nanos`, or
`at_event`. An `at_event` binding requires an `event_parent` table whose kind is
exactly `virtual_time`, `opportunity_operation`, `opportunity_state`, or
`node_counter`; `node_counter` also requires a stable node signal ID. Event
inputs and their declared parent projection are canonical identity, and an
opportunity parent requires the ordinary opportunity filter. Search is
`fixed`, `branch_outcome`, `branch_transition`, `branch_parameter`,
`mutate_trace_window`, or `mutate_mapping`; non-fixed forms require a bounded
`[plan.fault_binding.search_policy]` table.

`mutate_trace_window` requires `start_nanos`, `end_nanos`,
`maximum_mutations`, and a nonempty `candidates` array. Each candidate contains
`trace_node` and a nonempty, strictly ordered `samples` array of
`{ coordinate, event_sequence?, value }` replacements. Coordinates use mapped
virtual nanoseconds and must already exist in the selected normalized trace.
`mutate_mapping` requires `point_indices`, `maximum_mutations`, and a nonempty
`candidates` array. Each candidate contains a nonempty, strictly index-ordered
`points` array of `{ index, point = { input, output } }` replacements. Candidate
values must have the exact admitted trace-channel or mapped-parameter type. The
CLI enumerates the bounded Cartesian product and executes only the resulting
fixed-policy scenarios; no runtime mutation callback or implicit value
generator exists.

Mapping schemas:

| `kind` | Required fields | Output |
| --- | --- | --- |
| `active_when_true` | Boolean signal; optional `invert=false` | Active/inactive effect. |
| `active_when_equal` | enum signal, `value` | Active/inactive effect. |
| `threshold` | numeric signal, comparison, threshold, optional clear threshold and residence | Stateful activation. |
| `map_parameter` | signal, `parameter`, optional explicit unit conversion | Effect field value. |
| `piecewise_parameter` | signal, `parameter`, points/table, rounding, overflow | Effect field value. |
| `hazard` | probability signal or `probability_millionths`, opportunity filter | Keyed opportunity outcome. |
| `impulse_on_event` | typed event, optional payload-field mapping | One impulse per event identity. |
| `state_transition` | event/enum signal, exact request overrides, mandatory default transition | Exhaustive adapter transition request; unknown requests take the typed default and never fail during execution. |
| `service_profile` | numeric signals; ordered `{ role, shape }` input contracts; service kind and exact parameters | Named typed service contribution; roles, shapes, and values cross the adapter seam and enter action identity. |

Service-profile roles are closed by the selected effect contract. Adapters
select inputs by role and verify the accompanying shape; they never assign
meaning by authored signal name or by an untyped positional convention.

An opportunity-filter table contains adapter, operation, phase, and optional
typed target/operation-field predicates. Fields and values come from §8.2; the
filter cannot name arbitrary event JSON or inspect guest memory. A binding that
uses `at_opportunity` requires a filter unless its selector resolves to an effect
with exactly one legal operation and phase. The expanded filter is canonical
material.

The complete selector kinds are exactly those in §8.2 plus `fault_domain`, which
resolves to a finite set of typed targets, and `target_set`, which contains a
non-empty canonical list of selectors of one adapter domain. Cross-adapter
fan-out uses separate bindings sharing signals, never a heterogeneous selector.

Effect `kind`, fields, phases, and lifetimes are exactly §8.3–§8.5. The schema
registry expands each effect into a distinct closed field table; generic
`parameters`, arbitrary strings, and extension maps are forbidden.

## 9.6 Network world tables

| Table | Required fields | Optional/defaulted fields |
| --- | --- | --- |
| `world.network_interface` | `id`, `endpoint`, `technology` | `addresses=[]`, `fault_domains=[]` |
| `world.network_segment` | `id`, `kind`, endpoint/interface A and B, `minimum_latency_nanos` | directional base profiles, `medium`, `forwarders=[]`, `fault_domains=[]` |
| `world.network_medium` | `id`, `kind`, resources, access policy | channel geometry, capture/interference policy, `fault_domains=[]` |
| `world.network_forwarder` | `id`, `kind`, ports, bounded table and queue declarations | control-plane service, `fault_domains=[]` |
| `world.network_queue` | owner, `id`, capacity, discipline, overflow | class map, service reference |
| `world.network_path` | `id`, ordered segments/forwarders, direction | route policy and MTU/encapsulation policy |
| `world.network_attachment` | `id`, interface, canonical candidate segments, `technology`, semantic version, authentication policy, address-continuity policy | none |
| `world.network_contact_plan` | `id`; canonical finite contacts, each with `contact`, `service_resource`, positive `route_cost`, exact `routing_propagation_nanos`, directed endpoints, half-open interval, acquisition/teardown, capacity profile, beam, gateway, range, confidence, and provenance | none |

A contact interval's acquisition and teardown durations are its complete
transition policy. `network.contact` therefore references the interval set,
range-to-delay lookup, and admitted beam and gateway sets directly; it does not
accept a second state-machine artifact with ambiguous event names.

Contact records are strictly ordered by `(start_nanos, end_nanos, contact)` and
contact IDs are unique within the schedule version. Time overlap is valid for
different `service_resource` IDs, which permits simultaneous beams, radios,
links, gateways, and media. Intervals naming the same exclusive resource MUST
NOT overlap. A custody effect additionally requires `priority` in
`bulk|normal|expedited|critical` and a positive `max_visited_hops` bounded by
256. There are no omitted/defaulted route fields and no legacy direct-contact
form. The adapter stores at most 262,144 keyed contact-service states and
262,144 live contact reservation records in aggregate. Completed direct records
and custody records whose owning frame is no longer live fold into an exact
settled service cursor and cumulative
counters; path admission fails atomically if its complete hop set would exceed
the live-record bound.

An `overflow` policy artifact has `disposition`, optional `timeout_nanos`, and
optional `typed_error`. `timeout_nanos` is required only for `timeout`, and
`typed_error` is required only for `typed_error`. The referenced error class is
determined by the consumer and is checked when the plan is admitted:
`network.control_plane_service` requires a `control_result`, while
`network.custody_queue` requires a `typed_response` because it rejects a data
frame on the reverse path. A `control_result` is a closed `schema` ID plus
bounded canonical bytes. A `typed_response` is one of the closed packet
response variants in §8.3.4. There is no untyped extension map, legacy error
string, or cross-use of the two result classes. Control-service and transform
schema meanings are defined completely in §8.3.8.

`network.detected_frame_error(receiver_action=retry)` requires a positive retry
delay, retry limit, positive actual-attempt count no greater than that limit,
and a final success boolean. An exhausted result is valid only when actual
attempts equal the limit. `link_reset` instead requires only a positive reset
duration and creates an adapter-owned timed outage through that boundary.

`network.pause_backpressure` requires a canonical traffic-class ID. Its
optional positive duration is measured from the contribution transition
coordinate; omission means paused until that persistent contribution is
removed. An independent resume-event reference is not accepted. Queue
continuations retain exact remaining nano-bit demand so activation, expiry, and
removal reschedule existing work without replaying service already received.
| `world.network_recipient_membership` | version `id`; nonempty recipient records in identity order; each record has `member` and monotone `joined_sequence` | none |
| `world.mobile_endpoint` | `id`, node, truth trajectory | observed-position sensor ID is specification-only and rejected in v2 |

`network.recipient_subset` names one exact recipient-membership version.
Explicit drops must be a subset of that version and a retained count cannot
exceed it. `oldest` and `newest` use `joined_sequence` with recipient identity
as the tie-break; `canonical_order` uses identity order; `keyed_uniform` ranks
the complete membership from the scenario seed, binding, source-frame identity,
membership version, and recipient. All route-expanded copies of one multicast
frame therefore make one shared selection rather than independent draws.

Every `kind` resolves to a technology contract in §10. A technology table that
lacks its required parameters or state-machine semantic version is rejected.

## 9.7 Storage and node world additions

Block/9p declarations add required bounded durability/media tables from §11:

```toml
[world.block_device.persistence]
sector_bytes = 512
atomic_write_bytes = 512
volatile_cache_bytes = 8388608
controller_buffer_bytes = 1048576
controller_entries = 1024
flush_semantics = "ordered_barrier"
discard_semantics = "deterministic_zero"

[world.block_device.media]
kind = "flash"
erase_block_bytes = 2097152
program_page_bytes = 16384
endurance_cycles = 3000
```

Every `FaultObjectId` parameter used by a storage effect resolves in the
scenario-owned `world.storage_policy_artifact` registry below. An ID is only an
address; it has no built-in, host-local, or convention-by-name meaning. The
registry is canonical ID order, rejects duplicate IDs and unknown fields, uses
`semantic_version = 1`, contains at most 65,536 declarations, and permits at
most 65,536 entries or 16 MiB of inline bytes in one declaration.

| Artifact `kind` | Complete payload | Referenced by |
| --- | --- | --- |
| `typed_result` | exactly one protocol form: block `result = success/offline/read_only/invalid_range/busy/timeout/medium_error/integrity_error/io_error/no_space/not_found/stale`, or positive Linux 9p `errno` | operation failure, timeout, acknowledged write, flush, nested protocol errors |
| `service` | discipline `fifo/strict_priority/weighted_round_robin`; canonical classes with ID, nonempty operation set, priority, positive weight; whether rebuild shares service | `storage.service.service_policy` |
| `path` | selection `active_passive/round_robin/least_outstanding/stable_hash`; bounded positive attempt count; positive adjacent-attempt delay and recovery-probe interval; nonempty canonical retry-result set excluding success | every controller or array path declaration |
| `remote_protocol` | transport `nvme_tcp/iscsi/nbd`; bounded positive outstanding-command count; positive command timeout and reconnect delay; explicit cross-reconnect ordering | remote storage-media declarations |
| `duplicate_completion` | `ignore`, `protocol_error` with typed-result reference, or `reset` with a reset-kind `controller_transition` reference | `storage.duplicate_completion.protocol_policy` |
| `controller_transition` | exact transition `reset/reconnect/enumerate`; typed failure result; explicit unadmitted, queued, executing, resolved, and completed-undelivered treatments; controller-buffer/cache retention; request-ID epoch rule; duplicate-history rule; topology re-enumeration rule; positive recovery duration | duplicate-completion `reset` and `storage.controller_lifecycle.transition_policy` |
| `cache` | eviction `fifo/lru/writeback_sequence`; dirty eviction `persist` or `fail` with typed-result reference; power-loss protection | `storage.volatile_cache.cache_policy` |
| `persistence` | ready-fragment ordering `preserve/reverse_ready/descending_range/keyed_permutation`; added delay; barrier preservation | `storage.persistence_order.ordering_rule` |
| `retention` | positive minimum age, wear-age contribution, bit probability, bounded changed-bit count | `storage.flash_state.retention_rule` |
| `read_disturb` | positive read threshold, bounded neighbor distance, bit probability, bounded changed-bit count | `storage.flash_state.read_disturb_rule` |
| `program_erase` | normal program/erase and worn probabilities; explicit partial-program and partial-erase booleans | `storage.flash_state.program_erase_rule` |
| `array_state` | selected World array has one explicit guest-visible logical block device plus distinct backing members; separate canonical member and path tables contain every and only its members/paths, with explicit online state | required `storage_array.member_path_state`; optionally replaced by `storage.array_state.member_path_state` while that state machine is active |
| `array_selection` | `lowest_healthy/stable_hash/least_loaded` | required `storage_array.selection_policy`; optionally replaced by `storage.array_state.selection_policy` |
| `rebuild` | positive chunk bytes, bounded queue depth, positive byte rate | required `storage_array.rebuild_service`; optionally replaced by `storage.array_state.rebuild_service` |
| `array_consistency` | `require_quorum/degraded_commit/atomic_stripe`; the array and effect each reference a non-success block `typed_result` for requests with no legal quorum | required `storage_array.consistency_policy` and `storage_array.failure_result`; optionally replaced by the corresponding `storage.array_state` fields |
| `ninep_visibility` | scope `global/per_session/writer_immediate`; `atomic_metadata_and_data`; `retain_deleted_objects`; `data_visibility_lag_nanos` absent for atomic visibility and required positive for non-atomic visibility | `ninep.visibility.visibility_policy` |
| `ninep_object` | absolute canonical path including `/`; 32-bit 9p QID version sequence; Linux mode; bounded exact bytes; `deleted`; a deleted object requires zero mode and empty bytes, while live objects require directory, regular-file, or symlink mode and directories require empty bytes | stale or misdirected `ninep.result`; `ninep.visibility.update` |
| `bytes` | nonempty bounded exact bytes | static stale block-read versions |

Every `[[world.fault_topology.storage_array]]` row requires `device`,
`semantic_version`, `layout`, `chunk_bytes`, `read_quorum`, `write_quorum`,
canonical `members`, canonical `paths`, `member_path_state`, `selection_policy`,
`rebuild_service`, `consistency_policy`, `failure_result`, and `fault_domains`.
The logical `device` is distinct from every member device; backing devices are
unique; ordinals are the contiguous sequence beginning at zero; the member/path
state artifact is an exact table for the declaration; and member capacity after
layout overhead covers the logical device. These required references form the
fault-free baseline. An active `storage.array_state` action replaces the whole
baseline policy atomically and reversion restores the baseline; fields never
inherit piecemeal and there are no implicit defaults.

Plan admission checks every reference's artifact class, nested typed-result
references, namespace capacity/alignment against its exact device, path and
remote-media policy class, controller-owned namespace/path membership, exact
array member/path tables, static misdirection device, and flash-rule class.
Volatile-cache admission is the persistent `storage.volatile_cache` effect;
loss is a separate impulse-only `storage.volatile_cache_loss` binding whose
own signal edge is the event. Its closed selector is `all`, exclusive
`after_sequence`, absolute `range_intersection`, or `keyed_subset` with a
positive count. A block-range target first limits the eligible set to
intersecting entries. `loss = power_loss` excludes entries protected by the
cache policy, while `loss = protection_failure` makes protected entries
eligible. Resolution records the digest of the complete pre-loss entry set and
performs selection and removal atomically on the device-identity-bound worker.
Locked replay passes its recorded digest into that same atomic command as a
required precondition; a mismatch fails before mutation. Missing or
wrong-class references fail before guest start; there is no opaque policy
fallback.

Node declarations add a required `[world.node.fault_capabilities]` table naming
architecture, register schema, memory address spaces/page geometry, interrupt
controllers, clock sources, accelerator devices, and an exact DRAM geometry.
The v1 DRAM geometry is `{ channels = 2, ranks = 2, banks = 16,
interleave_bytes = 64, semantic_version = 1 }`: successive 64-byte GPA lines
select channel, bank, then rank, and the remaining coordinate selects the row
using the `row_bytes` declared by the rowhammer effect. Values must equal the
live QEMU capability handshake; authors cannot claim capabilities absent from
QEMU. The geometry is canonical world content and therefore participates in
scenario identity, checkpoint admission, and replay validation.

## 9.8 Capability and resource declarations

The builder derives `plan.fault_capabilities.required`; an explicitly authored
list must exactly equal the derived sorted list. `[plan.resource_limits]` uses
the fixed fields and hard ceilings in §13. Values may lower but never raise the
compiled hard ceilings.

## 9.9 Canonicalization

Canonical material expands defaults; sorts registry sets, IDs, selectors, and
commutative inputs where allowed; preserves semantic event/path/transform order;
normalizes rationals; includes source artifact hashes and semantic versions; and
excludes comments and TOML presentation order. The TOML serializer emits tables
in schema order and arrays in canonical or semantic order as appropriate.

- **[SCHEMA-4]** Every accepted example MUST round-trip TOML to model to canonical
  TOML and preserve canonical identity.
- **[SCHEMA-5]** Fuzzing MUST prove arbitrary unknown fields and variants fail;
  no `flatten`, catch-all enum, or ignored table is allowed in fault schema code.
- **[SCHEMA-6]** Schema additions require registry, reference, codec, golden,
  bounds, capability, and replay updates in the same change.

## 9.10 Network adapter checkpoint encoding

Network adapter checkpoint semantic version 7 encodes the evaluation
coordinate, per-coordinate and journal sequences, observation journal, token
buckets, queues, burst state, state machines, connection tables, shared-medium
ledgers, backpressure, custody queues, contact-service reservations, and all
boundary state. Every map with a non-string key is an array of key/value entry
pairs in strict key order. Nested connection tables apply the same rule at both
levels. Restore rejects duplicate or noncanonical entry order, inconsistent
sequence joins, broken reservation references, and every exceeded bound. No
earlier checkpoint version is accepted through a compatibility or legacy
decoding path.

The enclosing production fault-runtime checkpoint is version 3 and binds the
network adapter bytes to the scheduler network checkpoint, committed scheduler
frontier, pending routed frames, live QEMU node snapshots, and the canonical
network-state digest. The QEMU node-continuation checkpoint is independently
version 3. For each node it captures both shared-memory network rings, the next
router-to-plugin producer sequence, the next host-consumer sequence for the
plugin-to-router ring, and the next plugin-producer sequence after all live
outbound frames. Restore requires the live outbound frames to form the exact
contiguous sequence interval between those two cursors. A fresh plugin process
receives the authenticated producer cursor as a required launch argument before
registering its TX callback; it cannot reset plugin-local sequence state to
zero. Neither codec accepts an older version or synthesizes an omitted cursor.
After restoring these cursors, the host accepts QEMU's acknowledged `cont`
transition and publishes the next scheduler ceiling before requiring further
QMP progress. An idle restored simulator may park on the plugin barrier
immediately after `cont`, so a pre-ceiling `query-status` would form a control
ordering cycle. The first bounded node step is the required execution proof.
