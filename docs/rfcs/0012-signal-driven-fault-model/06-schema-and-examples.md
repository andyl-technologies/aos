# 06 — Scenario schema and worked examples

These are focused authoring excerpts, not complete standalone scenario files;
the exhaustive v2 grammar is
[`09-normative-schema.md`](09-normative-schema.md). Names shown for executable
selectors, mappings, and effects are normative. Surrounding world/plan fields
are omitted where they do not help the example. Angle-bracket digest payloads
are editorial replacement tokens and must be replaced by 64 lowercase
hexadecimal digits in accepted input. Unknown fields and values are rejected,
every ID is stable, and builder APIs calculate content addresses.

Network, storage/9p, and node examples describe first-PR executable schema.
Sensor examples deliberately specify a future complete adapter contract; the
first implementation rejects their target and effect kinds as unknown and does
not include dormant structs, enum variants, or feature flags for them.

## 6.1 Top-level plan additions

The `plan` gains signal programs and fault bindings while retaining existing
entries/events:

```toml
[plan]
id = "blake3:<generated-plan-id>"
kind = "event_graph"

[[plan.signal]]
id = "maintenance-window"
kind = "pulse"
domain = "virtual_time"
value_type = "bool"
start_nanos = 30000000000
duration_nanos = 5000000000
inactive = false
active = true

[[plan.fault_binding]]
id = "maintenance-link-outage"
signal = "maintenance-window"
mapping = { kind = "active_when_true" }
selector = { kind = "network_segment", segment = "client--server", direction = "both" }
effect = { kind = "network.availability", semantic_version = 1, state = "down" }
search = "fixed"
```

This is the sole form of a finite network partition. Static scenarios use the
same signal/binding path as recorded, spatial, or stateful scenarios; there is
no separate interval-fault schema.

## 6.2 Recorded trace source

```toml
[[plan.signal]]
id = "recorded-rack-vibration"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<normalized-trace-manifest>"
raw_provenance = "blake3:<raw-capture-or-provenance-record>"
channel = "acceleration_rms"
value_type = "u64"
unit = "micrometres_per_second_squared"
interpolation = "linear"
before = "error"
after = "hold"
missing = "error"

[plan.signal.time_mapping]
source_epoch = 1720000000000000000
virtual_epoch_nanos = 0
numerator = 1
denominator = 1
rounding = "floor"
```

## 6.3 Transfer function and hazard

```toml
[[plan.signal]]
id = "vibration-error-probability"
kind = "piecewise_linear"
input = "recorded-rack-vibration"
output_type = "probability_millionths"
rounding = "nearest_ties_to_even"
points = [
  { input = 0, output = 0 },
  { input = 5000, output = 0 },
  { input = 10000, output = 1000 },
  { input = 25000, output = 50000 },
  { input = 50000, output = 500000 },
]

[[plan.fault_binding]]
id = "vibration-caused-disk-read-error"
signal = "vibration-error-probability"
mapping = { kind = "hazard" }
selector = { kind = "block_device", device = "database-disk" }
opportunity = { operation = "read", phase = "resolve" }
effect = { kind = "storage.operation_failure", semantic_version = 1, operation_filter = "read", status = "io_error" }
search = "branch_outcome"
```

The probability decision is keyed by scenario seed, signal, binding, device, and
stable read opportunity. It does not consume the network or another disk's draw
cursor.

## 6.4 One common cause across network, storage, and sensors

The same vibration source can fan out:

```toml
[[plan.fault_binding]]
id = "vibration-caused-connector-flap"
signal = "recorded-rack-vibration"
mapping = { kind = "threshold", comparison = "greater_equal", threshold = 30000, clear_threshold = 20000, minimum_active_nanos = 100000000 }
selector = { kind = "fault_domain", domain = "rack-a-connectors" }
effect = { kind = "network.availability", semantic_version = 1, state = "down" }

[[plan.fault_binding]]
id = "vibration-caused-imu-noise"
signal = "recorded-rack-vibration"
mapping = { kind = "piecewise_parameter", parameter = "amplitude", table = "blake3:<vibration-to-imu-noise-table>" }
selector = { kind = "sensor_channel", sensor = "rack-imu", channel = "acceleration" }
effect = { kind = "sensor.noise", semantic_version = 1, distribution = "keyed_uniform" }
```

The failures are correlated because they share physical cause values. Their
operation-level decisions remain independently keyed by binding and opportunity.

## 6.5 Datacenter power and cooling cascade

```toml
[[plan.signal]]
id = "pdu-a-voltage"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<power-quality-trace>"
channel = "voltage_microvolts"
value_type = "u64"
unit = "microvolts"
interpolation = "hold_previous"
before = "hold"
after = "hold"
missing = "error"

[[plan.signal]]
id = "pdu-a-brownout"
kind = "hysteresis"
input = "pdu-a-voltage"
initial = false
set_when = { comparison = "less", value = 105000000 }
clear_when = { comparison = "greater_equal", value = 110000000 }
minimum_residence_nanos = 50000000

[[plan.fault_binding]]
id = "brownout-switch-reset"
signal = "pdu-a-brownout"
mapping = { kind = "impulse_on_rising_edge" }
selector = { kind = "network_forwarder", id = "top-of-rack-a" }
effect = { kind = "network.forwarder_lifecycle", semantic_version = 1, transition = "reset", downtime_nanos = 2000000000, queue_policy = "drop", table_policy = "lose_dynamic" }

[[plan.fault_binding]]
id = "brownout-storage-cache-loss"
signal = "pdu-a-brownout"
mapping = { kind = "impulse_on_rising_edge" }
selector = { kind = "fault_domain", domain = "rack-a-storage" }
effect = { kind = "storage.volatile_cache", semantic_version = 1, loss_selector = "all", reset_event = "power_loss" }

[[plan.fault_binding]]
id = "brownout-sensor-dropout"
signal = "pdu-a-brownout"
mapping = { kind = "active_when_true" }
selector = { kind = "fault_domain", domain = "rack-a-environmental-sensors" }
effect = { kind = "sensor.dropout", semantic_version = 1, stage = "sample", missing_status = "unavailable" }
```

One rising edge produces two impulses and one persistent dropout. Reset/cache
application order is adapter-defined and recorded.

## 6.6 Wired provider path with shared conduit

```toml
[[world.network_segment]]
id = "site-a-to-pop-a"
kind = "fiber"
endpoint_a = "site-a-router:wan0"
endpoint_b = "provider-pop-a:access0"
minimum_latency_nanos = 1000000
fault_domains = ["conduit-17", "provider-west"]

[[world.network_segment]]
id = "site-b-to-pop-a"
kind = "fiber"
endpoint_a = "site-b-router:wan0"
endpoint_b = "provider-pop-a:access1"
minimum_latency_nanos = 1200000
fault_domains = ["conduit-17", "provider-west"]

[[plan.signal]]
id = "conduit-17-construction-cut"
kind = "event_sequence"
domain = "virtual_time"
value_type = "event:availability-transition/v1"
events = [
  { at_nanos = 60000000000, sequence = 0, payload = { state = "down" } },
  { at_nanos = 90000000000, sequence = 0, payload = { state = "up" } },
]

[[plan.fault_binding]]
id = "conduit-17-all-fibers"
signal = "conduit-17-construction-cut"
mapping = { kind = "state_transition" }
selector = { kind = "fault_domain", domain = "conduit-17" }
effect = { kind = "network.availability", semantic_version = 1, state_from = "payload.state" }
```

Both site paths fail together. A separately routed segment that is not in the
conduit remains available.

## 6.7 Mobile endpoint through a city

```toml
[[world.mobile_endpoint]]
id = "delivery-vehicle"
node = "vehicle-computer"
truth_trajectory = "vehicle-position-truth"

[[plan.signal]]
id = "vehicle-position-truth"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<normalized-drive-trace>"
channel = "position_local_mm"
value_type = "vector3:i64"
unit = "millimetres"
interpolation = "linear"
before = "error"
after = "error"
missing = "error"

[[world.network_medium]]
id = "city-cellular"
kind = "cellular"
carrier_khz = 3500000
channel_width_khz = 100000
cells = ["sector-a", "sector-b", "sector-c"]
attenuation_field = "blake3:<city-attenuation-grid>"
interference_signal = "city-interference"

[[plan.signal]]
id = "city-interference"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<spectrum-monitor-trace>"
channel = "interference_mdbm"
value_type = "i64"
unit = "millidecibel_milliwatts"
interpolation = "linear"
before = "hold"
after = "hold"
missing = "interpolate"

[[plan.fault_binding]]
id = "vehicle-cellular-profile"
signals = ["vehicle-position-truth", "city-interference"]
mapping = { kind = "map_parameter", parameter = "external_interference_power", lookup = "blake3:<calibrated-city-cellular-model>" }
selector = { kind = "network_interface", endpoint = "delivery-vehicle", interface = "wwan0" }
effect = { kind = "network.rf_channel", semantic_version = 1, medium = "city-cellular" }
```

The channel model emits candidate quality and directed profiles. A separate
association state machine selects the serving cell:

```toml
[[plan.signal]]
id = "vehicle-serving-cell"
kind = "finite_state_machine"
semantic = "cellular-association/v1"
input = "vehicle-cellular-profile.candidates"
initial = "searching"
hysteresis_mdb = 3000
time_to_trigger_nanos = 500000000
handover_interruption_nanos = 75000000
tie_break = "canonical_cell_id"
```

Observed GNSS may be faulted independently without changing
`vehicle-position-truth`.

## 6.8 Satellite contact and rain fade

```toml
[[plan.signal]]
id = "sat-7-contact"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<normalized-contact-plan>"
channel = "ground-a-sat-7-contact"
value_type = "bool"
interpolation = "hold_previous"
before = "inactive"
after = "inactive"
missing = "error"

[[plan.signal]]
id = "ground-a-rain-rate"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<normalized-weather-trace>"
channel = "rain_micrometres_per_hour"
value_type = "u64"
unit = "micrometres_per_hour"
interpolation = "linear"
before = "hold"
after = "hold"
missing = "error"

[[plan.fault_binding]]
id = "sat-7-contact-availability"
signal = "sat-7-contact"
mapping = { kind = "active_when_true", invert = true }
selector = { kind = "network_segment", segment = "ground-a--sat-7" }
effect = { kind = "network.availability", semantic_version = 1, state = "down" }

[[plan.fault_binding]]
id = "sat-7-rain-fade"
signal = "ground-a-rain-rate"
mapping = { kind = "piecewise_parameter", table = "blake3:<rain-to-satellite-profile-table>" }
selector = { kind = "network_segment", segment = "ground-a--sat-7" }
effect = { kind = "network.profile_delta", semantic_version = 1, parameter_from_mapping = "attenuation_millidecibels" }
```

Range-varying propagation is another input to the segment profile. Contact and
weather remain separately observable causes.

## 6.9 Sensor truth versus observed value

```toml
[[world.sensor]]
id = "freezer-temperature"
kind = "temperature"
truth_signal = "freezer-temperature-truth"
sample_period_nanos = 1000000000
channels = ["temperature"]

[[plan.signal]]
id = "freezer-temperature-truth"
kind = "trace"
domain = "virtual_time"
artifact = "blake3:<freezer-thermal-trace>"
channel = "temperature_millicelsius"
value_type = "i64"
unit = "millicelsius"
interpolation = "linear"
before = "hold"
after = "hold"
missing = "error"

[[plan.signal]]
id = "sensor-bias"
kind = "ramp"
domain = "virtual_time"
value_type = "i64"
unit = "millicelsius"
start_nanos = 0
end_nanos = 86400000000000
start_value = 0
end_value = 2500
rounding = "floor"

[[plan.fault_binding]]
id = "freezer-sensor-drift"
signal = "sensor-bias"
mapping = { kind = "map_parameter", parameter = "bias" }
selector = { kind = "sensor_channel", sensor = "freezer-temperature", channel = "temperature" }
opportunity = { operation = "sample", phase = "produce" }
effect = { kind = "sensor.bias", semantic_version = 1, stage = "sample" }
```

Properties may compare the observed sample to system behavior, while debugger
telemetry can show both truth and observed value.

## 6.10 Capability requirements

The builder derives requirements from effects, but scenarios may declare the
expected set for review:

```toml
[plan.fault_capabilities]
required = [
  "signal.trace.v1",
  "signal.hysteresis.v1",
  "network.profile.v1",
  "network.association.cellular.v1",
  "block.volatile-cache-loss.v1",
  "qemu.memory.bit-flip.physical.v1",
]
```

Admission compares the derived set, declared set, and selected backend. A
missing capability is a usage error before any guest starts.

## 6.11 Locked replay sketch

```toml
[replay]
mode = "locked_effects"
scenario = "blake3:<scenario>"
schedule = "blake3:<schedule>"
resolved_effect_trace = "blake3:<effect-trace>"
required_capability_set = "blake3:<capability-set>"

[replay.validation]
verify_opportunity = true
verify_precondition_digest = true
verify_profile_digest = true
verify_final_fingerprint = true
```

Locked replay never means blind mutation. Each effect record must align with the
encountered opportunity and declared capability semantics.

## 6.12 Authoring guidance implied by the design

- Prefer one physical/environmental signal with several bindings over several
  unrelated faults that happen to share timestamps.
- Keep truth signals distinct from observed sensor channels.
- Use outcome replay for exact incidents, channel replay for calibrated behavior,
  and environment/mobility replay for counterfactual exploration.
- Use pulse or step signals for simple finite or permanent static faults; they
  use the same binding and adapter path as dynamic signals.
- Name failure domains explicitly when components share power, cooling, conduit,
  spectrum, chassis, enclosure, weather, or geography.
- Record units, interpolation, extrapolation, and missing-data behavior; never
  rely on importer defaults.
- Treat an unsupported high-fidelity effect as an admission error, not a request
  for silent approximation.
