# 12 — Complete future sensor adapter specification

This file fully specifies the sensor domain while deliberately adding no v2
schema or implementation. Crucible's current QEMU/device layer has no modeled
sensor transport. The first implementation PR must preserve this document and
negative tests proving every sensor target/effect is unknown. A later RFC may
activate this schema only by implementing the entire adapter and its live device
transport atomically.

## 12.1 Truth, internal state, and observation

The sensor model separates four values:

1. **physical truth:** the modeled environmental/body quantity;
2. **transducer input/internal state:** truth after placement/orientation and
   physical sensor dynamics;
3. **ideal sample:** quantized/calibrated result before faults;
4. **guest observation:** value, timestamp, validity, status, and sequence
   delivered through the modeled sensor device.

A fault names the stage it changes. Observation bias does not alter truth.
Physical-cause signals such as heat or vibration may affect several sensors and
other hardware through separate bindings.

- **[SENSOR-1]** Truth, internal state, ideal sample, and delivered observation
  MUST have distinct typed identities and event evidence.
- **[SENSOR-2]** A sensor fault MUST declare `stage = transducer`, `sample`,
  `timestamp`, `transport`, or `delivery`; no default is permitted.
- **[SENSOR-3]** Physical truth can change only through an explicit world-model
  signal, never as a side effect of corrupting an observation.

## 12.2 Future world schema

The later schema uses:

```toml
[[world.sensor]]
id = "freezer-temperature"
kind = "temperature"
device = "future-qemu-sensor-device-id"
truth_signal = "freezer-temperature-truth"
sample_period_nanos = 1000000000
channels = ["temperature"]

[world.sensor.clock]
source = "sensor-oscillator"
timestamp_epoch_nanos = 0

[world.sensor.calibration]
semantic_version = 1
artifact = "blake3:<64-lowercase-hex>"
```

Required sensor fields are ID, closed kind, live device/transport, truth signal,
positive sample period or explicit trigger source, channel declarations,
timestamp source, quantization, limits, calibration, warm-up state, and buffer
policy. A sensor cannot exist without a live device capability; an in-memory
sample producer is not production support.

## 12.3 Targets and opportunities

| Target | Stable identity |
| --- | --- |
| `sensor_device` | node/device ID plus sensor ID |
| `sensor_channel` | sensor ID plus channel ID |
| `sensor_axis` | sensor/channel plus axis enum |
| `sensor_frame` | sensor/channel plus frame format ID |
| `sensor_transport` | sensor plus modeled bus/device queue ID |

```text
truth update -> transducer update -> sample trigger -> ideal conversion
             -> calibration/quantization -> timestamp -> buffer/transport
             -> guest delivery
```

Stable sample identity is sensor ID, channel set version, trigger identity,
sample sequence, and subframe index. Opportunities are `transduce`, `sample`,
`convert`, `timestamp`, `enqueue`, `transport`, and `deliver`. Periodic triggers
are exact virtual-time events; interrupt/command triggers use the originating
operation ID.

## 12.4 Channel types

| Sensor kind | Required truth and observation channels |
| --- | --- |
| temperature | temperature, validity/status |
| humidity | relative humidity or absolute humidity with explicit unit, temperature compensation input |
| pressure/barometer | pressure, optional derived altitude metadata |
| light | illuminance or typed spectral bands |
| electrical meter | voltage, current, power, energy, phase where applicable |
| thermocouple/RTD | temperature plus open/short/reference-junction status |
| GNSS | position, velocity, fix state, accuracy/covariance fields, solution time |
| IMU | accelerometer, gyro, optional magnetometer, device temperature |
| magnetometer | magnetic vector, validity, calibration state |
| encoder/tachometer | count, position/speed, direction, index state |
| proximity/range | scalar range and return validity |
| radar | bounded typed detections with range, velocity, angle, strength, track ID |
| LiDAR | bounded point/return frame with coordinate frame and per-return fields |
| sonar | bounded return/range frame and medium parameters |
| camera | typed frame format, dimensions, exposure metadata, payload artifact/bytes |
| microphone | typed PCM frame, channels, cadence, gain/status |

All variable-size frames have schema bounds from §13 and deterministic canonical
ordering. Covariance, transforms, and calibration matrices use exact rationals or
content-addressed lookup artifacts, never native floats.

## 12.5 Transducer and calibration pipeline

The transducer stage may apply exact placement/orientation transform, response
lookup, warm-up dynamics, bounded integration/filter state, and environmental
sensitivity. Calibration then applies offset vector, gain/mixing matrix,
piecewise table, quantization, clipping, and status rules in declared order.

Every stage is independently versioned and logs input/output digests. Calibration
loss selects a declared alternate calibration artifact or identity/default table;
it does not erase an arbitrary implementation object.

## 12.6 Sensor effect registry

| Effect key | Stage/lifetime | Required fields | Composition and replay evidence |
| --- | --- | --- | --- |
| `sensor.dropout` | sample/transport/delivery; opportunity or persistent | channel/frame selector, probability or explicit event, missing-sample status | independent hazards; sample ID and suppressed stage |
| `sensor.delay` | transport/delivery; opportunity | `delay_nanos` | checked-sum; original/final coordinates |
| `sensor.stale` | sample/delivery; opportunity | eligible history bound or explicit sample ID, timestamp policy | conflict per channel; selected prior sample evidence |
| `sensor.duplicate` | delivery; opportunity | copies, gap, timestamp/sequence policy | bounded copy sum and stable order |
| `sensor.reorder` | delivery; opportunity | window, selector | maximum window with keyed shifts |
| `sensor.timestamp_transform` | timestamp; persistent/opportunity | offset, drift ratio, jitter/wander, jump, freeze, source state | clock algebra; raw/final timestamp and monotonicity action |
| `sensor.bias` | transducer/sample; persistent | unit-compatible scalar/vector signal | checked-sum |
| `sensor.gain` | transducer/sample; persistent | exact scalar or matrix rational | rational product or ordered matrix product |
| `sensor.noise` | transducer/sample; opportunity/state | recorded noise signal or exact keyed distribution and correlation | checked-sum in canonical binding order |
| `sensor.spike` | sample; opportunity | amplitude/value transform and duration/count | ordered-transform |
| `sensor.clip` | sample; persistent | minimum/maximum per channel | intersection of ranges; empty intersection conflicts |
| `sensor.quantize` | sample; persistent | step, origin, rounding | coarsest compatible step or ordered explicit transforms |
| `sensor.deadband` | transducer/sample; state | width, reference-update rule | one declared state machine per channel |
| `sensor.hysteresis` | transducer/sample; state | set/clear thresholds and residence | one declared state machine per channel |
| `sensor.stuck` | sample; persistent | constant/last value, status/timestamp policy | severity over normal; multiple unequal forced values conflict |
| `sensor.wrap` | sample; persistent | bit width, signedness, modulus/origin | ordered-transform |
| `sensor.axis_transform` | transducer/sample; persistent | permutation, sign vector, rational mixing/rotation matrix | ordered matrix product with bounds |
| `sensor.calibration_state` | transducer/sample; state | artifact/default selection and transition | one state machine per sensor |
| `sensor.validity` | sample/delivery; persistent/opportunity | valid/invalid/degraded plus typed reason | severity |
| `sensor.result_transform` | sample/frame; opportunity | typed kind-specific field/return/pixel/sample transform | ordered-transform with before/after digest |

## 12.7 Taxonomy mapping

| Taxonomy row | Required sensor effect program |
| --- | --- |
| dropout | `sensor.dropout(stage=sample or delivery)` |
| delayed sample | `sensor.delay` |
| stale sample | `sensor.stale` |
| duplicate sample | `sensor.duplicate` |
| reordered samples | `sensor.reorder` |
| timestamp offset | `sensor.timestamp_transform(offset)` |
| timestamp drift/jitter | `sensor.timestamp_transform(drift/jitter)` |
| additive bias | `sensor.bias` |
| scale/gain error | `sensor.gain` |
| drift | time/environment signal into `sensor.bias` + `sensor.gain` |
| noise | `sensor.noise` |
| burst noise/spikes | `sensor.spike` or stateful noise |
| saturation/clipping | `sensor.clip` |
| quantization loss | `sensor.quantize` |
| deadband | `sensor.deadband` |
| hysteresis | `sensor.hysteresis` |
| stuck-at | `sensor.stuck` |
| wrap/overflow | `sensor.wrap` |
| cross-axis coupling | `sensor.axis_transform` matrix |
| axis swap/inversion | `sensor.axis_transform` permutation/sign |
| orientation miscalibration | `sensor.axis_transform` rotation lookup/matrix |
| calibration loss | `sensor.calibration_state` |
| warm-up error | warm-up state signal into `sensor.bias` + `sensor.gain` + `sensor.noise` |
| temperature sensitivity | temperature signal into `sensor.bias` + `sensor.gain` |
| vibration sensitivity | vibration signal into `sensor.noise` + `sensor.dropout` + `sensor.bias` |
| electromagnetic interference | common signal into `sensor.noise` + `sensor.dropout` + `sensor.validity` |
| position offset/drift | GNSS-channel `sensor.bias`; truth unchanged |
| multipath jump | spatial/event signal into GNSS `sensor.result_transform` |
| loss of fix | GNSS `sensor.validity` state transition |
| stale fix | GNSS `sensor.stale` |
| spoofed solution | typed GNSS `sensor.result_transform(replace)` |
| accelerometer/gyro bias | axis-specific `sensor.bias` |
| integration drift | stateful `sensor.bias` + IMU `sensor.result_transform` |
| magnetic interference/hard-iron bias | magnetometer `sensor.bias` + `sensor.axis_transform` |
| blocked port/weather coupling | barometer `sensor.delay` + `sensor.stuck` + `sensor.result_transform` |
| occlusion/dropout | radar/LiDAR/sonar `sensor.dropout` + `sensor.result_transform` |
| ghost/range bias | return insertion/range `sensor.result_transform` |
| missed/extra transition | encoder `sensor.dropout` + `sensor.duplicate` |
| offset/saturation/phase error | electrical-meter `sensor.bias` + `sensor.clip` + `sensor.timestamp_transform` + `sensor.result_transform` |
| open/short/reference-junction fault | `sensor.validity` + rail/bias `sensor.result_transform` |
| dropped/corrupt frame | camera `sensor.dropout` + `sensor.result_transform` |
| exposure/focus fault | camera `sensor.result_transform` over typed metadata/pixels |
| dropout/clipping/noise | microphone `sensor.dropout` + `sensor.clip` + `sensor.noise` |
| humidity/pressure/light drift | corresponding channel `sensor.bias` + `sensor.gain` |

## 12.8 Truth versus GNSS/IMU in mobile networking

Network mobility always consumes `truth_trajectory`. When the sensor adapter
eventually ships, GNSS/IMU observations are separate device outputs. A scenario
may intentionally derive truth from a normalized recorded GNSS trace only by
declaring that trace as truth provenance; applying a GNSS observation fault
afterward still does not move the endpoint.

## 12.9 Buffer and transport semantics

The future device declares sample/frame buffer capacity, overflow policy,
transport service, interrupt/poll behavior, and reset treatment. Buffer entries
include complete sample identity and timestamp. Overflow is `drop_oldest`,
`drop_newest`, `reject_trigger`, or typed device-specific behavior. Transport
faults belong to the appropriate bus/network adapter; the sensor adapter records
whether failure occurred before or after the sample entered transport.

## 12.10 Future implementation gate

A sensor implementation cannot merge until:

1. A QEMU or other production device exposes every declared sensor kind/channel
   through a versioned live transport.
2. Every effect in §12.6 has strict schema, state, composition, live application,
   event, checkpoint, search, and both replay evidence.
3. Every taxonomy row in §12.7 has isolated, overlap, common-cause, truth versus
   observation, and malformed tests.
4. Variable-sized camera/radar/LiDAR/audio frames obey fixed resource bounds and
   content-addressed payload rules.
5. The v2 negative guards are removed only with a scenario schema major/minor
   version that explicitly activates the complete sensor registry.

- **[SENSOR-4]** Mock, fake, and test-double sensor backends are prohibited; the
  future adapter MUST pass its gates through production device transports.
- **[SENSOR-5]** No sensor schema key, enum, capability, or placeholder adapter
  may land before the complete future implementation is available.
