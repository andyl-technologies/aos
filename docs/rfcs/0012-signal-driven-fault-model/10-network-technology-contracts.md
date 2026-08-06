# 10 — Complete network technology and state-machine contracts

This file supplies the technology semantics behind every network taxonomy row.
All technologies use the common target, opportunity, profile, queue, and effect
contracts in §§3 and 8; technology models contribute typed inputs and state, not
alternate packet-delivery engines.

## 10.1 Universal traversal contract

Every emitted frame receives a stable `FrameId` from producer interface ID,
direction, producer sequence, protocol/flow key, and payload digest. Traversal is:

```text
produce -> interface admission -> medium/segment admission -> enqueue
        -> integrated service -> per-hop resolve -> forward/route
        -> next segment ... -> destination resolve -> deliver
```

At each hop the runtime records profile version, queue/service version, route or
association version, technology state, and applied effect contributors. Frames
never skip a modeled hop. An end-to-end outcome trace is represented as locked
per-hop or explicitly end-to-end evidence, not silently distributed among hops.

### Transition treatment

Every topology or technology transition declares all four policies:

| Traffic class | Required policy enum |
| --- | --- |
| not yet admitted | `reject`, `queue_new`, or `reroute` |
| admitted but not enqueued | `drop`, `complete_old`, or `reroute` |
| queued | `drop`, `drain_old`, `move_preserve_order`, or `move_resequence` |
| in flight | `deliver_old`, `drop`, or `duplicate_old_and_new` |

Defaults do not exist. A transition that omits one class is invalid. Duplicate
and resequence policies create new stable sub-opportunity IDs and are logged.

- **[NTECH-1]** Technology state MUST affect delivery only through registered
  profile, service, queue, forwarding, association, contact, or payload effects.
- **[NTECH-2]** Every technology transition and timer is virtual-coordinate
  state and is included in checkpoint and replay fingerprints.
- **[NTECH-3]** All table lookups use sorted integer keys, declared interpolation,
  fixed rounding, and explicit outside-range behavior.

## 10.2 Point-to-point physical technologies

| `segment.kind` | Required immutable parameters | Required state | Profile derivation |
| --- | --- | --- | --- |
| `ethernet_copper` | length, pair/lane count, supported modes, propagation velocity, FEC/CRC mode | connector, pair, transceiver, negotiation, duplex | mode table indexed by healthy lanes, attenuation/error inputs, and negotiation state |
| `ethernet_fiber` | length, wavelengths, supported modes, optical budget table, FEC | connector, laser, receiver, lane, wavelength, negotiation | transmit power minus attenuation/gain in femtowatts through exact optical lookup |
| `direct_fiber` | length, wavelength/path IDs, optical budget, amplifiers/repeaters | bend, connector, repeater/amplifier, ROADM route | ordered component budget and propagation lookup |
| `pon` | OLT/ONU IDs, split topology, wavelength/resources, ranging slots, mode table | registration, ranging, grant cycle, optical budget | shared upstream scheduler plus directed downstream profile |
| `dsl` | pair length/gauge profile, tone groups, interleave/FEC modes | synchronization, crosstalk/noise, retrain, negotiated mode | canonical SNR-bin lookup to rate/error/interleave delay |
| `docsis` | downstream/upstream channels, modem/CMTS IDs, minislot policy | registration, ranging, channel quality, grant and contention | shared upstream scheduler and channel lookup; directed downstream service |
| `power_line` | coupling endpoints, band/channel map, access policy | grid noise, appliance interferers, negotiated mode | shared-medium interference plus mode lookup |
| `microwave_ptp` | frequency, bandwidth, antenna patterns, path profile | pointing, obstruction, weather, oscillator, radio mode | RF channel model with fixed endpoint association |
| `free_space_optical` | wavelength, aperture/gain tables, path profile | pointing, obstruction, weather, optical mode | optical power lookup plus acquisition state |
| `subsea_fiber` | cable sections, repeaters, wavelengths, landing stations | section/repeater/wavelength state and route | ordered optical profile; a section fault fans out to wavelength paths |
| `serial` | baud/mode/framing, propagation | connector, baud/framing mode | exact serialization plus framing-error lookup |
| `leased_line` | provider segment/path and SLA profile | maintenance/provider state | profile/route transitions from provider signals |

### Training and negotiation state machine

```text
down -> detecting -> training -> up(mode)
  ^         |           |          |
  +---------+-----------+----------+
      failure, signal loss, or reset
```

Fields are `detection_nanos`, per-mode `training_nanos`, ordered candidate modes,
minimum quality/residence for each mode, fallback order, and recovery holdoff.
Candidate ties use canonical mode ID. A mode transition takes the link down or
degraded for its training interval according to the technology table; it is
never an instantaneous rate edit.

### Optical budget

Each component maps input femtowatts and state to output femtowatts through a
monotone content-addressed lookup. Split loss, connector/bend loss, amplifier
gain/noise, wavelength filter/ROADM selection, receiver sensitivity, and FEC
thresholds are ordered by physical path. Overflow is an error. The final lookup
returns corrected-error count, uncorrectable probability, supported mode, and
availability. No logarithmic platform math runs during simulation.

## 10.3 Queues and service

Queue capacity is simultaneously bounded by bytes and frames. Admission fails
when either bound would be exceeded. Queue order key is enqueue coordinate,
producer ID, producer sequence, and copy sequence.

Supported disciplines and exact behavior:

| Discipline | State and selection |
| --- | --- |
| `fifo` | Oldest canonical queue key first. |
| `strict_priority` | Lowest numeric class first, FIFO within class; starvation is observable. |
| `weighted_round_robin` | Integer deficit per class, positive quantum bytes, ascending class cursor. |
| `fixed_slots` | Ordered slot calendar; unused slot policy `idle` or `borrow_by_priority`. |
| `red` | Integer EWMA occupancy, exact thresholds, maximum probability millionths, keyed drop. |

Piecewise service integration uses bit-nanosecond rational remainder state. At a
rate boundary, it integrates only through the boundary, changes the service
version, then continues. Completion is the smallest virtual nanosecond at which
delivered service reaches frame bits, rounded up. Token buckets refill with
checked integer division and retain remainder. Shared schedulers conserve total
service exactly; the sum assigned cannot exceed medium/forwarder service.

Head-of-line blocking declares dependency classes. Bufferbloat is not a special
delay injection: it is queue occupancy produced by arrivals and service.
Priority starvation is the measured absence of service under the declared
discipline. Storms and loops consume real modeled queue/service capacity.

## 10.4 Ethernet and bus shared media

An Ethernet collision domain or wired bus owns a canonical set of active
transmissions. Each transmission has start, bit length, rate/mode, source,
recipient set, and propagation interval. Overlap is determined in virtual time
at each receiver.

- Half-duplex Ethernet applies collision detect, jam duration, retry count, and
  keyed binary exponential backoff with a fixed maximum exponent/retries.
- CAN uses message priority/arbitration ID bit comparison; losing senders retain
  their frame and retry after the winner. Error counters and bus-off state are
  explicit.
- RS-485/serial buses use declared arbitration or collision; no unspecified
  electrical resolution is inferred.
- PON/DOCSIS upstream uses exact grant/minislot schedules; contention regions
  use the configured collision/backoff rule.

Capture compares received power ratios using integer femtowatts and an exact
threshold. A receiver either decodes one winner, records a detected collision,
or—only under explicit `undetected_corruption`—delivers transformed bytes.

## 10.5 Switching, routing, and logical functions

### Forwarding tables

Tables are bounded ordered maps with semantic keys and explicit aging timers.
MAC learning records ingress port and coordinate. Route longest-prefix match
uses address bits, prefix length descending, administrative metric, then route
ID. ECMP hashes a versioned canonical flow tuple with the scenario seed and
route-set ID; no host hash is used.

Forwarding corruption is a typed overlay, never raw memory corruption:

| Mutation | Required fields | Behavior |
| --- | --- | --- |
| wrong port/next hop | match selector and replacement | Lookup resolves to declared replacement. |
| flood | match selector and recipient policy | Canonical eligible ports except ingress. |
| blackhole | match selector | Admit then drop at forwarding resolve. |
| loop | match selector and hop sequence/policy | Traverse until route changes or TTL/hop bound. |
| stale age | entries and timer transform | Retain/remove entries under explicit time rule. |

### Routing convergence

A route event carries route ID, prefixes, next hops, metric, validity, source,
and sequence. A convergence program is an explicit ordered event sequence or a
bounded control-plane queue/service model. Withdrawal, replacement, ECMP churn,
asymmetry, and traffic engineering all create new route-set IDs. No route changes
merely because host time passed.

### Network functions

| Function | Bounded state and failure semantics |
| --- | --- |
| firewall/ACL | Ordered typed rules; optional finite connection state; reject response is explicit. |
| conntrack | Canonical flow key, protocol state, expiry coordinate, maximum entries, exhaustion/reset policy. |
| NAT | Flow key to address/port mapping, deterministic allocator, expiry, capacity, reset behavior. |
| load balancer | Backend membership/version, health events, versioned hash/policy, existing-flow continuity. |
| tunnel/VPN | Endpoint, encapsulation overhead, MTU, keepalive/auth/key state, reconnect and in-flight policy. |
| MPLS | Label stack, bounded lookup, TTL, replacement action, route version. |
| SD-WAN | Controller policy version, candidate paths, selection/hysteresis, stale-policy behavior. |
| DNS | Bounded query/cache/server state, exact records/TTL, timeout/error/stale/wrong-answer effects. |

Protocol parsers accept only the modeled typed fields required by the function;
they do not embed an arbitrary guest-network stack. Unsupported protocols fail
scenario admission rather than bypassing the function model.

## 10.6 Canonical RF channel model

Canonical RF calculations use femtowatts. Importers may accept dBm/dB but
normalize through versioned monotone lookup tables. For receiver `r` and
transmitter `t` at opportunity `o`:

```text
signal_fw = tx_power_fw
          × antenna_gain_ratio(position, orientation, frequency)
          × path_gain_ratio(distance, environment, frequency)
          × fading_ratio(field_position, time_bucket, opportunity)

interference_fw = external_interference_fw
                + sum(other_received_transmitter_fw)
noise_fw = receiver_noise_fw(temperature, bandwidth, state)
sinr_ratio = signal_fw / (interference_fw + noise_fw)
profile = transfer_table(mode, sinr_ratio, load_state)
```

Gain tables return nonnegative ratios in millionths. Each multiplication and
the final SINR division use checked `u128` intermediates and round ties to even;
power sum or result-width overflow fails. Propagation and transfer are distinct
artifact kinds, so neither declaration carries ignored fields. The transfer table returns candidate mode/service,
detected/undetected error probabilities, retry distribution table, and quality
telemetry. Spatial fading keys include field ID, quantized position, frequency
resource, and time bucket; per-frame fast fading additionally includes frame ID.

RF configuration requires carrier Hz, bandwidth Hz, transmit power and receiver
noise in femtowatts, antenna/path gain-ratio artifact, transfer artifact,
spatial/time correlation scales, channel resources, and outside-table behavior.
No free-form radio model name is accepted.

The RF service-profile input contract is ordered `distance: u64 millimetres`,
`orientation: i64 millidegrees`, `interference: u64 femtowatts`, and
`fading: u64 parts_per_million`, all at decimal scale zero. A constant
`1_000_000` fading signal represents no fading. `interference` is the exact sum of external interference and other
received transmitters at the joint medium opportunity. Contact service profiles
separately require `range: u64 millimetres` at scale zero. These role names and
shapes are normative; admission rejects aliases and omissions.

## 10.7 Wireless technology machines

### Wi-Fi

States are `disabled`, `scanning`, `authenticating`, `associating`,
`associated`, `roaming`, and `failed`. Inputs are beacon outcomes, AP candidates,
channel/profile, credentials outcome, load, hysteresis, scan cadence, and timers.
Outputs select AP/channel/path and an interruption/buffering/address policy.
Rate adaptation is a closed state machine or imported event trace; it cannot use
host Wi-Fi algorithms.

### Cellular

States are `powered_off`, `searching`, `camped`, `attaching`, `idle`,
`connected`, `handover`, `reconnecting`, `limited`, and `failed`. Required
configuration includes cells/sectors, radio resources, candidate-quality table,
selection priorities, hysteresis, time-to-trigger, authentication result,
RRC timers, handover interruption, buffering, address continuity, cell load,
core/backhaul path, and modem reset policy. Reselection and handover ties use
cell ID. Ping-pong behavior emerges from the exact state/timer inputs.

### Bluetooth LE, Zigbee, LoRa/LPWAN, UWB, NFC/RFID, and land-mobile radio

| Technology | Required state |
| --- | --- |
| Bluetooth LE | advertising/scanning, channel map, connection interval/event counter, supervision timeout, retries. |
| Zigbee/mesh | discovery, parent and route, channel map, retry/ack, partition/merge membership. |
| LoRa/LPWAN | channel/spreading factor, duty-cycle tokens, airtime, gateway candidates, confirmed retry state. |
| UWB | session/peer, channel, clock/ranging exchange, line-of-sight state, typed range result. |
| NFC/RFID | field/coupling, initiator/targets, anticollision tree, transaction state. |
| land-mobile | channel/repeater/group, push-to-talk admission, half-duplex occupancy, recipient subset. |

Each uses the shared RF/medium/profile machinery and a closed technology state
machine. Technology-specific measurement results use a registered typed control
result effect; they are not sensor-device samples.

## 10.8 Mobility, truth, and observation

A truth trajectory produces position, velocity, and orientation in a local
integer frame. It is sampled at exact channel/profile opportunities and exact
zone/contact crossings. Supported trajectory sources are normalized trace,
piecewise-linear waypoints with exact segment timing, path-distance profile, and
exact constant-acceleration segments with lookup-based square-root solutions.

The network adapter may expose modem/network observations such as serving cell,
RSSI/RSRP/RSRQ/SINR, CQI, rate, retransmissions, and attachment state. GNSS and
IMU are sensor observations and remain specification-only. A network scenario
must not feed an unavailable sensor target back into truth.

## 10.9 Satellite and delay-tolerant networking

Satellite inputs are normalized ephemeris/position traces or contact plans; the
runtime does not embed an orbital propagator. A contact record contains start,
end, endpoints, beam, gateway, minimum range, maximum range, capacity profile,
acquisition/teardown, and confidence/provenance.

Contact states are `closed`, `acquiring`, `open`, `degraded`, and `teardown`.
Range determines propagation through an exact lookup. RF effects add pointing,
weather, scintillation, solar interference, Doppler/acquisition, transponder
load, and gateway state. Beam/gateway handover uses the association contract.

Delay-tolerant routing uses a finite contact graph known to the schedule version.
Each bundle has stable ID, size, priority, expiry, custody state, and visited-hop
bound. Route selection minimizes declared integer cost with contact/path ID ties.
Custody queues are bounded and checkpointed; overflow, expiry, contact-plan
mutation, stale plan, and missed contact are explicit outcomes.

## 10.10 Failure domains and correlation

Conduit, rack/chassis, provider, spectrum region, cell/sector, beam/gateway,
weather zone, and shared controller domains are declared memberships. A cause
uses one signal and separate typed bindings to all affected targets. Dynamic
membership, such as a vehicle entering a jammer/weather zone, changes only at
an exact geometric crossing or trace event.

Independent keyed hazards remain independent even when driven by a common
probability signal; exact correlated outcomes use a shared event/state signal.
Equal seeds never imply correlation.

## 10.11 Network conformance

- **[NTECH-4]** Every `segment.kind`, medium kind, forwarder kind, network
  function, and association technology MUST have strict configuration,
  state-codec, transition, profile, event, checkpoint, and replay vectors.
- **[NTECH-5]** Tests MUST cover every transition traffic policy in §10.1 with
  frames in all four states and prove no duplication/loss beyond policy.
- **[NTECH-6]** Shared-service tests MUST prove conservation, deterministic
  fairness/order, queue bounds, and checkpoint equivalence under simultaneous
  transmissions.
- **[NTECH-7]** RF tests MUST use committed integer lookup vectors and prove
  spatial revisit, correlated field behavior, interference power addition,
  handoff, and outcome replay without floating-point execution.
- **[NTECH-8]** Every taxonomy ledger row in the two network tables of §8.7 MUST
  have an isolated test and at least one overlap/common-cause test.
