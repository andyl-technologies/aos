# 03 — Network segments, paths, media, mobility, and interference

Networking is the first and broadest consumer of the signal-driven framework.
This design covers physical and logical links rather than equating networking
with mobile radio. Wired point-to-point links, shared buses, Wi-Fi and cellular,
switching fabrics, routed and overlay paths, undersea cable, microwave,
satellite, and intermittent contacts resolve through a common directed service
profile while retaining technology-specific state and observations.

## 3.1 Network structure

The immutable world may declare:

- **endpoint/interface:** traffic producer or consumer and its interface;
- **segment:** one directed or bidirectional transport hop;
- **medium:** a shared capacity/interference/arbitration domain;
- **forwarder:** switch, bridge, router, gateway, modem, base station, or relay;
- **queue:** explicit buffering/service point;
- **path:** an ordered or policy-selected segment sequence;
- **route/association state:** the currently selected path, cell, AP, beam,
  gateway, or next hop;
- **network fault domain:** a common physical or administrative cause such as a
  conduit, chassis, rack, provider, spectrum region, beam, or ground station.

A concise symmetric segment declaration produces two directed segment runtimes
inside the same network model. It is syntax sugar in the new schema, not a
second link type or compatibility execution path. Rich scenarios declare
explicit interfaces, segments, media, and paths.

- **[NET-1]** Runtime behavior MUST be directional even when authoring syntax is
  symmetric. Uplink/downlink and A-to-B/B-to-A profiles may differ.
- **[NET-2]** A path MUST retain the ordered segment and queue identities that
  produced its outcome so replay and diagnosis can attribute degradation.
- **[NET-3]** Shared media and fault domains MUST be first-class state; correlated
  effects MUST NOT be approximated as independently seeded link faults.

## 3.2 Common directed link profile

Every segment evaluator produces an `EffectiveLinkProfile` at a canonical
coordinate/opportunity:

| Field | Meaning |
| --- | --- |
| `availability` | `up`, `down`, `degraded`, `receive_only`, or `transmit_only`. |
| `minimum_latency_nanos` | Conservative invariant floor used for causality. |
| `propagation_delay_nanos` | Distance/medium propagation above the floor. |
| `access_delay_nanos` | Arbitration, scheduling, contention, or retransmission delay. |
| `queue_delay_nanos` | Current modeled queue contribution. |
| `jitter_window_nanos` | Exact seeded nonnegative delay window. |
| `reorder_window_nanos` | Additional delivery shift that may cross sibling frames. |
| `service` | Unlimited, fixed rate, token bucket, or versioned service curve. |
| `loss` | Independent, signal-driven, burst-state, or explicit outcome source. |
| `duplicate` | Probability and gap, or explicit event. |
| `corruption` | Closed payload/header transformations and probability. |
| `mtu_bytes` | Segment MTU and oversize policy. |
| `queue_policy` | Capacity, discipline, priorities, and overflow behavior. |
| `technology_state` | Typed observable metadata, not interpreted by generic delivery. |

Ordinary radio or copper bit errors generally become retries, CRC errors, or
loss. Delivering silently corrupted payload is a separate explicit
`undetected_corruption` effect.

- **[NET-4]** Dynamic latency MUST never reduce delivery below the immutable
  minimum latency floor admitted to the scheduler.
- **[NET-5]** A profile change that changes availability, path membership, or a
  scheduler-visible lower bound MUST occur at an exact admitted boundary.
- **[NET-6]** Per-frame outcome evaluation MUST use the frame's stable emission
  opportunity and the profile version/state visible at that coordinate.
- **[NET-7]** The emitted event log MUST distinguish propagation, serialization,
  access, queue, jitter, reorder, and retransmission contributions rather than
  retaining only an unexplained total delay.

## 3.3 Service and queue semantics

The implementation provides one complete service model:

1. A fixed-rate link is represented as a piecewise-constant service curve with
   one interval, not a separate sample-at-emission engine.
2. A token bucket checkpoints tokens, refill coordinate, burst size, and queue
   and feeds the same service integration path.
3. A piecewise-constant service curve gives a queued frame service as capacity
   changes; completion is the first exact coordinate where accumulated service
   covers frame bits.
4. A shared scheduler assigns service among queues by a closed discipline such
   as strict priority, weighted round-robin, or fixed time slots.

All four forms use the same queue, accounting, checkpoint, event, and replay
implementation. There is no stateless lower-fidelity rate path.

- **[NET-8]** A scenario MUST name its service semantic version. Changing from
  sample-at-emission to an integrated service curve changes scenario identity.
- **[NET-9]** Queue capacity, overflow policy, service discipline, tie-breaking,
  and byte/bit rounding MUST be explicit.
- **[NET-10]** Queue, token, and scheduler state MUST be checkpointed and included
  in replay fingerprints.

## 3.4 Path composition

A frame traversing a path composes segment profiles and forwarder effects:

- availability requires all required segments and forwarding states;
- propagation, access, queue, and processing delays add in traversal order;
- each segment applies its own service/queue behavior rather than reducing all
  capacity to a stateless minimum;
- path MTU is the minimum effective MTU unless encapsulation/fragmentation
  adapters specify otherwise;
- loss and corruption opportunities remain attributed to segments;
- duplicate and reorder transformations preserve stable traversal identity;
- encapsulation adds exact overhead and may change the next segment's frame size;
- routing can replace the path only through a boundary transition.

- **[NET-11]** Path evaluation MUST preserve segment-local opportunities and
  outcomes; it MUST NOT draw one unexplained end-to-end loss decision when a
  segment model is present.
- **[NET-12]** A route transition MUST record old path, new path, cause binding,
  transition coordinate, buffering policy, and treatment of in-flight frames.
- **[NET-13]** Routing loops MUST be bounded and observable; the model MUST use an
  explicit hop/TTL limit and deterministic drop outcome.

## 3.5 Point-to-point media

Point-to-point models cover Ethernet links, direct fiber, copper pairs, serial
links, microwave point-to-point, optical free-space, leased lines, tunnels with
fixed endpoints, and similar segments.

Inputs may include:

- length and propagation velocity;
- negotiated rate/duplex/modulation;
- cable/fiber attenuation or bit-error trace;
- connector, transceiver, repeater, and amplifier state;
- temperature, vibration, bend, water ingress, construction, power, and
  maintenance signals;
- upstream provider/path load.

Effects include down/flap/one-way behavior, BER/burst error, CRC loss,
negotiation fallback, duplex mismatch, pause/storm behavior, latency, capacity,
and connector intermittence.

- **[NET-14]** Physical common causes such as a conduit cut or shared transceiver
  power rail SHOULD be one fault-domain signal fanned out to all affected
  segments.
- **[NET-15]** Negotiated mode changes MUST be state transitions with explicit
  training/recovery intervals, not instantaneous unrecorded rate edits.

## 3.6 Shared media and buses

Shared media include Wi-Fi channels, cellular spectrum, broadcast radio, LoRa,
BLE/Zigbee channels, Ethernet collision domains, CAN, RS-485, and other buses.
They require joint evaluation because one participant changes another's service
and interference.

A `NetworkMedium` owns:

- attached interfaces and current participation state;
- channel/frequency/resource partitions;
- arbitration or access discipline;
- external and internal interference sources;
- occupancy/load and shared queues;
- collision/capture rules;
- medium-wide environmental fields;
- deterministic resource-allocation state.

- **[NET-16]** Medium evaluation MUST be a deterministic joint function of
  admitted transmissions and medium state, ordered by scheduler event keys.
- **[NET-17]** Collision, capture, backoff, slot, or allocation decisions MUST be
  explicit keyed decisions or closed deterministic state transitions.
- **[NET-18]** A shared medium MUST expose enough typed telemetry to explain
  capacity and loss attribution without exposing host-dependent implementation
  detail.

## 3.7 Switched, routed, and overlay networks

Forwarder models cover:

- per-port/link state and negotiation;
- forwarding tables and aging;
- queues, buffers, RED/tail drop, and priority classes;
- ECMP/path selection;
- route announcement, withdrawal, convergence, blackhole, and loop;
- ACL/firewall rejection and connection-state loss;
- NAT mapping exhaustion/expiry/reset;
- tunnel encapsulation, MTU overhead, keepalive, and endpoint change;
- load balancer backend membership and hashing;
- control-plane CPU or memory pressure;
- chassis, line-card, supervisor, and power fault domains.

This is network behavior, not necessarily a “hardware fault.” The binding system
can drive it from load, power, configuration-event, or recorded route traces.

- **[NET-19]** Forwarding and connection-state tables that affect delivery MUST
  be bounded, checkpointed modeled state.
- **[NET-20]** ECMP and load-balancing choices MUST use stable flow keys and
  versioned hashing, not host library hashes.
- **[NET-21]** Control-plane convergence MUST be represented by explicit state
  transitions or imported events; it MUST NOT complete after host elapsed time.

## 3.8 Mobility and radio channels

A mobile endpoint has separate **physical truth** and **observed sensors**:

- truth: position, velocity, orientation, environment, and radio attachment;
- observation: GPS/IMU/modem measurements delivered to the guest.

A GPS fault normally changes observation without moving physical truth. A
scenario may explicitly use an estimated-position trace as truth when replaying
only what was recorded, but that choice is identity-bearing.

Trajectory sources include normalized recordings, waypoints, exact kinematics,
path-constrained motion, and trace-plus-perturbation. Radio models may consume:

- endpoint and transmitter position/orientation;
- carrier, bandwidth, antenna pattern, power, noise figure;
- path-loss lookup, attenuation zones, buildings/tunnels/terrain;
- spatial shadowing and time/space fast-fading fields;
- external interferers and other modeled transmissions;
- cell/AP/beam load and backhaul profile;
- recorded RSSI, RSRP, RSRQ, SINR, CQI, serving-cell, and error channels.

Derived link behavior includes propagation delay, service rate, retransmission,
loss/burst state, outage, association, handoff, Doppler-derived degradation, and
technology-specific metrics.

- **[NET-22]** Spatial radio randomness MUST be spatially keyed so revisiting the
  same modeled location under the same field produces the same shadowing value,
  independent of frame count.
- **[NET-23]** Fast per-frame fading MAY additionally key on time bucket and frame
  opportunity, but its spatial/time correlation scales MUST be explicit.
- **[NET-24]** Movement truth and guest-observed location MUST be distinct signal
  channels unless an explicit binding equates them.

## 3.9 Association and handoff

Wi-Fi roaming, cellular handoff, satellite beam/gateway handover, and mobile mesh
parent change use a typed association state machine:

```text
detached -> searching -> candidate -> associated -> transferring
               ^             |             |             |
               +-------------+-------------+-------------+
                              failure / timeout
```

Technology refinements may add `camped`, `idle`, `connected`, `handover`,
`reconnect`, or `beam_switch`, but the state set is closed per semantic version.

Inputs include candidate quality, selection policy, hysteresis, time-to-trigger,
authentication, resource availability, movement, and recorded association
events. Outputs include selected attachment, interruption, buffering, packet
loss/reorder, address continuity, and path change.

- **[NET-25]** Association state, candidates, timers, and selected attachment
  MUST be checkpointed.
- **[NET-26]** A handoff MUST define treatment of frames already queued, in
  flight, buffered at the old attachment, and emitted during interruption.
- **[NET-27]** Selection tie-breaking MUST use canonical attachment identity
  after policy metrics.

## 3.10 Satellite and contact networks

Satellite, high-altitude, intermittently connected, and delay-tolerant networks
add:

- ephemeris/trajectory or imported visibility windows;
- propagation delay varying with range;
- Doppler and oscillator compensation state;
- beam footprint and beam handover;
- ground station/gateway availability;
- rain fade, scintillation, solar/weather interference, and antenna pointing;
- scheduled contacts and acquisition time;
- shared transponder capacity and queueing;
- store-and-forward custody and contact-plan routing;
- radiation effects on onboard compute/memory as correlated non-network bindings.

The implementation need not derive orbits from first principles. Canonical
position/contact traces or lookup tables are the supported ephemeris boundary;
the satellite adapter consumes them with exact, versioned contact, propagation,
association, and queue semantics.

- **[NET-28]** Contact availability MUST be an exact interval/event signal with
  explicit acquisition and teardown semantics.
- **[NET-29]** Time-varying propagation MUST preserve the global admitted
  minimum floor and record the evaluated range/delay contribution.
- **[NET-30]** Store-and-forward queues and custody state MUST be bounded,
  checkpointed, and attributed in event logs.

## 3.11 Network trace fidelity modes

Recorded networking data supports three levels:

1. **Outcome replay:** recorded packet/frame disposition, delay, rate, and path
   events directly control the simulated segment/path.
2. **Channel replay:** recorded physical/link metrics feed a deterministic
   transfer model that derives operation outcomes.
3. **Mobility/environment replay:** recorded movement, weather, load, or
   interference feeds a synthetic network model.

A scenario may mix levels by segment. For example, cellular access uses channel
replay while datacenter backhaul uses a synthetic congestion model.

- **[NET-31]** Fidelity level MUST be explicit per modeled segment/path and enter
  scenario identity.
- **[NET-32]** Outcome replay MUST define how recorded operations align to
  simulated opportunities: stable packet key, ordered sequence, time window, or
  declared aggregate bucket.
- **[NET-33]** A mismatch between a locked recorded outcome and the simulated
  opportunity MUST fail loudly with alignment evidence.

## 3.12 Network fault and degradation vocabulary

The network adapter must ultimately cover these effect families; detailed
cross-domain enumeration is in [`04-fault-taxonomy.md`](04-fault-taxonomy.md):

- physical cut, unplug, connector intermittence, transceiver failure;
- link down, flap, one-way/receive-only/transmit-only, negotiation failure;
- propagation/access/processing/queue latency and jitter;
- rate limit, throttling, congestion, buffer pressure, queue starvation;
- independent and burst loss, CRC/FCS failure, retransmission exhaustion;
- duplication, reordering, truncation, corruption, framing error;
- MTU/fragmentation/encapsulation mismatch;
- collision, interference, jamming, desense, fading, shadowing, obstruction;
- route withdrawal, blackhole, loop, asymmetry, churn, ECMP change;
- switch/router/AP/base-station/beam/gateway restart or overload;
- association, authentication, roaming, handoff, reconnect, address discontinuity;
- contact-window loss, pointing loss, rain fade, Doppler acquisition failure;
- DNS, NAT, firewall, load-balancer, and tunnel state failures when those
  logical network functions are modeled as path components.

## 3.13 Atomic network implementation scope

The implementation PR delivers the complete network adapter described by this
RFC in one runtime path:

1. directed interfaces, segments, forwarders, queues, paths, media, and fault
   domains;
2. fixed, token-bucket, integrated service-curve, and shared-scheduler service;
3. every `Core`, `Next`, and `Advanced` network effect in the taxonomy;
4. switched, routed, overlay, point-to-point, shared-medium, mobile-radio,
   cellular, Wi-Fi, IoT-radio, satellite, and contact-network state needed by
   those effects;
5. truth trajectories, spatial fields, association/handoff, route changes,
   contact windows, and shared interference/load;
6. opportunity-keyed decisions, typed composition, full event attribution,
   checkpoints, search, recomputed replay, and locked replay;
7. exhaustive schema/reference tables and live network integration gates.

No point-to-point-only, sample-at-emission, feature-flagged, reduced-tier, or
accepted-but-unapplied networking mode may merge.
