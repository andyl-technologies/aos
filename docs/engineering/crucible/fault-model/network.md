# Network fault adapter

Networking is the broadest consumer of the fault model. Wired point-to-point
links, shared buses and radio channels, switched and routed fabrics, overlays,
mobile endpoints, satellites, and intermittent contacts all resolve through one
directed traversal and one service implementation, while retaining typed
technology state for attribution.

Sources: effect parameters in
[`network_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/network_effect.rs);
the production adapter in
[`crucible-daemon/src/vm_lifecycle/network_faults.rs`](../../../../crates/crucible/crucible-daemon/src/vm_lifecycle/network_faults.rs)
and its `route/` and `boundary` modules; the per-link device model in
[`crucible-device/src/netlink/`](../../../../crates/crucible/crucible-device/src/netlink/).

## Where interception happens

The network adapter lives inside the backend quantum loop. Frames committed by
QEMU cross the shared-memory router ring and are intercepted at an exact
pre-routing fault boundary, so no frame can bypass the fault runtime. The
runtime is owned by that loop and is never shared through a process-global or
test-only side channel.

## World structure

The world may declare interfaces, directed segments, shared media, forwarders
(switches, routers, gateways, base stations, relays), queues, paths, attachments
(cell, access point, beam, gateway), contacts, and fault domains. A symmetric
segment declaration is authoring shorthand for two directed segment runtimes;
runtime behavior is always directional. A path retains the ordered segment and
queue identities that produced its outcome, so degradation stays attributable
per hop rather than as one unexplained end-to-end draw.

## Availability and transitions

`network.availability` sets a direction-aware state: `up`, `down`,
`receive_only`, or `transmit_only`. Every availability, route, or technology
transition names how traffic already admitted is treated through
`NetworkInFlightPolicy`:

| Policy | Treatment |
| --- | --- |
| `preserve` | Complete under the profile captured at admission. |
| `reevaluate` | Re-resolve at the next declared adapter phase. |
| `drop` | Drop at the transition. |
| `typed_error` | Return the effect-specific typed error. |

Availability takes separate `queued_policy` and `in_flight_policy` values;
there are no defaults. Transitions that change availability, path membership,
or a scheduler-visible lower bound happen only at exact admitted boundaries.

## Latency and causality

The link model is the one source of conservative uncertainty in the scheduler:
its immutable minimum latency floor is the scheduler's lookahead bound. Dynamic
latency (`propagation_delay`, `access_delay`, `jitter`, `profile_delta`) never
delivers below that floor, and a shift that would deliver into a consumer's past
fails loudly. Each contribution (propagation, serialization, access, queue,
jitter, reorder, retransmission) is recorded separately rather than as a single
total delay.

## Service and queues

There is one service implementation and no stateless "sample at emission" rate
path:

- `network.service_curve` gives a piecewise-constant service curve. A queued
  frame completes at the first exact coordinate where accumulated service
  covers its bits; at a rate boundary, service is integrated through the
  boundary before the new rate applies, and only remaining demand is
  rescheduled.
- `network.token_bucket` checkpoints tokens, burst size, and refill coordinate
  and feeds the same integration path.
- `network.queue_policy` bounds a queue by bytes and frames simultaneously and
  selects a `NetworkQueueDiscipline` (`fifo`, `strict_priority`,
  `weighted_round_robin`, `deficit_round_robin`, `red`) and an overflow policy
  (`tail_drop`, `head_drop`, `keyed_drop`, `typed_error`).
- `network.pause_backpressure` pauses one class for a duration or until its
  contribution is removed; sibling classes keep running.

Queue, token, and scheduler state is checkpointed and fingerprinted. Storms,
loops, and bufferbloat consume real modeled queue and service capacity rather
than being injected as delay.

## Per-frame outcomes

Loss (`frame_loss`, `burst_error_state`), duplication, reordering, payload
transforms, detected frame errors with receiver retry/reset actions, MTU
handling with optional modeled IPv4 fragmentation, and recipient-subset delivery
are evaluated at the frame's stable emission opportunity against the profile
state visible at that coordinate. Hazards use keyed choices, so a frame's
outcome depends only on its identity. Ordinary bit errors become detected
errors, retries, or loss; delivering silently corrupted payload is the explicit
`network.payload_transform` effect.

Frame ancestry is bounded: at most `HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH`
(256) protocol expansions, `HARD_NETWORK_RESPONSE_DEPTH` (8) generated
reverse-path responses, and `HARD_NETWORK_FORWARDING_MUTATION_DEPTH` (64)
forwarding mutations per frame. A frame traverses at most `network_path_hops`
plus `network_loop_hops`, and route mutation cannot reset the consumed hop
budget, so routing loops terminate with a deterministic drop.

## Forwarding, routing, and logical functions

`forwarder_lifecycle`, `forwarding_mutation`, `route_transition`,
`control_plane_service`, `control_result_transform`, `firewall_disposition`,
and `connection_state` model forwarding tables, route changes with explicit
convergence events, control-plane processing capacity, firewall rules, and
per-flow connection state (`nat`, `conntrack`, `load_balancer`, `tunnel`,
`dns`). Forwarding and connection tables
are bounded, checkpointed state. Path selection uses stable flow keys and
versioned hashing, never host hash functions. Control-plane convergence
completes through modeled events, never host elapsed time. A route transition
records old and new route, cause, convergence, and in-flight treatment.

## Shared media and radio

`network.shared_medium` evaluates contenders, allocation, collision, capture,
and service jointly in scheduler event order; collision and backoff choices are
keyed decisions or closed state transitions. Correlated interference is a
shared signal into every affected medium or channel, never independently seeded
link faults.

`network.rf_channel` is a service-profile effect: geometry, spatial fields,
interference, and fading enter as typed, role-named signal inputs. Spatial
shadowing is keyed by location so revisiting a place reproduces it. Mobile
endpoints have a physical truth trajectory (position, velocity, orientation)
that is network-model state; it is not a guest sensor, and guest-observed
location would be a separate channel.

`network.association` is a typed state machine over candidates, timers, and the
selected attachment (Wi-Fi roaming, cellular handoff, beam or gateway
handover). Candidate selection breaks ties by canonical attachment identity,
and each handoff states its traffic treatment.

## Satellite and contact networks

`network.contact` models exact contact intervals with acquisition and teardown
over range, beam, and gateway state; `network.propagation_delay` consumes range
traces above the admitted floor; `network.custody_queue` models bounded
store-and-forward custody with bundle priorities (`bulk`, `normal`,
`expedited`, `critical`). Orbits are not derived from first principles:
canonical position or contact traces and lookup tables are the ephemeris
boundary.

## Checkpoint encoding

The network adapter checkpoint (`NETWORK_ADAPTER_CHECKPOINT_VERSION`) encodes
the evaluation coordinate, sequences, observation journal, token buckets,
queues, burst state, state machines, connection tables, shared-medium ledgers,
backpressure, custody queues, contact-service reservations, and boundary state.
Every map with a non-string key is an array of key/value pairs in strict key
order. Restore rejects duplicate or noncanonical order, broken references, and
exceeded bounds; older versions are not decoded.

Outcome-only network replay and frame-key alignment are described in
[replay and observability](replay-and-observability.md).
