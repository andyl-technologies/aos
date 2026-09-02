# Network faults

Crucible places guest-emitted frames on deterministic routes between declared
VM interfaces. Network faults act inside that modeled route, so delay, loss,
queue state, forwarding decisions, and delivery evidence use virtual time and
survive checkpoint/replay. No host bridge impairment, `tc`, or `netem` setup is
required.

## Start with an unfaulted route

Before adding bindings, prove that both guests exchange traffic through a
`LinkDef`. The production example
[`crucible-qemu-live-world-network.rs`](../../../crates/crucible-api/examples/crucible-qemu-live-world-network.rs)
does this and verifies both scheduler delivery and a guest acknowledgement.

A logical world link supplies baseline one-way latency, subtractive jitter,
loss probability, and optional bandwidth. Its loss choices are keyed to the
scenario seed and frame identity. It is enough for simple transport tests.

Add `WorldFaultTopology` when faults need a physical target more precise than
the logical link. A direct segment topology declares two endpoint interfaces
and a segment; admission can derive the corresponding directed paths. Declare
explicit paths when traffic traverses queues, forwarders, media, tunnels, or
multiple segments.

## Choose the physical target

| Intended failure | Prefer this target |
|---|---|
| One VM cannot transmit or receive | Interface |
| Cable, direct virtual link, or shared conduit fails | Segment |
| Wireless/bus contention affects all participants | Medium |
| Switch, router, firewall, NAT, tunnel, or load balancer fails | Forwarder |
| Congestion, overflow, priority, or backpressure | Queue |
| Only one end-to-end route changes or fails | Path |
| Authentication, roaming, handoff, or reconnect changes | Attachment |
| Scheduled satellite/disrupted connectivity | Contact plan/contact |
| One physical cause affects several objects | Fault domain resolving to those typed targets |

Selectors resolve before execution. They cannot discover a host interface or
create a route dynamically. Stable object IDs become part of fault evidence,
search identity, and replay validation.

## Choose the effect family

| Experiment | Effect |
|---|---|
| Directional outage or partition | `network.availability` |
| Timed down/training/recovery sequence | `network.flap` |
| Negotiated rate, duplex, lanes, or training | `network.negotiated_mode` |
| Added latency, jitter, rate, or error profile | `network.profile_delta`, `network.propagation_delay`, `network.access_delay`, `network.jitter` |
| Bandwidth and burst constraints | `network.service_curve`, `network.token_bucket` |
| Queue capacity, discipline, class, and overflow | `network.queue_policy` |
| Independent or correlated frame loss | `network.frame_loss`, `network.burst_error_state` |
| Duplicate, reorder, truncate, corrupt, or report detected frame error | `network.duplicate`, `network.reorder`, `network.payload_transform`, `network.detected_frame_error` |
| MTU or pause behavior | `network.mtu`, `network.pause_backpressure` |
| Multicast/broadcast membership filtering | `network.recipient_subset` |
| Forwarder restart, wrong port, flood, blackhole, loop, or route convergence | `network.forwarder_lifecycle`, `network.forwarding_mutation`, `network.route_transition` |
| Firewall or state-table behavior | `network.firewall_disposition`, `network.connection_state`, `network.control_plane_service` |
| Shared bus/radio contention | `network.shared_medium` |
| RF attenuation/interference and association | `network.rf_channel`, `network.association` |
| Technology control-operation result mutation | `network.control_result_transform` |
| Satellite/disrupted contact and custody | `network.contact`, `network.custody_queue` |

Use the [effect registry](reference.md#exhaustive-effect-registry) for exact target kinds,
phases, lifetimes, operations, and parameter definitions.

## Complete network effect contract

Every network effect uses semantic version `1`. In the matrix, **all** means
all eight network target kinds listed above. The narrower target sets are
spelled out. Capability names are negotiated with the production adapter before
guest execution.

| Effect | Targets; phases; lifetimes; composition | Capability | Complete top-level parameters |
|---|---|---|---|
| `network.availability` | all; `admit`, `resolve`; `persistent`; `outage_or` | `network.availability.v1` | `state`, `queued_policy`, `in_flight_policy` |
| `network.flap` | all; `boundary`; `state_machine`; `state_machine` | `network.flap.v1` | positive `down_nanos`, `training_nanos`, `recovery_nanos` |
| `network.negotiated_mode` | all; `boundary`; `state_machine`; `composite` | `network.negotiation.v1` | positive `rate_bps`, `duplex`, positive bounded `lanes`, `fec`, positive `training_nanos` |
| `network.profile_delta` | all; `resolve`; `persistent`; `composite` | `network.profile.v1` | optional signed `latency_nanos`, positive `rate_cap_bps`, `loss_hazard`, `corruption_hazard`, `technology_metrics` |
| `network.propagation_delay` | all; `resolve`; `persistent` or `opportunity`; `checked_sum` | `network.propagation.v1` | exactly one of positive `delay_nanos` and `distance_velocity_lookup` |
| `network.access_delay` | all; `resolve`; `opportunity`; `checked_sum` | `network.access-delay.v1` | positive `delay_nanos`, typed `cause` ID |
| `network.jitter` | all; `resolve`; `opportunity`; `checked_sum` | `network.jitter.v1` | positive `maximum_nanos`, integer `distribution`, required lookup for non-uniform distributions |
| `network.service_curve` | all; `queue`; `persistent`; `minimum` | `network.service-curve.v1` | ordered non-overlapping positive-rate `segments` |
| `network.token_bucket` | all; `queue`; `persistent` or `state_machine`; `minimum` | `network.token-bucket.v1` | positive `rate_bps`, positive `burst_bits`, `initial_bits <= burst_bits` |
| `network.queue_policy` | all; `admit`, `queue`; `persistent` or `state_machine`; `conflict` | `network.queue.v1` | positive byte/frame capacity, `discipline`, optional discipline parameters, `overflow`, typed error only when required |
| `network.frame_loss` | all; `resolve`, `deliver`; `opportunity`; `independent_hazards` | `network.frame-loss.v1` | exactly one of `probability` and explicit `outcome` |
| `network.burst_error_state` | all; `resolve`; `state_machine`; `conflict` | `network.burst-errors.v1` | good-to-bad and bad-to-good probabilities, registered per-state parameter table |
| `network.duplicate` | all; `deliver`; `opportunity`; `checked_sum` | `network.duplicate.v1` | probability, bounded additional `copies`, `gap_nanos` |
| `network.reorder` | all; `deliver`; `opportunity`; `composite` | `network.reorder.v1` | positive `window_nanos`, deterministic `selection` |
| `network.payload_transform` | all; `resolve`; `opportunity`; `ordered_transform` | `network.payload-transform.v1` | typed `mutation` including its selector |
| `network.detected_frame_error` | all; `resolve`; `opportunity`; `severity` | `network.detected-error.v1` | error `kind`, receiver action; retry-only delay/limit/attempt/success fields; reset duration only for link reset |
| `network.mtu` | all; `admit`; `persistent`; `composite` | `network.mtu.v1` | positive `mtu_bytes`, oversize disposition; protocol only for fragment; result artifact only for typed error |
| `network.pause_backpressure` | all; `queue`; `persistent` or `state_machine`; `state_machine` | `network.backpressure.v1` | traffic `class`, optional positive pause duration (absent means until deactivation) |
| `network.recipient_subset` | all; `deliver`; `opportunity`; `ordered_transform` | `network.recipient-subset.v1` | membership version; exactly one of explicit dropped members or keyed selection; retain count with selection |
| `network.forwarder_lifecycle` | all; `boundary`; `impulse` or `state_machine`; `severity` | `network.forwarder-lifecycle.v1` | transition, positive downtime, queue and table retention policies |
| `network.forwarding_mutation` | all; `resolve`; `persistent` or `impulse`; `ordered_transform` | `network.forwarding-mutation.v1` | typed lookup `selector`, mutation |
| `network.route_transition` | all; `boundary`, `resolve`; `state_machine`; `state_machine` | `network.route-transition.v1` | old/new route IDs, convergence-event sequence, in-flight policy |
| `network.control_plane_service` | forwarder/path/attachment/contact; `boundary`; `persistent` or `state_machine`; `minimum` | `network.control-plane.v1` | service curve, positive queue bound, overflow policy, positive work bits per event |
| `network.firewall_disposition` | all; `admit`; `opportunity` or `state_machine`; `severity` | `network.firewall.v1` | action, rejection only when required, rule, state machine, exhaustive transition event |
| `network.connection_state` | all; `resolve`; `state_machine`; `state_machine` | `network.connection-state.v1` | function kind, positive table bound, flow key, state machine, transition event, overflow behavior |
| `network.shared_medium` | medium only; `admit`, `queue`, `resolve`; `persistent` or `state_machine`; `conflict` | `network.shared-medium.v1` | complete resource set, policy artifact, positive transmit power |
| `network.rf_channel` | all; `resolve`; `persistent` or `opportunity`; `composite` | `network.rf-channel.v1` | positive carrier/bandwidth, transmit/noise power, propagation-field bundle, SINR transfer |
| `network.association` | attachment only; `boundary`; `state_machine`; `conflict` | `network.association.v1` | complete association policy artifact |
| `network.control_result_transform` | forwarder/path/attachment/contact; `resolve`; `opportunity`; `ordered_transform` | `network.control-result-transform.v1` | technology, nonempty operations, transform kind, result artifact only for bias/replace/error |
| `network.contact` | all; `boundary`, `resolve`; `state_machine`; `outage_or` | `network.contact.v1` | interval artifact, range-delay lookup, beam set, gateway set |
| `network.custody_queue` | all; `queue`; `persistent` or `state_machine`; `conflict` | `network.custody.v1` | positive byte/bundle capacity and expiry, custody policy, route/contact plan, priority, positive hop bound |

### Closed network parameter choices

- Availability state is `up`, `down`, `receive_only`, or `transmit_only`.
  Queued/in-flight policy is `preserve`, `reevaluate`, `drop`, or `typed_error`.
- Duplex is `half` or `full`. FEC is `none`, `reed_solomon`, `ldpc`, or
  `convolutional`.
- Integer distributions are `uniform`, `normal_lookup`, or
  `exponential_lookup`; lookup forms require their registered table and
  non-uniform forms cannot depend on host floating point.
- Queue discipline is FIFO, strict priority, weighted round robin, deficit
  round robin, or RED. Overflow is tail drop, head drop, keyed drop, or a
  registered typed error; required class/weight parameters
  live in the referenced policy object.
- Payload mutations are bit flip, typed field mutation, truncation, or
  undetected corruption. Detected errors distinguish CRC, FCS, framing, and
  FEC and select corrected, retry, drop, or link-reset behavior.
- MTU oversize behavior is drop, fragment, or typed error. Fragmentation names
  its parser/encoder protocol; arbitrary byte splitting is not admitted.
- Forwarding mutation is wrong port, flood, blackhole, loop, or stale-age
  behavior. Firewall action is accept, reject, or drop. Connection state is
  scoped to NAT, conntrack, load-balancer, tunnel, or DNS behavior.
- Control-result transforms are drop, stale, bias, replace, or typed error.
  Every referenced policy/table is a declared, content-addressed topology
  artifact and is included in the replay closure.

The complete nested network value vocabulary is:

| Type/field | Accepted variants and variant fields |
|---|---|
| availability `state` | `up`, `down`, `receive_only`, `transmit_only` |
| queued/in-flight policy | `preserve`, `reevaluate`, `drop`, `typed_error` |
| bundle priority | `bulk`, `normal`, `expedited`, `critical` (highest) |
| duplex / FEC | duplex `half`, `full`; FEC `none`, `reed_solomon`, `ldpc`, `convolutional` |
| jitter distribution | `uniform`, `normal_lookup`, `exponential_lookup`; lookup variants require `distribution_lookup` |
| service segment | `at_nanos`, positive `rate_bps`; first starts at zero and coordinates strictly increase |
| queue discipline | `fifo`, `strict_priority`, `weighted_round_robin`, `deficit_round_robin`, `red` |
| queue overflow | `tail_drop`, `head_drop`, `keyed_drop`, `typed_error`; only typed error carries the adjacent response artifact |
| selection | `keyed_uniform`, `oldest`, `newest`, `canonical_order` |
| explicit loss outcome | `preserve`, `drop` |
| payload mutation | `bit_flip { offset_bytes, length_bytes, mask }`, `field_mutation { field, replacement }`, `truncate { length_bytes }`, `undetected_corruption { transform }` |
| detected error | kind `crc`, `fcs`, `framing`, `fec_uncorrectable`; action `corrected`, `retry`, `drop`, `link_reset` with the action-specific top-level fields in the matrix |
| MTU disposition | `drop`, `fragment`, `typed_error`; the only fragmentation protocol is `ethernet_ipv4` |
| forwarder transition/state | transition `restart`, `reset`, `power_loss`; queue/table policy `preserve`, `clear`, `drain` |
| forwarding mutation | `wrong_port { recipient }`, `flood { recipients }`, `blackhole`, `loop { next_hop, hop_limit }`, `stale_age { age_nanos, expiration_nanos, expired }` |
| stale-entry disposition | `preserve`, `blackhole`, `flood { recipients }` |
| firewall action | `accept`, `reject`, `drop`; rejection alone requires `typed_reject` |
| connection kind | `nat`, `conntrack`, `load_balancer`, `tunnel`, `dns` |
| connection overflow | `drop_newest`, `evict_oldest`, `keyed_eviction`, `typed_error { response }` |
| control-result kind | `drop`, `stale`, `bias`, `replace`, `error`; bias/replace/error require the typed `result` artifact |

All object IDs in this table resolve to the declared World topology. Object-ID
fields never name host files or callbacks.

### Required replay evidence

The descriptor for every row also names mandatory evidence. Depending on the
effect this includes old/new state, frame and draw identities, queue/service
ledgers, contributor lists, before/after digests, retry state, route and
convergence state, firewall/connection transitions, RF geometry and resolved
profile, or contact/custody transitions. A backend capability acknowledgment
without this evidence does not satisfy locked replay.

## Persistent outage versus one-frame loss

A partition normally uses:

```text
Boolean step/pulse
  -> sample at boundary
  -> active_when_true
  -> exact segment/path/interface selector
  -> persistent network.availability
```

The effect declares direction and what happens to queued and in-flight frames.
When the Boolean becomes false, the contribution is removed at a recorded
boundary. There is no out-of-band “heal” command.

A one-frame loss instead uses an operation-domain or stochastic signal sampled
at the frame opportunity, an impulse mapping, and `network.frame_loss` at the
registry-approved phase. Do not model a partition as repeated probabilistic
loss: that changes its causal identity, search space, and queue semantics.

## Direction and state treatment

Every outage or transition should answer three questions:

1. Is the object down in both directions, transmit-only, or receive-only?
2. What happens to frames already queued?
3. What happens to frames already in flight?

The corresponding effect carries those policies. Defaults that silently depend
on when the host happened to process a frame would break replay, so Crucible
requires the treatment to be modeled.

Forwarder lifecycle and route transition effects similarly declare table,
queue, and in-flight retention. Queue effects declare byte/frame limits,
discipline, and overflow behavior. All mutable adapter state is included in an
exact checkpoint.

## Shared causes and composition

Reuse one signal output when a rack, provider, power event, or environmental
trace affects multiple network objects. Bind that output separately to each
target or use an admitted fault-domain selector. At each opportunity the
network adapter composes all active contributors using the effect family's
closed rules and records both the contributors and final result.

The shared-cause production example powers down a forwarder while the same
event crashes a VM and loses volatile storage cache:
[`crucible-qemu-signal-shared-cause.rs`](../../../crates/crucible-api/examples/crucible-qemu-signal-shared-cause.rs).

## What to assert

Network adapter evidence proves that a frame was admitted, queued, transformed,
dropped, or delivered to the QEMU input boundary. It does not by itself prove
that an application accepted the data.

For end-to-end tests, combine:

- transport/topology properties for modeled network behavior;
- a guest marker or stable console assertion for application behavior;
- a bounded recovery or failure deadline; and
- canonical event-log retention on failure.

This distinction remains valid for encrypted protocols: the network adapter
can prove delivery while the guest reports semantic success.

## Explore and reproduce

Baseline link loss, stochastic sources, and search-enabled bindings expose
stable choices. Use `search` with depth/state bounds to find a counterfactual,
then replay the emitted artifact through the ordinary production backend.
Exact checkpoints retain frames, queues, forwarder state, route state, signal
state, and keyed-choice history.

When a replay diverges, inspect evidence in this order: signal sample, selector
resolution, route/opportunity identity, composed effect, frame decision,
backend injection, guest assertion, and terminal fingerprint. See
[Reproduction and branching](reproduction.md) and
[Troubleshooting](troubleshooting.md).
