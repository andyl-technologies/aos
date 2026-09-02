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
