# 08 — Executable effect registry and taxonomy ledger

This file is the normative closed registry for the network, storage/9p, and node
adapters. Every accepted effect has one key, target set, opportunity phase,
lifetime, parameter contract, composition rule, capability, state obligation,
and replay evidence. The implementation generates schema/reference coverage
from this registry. A taxonomy row is executable only through the exact mapping
in §8.7; adapters may not replace it with a vaguely similar generic effect.

## 8.1 Common contract

Every effect record contains:

```text
EffectRecord {
  effect_key
  semantic_version
  binding_id
  resolved_target
  opportunity_id?
  coordinate
  lifetime
  canonical_parameters
  contributor_ids
  capability_id
  precondition_digest?
}
```

Parameter names below are exact TOML field names. Durations are `u64` virtual
nanoseconds; rates are `u64` units per virtual second; probabilities are `u32`
millionths; signed quantities are `i64` in the named unit; masks and payloads
are lowercase even-length hexadecimal strings; IDs are canonical scenario IDs.
Unknown fields, unit suffixes, enum variants, and zero values where a positive
quantity is required are rejected.

Composition abbreviations:

| Algebra | Exact rule |
| --- | --- |
| `outage-or` | Target is unavailable while any contribution is active; all contributor IDs are retained. |
| `checked-sum` | Add in canonical binding-ID order using checked width; overflow is an error. |
| `minimum` | Choose the minimum non-null cap; retain every limiting contributor. |
| `rational-product` | Multiply reduced rationals in binding-ID order with checked intermediates and reduce after each multiply. |
| `ordered-transform` | Apply in canonical binding-ID order and record the digest before and after each transform. |
| `severity` | Choose the greatest value in the effect-specific closed precedence lattice and retain ties. |
| `state-machine` | Same-coordinate events use the effect's declared transition precedence, then binding ID. Invalid transitions fail. |
| `independent-hazards` | Evaluate every keyed hazard; any firing effect applies, and all decisions are logged. |
| `conflict` | More than one non-identical contribution is rejected at admission or the boundary. |

- **[FX-1]** Effect keys and semantic versions are stable canonical material.
- **[FX-2]** Every effect kind MUST expose all evidence columns in the generated
  completeness matrix described by §7.10.
- **[FX-3]** An adapter MUST reject an effect at a phase not listed here and
  MUST NOT translate it to another phase.
- **[FX-4]** Technology causes remain typed signal/event metadata. They select
  the mapped effect program in §8.7 but do not create hidden effect variants.

## 8.2 Target and opportunity registry

| Domain | Target kind | Stable identity | Opportunity operations and phases |
| --- | --- | --- | --- |
| Network | `network_interface` | endpoint ID plus interface ID | transmit/receive at produce, admit, queue, resolve, deliver |
| Network | `network_segment` | directed segment ID | traverse at admit, queue, resolve, deliver |
| Network | `network_medium` | medium ID plus channel/resource ID | contend, transmit, receive, allocate at admit, queue, resolve |
| Network | `network_queue` | forwarder/medium ID plus queue ID | enqueue, serve, dequeue at admit, queue, resolve |
| Network | `network_forwarder` | forwarder ID | learn, lookup, route, translate, encapsulate at admit/resolve |
| Network | `network_path` | path version ID plus direction | select, traverse, change at admit/resolve |
| Network | `network_attachment` | endpoint/interface plus attachment ID | discover, authenticate, associate, handoff at resolve |
| Network | `network_contact` | endpoint pair plus contact ID | acquire, transmit, custody, teardown at resolve |
| Storage | `block_device` | device content ID | read, write, flush, discard, get_length, reset at all five phases |
| Storage | `block_range` | device ID plus start byte plus length | read/write/erase/refresh at produce/resolve/persist |
| Storage | `storage_controller` | controller ID plus namespace/path | admit, submit, complete, reset, enumerate at admit/resolve/deliver |
| Storage | `storage_array` | array ID plus member/path ID | select, rebuild, read, write, flush at admit/queue/resolve/persist |
| Storage | `ninep_device` | device content ID | every typed 9p request at all five phases plus persist/visibility |
| Node | `node` | node ID | boot, run, pause, reset, stop, resume at boundary/resolve |
| Node | `vcpu` | node ID plus vCPU ID | before-instruction, after-instruction, exception, halt, resume |
| Node | `register` | node, vCPU, architecture, register ID, bit range | before-read, after-read, before-write, after-write, boundary |
| Node | `memory_range` | node, address space, resolved GPA, length | fetch, load, store, DMA-read, DMA-write, refresh, boundary |
| Node | `interrupt` | node, controller/source, target vCPU, vector/type | raise, route, acknowledge, deliver, return |
| Node | `clock_source` | node plus source ID | read, arm, fire, synchronize, source-switch |
| Node | `accelerator` | node plus bus/device/function or declared device ID | submit, execute, complete, memory access, reset |

`persist` and `visibility` are storage-specific refinements between resolve and
deliver. `boundary` is an exact scheduler/QEMU safe boundary with all affected
vCPUs quiescent. Symbolic register and virtual-address targets are resolved to
architecture IDs and GPA ranges before application and their resolution enters
the effect record.

## 8.3 Network effect registry

| Effect key | Lifetime and phase | Required parameters | Composition | Capability and replay evidence |
| --- | --- | --- | --- | --- |
| `network.availability` | persistent; admit/resolve | `state = up/down/receive_only/transmit_only` | outage-or with directional lattice | `network.availability.v1`; old/new state, direction, queued/in-flight policy |
| `network.flap` | state-machine; boundary | `down_nanos`, `training_nanos`, `recovery_nanos` | state-machine | `network.flap.v1`; transition sequence and timer state |
| `network.negotiated_mode` | state-machine; boundary | `rate_bps`, `duplex`, `lanes`, `fec`, `training_nanos` | minimum rate plus conflict for duplex/FEC | `network.negotiation.v1`; old/new mode and training outcome |
| `network.profile_delta` | persistent; resolve | optional signed latency components, rate cap, loss/corruption hazard IDs, technology metrics | component-specific checked-sum/minimum/independent-hazards | `network.profile.v1`; input profile, contributors, resolved profile digest |
| `network.propagation_delay` | persistent/opportunity; resolve | `delay_nanos` or distance/velocity lookup ID | checked-sum above immutable floor | `network.propagation.v1`; range/input and delay |
| `network.access_delay` | opportunity; resolve | `delay_nanos` | checked-sum | `network.access-delay.v1`; arbitration/retry cause |
| `network.jitter` | opportunity; resolve | `maximum_nanos`, `distribution` | checked-sum keyed draws | `network.jitter.v1`; draw key/value |
| `network.service_curve` | persistent; queue | ordered `segments = [{at_nanos, rate_bps}]` | minimum simultaneous service constraints | `network.service-curve.v1`; service interval integration ledger |
| `network.token_bucket` | persistent state; queue | `rate_bps`, `burst_bits`, `initial_bits` | all buckets constrain service | `network.token-bucket.v1`; before/after tokens and refill coordinate |
| `network.queue_policy` | persistent state; admit/queue | `capacity_bytes`, `capacity_frames`, `discipline`, discipline parameters, `overflow`; `typed_error` response artifact iff overflow is `typed_error` | conflict per queue | `network.queue.v1`; occupancy, selected class, overflow decision and response ID |
| `network.frame_loss` | opportunity; resolve/deliver | `probability_millionths` or explicit outcome | independent-hazards | `network.frame-loss.v1`; frame ID, decisions, loss cause |
| `network.burst_error_state` | state-machine; resolve | good/bad transition probabilities and per-state loss/corruption parameters | conflict per named burst process | `network.burst-errors.v1`; prior/new burst state and decision keys |
| `network.duplicate` | opportunity; deliver | `probability_millionths`, `gap_nanos`, `copies` | checked sum of bounded copies then canonical delivery order | `network.duplicate.v1`; copy IDs and delivery coordinates |
| `network.reorder` | opportunity; deliver | `window_nanos`, `selection` | maximum window; keyed shift per contributor | `network.reorder.v1`; original/resolved order and shifts |
| `network.payload_transform` | opportunity; resolve | `kind = bit_flip/field_mutation/truncate/undetected_corruption`, kind fields | ordered-transform | `network.payload-transform.v1`; byte/field selectors and before/after digests |
| `network.detected_frame_error` | opportunity; resolve | `kind = crc/fcs/framing/fec_uncorrectable`, `receiver_action`; retry declares delay, limit, actual attempts, and final success; reset declares retraining duration | severity `corrected < retry < drop < link_reset` | `network.detected-error.v1`; syndrome/class, attempts, final outcome, and action |
| `network.mtu` | persistent; admit | `mtu_bytes`, `oversize = drop/fragment/typed_error`; fragmentation protocol iff fragment; response artifact iff typed error | minimum MTU; conflict on oversize rule | `network.mtu.v1`; original size, disposition, expansion path or response ID |
| `network.pause_backpressure` | persistent/state; queue | `class`, optional `pause_nanos`; omission pauses until contribution removal | maximum pause boundary per class | `network.backpressure.v1`; queue/service suspension ledger |
| `network.recipient_subset` | opportunity; deliver | `membership_version`, `drop_members` or keyed selection | ordered set intersection | `network.recipient-subset.v1`; candidate and delivered IDs |
| `network.forwarder_lifecycle` | impulse/state; boundary | `transition = restart/reset/power_loss`, `downtime_nanos`, queue/table policies | severity | `network.forwarder-lifecycle.v1`; state and lost/preserved data |
| `network.forwarding_mutation` | impulse/persistent; resolve | `kind = wrong_port/flood/blackhole/loop/stale_age`, selector and replacement | ordered-transform by rule identity | `network.forwarding-mutation.v1`; lookup inputs, before/after entries, chosen hop |
| `network.route_transition` | state-machine; boundary/resolve | old/new route IDs, convergence events, in-flight policy | state-machine | `network.route-transition.v1`; paths, cause, convergence and traffic treatment |
| `network.control_plane_service` | persistent state; queue/resolve | service curve, queue bound, drop/timeout policy | minimum service and shared queue | `network.control-plane.v1`; queued events and applied transitions |
| `network.firewall_disposition` | opportunity/state; admit | `action = accept/reject/drop`, response artifact iff reject, rule/state IDs | most restrictive unless explicit ordered chain | `network.firewall.v1`; rule trace, state transition and response ID |
| `network.connection_state` | state-machine; resolve | `kind = nat/conntrack/load_balancer/tunnel/dns`, table bounds and transition event | state-machine | domain capability; entry before/after, mapping/backend/answer/path result |
| `network.shared_medium` | persistent state; admit/queue/resolve | channel resources, arbitration, collision, capture, backoff and duty-cycle parameters | one conflict-free policy per medium; signals combine as inputs | `network.shared-medium.v1`; contenders, allocation, collision/capture, service |
| `network.rf_channel` | persistent/opportunity; resolve | carrier/bandwidth, power, noise, gain, attenuation, SINR transfer table, fading field IDs | power/interference sum in exact linear unit then transfer lookup | `network.rf-channel.v1`; sampled geometry/field/power and resulting profile |
| `network.association` | state-machine; boundary/resolve | technology, candidates, selection, hysteresis, timers, auth, buffering/address policy | one machine per interface; inputs combine before selection | technology capability; candidates, timers, old/new attachment and traffic policy |
| `network.control_result_transform` | opportunity; resolve/deliver | technology, operation, kind `drop/stale/bias/replace/error`, typed result fields | ordered-transform or severity for errors | technology capability; request/result schema and before/after evidence |
| `network.contact` | state-machine; boundary/resolve | contact-plan intervals with acquisition/teardown, range-delay lookup, beam/gateway IDs | contact availability AND other outages | `network.contact.v1`; contact interval, range, selected beam/gateway |
| `network.custody_queue` | persistent state; queue | capacity, expiry, custody policy, route/contact plan | one bounded queue policy | `network.custody.v1`; bundle identity, custody transitions, drops and next contact |

### 8.3.1 MTU and IPv4 fragmentation

`network.mtu.mtu_bytes` is the maximum complete Ethernet frame length, including
the 14-byte Ethernet header and every protocol header. The effective MTU is the
smallest simultaneous value. Simultaneous contributors MUST agree on the
oversize disposition, fragmentation protocol, and typed-error artifact; an
otherwise ambiguous composition is rejected.

`fragmentation_protocol = ethernet_ipv4` accepts only an untagged Ethernet II
frame whose EtherType is IPv4 and whose IPv4 header and total-length fields are
valid. It rejects VLAN-tagged and non-IPv4 frames. It can re-fragment an
existing fragment at a smaller later-hop MTU: the prior offset is added to each
child offset and a prior `MF` remains set on every child. It preserves Ethernet
addresses, IPv4 options, identification, payload bytes, and the reserved flag;
clears `DF`; sets `MF` and the fragment offset; and recomputes every IPv4 header
checksum. Every non-final fragment payload is a positive multiple of eight
bytes. If `DF` is set, the forward datagram is dropped. Ethernet padding beyond
the IPv4 total length is not copied into fragments.

Fragmentation expands one scheduler frame into an ordered, bounded set of real
scheduler frames. Every child resumes immediately after the completed MTU
phase and independently traverses every downstream path phase and later hop.
Consequently queue frame and byte capacity, service curves, token accounting,
link serialization, downstream loss, duplication, corruption, and a smaller
later-hop MTU operate on actual fragments and include every copied header. The
checkpoint records each fragment as an ordinary pending frame, so restore and
replay cannot re-fragment or change fragment boundaries. Expansion clears the
parent's completed-serialization marker; a downstream queue accounts each
child, or the destination link serializes it when no downstream queue does.

Each child carries a parent-to-child `protocol_expansion_path` of zero-based
ordinals. The path enters pending-frame ordering, checkpoint identity, and
every downstream opportunity ID; two byte-identical child frames therefore
cannot alias. Nested expansion depth is bounded at 256 and fails atomically
before staging child frames.

### 8.3.2 Typed reverse-path responses

MTU `typed_error`, firewall `reject`, and queue `typed_error` all reference the
same `typed_response` world artifact class. They never return host errors or
inject packets directly into a guest. The forward frame is rejected, and the
scheduler either suppresses the protocol response or stages a complete Ethernet
response from the selected route endpoint to the original producer. That frame
has no locked route and traverses ordinary reverse route resolution, fault
targets, phases, queues, service constraints, serialization, loss, corruption,
and later generated-response effects.

A typed-response artifact contains a nonempty ordered list of response variants
and `unmatched = suppress/fail_closed`. Variants are tried in declaration order.
Only `protocol_mismatch` advances to the next variant. A matching protocol's
suppression rule ends response processing without a packet; a malformed matching
packet or encoder failure fails the scheduler closed. `opaque_ethernet` matches
every request and therefore may appear only as the final variant. These rules
let one MTU or firewall policy carry IPv4 and IPv6 responses without treating
normal dual-stack traffic as malformed.

The closed response variants are:

| Variant | Required fields | Generated result and restrictions |
| --- | --- | --- |
| `icmpv4_destination_unreachable` | code `0..=15` except 4; quoted payload byte limit | Ethernet + IPv4 + ICMP type 3; quotes the complete variable-length IPv4 header plus the bounded payload prefix |
| `icmpv4_packet_too_big` | quoted payload byte limit; next-hop MTU at least 68 | Ethernet + IPv4 + ICMP type 3 code 4 with the MTU in the low 16 bits of the unused field |
| `icmpv4_time_exceeded` | code 0 or 1; quoted payload byte limit | Ethernet + IPv4 + ICMP type 11 |
| `icmpv6_destination_unreachable` | code `0..=7`; quoted payload byte limit | Ethernet + IPv6 + ICMPv6 type 1; quotes the base header plus the bounded original payload prefix |
| `icmpv6_packet_too_big` | quoted payload byte limit; next-hop MTU at least 1280 | Ethernet + IPv6 + ICMPv6 type 2 with the 32-bit MTU |
| `tcp_reset` | no kind-specific fields | IPv4 or IPv6 TCP reset with ports reversed and standard sequence/acknowledgement rules; IPv6 extension headers are walked; incoming resets and non-initial fragments are suppressed |
| `opaque_ethernet` | complete 14-byte-or-larger bounded frame | Emits the exact declared bytes; no generated header field may be configured |

Each generated-protocol variant declares a positive TTL/hop limit, optional
source MAC, optional family-appropriate source IP, an IPv4 identification where
applicable, and optional positive virtual response delay. Absent source values
reverse the request addresses. IPv4 and IPv6 transport and ICMP checksums are
recomputed. IPv6 extension walking is bounded at 16 headers; malformed or
overlong chains fail closed. Opaque responses use only their exact bytes and
optional delay, so every generated-header field must be its zero/absent value.

ICMPv4 errors are suppressed for link/IP multicast or broadcast destinations,
unspecified, broadcast, or multicast sources, non-initial fragments, and ICMP
errors in response to ICMP errors. ICMPv6 errors are suppressed for unspecified
or multicast sources and ICMPv6 errors in response to ICMPv6 errors. Multicast
destinations suppress ICMPv6 errors except Packet Too Big. TCP reset generation
suppresses a reset in response to a reset.

The configured response delay is measured from the rejecting opportunity. A
delayed response is a checkpointed pending frame and installs an exact scheduler
wakeup. Every response continuation records the cause opportunity and an
ancestry depth. Both enter ordering and downstream opportunity identity. Forward
cursor completions, protocol-expansion paths, availability preservation, and
resolved frame effects are reset because they belong to the rejected frame.
Response ancestry is bounded at eight; exceeding the bound fails atomically and
prevents response loops from growing without limit. Simultaneous rejecting
effects must select the same response artifact or the opportunity fails closed.

## 8.4 Storage and 9p effect registry

| Effect key | Lifetime and phase | Required parameters | Composition | Capability and replay evidence |
| --- | --- | --- | --- | --- |
| `storage.availability` | persistent/state; admit | `state = online/offline/read_only/degraded`, reconnect policy | severity | `storage.availability.v1`; old/new state and rejected operation |
| `storage.reported_capacity` | persistent; produce/admit | `length_bytes`, shrink policy | minimum with conflict on policy | `storage.capacity.v1`; old/new length and affected ranges |
| `storage.latency` | opportunity; resolve/deliver | operation filter, `extra_nanos`, `jitter_nanos` | checked-sum | `storage.latency.v1`; component delays and keyed jitter |
| `storage.service` | persistent state; queue | `bytes_per_second`, optional `iops`, queue depth, token/service parameters | minimum constraints | `storage.service.v1`; service and queue ledger |
| `storage.operation_failure` | opportunity; resolve | operation filter, probability, typed status/errno | severity plus independent-hazards | `storage.failure.v1`; decision and returned status |
| `storage.stall_timeout` | opportunity/state; resolve | `stall_nanos` or recovery event, timeout result | maximum stall and earliest modeled timeout | `storage.stall.v1`; wait/recovery/timeout coordinates |
| `storage.completion_reorder` | opportunity; deliver | `window_nanos`, selection | maximum window with keyed shifts | `storage.reorder.v1`; original/resolved completion order |
| `storage.duplicate_completion` | opportunity; deliver | copies, gap, protocol-valid duplicate policy | bounded checked copies | `storage.duplicate.v1`; duplicate IDs and guest-visible disposition |
| `storage.read_transform` | opportunity; resolve | `kind = bit_flip/stale/misdirected`, selector/version/range fields | ordered-transform | `storage.read-transform.v1`; source version/range and before/after digest |
| `storage.write_disposition` | opportunity; persist | `kind = apply/lost/torn/misdirected`, acknowledged status, deterministic byte/sector selector | conflict per write; ordered-transform for misdirection | `storage.write-disposition.v1`; intended/applied ranges, bytes and durability |
| `storage.persistence_order` | persistent/opportunity; persist | ordering group, delay/barrier rule | declared partial order then operation ID | `storage.persistence-order.v1`; volatile and durable sequence ledger |
| `storage.volatile_cache` | persistent state/impulse; persist/boundary | capacity, policy, loss selector, reset/power event | one cache policy; loss impulses union selected entries | `storage.volatile-cache.v1`; cache entries and durable frontier before/after |
| `storage.flush_disposition` | opportunity; persist | `kind = honest/error/lie/stall`, status | severity `honest < lie < stall < error` only where comparable; otherwise conflict | `storage.flush.v1`; requested barrier, reported status, actual durable frontier |
| `storage.media_range` | persistent/state; resolve/persist | range, state `bad/latent/poisoned/read_only`, operation/count/time thresholds | range overlay in canonical start/length/binding order | `storage.media-range.v1`; resolved range state and thresholds |
| `storage.flash_state` | persistent state; persist | erase-block geometry, wear counters, endurance, retention/read-disturb/program rules | state-machine per erase block | `storage.flash.v1`; counters, temperature/time inputs, changed cells/ranges |
| `storage.controller_lifecycle` | state-machine; boundary | reset/reconnect/enumeration, queue treatment, namespace/path changes | severity/state-machine | `storage.controller.v1`; old/new controller, queues and namespace/path set |
| `storage.array_state` | state-machine; resolve/persist | layout, member/path state, selection, rebuild service, consistency policy | one array policy plus member outages | `storage.array.v1`; selected members, degraded/rebuild state and durability |
| `ninep.result` | opportunity; resolve | operation, `kind = errno/stale/misdirected`, errno/version/object fields | severity or ordered-transform | `ninep.result.v1`; request fields and response/error evidence |
| `ninep.visibility` | stateful; persist/deliver | object/update ID, visibility delay/event, namespace/data policy | operation order plus declared delay | `ninep.visibility.v1`; committed and visible frontiers, lookup result |

## 8.5 Node, CPU, memory, clock, interrupt, and accelerator registry

| Effect key | Lifetime and phase | Required parameters | Composition | Capability and replay evidence |
| --- | --- | --- | --- | --- |
| `node.lifecycle` | impulse/state; boundary | transition, downtime, restart/boot policy, volatile/device state policy | severity/state-machine | `qemu.node.lifecycle.v1`; QMP/plugin acknowledgement, old/new run state, state loss |
| `node.hang` | persistent; boundary/run | scope, recovery event, watchdog policy | outage-or | `qemu.node.hang.v1`; progress counters and recovery |
| `cpu.service` | persistent state; run | vCPU selector, rational capacity, quantum/service rule | minimum capacity | `qemu.cpu.service.v1`; retired budget, service ledger, vCPU schedule |
| `cpu.vcpu_state` | state-machine; boundary | state `online/offline/stalled`, transition/recovery | severity/state-machine | `qemu.cpu.vcpu-state.v1`; RR cursor and topology/run-state evidence |
| `cpu.register_transform` | impulse/persistent/opportunity; listed register phases | register ID/range, kind `bit_flip/stuck/replace`, mask/value, occurrence | ordered-transform | architecture capability; resolved register, before/after value and icount |
| `cpu.instruction_transform` | opportunity; before/after-instruction | kind `result_corrupt/skip/replay`, PC/TB/instruction selector, destination/result transform, replay count | conflict per instruction except ordered result transforms | architecture capability; decoded instruction identity, operands/results, PC and state digest |
| `cpu.exception` | impulse; before/after-instruction/boundary | architecture, exception kind/vector/syndrome/error fields | severity/conflict | architecture capability; injected exception and architectural acknowledgement |
| `interrupt.disposition` | opportunity/state; raise/route/deliver | kind `drop/delay/duplicate/replace`, delay/copies/vector fields | ordered by source event then binding | `qemu.interrupt.control.v1`; source/target/vector, original/final deliveries |
| `interrupt.storm` | state/event sequence; raise | vector/source, period/burst/count, routing | event merge by coordinate/sequence | `qemu.interrupt.storm.v1`; generated event sequence and acknowledgements |
| `memory.mutation` | impulse; boundary | address space, address/range, kind `bit_flip/replace`, mask/bytes, atomicity | ordered-transform with overlap evidence | `qemu.memory.mutate.v1`; translation, before/after bytes, dirty tracking and icount |
| `memory.access_transform` | persistent/opportunity; fetch/load/store/DMA | range, kind `stuck/read_corrupt/lost_write/torn_write/poison`, masks/selectors/outcome | range overlay then ordered-transform | `qemu.memory.access-transform.v1`; access, transformed bytes/outcome and range state |
| `memory.ecc_event` | impulse/opportunity; access/boundary | corrected/uncorrectable, address, syndrome, bank/channel/rank, guest visibility | severity | architecture capability; injected platform record/exception and acknowledgement |
| `memory.region_state` | persistent state; access/refresh | range, kind `failed/retention/rowhammer`, threshold/decay/access-pattern model | range overlay and state-machine | `qemu.memory.region-state.v1`; counters, aggressor/victim rows, changed bits/outcomes |
| `memory.service` | persistent state; access/queue | latency/service/bandwidth parameters and sharing scope | checked-sum latency; minimum service | `qemu.memory.service.v1`; access service ledger |
| `clock.transform` | persistent/impulse/opportunity; read/arm/fire | source, offset, drift ratio, jump, freeze value, jitter/wander process, monotonicity | offset checked-sum; drift rational-product; freeze severity; jitter ordered | `qemu.clock.transform.v1`; raw/transformed values, timer consequences and state |
| `clock.source_state` | state-machine; source-switch/synchronize | sources, failure/fallback, sync correction/rate policy | one source machine per guest clock | `qemu.clock.source-state.v1`; old/new source, offset/rate and timer rearm evidence |
| `accelerator.lifecycle` | state-machine; boundary/submit | device, transition `disappear/reset/reconnect`, queue/memory policy | severity/state-machine | device capability; enumeration/run state and queue treatment |
| `accelerator.result_transform` | opportunity; execute/complete | API/device job selector, field/buffer transform | ordered-transform | device capability; job identity and before/after result digest |
| `accelerator.memory_event` | opportunity/impulse; memory access/boundary | address/range, corrected/uncorrectable, syndrome or transform | severity/ordered-transform | device capability; device-memory evidence and guest driver outcome |
| `accelerator.service` | persistent state; execute/queue | rational capacity, memory/service cap, thermal/power metadata | minimum constraints | device capability; queue/job service ledger |

## 8.6 Closed precedence lattices

| Family | Lowest to highest precedence |
| --- | --- |
| Network availability | `up < degraded < receive_only/transmit_only < down`; incomparable directions combine to `down` |
| Storage availability | `online < degraded < read_only < offline` |
| Node lifecycle | `running < throttled < stalled < hung < resetting < powered_off < permanently_failed` |
| Operation outcome | success < corrected < retry < typed_error < timeout < fatal |
| Memory/ECC | normal < corrected < poisoned < uncorrectable < fatal |
| Accelerator lifecycle | online < degraded < reset < disappeared < permanently_failed |

Precedence does not authorize an adapter to discard contributors or skip an
effect's state transition. If two effects are not in the same lattice, they
compose independently or conflict as declared in the registry.

## 8.7 Exhaustive taxonomy-to-effect ledger

The following tables map every executable taxonomy row. A `+` means one cause
must drive all listed effects through separate bindings so each remains
observable. Parenthesized text names required technology state or signal input,
not an alternate untyped implementation.

### Wired and logical network rows

| Taxonomy fault/degradation | Required effect program |
| --- | --- |
| cable/fiber cut | `network.availability(down)` on every segment in the conduit domain |
| unplugged/loose connector | `network.flap` or `network.availability` from connector state |
| connector contamination/corrosion | wired quality input into `network.profile_delta` + `network.detected_frame_error` + `network.negotiated_mode` |
| fiber bend/microbend | attenuation signal into `network.profile_delta` and `network.detected_frame_error` |
| water ingress | shared attenuation/leakage state into `network.profile_delta` + `network.flap` |
| transceiver failure | `network.forwarder_lifecycle` for port/transceiver + directional `network.availability` |
| laser/receiver degradation | optical budget into `network.detected_frame_error` + `network.negotiated_mode` |
| repeater/amplifier failure | `network.availability` or gain degradation in `network.profile_delta` |
| duplex mismatch | `network.negotiated_mode` + shared-medium collision/throughput policy |
| polarity/pair fault | `network.negotiated_mode` lane/rate fallback or `network.availability` |
| autonegotiation failure | `network.negotiated_mode` state machine |
| FEC/lane degradation | `network.detected_frame_error` + `network.negotiated_mode` |
| wavelength/ROADM failure | `network.forwarding_mutation` on optical path + `network.availability` |
| amplifier saturation/noise | optical budget state into `network.detected_frame_error` and profile |
| OLT/ONU/ranging failure | `network.association` + `network.availability` + shared-medium timing state |
| split/shared-upstream contention | `network.shared_medium` + `network.service_curve` |
| loss of synchronization | `network.flap` with retraining + `network.negotiated_mode` |
| impulse noise/crosstalk | `network.burst_error_state` + `network.detected_frame_error` + fallback |
| ingress and microreflections | channel quality into errors, retries, and `network.negotiated_mode` |
| CMTS/upstream contention | `network.shared_medium` + `network.queue_policy` + service |
| appliance/grid interference | shared interference signal into `network.burst_error_state` and fallback |
| obstruction/misalignment | spatial/weather signal into `network.profile_delta` + `network.availability` |
| cut/repeater degradation | conduit-domain `network.availability` + `network.profile_delta` |
| link down | `network.availability(down)` |
| link flap | `network.flap` |
| one-way failure | directional `network.availability` |
| negotiation failure | `network.negotiated_mode` |
| bit-error rate | `network.detected_frame_error` or explicit undetected payload transform |
| burst errors | `network.burst_error_state` |
| frame loss | `network.frame_loss` |
| duplicate frame | `network.duplicate` |
| frame reordering | `network.reorder` |
| frame corruption | `network.payload_transform` |
| framing/CRC failure | `network.detected_frame_error` |
| propagation change | `network.propagation_delay` |
| latency/jitter | `network.profile_delta` + `network.jitter` |
| bandwidth restriction | `network.service_curve` or `network.token_bucket` |
| MTU reduction | `network.mtu` |
| pause/backpressure | `network.pause_backpressure` |
| broadcast/multicast loss | `network.recipient_subset` |
| tail drop | `network.queue_policy(overflow=tail_drop)` |
| RED/early drop | `network.queue_policy(discipline=red)` with keyed occupancy hazard |
| bufferbloat | bounded `network.queue_policy` + load-driven `network.service_curve` |
| priority starvation | `network.queue_policy` + class-scoped `network.service_curve` |
| head-of-line blocking | `network.queue_policy` dependency rule + `network.service_curve` |
| queue reset | `network.forwarder_lifecycle` with queue policy |
| port failure | port `network.availability` |
| line-card failure | fault-domain `network.forwarder_lifecycle` across member ports/queues |
| supervisor restart | `network.forwarder_lifecycle` + control-plane convergence |
| forwarding-table corruption | `network.forwarding_mutation` |
| MAC-table aging anomaly | `network.forwarding_mutation(stale_age/flood)` |
| switching-loop/storm | `network.forwarding_mutation(loop)` + `network.duplicate` + `network.service_curve` + `network.queue_policy` |
| interface failure | interface/segment `network.availability` |
| route withdrawal | `network.route_transition` |
| route blackhole | route transition or `network.forwarding_mutation(blackhole)` |
| routing loop | `network.forwarding_mutation(loop)` with bounded hop limit |
| asymmetric route | directional `network.route_transition` |
| convergence delay | route state machine + `network.control_plane_service` |
| ECMP churn | `network.route_transition` with versioned flow hashing |
| control-plane overload | `network.control_plane_service` |
| firewall reject/drop | `network.firewall_disposition` |
| connection-tracking loss | `network.connection_state(kind=conntrack)` reset |
| NAT exhaustion | bounded `network.connection_state(kind=nat)` admission failure |
| NAT state reset | `network.connection_state(kind=nat)` reset |
| load-balancer backend loss | `network.connection_state(kind=load_balancer)` + `network.route_transition` |
| tunnel endpoint loss | `network.connection_state(kind=tunnel)` + `network.availability` |
| tunnel MTU mismatch | tunnel state + `network.mtu` |
| VPN key/session expiry | `network.connection_state(kind=tunnel)` authentication/reconnect |
| MPLS label-state failure | `network.forwarding_mutation` keyed by label stack |
| SD-WAN policy/controller loss | `network.route_transition` + `network.control_plane_service` |
| DNS service/path failure | `network.connection_state(kind=dns)` with delay/error/stale/wrong result |
| maintenance window | scheduled `network.profile_delta` + `network.availability` transition |
| peering/transit failure | `network.route_transition` + `network.availability` + `network.service_curve` |
| traffic-engineering change | `network.route_transition` + `network.profile_delta` + `network.service_curve` |
| conduit cut | fault-domain `network.availability` fan-out |
| rack/chassis power loss | common signal into `network.forwarder_lifecycle` + node/storage bindings |

### Radio, mobile, IoT-radio, satellite, and contact rows

| Taxonomy fault/degradation | Required effect program |
| --- | --- |
| path loss | geometry into `network.rf_channel` |
| shadowing/obstruction | spatial attenuation field into `network.rf_channel` |
| building/tunnel entry | zone signal into `network.rf_channel` + `network.association` + `network.route_transition` |
| multipath fading | correlated spatiotemporal field into `network.rf_channel` |
| Doppler | relative-velocity signal into `network.rf_channel` + `network.association` acquisition state |
| rain/weather fade | weather field into `network.rf_channel` |
| foliage/seasonal attenuation | environment/spatial field into `network.rf_channel` |
| narrowband interference | channel-scoped interference power into `network.rf_channel` |
| broadband interference | fault-domain interference fan-out into `network.rf_channel` |
| pulsed/intermittent interference | event waveform into `network.burst_error_state` + `network.rf_channel` |
| adjacent-channel interference | allocation and spectral-mask lookup into `network.rf_channel` |
| self-interference/desense | co-located transmitter state into `network.rf_channel` receiver noise |
| intentional jamming | spatial/temporal interferer into `network.shared_medium` + `network.rf_channel` |
| antenna disconnect/damage | antenna state into `network.rf_channel` + `network.availability` |
| antenna orientation/polarization mismatch | orientation/antenna lookup into `network.rf_channel` |
| oscillator drift | frequency error into `network.rf_channel` + `network.association` |
| transmit-power reduction | power signal into `network.rf_channel` |
| receiver-noise increase | temperature/component noise into `network.rf_channel` |
| collision | `network.shared_medium` collision outcome |
| hidden terminal | visibility graph into `network.shared_medium` collision/backoff |
| exposed terminal | visibility graph into `network.shared_medium` deferral/service |
| capture effect | `network.shared_medium` capture rule |
| backoff anomaly | `network.shared_medium` backoff-state mutation |
| channel occupancy | `network.shared_medium` admitted transmission/load state |
| duty-cycle restriction | `network.shared_medium` transmit eligibility/token state |
| AP outage/restart | `network.forwarder_lifecycle` + `network.association` |
| authentication failure | `network.association` authentication failure |
| roaming/handoff | `network.association` transition |
| rate adaptation fallback | `network.rf_channel` into `network.negotiated_mode` + `network.service_curve` |
| beacon loss | `network.frame_loss` into `network.association` timeout state |
| no coverage | `network.rf_channel` candidate set into `network.association` + `network.availability` |
| cell congestion | `network.shared_medium` + `network.service_curve` + `network.queue_policy` + `network.access_delay` |
| cell/sector outage | fault-domain `network.forwarder_lifecycle` + `network.association` |
| handover interruption | `network.association` transition with declared buffer/in-flight policy |
| handover failure | `network.association` failure/reconnect state |
| ping-pong handover | `network.association` hysteresis/timer state machine |
| RRC idle/reconnect delay | `network.association` + `network.access_delay` |
| core/backhaul congestion | `network.queue_policy` + `network.service_curve` + `network.profile_delta` |
| SIM/authentication failure | `network.association` authentication outcome |
| modem reset | `network.forwarder_lifecycle` + `network.association` reset |
| advertising loss | `network.frame_loss` + `network.recipient_subset` into discovery state |
| channel-map degradation | `network.shared_medium` resource-set transition |
| connection-interval miss | `network.shared_medium` + `network.control_result_transform(drop)` |
| ranging bias/dropout | `network.rf_channel` + `network.control_result_transform(bias/drop)` |
| coupling loss/collision | `network.shared_medium` + `network.rf_channel` + `network.control_result_transform(error)` |
| duty-cycle exhaustion | `network.shared_medium` transmit-admission state |
| spreading-factor/rate change | `network.negotiated_mode` + `network.service_curve` |
| repeater/channel loss | `network.forwarder_lifecycle` + `network.availability` + `network.recipient_subset` |
| parent/route loss | `network.association` + `network.route_transition` |
| partition/merge | `network.association` membership + `network.route_transition` |
| gateway outage | `network.forwarder_lifecycle` + `network.availability` |
| uplink degradation | `network.profile_delta` + `network.service_curve` |
| visibility-window closure | `network.contact` availability transition |
| acquisition delay/failure | `network.contact` acquisition state |
| antenna pointing loss | `network.rf_channel` + `network.contact` |
| beam handover | `network.association` + `network.contact` |
| gateway handover | `network.contact` + `network.route_transition` |
| range-varying delay | range trace into `network.propagation_delay` |
| Doppler acquisition error | `network.rf_channel` + `network.contact` acquisition state |
| rain fade | weather into `network.rf_channel` |
| ionospheric scintillation | `network.burst_error_state` + `network.rf_channel` |
| solar interference | scheduled/spatial interferer into `network.rf_channel` |
| transponder contention | `network.shared_medium` + `network.service_curve` |
| ground-station congestion | `network.queue_policy` + `network.service_curve` |
| ground-station outage | `network.forwarder_lifecycle` + `network.contact` + `network.route_transition` |
| inter-satellite link loss | `network.availability` + `network.route_transition` |
| contact-plan error | `network.contact` + `network.custody_queue` + `network.route_transition` |
| custody queue overflow | `network.custody_queue` overflow policy |
| stale route/contact data | `network.contact` + `network.route_transition` state mutation |
| radiation upset | common signal into `memory.mutation` + `cpu.exception` or `node.lifecycle`; never a network approximation |
| thermal cycle | common signal into `network.rf_channel` + `cpu.service` + `clock.transform` + `storage.service` |
| power eclipse | energy signal into `node.lifecycle` + `cpu.service` + `network.availability` |

### Node, CPU, interrupt, memory, clock, and accelerator rows

| Taxonomy fault/degradation | Required effect program |
| --- | --- |
| crash | `node.lifecycle(powered_off/crashed)` |
| power-cycle reset | `node.lifecycle` with declared volatile/device reset policy |
| hang | `node.hang` |
| intermittent reset | event/state signal into repeated `node.lifecycle` transitions |
| boot failure | `node.lifecycle` boot transition failure/timeout |
| capacity throttle | `cpu.service` |
| thermal throttle | temperature signal into `cpu.service` |
| vCPU stall | `cpu.vcpu_state(stalled)` |
| vCPU offline | `cpu.vcpu_state(offline)` |
| machine check | architecture `cpu.exception` with hardware-error fields |
| reset/triple fault | architecture `cpu.exception` + `node.lifecycle` transition |
| register bit flip | `cpu.register_transform(bit_flip)` |
| instruction-result corruption | `cpu.instruction_transform(result_corrupt)` |
| instruction skip/replay | `cpu.instruction_transform(skip/replay)` |
| illegal/spurious exception | `cpu.exception` |
| dropped interrupt | `interrupt.disposition(drop)` |
| delayed interrupt | `interrupt.disposition(delay)` |
| duplicate/spurious interrupt | `interrupt.disposition(duplicate/replace)` |
| interrupt storm | `interrupt.storm` |
| transient bit flip | `memory.mutation(bit_flip)` |
| stuck-at bit | `memory.access_transform(stuck)` |
| read corruption | `memory.access_transform(read_corrupt)` |
| lost/torn write | `memory.access_transform(lost_write/torn_write)` with exact write selector |
| poison | `memory.access_transform(poison)` |
| ECC corrected error | `memory.ecc_event(corrected)` |
| ECC uncorrectable error | `memory.ecc_event(uncorrectable)` plus architecture outcome |
| row/region failure | `memory.region_state(failed)` |
| retention decay | `memory.region_state(retention)` |
| rowhammer-style disturbance | `memory.region_state(rowhammer)` |
| latency/bandwidth degradation | `memory.service` |
| offset/skew | `clock.transform(offset)` |
| drift/rate error | `clock.transform(drift)` |
| jump/step | `clock.transform(jump)` |
| freeze | `clock.transform(freeze)` |
| jitter/wander | `clock.transform(jitter/wander)` |
| source failure/fallback | `clock.source_state` |
| synchronization loss | `clock.source_state` + `clock.transform` evolution |
| device disappearance/reset | `accelerator.lifecycle` |
| compute corruption | `accelerator.result_transform` |
| memory/ECC error | `accelerator.memory_event` |
| thermal/power throttle | `accelerator.service` |

### Storage, flash, array, and filesystem-facing rows

| Taxonomy fault/degradation | Required effect program |
| --- | --- |
| disappearance/offline | `storage.availability(offline)` |
| reset/reconnect | `storage.controller_lifecycle` |
| read-only transition | `storage.availability(read_only)` |
| capacity change | `storage.reported_capacity` |
| read latency | operation-filtered `storage.latency` |
| write latency | operation-filtered `storage.latency` |
| flush latency | operation-filtered `storage.latency` or stall |
| bandwidth cap | `storage.service(bytes_per_second)` |
| IOPS cap | `storage.service(iops)` |
| queue-depth restriction | `storage.service` queue state |
| read error | `storage.operation_failure(read)` |
| write error | `storage.operation_failure(write)` |
| flush error | `storage.operation_failure(flush)` |
| timeout/dropped completion | `storage.stall_timeout` |
| completion reorder | `storage.completion_reorder` |
| duplicate completion | `storage.duplicate_completion` |
| read bit corruption | `storage.read_transform(bit_flip)` |
| stale read | `storage.read_transform(stale)` |
| misdirected read/write | `storage.read_transform(misdirected)` or `storage.write_disposition(misdirected)` |
| lost write | `storage.write_disposition(lost)` |
| torn/partial write | `storage.write_disposition(torn)` |
| reordered persistence | `storage.persistence_order` |
| volatile-cache loss | `storage.volatile_cache` loss impulse |
| lying flush | `storage.flush_disposition(lie)` |
| bad sector/range | `storage.media_range(bad)` |
| latent sector error | `storage.media_range(latent)` with threshold state |
| erase-block wear | `storage.flash_state` |
| program/erase failure | `storage.flash_state` + `storage.write_disposition` or `storage.operation_failure` |
| retention error | `storage.flash_state` retention transition + `storage.read_transform` |
| read disturb | `storage.flash_state` access-count transition + `storage.read_transform` |
| controller reset | `storage.controller_lifecycle(reset)` |
| namespace/path loss | `storage.controller_lifecycle` namespace/path transition |
| member/path failure | `storage.array_state` |
| rebuild load/failure | `storage.array_state` + `storage.service` + `storage.operation_failure` |
| errno injection | `ninep.result(errno)` |
| stale metadata/data | `ninep.result(stale)` |
| delayed visibility | `ninep.visibility` |

## 8.8 Registry completeness requirements

- **[FX-5]** CI MUST parse the taxonomy tables and prove that every row in
  §§4.2–4.6 has exactly one ledger row here, allowing repeated display names only
  when section identity disambiguates them.
- **[FX-6]** Every ledger program MUST resolve entirely to registered signals,
  mappings, effects, and supported target kinds. Free-form prose cannot satisfy
  registry coverage.
- **[FX-7]** Every architecture- or technology-specific capability MUST have a
  live production-backend conformance test. Mock, fake, and test-double
  backends are prohibited as application evidence.
- **[FX-8]** Generated user reference tables MUST link each accepted effect key
  to fields, units, examples, composition, capability, backend support, and the
  taxonomy causes that map to it.
