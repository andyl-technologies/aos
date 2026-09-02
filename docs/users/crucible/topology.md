# Fault topology reference

`WorldFaultTopology` is the immutable, scenario-owned registry of every object
that a signal-driven fault may address. It turns a logical `World` into a typed
physical model without discovering host devices or creating runtime resources.

Attach the complete registry with `World::with_fault_topology`. Admission
canonicalizes collections, derives eligible direct paths, resolves every
reference, verifies geometry and capability contracts, and computes the world
identity before a guest starts.

## Canonical TOML locations

Fault topology arrays are direct children of `[world]`; there is no
`[world.fault_topology]` wrapper. Rust collection names are plural, while the
canonical TOML array names are singular:

| Rust collection | Canonical TOML row |
|---|---|
| `fault_domains` | `[[world.fault_domain]]` |
| `network_interfaces` | `[[world.network_interface]]` |
| `network_segments` | `[[world.network_segment]]` |
| `network_media` | `[[world.network_medium]]` |
| `network_forwarders` | `[[world.network_forwarder]]` |
| `network_queues` | `[[world.network_queue]]` |
| `network_paths` | `[[world.network_path]]` |
| `network_attachments` | `[[world.network_attachment]]` |
| `network_contact_plans` | `[[world.network_contact_plan]]` |
| `network_policy_artifacts` | `[[world.network_policy_artifact]]` |
| `mobile_endpoints` | `[[world.mobile_endpoint]]` |
| `storage_devices` | `[[world.storage_device]]` |
| `storage_controllers` | `[[world.storage_controller]]` |
| `storage_arrays` | `[[world.storage_array]]` |
| `storage_policy_artifacts` | `[[world.storage_policy_artifact]]` |
| `node_capabilities` | `[[world.node_fault_capabilities]]` |

Nested structs serialize beneath the owning row using their field names. For
example, controller `namespaces` and `paths`, array `members` and `paths`, and
node register/memory/interrupt/clock/accelerator manifests remain nested arrays
inside that direct World row. Generate them through
`ScenarioDefForm::to_canonical_toml`; the model tables below define their exact
fields and constraints.

## Authoring rules

- IDs are stable scenario identities, not display labels. They must be unique
  within the collection and must satisfy `SignalId` or `FaultObjectId` syntax.
- Collection order is canonicalized. Do not use declaration order as a policy.
- All references resolve within the same admitted `WorldFaultTopology` or to a
  compatible node/link/I/O object in the enclosing `World`.
- Empty optional collections mean that capability is absent. They do not grant
  a wildcard capability.
- Policy artifacts are closed, versioned scenario data. They replace callbacks,
  host file reads, and implementation-private lookup tables.
- Resource limits apply both to direct collection counts and to material
  expanded from paths, selectors, policies, and capabilities.
- Sensor, battery, power, and cooling-device targets are rejected. Their values
  may be modeled as signals that drive supported targets.

## Top-level registry

```rust
pub struct WorldFaultTopology {
    pub fault_domains: Vec<WorldFaultDomain>,
    pub network_interfaces: Vec<WorldNetworkInterface>,
    pub network_segments: Vec<WorldNetworkSegment>,
    pub network_media: Vec<WorldNetworkMedium>,
    pub network_forwarders: Vec<WorldNetworkForwarder>,
    pub network_queues: Vec<WorldNetworkQueue>,
    pub network_paths: Vec<WorldNetworkPath>,
    pub network_attachments: Vec<WorldNetworkAttachment>,
    pub network_contact_plans: Vec<WorldNetworkContactPlan>,
    pub network_policy_artifacts: Vec<WorldNetworkPolicyArtifact>,
    pub mobile_endpoints: Vec<WorldMobileEndpoint>,
    pub storage_devices: Vec<WorldStorageFaultDevice>,
    pub storage_controllers: Vec<WorldStorageController>,
    pub storage_arrays: Vec<WorldStorageArray>,
    pub storage_policy_artifacts: Vec<WorldStoragePolicyArtifact>,
    pub node_capabilities: Vec<WorldNodeFaultCapabilities>,
}
```

`WorldFaultTopology::default()` is valid and declares no fault-addressable
objects. Logical links still work in that world, but selectors cannot target a
physical segment, queue, forwarder, storage layer, or hardware capability that
was not declared.

## Fault domains

A fault domain names a finite set of typed target references:

| Field | Contract |
|---|---|
| `id` | Stable domain identity. |
| `targets` | Canonical non-duplicated `WorldFaultTargetRef` members. |

Supported member kinds are network interface, directed segment, medium
resource, forwarder, queue, directed path, attachment, contact, block device,
9p device, storage controller namespace/path, storage array member/path, and VM
node.

Fault domains are for causal fan-out, not runtime discovery. A selector that
names a domain resolves its finite members during plan admission. Each member
must still be legal for the requested effect; a mixed domain cannot make an
invalid effect/target pair valid.

## Network interfaces

| Field | Contract |
|---|---|
| `id` | Stable interface identity. |
| `endpoint` | Owning VM endpoint or declared forwarding endpoint. |
| `technology` | `ethernet`, `wifi`, `cellular`, `bluetooth`, `lora`, `zigbee`, `thread`, `can`, `serial`, `optical`, `microwave`, `satellite`, `acoustic`, or `virtual`. |
| `addresses` | Canonical stable address IDs; not host interface addresses discovered at runtime. |
| `fault_domains` | Domains that include this interface. |

An interface is the narrowest target for transmit-only, receive-only,
association, or endpoint-specific availability behavior.

## Network segments

| Field | Contract |
|---|---|
| `id` | Stable segment identity. |
| `kind` | `ethernet`, `wifi`, `cellular`, `bluetooth`, `low_power_mesh`, `can`, `serial`, `optical`, `microwave`, `satellite`, `acoustic`, `tunnel`, or `virtual`. |
| `interface_a`, `interface_b` | Distinct declared endpoint interfaces. |
| `minimum_latency_nanos` | Strict deterministic latency floor. Dynamic delay cannot reduce delivery below it. |
| `mtu_bytes` | Positive baseline maximum frame size before an MTU effect. |
| `medium` | Optional declared medium traversed by the segment. |
| `forwarders` | Declared forwarding elements associated with this segment. |
| `fault_domains` | Domain memberships. |

Segments are bidirectional objects, but targets carry an explicit direction.
When the topology contains only direct segments between world endpoints,
admission derives canonical directed paths. Declare paths explicitly for
multi-hop routing, queues, forwarders, or policy-sensitive alternatives.

## Network media

| Field | Contract |
|---|---|
| `id` | Stable medium identity. |
| `kind` | `dedicated_wire`, `shared_wire`, `fiber`, `free_space_rf`, `guided_rf`, `optical_free_space`, `acoustic`, or `virtual`. |
| `resources` | Closed channel/resource IDs shared by medium users. |
| `access_policy` | Network policy artifact controlling arbitration/access. |
| `fault_domains` | Domain memberships. |

A medium owns shared occupancy and arbitration state. Independent per-frame
loss effects cannot reproduce shared collision, capture, duty-cycle, or
contention ordering.

## Network forwarders

| Field | Contract |
|---|---|
| `id` | Stable forwarding-element identity. |
| `kind` | `bridge`, `switch`, `router`, `gateway`, `nat`, `firewall`, `repeater`, or `satellite_relay`. |
| `ports` | Declared attached interface IDs. |
| `table_capacity` | Maximum deterministic forwarding/state-table entries. |
| `fault_domains` | Domain memberships. |

Forwarder lifecycle faults explicitly control queue and table retention.
Forwarding mutations and route transitions operate on declared ports and paths;
they cannot invent an undeclared output.

## Network queues

| Field | Contract |
|---|---|
| `id` | Stable queue identity. |
| `owner` | Interface, medium, or forwarder that owns the queue. |
| `capacity_packets` | Maximum queued frame count. |
| `capacity_bytes` | Maximum queued bytes, or zero when only packet count bounds it. |
| `discipline` | `fifo`, `strict_priority`, `weighted_round_robin`, `deficit_round_robin`, or `fair_queue`. |
| `overflow` | `drop_tail`, `drop_head`, or `mark_ecn`. |
| `fault_domains` | Domain memberships. |

The world declaration is the baseline. `network.queue_policy` may contribute a
dynamic capacity, discipline, class, or overflow policy at admitted queue
phases. Queue contents, service position, class state, and overflow decisions
are checkpointed adapter state.

## Network paths

| Field | Contract |
|---|---|
| `id` | Stable path identity. |
| `direction` | Direction of the complete endpoint-to-endpoint path. |
| `hops` | Ordered segment, forwarder, and queue hops. |
| `mtu_bytes` | Positive effective path MTU. |

Segment hops name a segment and direction. Forwarder and queue hops name their
declared objects. Admission rejects disconnected hop sequences, inconsistent
endpoints, duplicate IDs, invalid direction, or a path that references objects
outside the route.

A logical world link may map to one or more path candidates. Route selection,
transition, and in-flight treatment always use these admitted identities.

## Attachments

| Field | Contract |
|---|---|
| `id` | Stable association-machine identity. |
| `interface` | Controlled endpoint interface. |
| `candidates` | Closed candidate segment set. |
| `technology` | Technology contract used by control operations. |
| `semantic_version` | Exact attachment-machine schema version. |
| `authentication` | Registered authentication policy ID. |
| `address_continuity` | Registered address-continuity policy ID. |

Attachments model association, authentication, roaming, handoff, reconnect,
and traffic treatment. A candidate must already exist; signals change state and
selection rather than creating access points or links.

## Contact plans

A `WorldNetworkContactPlan` declares:

| Field | Contract |
|---|---|
| `id` | Stable plan identity. |
| `endpoint_a`, `endpoint_b` | Declared world endpoints. |
| `contacts` | Ordered, non-overlapping finite intervals. |
| `routing_policy` | Registered contact-routing policy. |
| `custody_policy` | Registered custody/forwarding policy. |

Each contact has `id`, inclusive `start_nanos`, exclusive `end_nanos`,
`range_delay_nanos`, positive `rate_bps`, and optional `beam` and `gateway`
IDs. Contact acquisition, teardown, service, range delay, and custody queues are
explicit state; wall-clock schedules never participate.

## Mobile endpoints

| Field | Contract |
|---|---|
| `id` | Stable mobile-endpoint identity. |
| `node` | Owning VM node. |
| `truth_trajectory` | Admitted spatial signal output. |

The trajectory is host-model truth used by spatial/RF evaluation. It does not
create a GPS, inertial sensor, battery, or other guest device.

## Network policy artifacts

Every `WorldNetworkPolicyArtifact` contains a stable `id`,
`semantic_version = 1`, and one typed payload. The closed payload classes are:

| Class | Contents and users |
|---|---|
| `integer_lookup` | Integer transfer, quantile, attenuation, or distribution table with explicit interpolation/out-of-range policy. |
| `error_state_table` | Complete good/bad correlated error states and transitions. |
| `queue_discipline` | Classes, weights/quanta, and optional RED parameters. |
| `byte_template` | Bounded replacement or corruption bytes. |
| `packet_selector` | Conjunctive typed byte matches. |
| `packet_key` | Ordered non-overlapping byte ranges forming a stable flow key. |
| `state_machine` | Closed initial state, state set, and transition set. |
| `service_curve` | Ordered service segments beginning at offset zero. |
| `medium_access` | Arbitration, contention, collision, backoff, retry, and duty-cycle policy. |
| `rf_propagation` | Integer propagation and antenna-gain tables. |
| `rf_transfer` | Integer SINR-to-result transfer table. |
| `association` | Candidates, authentication, selection, hysteresis, timers, and handoff policy. |
| `control_result` | Versioned schema plus canonical encoded result bytes. |
| `typed_response` | Closed generated reverse-path response set. |
| `overflow` | Overflow/expiry disposition, timeout, and optional typed response. |
| `contact_plan` | Canonical finite intermittent-contact intervals. |
| `recipient_membership` | Versioned multicast/broadcast candidate membership. |

Nested network payloads use these complete shapes:

| Kind | Payload |
|---|---|
| `integer_lookup` | input/output unit IDs, interpolation (`step`/`linear_ties_to_even`), outside behavior (`clamp`/`typed_error`), strictly ordered `{ input, output }` points |
| `error_state_table` | distinct good/bad IDs, initial ID, exactly two `{ state, loss, corruption, corruption_transform? }` rows |
| `queue_discipline` | `{ class, selector, priority, weight, quantum_bytes }` rows and optional complete RED min/max/probability/weight fields |
| `byte_template` | bounded exact `bytes` |
| `packet_selector` | conjunctive `{ offset_bytes, value, mask }` rows with equal value/mask lengths |
| `packet_key` | strictly ordered, non-overlapping byte ranges |
| `state_machine` | initial ID, finite states, exhaustive `{ from, event, to, delay_nanos, traffic_policy }` transitions |
| `service_curve` | segments starting at zero with increasing `at_nanos` and positive `rate_bps` |
| `medium_access` | arbitration, optional key/fixed slot/contention, positive duty-cycle ratio; contention contains collision, capture/transform conditionals, backoff slot/exponent and retry limit |
| `rf_propagation` | path/antenna integer tables, positive spatial cell and fading bucket |
| `rf_transfer` | ordered `{ minimum_sinr, rate_bps, loss, corruption, corruption_action, maximum_retries, retry_delay_nanos }` profiles |
| `association` | hysteresis and trigger/scan/auth/interruption timing, queue/address preservation, `{ candidate, score }` rows |
| `control_result` | schema ID and canonical encoded bytes |
| `typed_response` | ordered ICMPv4/v6, TCP-reset, or opaque-Ethernet responses; header source addresses, hop limit, IPv4 ID, optional delay; unmatched `suppress`/`fail_closed` |
| `overflow` | disposition `drop_newest`, `drop_oldest`, `typed_error`, or `timeout`, with exactly its conditional timeout/error reference |
| `contact_plan` | ordered half-open intervals with contact/service resource/route cost/propagation, endpoints, beam/gateway, range, capacity profile, acquisition/teardown, confidence, provenance |
| `recipient_membership` | nonempty canonical `{ member, joined_sequence }` rows |

Medium arbitration is `fifo`, `strict_priority`, `can_dominant_bit`,
`fixed_slots`, or `contention`; collision is `drop_all`, `capture`, or
`undetected_transform`. RF corruption is `corrected`, `detected`, or
`undetected { transform }`.

Effects validate that a referenced artifact has the required class. Reusing an
ID for a different class or semantic version is an admission error.

## Storage devices

`WorldStorageFaultDevice` connects one world I/O node to an executable storage
contract:

| Field | Contract |
|---|---|
| `id` | Stable fault-device identity. |
| `device` | Referenced block or 9p `WorldIoNode`. |
| `kind` | `block` or `nine_p`, matching the referenced node. |
| `persistence` | Complete geometry, cache, ordering, and completion contract. |
| `media` | Flash, magnetic, RAM, or remote media geometry. |
| `fault_domains` | Domain memberships. |

### Persistence contract

| Field | Contract |
|---|---|
| `logical_block_bytes` | Power of two from 512 through 65,536. |
| `physical_sector_bytes` | Power-of-two multiple of logical block size. |
| `atomic_write_bytes` | Positive logical-block multiple no larger than a physical sector. |
| `length_bytes` | Positive logical-block-aligned device/namespace length. |
| `discard_granularity_bytes` | Zero when unsupported, otherwise an aligned power of two. |
| `maximum_request_bytes` | Positive aligned bound, no larger than device length or 64 MiB. |
| `volatile_cache_bytes`, `cache_entries` | Both zero or both nonzero; bound volatile cached writes. |
| `controller_buffer_bytes`, `controller_entries` | Both zero or both nonzero; bound controller-accepted writes. |
| `flush_semantics` | `ordered_barrier`, `writeback_barrier`, or `force_unit_access`. |
| `discard_semantics` | `deterministic_zero`, `reads_old_data`, or `undefined_recorded`. |
| `completion_durability` | `controller_accepted`, `volatile_cache_accepted`, or `durable`. Required buffer/cache must exist. |
| `persistence_dependencies` | Maximum retained durability dependency edges. |
| `retained_versions_per_interval` | Positive version-history bound, at most 1,024. |

The persistence contract defines baseline truth. A lying flush, lost cache
entry, torn write, stale read, and completion error act at distinct layers and
do not implicitly rewrite this contract.

### Media variants

| Kind | Fields | Contract |
|---|---|---|
| `flash` | `erase_block_bytes`, `program_page_bytes`, `endurance_cycles` | Positive geometry; erase block is a multiple of program page. |
| `magnetic` | `sector_bytes`, `track_bytes` | Positive geometry; track is a multiple of sector. |
| `ram` | `page_bytes` | Power-of-two page size. |
| `remote` | `protocol` | Registered remote-protocol policy ID. |

## Storage controllers and paths

A controller has `id`, `semantic_version`, canonical `namespaces`, canonical
`paths`, and `fault_domains`.

| Namespace field | Contract |
|---|---|
| `id` | Stable identity within the controller. |
| `device` | Referenced storage fault device. |
| `capacity_bytes` | Positive guest-visible capacity consistent with the device. |
| `supports_fua` | Whether force-unit-access requests are admitted. |
| `supports_discard` | Whether discard requests are admitted. |

| Path field | Contract |
|---|---|
| `id` | Stable identity within its controller or array. |
| `queue_depth` | Maximum admitted in-flight operations. |
| `policy` | Registered path-selection, retry, and recovery policy. |

Controller lifecycle effects name a controller and namespace/path target, then
declare reset/reconnect/enumeration behavior and pending-I/O treatment.

## Storage arrays

| Field | Contract |
|---|---|
| `id` | Stable array identity. |
| `device` | Guest-visible logical block node backed by the array. |
| `semantic_version` | Exact array/parity state-machine version. |
| `layout` | `mirror`, `stripe`, `single_parity`, or `dual_parity`. |
| `chunk_bytes` | Positive aligned stripe chunk size. |
| `read_quorum`, `write_quorum` | Positive quorums consistent with layout/member count. |
| `members` | Canonical member ID, referenced device, and unique ordinal rows. |
| `paths` | Closed multipath declarations. |
| `member_path_state` | Baseline online-state artifact. |
| `selection_policy` | Baseline deterministic member-selection artifact. |
| `rebuild_service` | Bounded rebuild-service artifact. |
| `consistency_policy` | Partial-update consistency artifact. |
| `failure_result` | Typed non-success result for unavailable quorum. |
| `fault_domains` | Domain memberships. |

Array effects may change member/path state and rebuild service, but cannot add a
member, renumber an ordinal, or change layout after admission.

## Storage policy artifacts

Every storage policy has a stable `id`, `semantic_version = 1`, and one typed
payload:

| Class | Purpose |
|---|---|
| `typed_result` | Block protocol status or positive 9p errno. |
| `service` | Queue discipline, operation classes, integrated bandwidth/IOPS service. |
| `path` | Multipath selection, retry, timeout, and recovery. |
| `remote_protocol` | Remote-media wire/reconnect behavior. |
| `cache` | Volatile-cache admission, eviction, dirty eviction, and protection. |
| `duplicate_completion` | Guest protocol treatment of an additional completion. |
| `controller_transition` | Reset epoch and pending-request transition policy. |
| `persistence` | Durability dependency/order graph. |
| `retention` | Flash retention thresholds and outcomes. |
| `read_disturb` | Flash read-disturb counters and outcomes. |
| `program_erase` | Flash program/erase failure policy. |
| `array_selection` | Deterministic member selection. |
| `array_state` | Canonical member and path states. |
| `rebuild` | Bounded rebuild service and work accounting. |
| `array_consistency` | Partial-update consistency behavior. |
| `nine_p_visibility` | Committed-versus-visible frontier policy. |
| `nine_p_object` | Immutable 9p object version. |
| `bytes` | Immutable retained byte content. |

Nested storage policy payloads use these complete shapes:

| Kind | Payload |
|---|---|
| `typed_result` | `block { result }` or `nine_p { errno }`; block result is success, offline, read-only, invalid-range, busy, timeout, medium/integrity/I/O error, no-space, not-found, or stale |
| `service` | `fifo`, `strict_priority`, or `weighted_round_robin`; `{ class, operations, priority, weight }` rows; rebuild-sharing flag |
| `path` | `active_passive`, `round_robin`, `least_outstanding`, or `stable_hash`; attempt bound, retry/probe delays, retry-result set |
| `remote_protocol` | `nvme_tcp`, `iscsi`, or `nbd`; outstanding bound, command timeout, reconnect delay, preserve-order flag |
| `cache` | eviction `fifo`, `lru`, or `writeback_sequence`; dirty eviction `persist` or `fail { result }`; power-loss protection |
| `duplicate_completion` | `ignore`, `protocol_error { result }`, or `reset { transition_policy }` |
| `controller_transition` | transition/failure result; unadmitted, queued, executing, resolved, undelivered treatment; controller/cache/history state; request-ID epoch; topology; recovery duration |
| `persistence` | `preserve`, `reverse_ready`, `descending_range`, or `keyed_permutation`; delay and barrier-preservation flag |
| `retention` | minimum/wear age, bit probability, maximum changed bits |
| `read_disturb` | read threshold, neighbor pages, bit probability, maximum changed bits |
| `program_erase` | program/erase/worn probabilities and partial-program/erase flags |
| `array_selection` | `lowest_healthy`, `stable_hash`, or `least_loaded` |
| `array_state` | canonical `{ member, online }` and `{ path, online }` rows |
| `rebuild` | positive chunk bytes, queue depth, byte rate |
| `array_consistency` | `require_quorum`, `degraded_commit`, or `atomic_stripe` |
| `nine_p_visibility` | `global`, `per_session`, or `writer_immediate`; metadata/data atomicity, optional lag, retained-deletion flag |
| `nine_p_object` | path, version, mode, bytes, deleted flag |
| `bytes` | bounded exact bytes |

Controller transitions distinguish new-request `reject`/`wait_for_recovery`;
pending `fail`/retry-same-ID/retry-new-ID; resolved/undelivered completion,
failure and retry (plus undelivered drop); state `preserve`/`lose`; request IDs
`preserve_monotonic`/`new_epoch_from_zero`; and topology
`preserve`/`reenumerate_declared`.

Cross-artifact references are class-checked. For example, an array's rebuild
reference cannot name a byte template, and a 9p stale-object result cannot name
a network control response.

## Node capability declarations

`WorldNodeFaultCapabilities` is an exact contract with the realized patched
QEMU machine:

| Field | Contract |
|---|---|
| `id` | Stable capability declaration identity. |
| `node` | Referenced VM node. |
| `architecture` | `x86_64` or `aarch64`, matching the VM. |
| `cpu_model` | Exact realized printable QOM CPU typename. |
| `register_schema` | Content hash of the canonical register manifest. |
| `registers` | Nonempty exact register rows. |
| `address_spaces` | Nonempty admitted memory ranges. |
| `page_bytes` | Power-of-two guest page size. |
| `dram_geometry` | Exact implemented `2c2r16b64` GPA mapping. |
| `interrupts` | Exact routable interrupt rows; may be empty. |
| `hardware_errors` | Exact architecture/platform error rows; may be empty. |
| `clock_sources` | Exact guest-visible clock rows; may be empty. |
| `accelerators` | Exact deterministic fault-device rows; may be empty. |
| `ready_markers` | Closed guest marker set eligible for ready policies. |
| `semantic_version` | `1`. |

The backend handshake checks the declaration against realized QEMU. Scenario
admission alone is not proof that the installed backend implements it.

## Register rows

Each register row contains `id`, canonical lowercase `name`, nonzero
`numeric_id`, register `group`, `width_bits`, `per_vcpu`, legal `model_phases`,
derived `side_effects`, `impulse`, `persistent`, `vmstate`, and four exact-width
lowercase byte-order masks: `writable_mask_hex`, `reserved_mask_hex`,
`ignored_mask_hex`, and `read_only_mask_hex`.

Groups are general-purpose, control-flow, flags, segment, control, system,
debug, floating-point, vector, and error. Derived setter actions are TLB flush,
translation-block flush, flags recomputation, interrupt reevaluation, timer
rearm, and control-flow synchronization.

Writable, reserved, ignored, and read-only masks must be mutually consistent.
A binding cannot mutate an undeclared bit or use a lifetime/phase the row does
not advertise.

## Memory and DRAM rows

Each address space has `id`, inclusive `start_address`, and positive
`length_bytes`; ranges must not wrap or overlap illegally. Memory targets name
the declared space and an address/range within it.

The current DRAM geometry is exactly:

```text
channels = 2
ranks = 2
banks = 16
interleave_bytes = 64
semantic_version = 1
```

Rowhammer and region processes use that deterministic GPA mapping. A different
geometry is rejected rather than approximated.

## Interrupt rows

| Field | Contract |
|---|---|
| `id`, `controller`, `source` | Stable route identities. |
| `controller_version` | Exact realized implementation/version string. |
| `family` | x86 local APIC, IPI, I/O APIC, PIC, MSI, MSI-X, NMI, timer; or Arm GIC SGI/PPI/SPI/LPI, timer. |
| `vector_start`, `vector_end` | Runtime vector/INTID range. |
| `replacement_vector_start`, `replacement_vector_end` | Range legal for replacement mutations. |
| `trigger` | `edge` or `level`. |
| `polarity` | `active_high` or `active_low`. |
| `target_vcpus` | Closed routable destination vCPU set. |
| `model_phases` | Implemented interception phases. |
| `priority` | Controller priority used for deterministic ordering. |
| `delivery_drop` | `consume_edge` or `repend_asserted_level`. |
| `vmstate` | Complete controller/fault overlay continuation coverage. |

Architecture-specific vector ranges, trigger/polarity combinations, and
delivery semantics are validated. An interrupt mutation cannot replace a
vector outside the row's replacement range.

## Hardware-error rows

Each row declares stable `id`, bank/channel/rank identities, firmware and state
prerequisites, record kind, error class, publication mechanism, guest-visible
consequences, bank range, vector, required/allowed status and syndrome masks,
legal phases, privilege levels, corrected/maskable behavior, and VMState
coverage.

Record kinds are x86 machine check, AArch64 RAS, and memory ECC. Mechanisms are
x86 MCA, ACPI GHES, and AArch64 RAS. Visibility may include telemetry,
interrupt, and exception. The requested status/syndrome bits must include all
required bits and no bit outside the allowed mask.

## Clock-source rows

| Field | Contract |
|---|---|
| `id`, `implementation` | Stable source and exact QEMU subsystem identity. |
| `source_kind` | x86 TSC/RTC/PIT/HPET/APIC timer/ACPI PM timer, Arm counter/RTC, or registered device source. |
| `base_domain` | `scheduler_virtual` or deterministic `rtc_epoch`. |
| `timer_relationship` | `none` or `programmable`. |
| `width_bits`, `wraps`, `read_error` | Architectural read contract. |
| `frequency_numerator`, `frequency_denominator` | Positive exact ticks-per-second ratio. |
| `model_phases` | Implemented read, arm, fire, synchronize, or source-switch opportunities. |
| `monotonicity` | `allow_backward`, `clamp_monotonic`, or `fault_on_backward`. |
| `vmstate` | Source, transform, timer, and synchronization continuation coverage. |
| `semantic_version` | Exact transform schema version. |

Clock effects change guest-visible values and timer behavior. They never change
the scheduler's authoritative virtual time.

## Accelerator rows

| Field | Contract |
|---|---|
| `id` | Stable deterministic fault-device identity. |
| `classes` | Canonical nonempty subset of `gpu`, `tpu`, and `fpga`. |
| `semantic_version` | Exact accelerator fault-device version. |
| `capability_manifest` | Content hash of device-specific operations, fields, queues, memory, and service capabilities. |

These rows describe the Crucible deterministic QEMU device, not arbitrary host
accelerators or passthrough hardware.

## Admission and canonicalization

`World::with_fault_topology` performs the following before execution:

1. Enforce hard collection and nested resource limits.
2. Canonicalize registries and reject duplicate identities.
3. Expand eligible direct-segment paths.
4. Resolve all network, storage, node, domain, and policy references.
5. Validate path connectivity and direction.
6. Validate storage geometry, capacity, layout, and policy classes.
7. Validate architecture capability rows and exact supported versions.
8. Reject specification-only sensor-backed concepts.
9. Compute the canonical topology and world content identities.

Plan admission then resolves selectors against this admitted topology and
validates each effect tuple. Backend capability negotiation is a separate,
later fail-closed check.

## Continuation and evidence

Topology declarations are immutable and content-addressed. Mutable state lives
in adapters and includes queues, forwarding tables, route state, attachments,
contacts, storage caches, durability frontiers, media counters, controller and
array epochs, hardware overlays, and clock/accelerator state.

Exact checkpoints retain that mutable state together with topology identity.
Replay rejects a target, capability, policy, or topology hash mismatch rather
than applying evidence to a similar-looking object.
