# RFC-0025 — 02. Ports, capabilities, and admission

## Scope

This chapter specifies how a coordinator determines whether a declared node
graph can execute with its requested semantics. It covers compute, storage,
filesystem, network, clock, interrupt, and external-device nodes. A node's role
does not select its implementation, process placement, timing mode, or capture
strategy.

The contracts in this chapter describe a resolved execution graph. An authored
scenario may contain implementation choices or requirements. Resolution fixes
those choices before activation; it does not modify a running node's contract.

The common model and identity vocabulary are defined in
[Conventions and Model](00-conventions-and-model.md). The lifecycle of an
execution owner is defined in [Node Contract](01-node-contract.md). Exact and
quantized timing semantics are defined in
[Time and Scheduling](03-time-and-scheduling.md) and
[Quantized and Physical Nodes](04-quantized-and-physical-nodes.md). State
ownership and replay compatibility are defined in
[State and Replay](05-state-and-replay.md).

## Typed Ports

### Endpoint and Lane Identity

A port is a named semantic interface of one logical node. It is not a socket,
file descriptor, shared-memory offset, native object pointer, or execution
owner. A port may be implemented inside a composite owner or connected through
a process protocol without changing its semantic identity.

**[CN-PORT-1]** Every exposed port MUST have an endpoint identity consisting of
its logical `NodeId` and a locally unique `port_id`. Port and lane identifiers
MUST remain stable within the frozen realization. A new physical connection,
process, or shared-memory mapping MUST NOT silently change the logical
endpoint or transfer its authority to another endpoint.

Request/response interfaces have distinct directed lanes. For example, a
storage client emits requests and receives completions; an interrupt source
emits line transitions and may receive acknowledgments. Bidirectional does not
mean unordered or interchangeable directions.

**[CN-PORT-2]** A port descriptor MUST enumerate every admitted lane and its
direction relative to the node, using `input` or `output`. Each lane MUST select
one protocol identity, semantic version, payload schema, ordering contract,
visibility contract, and resource bound. A connection MUST pair an output lane
with a compatible input lane. An undeclared reverse lane MUST NOT be inferred
from the existence of the forward lane.

The following table defines the semantic fields of a `PortDescriptor`. Their
wire representation and canonical encoding follow
[Provider Protocol and Security](06-provider-protocol-and-security.md).

| Field | Meaning |
| --- | --- |
| `endpoint` | Logical node and local port identity. |
| `interface_id` | Registered semantic interface or namespaced extension. |
| `lanes` | Complete directed lane declarations. |
| `feature_requirements` | Features required by this endpoint's configuration. |
| `connection_limits` | Maximum producers, consumers, and outstanding connections. |
| `arbitration` | Defined serialization or broadcast policy for multiple peers. |
| `execution_owner` | Owner through which the port's mutable effects execute. |
| `state_domains` | References to mutable domains represented by this port. |
| `internal` | Whether the containing composite owner mediates the port internally. |

| Lane field | Meaning |
| --- | --- |
| `lane_id`, `direction` | Locally unique lane and direction. |
| `protocol_id`, `semantic_version` | Exact selected semantic protocol version. |
| `schema_ref` | Canonical schema identity for admitted payloads. |
| `features` | Exact negotiated feature set. |
| `payload_bounds` | Per-message bytes, nested collection bounds, and supported operation limits. |
| `queue_bounds` | Outstanding messages/bytes and correlation-record limits. |
| `flow_control` | Credit, refusal, or bounded loss semantics. |
| `ordering` | Sequence domain, correlation rules, barriers, and retry identity. |
| `visibility` | Exact publication or quantized boundary policy. |
| `minimum_lookahead` | Proven lower bound on earliest downstream visibility. |
| `effect_phases` | Admitted observation and mutation phases. |

### Protocol Selection and Payloads

**[CN-PORT-3]** A connection MUST select one explicitly supported semantic
version and schema for each lane. Matching protocol names or major versions
alone MUST NOT establish compatibility. Negotiation MUST verify required
features, numeric widths, endianness where relevant, operation meanings, error
meanings, and payload interpretation. Any permitted subset or conversion MUST
be named by an admitted contract rather than inferred from successful decoding.

**[CN-PORT-4]** Payload and queue bounds MUST be finite and checked before
allocation or publication. Receivers MUST reject values exceeding the selected
schema or bounds. A sender MUST NOT publish a larger payload merely because the
underlying transport can carry it. Integer conversion and size arithmetic MUST
be checked for overflow.

**[CN-PORT-5]** Every request/response lane pair MUST define correlation identity,
completion multiplicity, cancellation semantics, and duplicate handling. A
transport retry MUST preserve the original operation identity. A duplicate
MUST NOT create an additional device effect, completion, credit, or interrupt.
If a receipt is uncertain, the operation MUST remain owned and unresolved until
the contract's recovery or terminal containment procedure completes.

Portable interface semantics and guest-facing hardware ABIs are separate.
A block service can use a common semantic protocol while a compute provider
exposes a particular controller model to its guest. The controller frontend's
feature set, descriptor layout, DMA behavior, and interrupt mechanism remain
part of the admitted machine profile.

**[CN-PORT-6]** An adapter between a guest-visible device and a semantic port MUST
declare both contracts and the mapping between them. Admission MUST reject an
unsupported guest-visible operation or feature before activation. A provider
MUST NOT advertise device parity based solely on a shared role name, boot
success, or a subset of exercised operations.

### Backpressure and Ordering

**[CN-PORT-7]** Every lane MUST define bounded flow control. Exhausting credits
or capacity MUST either retain an owned pending operation, refuse it without
effects, or apply an explicitly admitted loss policy. Blocking a host worker
MUST NOT advance logical time, manufacture receipt acknowledgment, or change
the logical order of operations.

**[CN-PORT-8]** Credit issuance, consumption, release, and return MUST be
associated with unambiguous operation and connection identities. Outstanding
credits and retained operations MUST be included in the appropriate state
owner's continuation. Reconnection MUST NOT regenerate credits that remain
outstanding in preserved state.

**[CN-PORT-9]** Each lane MUST specify its ordering scope, including whether
operations are FIFO, independently reorderable, barrier-ordered, or serialized
by an explicit arbitration model. The coordinator MUST preserve canonical
event ordering within the selected semantics. Native callback order, host
worker completion order, and arrival order at a transport MUST NOT supply an
undeclared tie-breaking rule.

**[CN-PORT-10]** A lane permitting drops or reordering MUST identify the owner
of the decision and its source. Deterministic modeled decisions MUST use
preserved model state and recorded decisions as applicable. Live external
decisions MUST retain nondeterministic provenance. Dropping an operation MUST
apply the selected completion, credit, and cancellation rules rather than
silently abandoning ownership.

### Effect Visibility and Lookahead

Logical publication determines when another node can observe an effect.
Physical execution, host observation, transport enqueue, semantic acceptance,
and downstream visibility are distinct milestones.

**[CN-PORT-11]** Every lane MUST declare a visibility contract in shared
picosecond ticks. Exact lanes MUST follow exact event admission and no-outrun
rules. Quantized lanes MUST name their grid, phase, ingress sampling, egress
publication, and lateness policy. A connection between modes MUST declare the
conversion policy at the edge. An adapter MUST NOT silently weaken an exact
requirement into quantized delivery.

**[CN-PORT-12]** A published effect MUST retain its producer endpoint,
connection, sequence or correlation identity, selected visibility policy, and
logical publication coordinate. Quantized or physical observations MUST also
retain the provenance and uncertainty required by the selected mode. An effect
MUST NOT be backdated into an already committed interval.

**[CN-PORT-13]** Advertised minimum lookahead MUST be a proven lower bound on
downstream visibility for every operation admitted by the lane. The bound MUST
account for immediate errors, cache hits, cancellations, unsolicited events,
and side channels. An average latency, intended delay, current absence of
observations, or measured host runtime MUST NOT establish lookahead.

**[CN-PORT-14]** Unknown future-input enumeration MUST remain distinguishable
from complete enumeration with no pending input. The coordinator MUST refuse
an advance requiring a bound that has not been established. A declared infinite
bound MUST mean that the selected contract excludes future effects until a
specified change or activation event, rather than that a provider currently
has no queued effect.

**[CN-PORT-15]** Zero-delay edges MUST retain their declared semantics. The
coordinator MUST either resolve a zero-delay dependency using the admitted
same-time arbitration procedure or refuse a graph that cannot make safe
progress. Admission MUST NOT invent a positive latency, round a ceiling upward,
or rely on eventual host execution to resolve such a dependency.

### Storage, Clock, and Interrupt Requirements

**[CN-PORT-16]** A storage interface MUST declare request units, alignment,
address and length limits, supported operations, completion interpretation,
ordering/barrier rules, persistence semantics, error semantics, and its
capture owner. Write acceptance, completion, and persistence MUST remain
distinct where the selected device model distinguishes them. Shared storage
MUST declare arbitration, client ordering scopes, and visibility of one
client's writes to another.

**[CN-PORT-17]** A clock interface MUST distinguish coordinator time from
guest-visible readings. Its descriptor MUST bind source frequency, width,
wrap behavior, epoch where applicable, read/error behavior, transform policy,
and alarm/interrupt semantics. Clock state changes MUST NOT move the
coordinator's committed frontier backward. Modeled drift or skew MUST affect
the clock model through its admitted mapping and events.

**[CN-PORT-18]** An interrupt interface MUST bind line or message identity,
trigger type, assertion/deassertion semantics, priority/routing where exposed,
masking, acknowledgment, and pending-state ownership. An interrupt source MUST
NOT treat transport publication as guest delivery or acknowledgment. A level
transition and repeated delivery of an edge MUST follow their distinct admitted
semantics.

**[CN-PORT-19]** A device that can modify memory, issue DMA, observe a clock,
or generate an interrupt outside its nominal request/response lanes MUST
declare those causal connections. Hidden shared memory, passthrough, polling
callbacks, and native device paths MUST NOT bypass the admitted graph's effect
visibility or state ownership rules.

### Core Interface Families

The following interface families describe portable semantic connections. The
selected payload schema gives exact types and bounds; a family label does not
identify a guest device controller or authorize an operation.

| Interface | Directed lanes and required semantics |
| --- | --- |
| `core.frame/1` | Frame output/input: frame bytes, link metadata, and explicit loss/error policy; no implicit host network attachment. |
| `core.block/1` | Request/completion: read, write, flush, and length query with request ID, byte offset/length, bounded data, result/error, and declared persistence scope. |
| `core.filesystem/1` | Request/reply: selected filesystem operation schema with object/handle identities, data bounds, permissions, ordering, cancellation, and error semantics. |
| `core.clock/1` | Read/result and control/event lanes: source identity, reading, alarm ID/deadline, transform changes, and selected wrap/error behavior. |
| `core.irq/1` | Signal/acknowledgment lanes: source and target identity, line/message ID, assertion or message payload, trigger/routing, and pending-state semantics. |

**[CN-PORT-20]** A core interface realization MUST select an exact payload
schema covering every admitted operation, its validation and error behavior,
and the semantics identified in this table. An operation absent from that
schema MUST be refused without effects. Core version `1` identifies the
semantic family; admission MUST still compare the exact selected schema,
feature set, phases, bounds, and guarantees. A partial family implementation
MUST NOT claim support for operations omitted from its selected profile.

**[CN-PORT-21]** Finite publication coordinates and causal bounds MUST use
checked unsigned 64-bit picosecond quantities. A clock's native units MUST be
converted by its selected mapping before they authorize coordinator progress.
Unknown and unbounded lookahead MUST use distinct tagged meanings; the maximum
integer value MUST NOT double as a sentinel or justify unchecked arithmetic.

## Manifests and Capability Facets

### Provider, Node, and Realization

The manifest hierarchy separates implementation support from configuration
selection and realized ownership. A provider can implement several node roles
and modes. A selected realization binds exactly one accepted combination for
each admitted node.

| Manifest | Immutable content |
| --- | --- |
| `ProviderManifest` | Provider identity, implementation artifacts, protocol support, supported profiles, extensions, and qualification references. |
| `NodeManifest` | Role/profile configuration schema, supported mode combinations, port templates, state formats, and operation facets. |
| `RealizationManifest` | Selected node/profile/configuration, mode facets, exact port descriptors, execution/capture ownership, and negotiated capability identities. |
| `ConnectionDescriptor` | Endpoints/lanes, selected protocols/features, bounds, arbitration, visibility conversion, and proven causal bounds. |
| `GraphAdmissionRecord` | Complete selected realization graph, coordinator contract, scenario requirements, validation result, and execution binding. |

The common node descriptor contains logical identity, roles, ports, immutable
model configuration, and initialization policy. The realized binding adds
implementation/profile identity, selected operating contract, owner roster,
capability and guarantee selection, and live incarnation information, as
defined by the node contract. Provider and node manifests describe supported
combinations; the realized binding describes the selected combination.
Durable compatibility identity and live authority are separate projections:
restoration creates fresh live owners without relabeling durable state.
Reference types and canonical representation are defined in chapter 06.

**[CN-CAP-1]** Every provider manifest MUST bind its installed implementation,
adapter, applied patch set, model definitions, and relevant protocol/state
formats through the identities defined by this RFC. A release label or
executable filename MUST NOT substitute for implementation identity. The
coordinator MUST authenticate the selected installed artifacts before using
their capability claims for admission.

**[CN-CAP-2]** A provider manifest MUST enumerate supported configurations and
mode combinations, including conditional restrictions. A realization MUST
select one allowed combination explicitly. Admission MUST NOT derive a
combination by taking the union of features supported in mutually exclusive
profiles or modes.

**[CN-CAP-3]** Realization MUST freeze the selected implementation, model and
device parameters, boot/input artifacts where relevant, port contracts,
ownership, timing and guarantee facets, and qualification basis before
activation. Those selections MUST be part of the graph's execution binding.
Parameter defaults influencing execution MUST be resolved into that binding
instead of inherited from a mutable installation or host environment.

The following facets are orthogonal. Names here describe semantic axes rather
than interchangeable guarantees.

| Facet | Questions admission answers |
| --- | --- |
| Role | Compute, storage, link, clock, interrupt fabric, external adapter, or registered extension? |
| Timing | Exact ceilings, passive exact events, or quantized admission/publication? |
| Execution repeatability | Qualified deterministic, conditionally repeatable, nondeterministic, or unqualified? |
| Capture scope | Complete future-affecting state, architectural subset, transcript, or unsupported? |
| Continuation | Exact suffix equivalence, qualified restricted continuation, best effort, or unsupported? |
| Replay | Exact replay, conditional transcript replay, observed rerun, or unsupported? |
| Operations | Supported pause, reset, cancellation, fault, introspection, debug, coverage, and device behaviors? |
| Qualification | Which exact implementation/configuration combinations and claims have accepted evidence? |

**[CN-CAP-4]** A capability descriptor MUST state each required facet
independently. Deterministic forward execution MUST NOT imply exact capture,
and successful restoration MUST NOT imply repeatable continuation. Quantized
logical ordering MUST NOT imply exact physical stopping. A complete transcript
MUST NOT be represented as preserved producer state.

**[CN-CAP-5]** A capability requirement MUST identify its semantic operation,
version, permitted phases, parameter limits, guarantee scope, and qualification
requirement. The requirement MUST be evaluated against the selected
realization, not only a provider's broader advertised support. An absent or
unknown requirement result MUST refuse admission when that requirement is
mandatory for the scenario.

**[CN-CAP-6]** A selected capability MUST have a manifest-bound evidence scope
covering the actual implementation, model parameters, mode, devices, and
operations for which it is claimed. The coordinator MUST distinguish
implemented but unqualified support from accepted qualification. It MUST NOT
promote a model-only fixture, a different profile's evidence, or successful
startup into qualification of live execution guarantees.

**[CN-CAP-7]** Capability claims MUST NOT confer native execution, queue,
capture, or receipt authority. Operations requiring such authority MUST also
authenticate the actual live owner, retained operation, generation, and
execution binding according to the node and protocol contracts. A copied
manifest, owner identifier, or scalar deadline MUST NOT satisfy that check.

### Owners and Multiple Consumers

**[CN-CAP-8]** Every mutable state domain MUST identify one authoritative
capture owner. Multiple logical nodes or ports MAY reference one owner, but
admission MUST reject overlapping independent ownership of the same state
domain. The execution binding MUST describe the complete ownership relation
and distinguish logical IDs from live execution/capture owner IDs.

**[CN-CAP-9]** A composite realization MUST identify independently scheduled
nodes and internally advanced components. The coordinator MUST NOT grant
independent execution to an internal component while its parent owns and
advances that component's state. Internal ports MUST remain part of the causal
and capture manifest even when their transport is process-private.

**[CN-CAP-10]** A multi-consumer node MUST declare whether it supports shared
access, broadcast, replicated state, or serialized access. Each admitted client
connection MUST have separate correlation and flow-control identities where
required by the interface. Shared mutable state MUST remain owned once; a
client's checkpoint MUST NOT independently replace the shared node's state.

**[CN-CAP-11]** Independently captured owners MUST declare their cross-owner
dependencies and in-flight transfer state. Admission of exact world capture
MUST establish a capture procedure covering those dependencies without losing
or duplicating effects. If an owner cannot close or preserve its participation
at that cut, exact capture MUST be refused.

### Dynamic Reports

Dynamic reports describe facts about one already selected realization. They
include capacity, live queue inventory, retained requests, endpoint availability,
progress, clock observations, health, and resource leases. They do not extend
supported semantics.

| Dynamic report field | Binding or interpretation |
| --- | --- |
| `realization_ref` | Frozen selected descriptor identity. |
| `owner_instance` | Authenticated live owner incarnation. |
| `generation` | Report generation in the relevant owner/queue scope. |
| `scope` | Node, port, lane, queue, or operation being reported. |
| `completeness` | Complete enumeration, explicitly empty, or unknown. |
| `observations` | Typed bounded facts with their mode/provenance. |
| `validity` | Conditions under which the report remains usable. |

**[CN-CAP-12]** Dynamic reports MUST bind the frozen realization, owner
incarnation, scope, and generation. Their validity MUST be checked before they
authorize execution or publication. A stale report or a report naming a
different owner MUST NOT be accepted because its numeric contents match.

**[CN-CAP-13]** Loss of a selected capability or ownership condition during
execution MUST invalidate affected grants and trigger the specified containment
procedure. The coordinator MUST NOT switch provider, mode, device model,
visibility policy, or replay guarantee as a recovery shortcut. A revised
configuration MUST undergo explicit resolution and admission with a new
binding.

## Whole-Graph Admission

Admission is a staged transaction. Preparation can reserve resources or create
stopped provider instances. Activation permits modeled execution or external
effects. Reversible resource preparation is not permission to publish effects.

| Stage | Required result before proceeding |
| --- | --- |
| Parse | Bounded, strictly decoded scenario and manifest references. |
| Resolve | Fixed implementations, configurations, modes, artifacts, and interfaces. |
| Authenticate | Trusted installed identity and accepted qualification basis. |
| Validate nodes | Every requirement admitted by the selected realization. |
| Validate edges | Complete port compatibility and timing/ownership relations. |
| Validate graph | Causal progress, capture closure, world guarantees, and operational policy. |
| Prepare | Resource reservation and stopped realization with authenticated live owners. |
| Seal | Final realized descriptors and whole-graph execution binding verified. |
| Activate | Coordinator releases only the sealed admitted graph. |

**[CN-CAP-14]** The coordinator MUST complete whole-graph validation and seal
the execution binding before activating any participant. Preparation MUST
prevent guest/device execution and outward effects not authorized as preparation
by an explicit operational contract. Failure at any stage MUST leave no
partially activated world.

**[CN-CAP-15]** Realized descriptors MUST match the selections admitted during
resolution. The coordinator MUST revalidate any parameter or resource condition
that can change between preparation and activation. A provider discovering a
different device, ISA feature, state format, or timing capability MUST report a
mismatch rather than silently constructing a substitute.

**[CN-CAP-16]** Graph validation MUST cover every declared or effective causal
path, including storage completions, interrupts, clock alarms, DMA, external
inputs, shared devices, and composite boundaries. Complete network-link
validation alone MUST NOT authorize progress when another input source lacks
the required bound or inventory.

**[CN-CAP-17]** The coordinator MUST derive effective world guarantees from
the selected participants and interactions. An interacting world containing a
nondeterministic participant MUST retain nondeterministic provenance. Conditional
transcript replay MUST bind the transcript and report its conditional scope;
it MUST NOT relabel the original live producer or world as deterministic.

**[CN-CAP-18]** A scenario requiring exact preservation and continuation MUST
admit only owners whose selected contracts preserve all future-affecting state
at the required world cut. Architectural-only capture, draining to another
boundary, cold-state reconstruction, and observed rerun MUST NOT satisfy that
requirement. The coordinator MUST refuse the scenario rather than weaken its
recorded contract.

**[CN-CAP-19]** Admission of a quantized or physical node MUST require explicit
scenario acceptance of its timing, nondeterminism, capture, and replay limits.
The coordinator MUST NOT derive that acceptance from a requested speed target,
available accelerator, omitted implementation selector, or failure of an exact
provider.

**[CN-CAP-20]** Operational resource and watchdog policies MUST remain
separate from simulated-time authority. Admission MUST verify policy-required
limits and cancellation/containment mechanisms. Exhausting host resources or
host time MUST NOT be reported as a modeled deadline or exact simulated stop
without the corresponding causal evidence.

**[CN-CAP-21]** Capture, replay, restore, and fork requests MUST be checked
against the frozen realization and graph binding. A foreign implementation or
incompatible model/device configuration MUST be refused. A state conversion
MUST be a separately identified operation with source and destination contracts,
new provenance, and a newly admitted binding; it MUST NOT be treated as an
ordinary accepted restore.

## Extensions and Negotiation

**[CN-CAP-22]** Vendor interfaces and capabilities MUST use a collision-resistant
namespace identifying their authority and versioned semantic definition.
Extensions MUST declare payload bounds, phases, ownership, visibility, capture,
and compatibility semantics needed for admission. An extension MUST NOT
override a core contract while retaining the core identity.

**[CN-CAP-23]** Negotiation MUST select explicitly supported versions and
features. Unknown mandatory extensions MUST refuse admission. Unknown optional
annotations MAY be ignored only when the enclosing schema explicitly permits
them and they do not influence execution, state identity, or guarantee claims.
There MUST be no automatic downgrade after activation.

**[CN-CAP-24]** Canonical manifests, references, and selected graph bindings MUST
use the encoding and identity rules of
[Provider Protocol and Security](06-provider-protocol-and-security.md).
Extensions MUST NOT introduce an alternative hash or canonicalization rule for
objects participating in the same execution binding. Namespaced payload codecs
MAY define their own bounded representations when selected by a port schema.

## Refusal and Containment Catalogue

The following categories are semantic errors. Transport failures are separate
and do not imply that a requested effect was refused without execution.

| Error | Meaning |
| --- | --- |
| `unknown_interface` | No admitted semantic definition for a port/capability. |
| `version_mismatch` | No explicitly compatible selected protocol/schema. |
| `feature_mismatch` | Required operation or feature absent from selected realization. |
| `bound_mismatch` | Payload, queue, alignment, or resource bounds cannot be satisfied. |
| `direction_mismatch` | Connected lanes have incompatible directions. |
| `ordering_mismatch` | Ordering, barriers, retries, or arbitration differ. |
| `visibility_mismatch` | Exact/quantized visibility cannot meet scenario requirements. |
| `lookahead_unproven` | Required causal lower bound is absent or invalid. |
| `causal_progress_unavailable` | Graph cannot make safe representable progress. |
| `owner_conflict` | Duplicate, overlapping, or incompatible state/execution ownership. |
| `identity_mismatch` | Actual realization, artifact, or state differs from frozen selection. |
| `qualification_unavailable` | Required live claim lacks accepted evidence. |
| `capture_unsupported` | Required cut or preservation scope cannot be satisfied. |
| `replay_unsupported` | Requested replay authority exceeds selected guarantees. |
| `nondeterminism_unaccepted` | Scenario did not accept the selected weaker contract. |
| `stale_report` | Owner incarnation/generation/validity no longer matches. |
| `capability_lost` | A required condition failed after admission. |
| `operation_uncertain` | Effect or acknowledgment state is unresolved. |

**[CN-CAP-25]** A refusal MUST identify the failing stage, affected node/port
or connection, required contract, observed mismatch, and whether effects are
absent, retained, or uncertain. Errors MUST preserve nondeterministic and
implementation provenance needed to interpret the evidence. An uncertain
operation MUST NOT be retried as a fresh operation or represented as a
side-effect-free incompatibility.

**[CN-CAP-26]** Admission failure MUST release or quarantine prepared resources
according to their actual ownership and effect state. Cleanup failure MUST
retain an operational record and prevent resource reuse that could expose
foreign mutable state. A failed graph MUST NOT be admitted merely because the
failing node can be omitted from an otherwise compatible graph.

## Informative Manifest Excerpt

This semantic excerpt illustrates two directed lanes on an exact storage port
realization. It is not a complete provider message or a substitute for the
CNP/1 schema: identity references, manifests, proof references, and framing are
omitted. The tick values are small examples of shared picosecond coordinates.

```json
{
  "id": "storage-a",
  "roles": ["storage"],
  "operating_contract": { "timing": "exact" },
  "execution_owner": "storage-owner-a",
  "capture_owner": "storage-owner-a",
  "ports": [
    {
      "port_id": "client-a",
      "interface_id": "core.block/1",
      "lanes": [
        {
          "lane_id": "request",
          "direction": "input",
          "semantic_version": "1.0.0",
          "payload_bounds": { "maximum_message_bytes": "65536" },
          "queue_bounds": { "maximum_messages": "32" },
          "flow_control": "credit",
          "ordering": "per-client-fifo",
          "visibility": "exact"
        },
        {
          "lane_id": "completion",
          "direction": "output",
          "semantic_version": "1.0.0",
          "payload_bounds": { "maximum_message_bytes": "65536" },
          "queue_bounds": { "maximum_messages": "32" },
          "flow_control": "credit",
          "ordering": "correlated-completion",
          "visibility": "exact",
          "minimum_lookahead": "1000"
        }
      ]
    }
  ]
}
```

The bound of 1,000 ps in this example is admissible only if all completion
paths, including errors and cancellation, satisfy it. A zero-delay error path
would invalidate that advertised bound. A second client requires its own
connection and correlation scope plus a declared shared-storage arbitration
policy; it does not create another capture owner.
