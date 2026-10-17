# CNP/1 core object schemas

This reference is normative for RFC-0025 Chapter 06. It fixes the portable
representations of common objects; selected model, payload, and state schemas
remain separately versioned content. A conforming vendor can implement these
tables without using Crucible's Rust types. Semantic requirements in Chapters
01–05 still apply; a well-formed object does not establish truthful guarantees.

## R.1 Schema conventions

All object fields listed below are required unless marked optional. Objects
listing `extensions` require that object, empty for the baseline. Compact value
objects `Position`, `Endpoint`, `OwnerRef`, `Bound`, `HashRef`, and `ContentRef`
have exactly their listed fields and no extension field. Unknown fields outside
an explicitly listed extension object are refused. `Id`, `U64`, `I64`, `Tick`, `HashRef`, `ContentRef`,
and `IdSet` are defined in Chapter 06. Nullable fields are explicitly present
as null. Arrays representing sets are sorted by the specified ASCII ID or hash
key; arrays representing ordered events retain their semantic order. Limits
are enforced before model allocation. No core schema accepts floating-point
time, implicit host references, or unbounded numeric values.

Every array is bounded to at most 65536 elements and also by negotiated frame
and memory limits; a profile can require a smaller positive maximum. Sets reject
duplicates before native allocation. Event arrays additionally obey per-port
pending-event and payload-byte limits. A limit is a maximum, not an allocation
request or permission to exceed an admitted resource ceiling.

A `SchemaRef` has `id: Id`, `version: Version`, `definition: ContentRef`, and
`extensions`. Version is positive. `definition` contains a complete JSON Schema
2020-12 object with its required fields, closed property rules, and bounded
types, plus any separately bound semantic specification. Format assertions are
required, not optional annotations. Referenced schema content MUST already be
available and verified before its first use. No network resolution of `$ref`
is permitted; every external reference resolves through admitted content refs.
Providers advertising a schema MUST be able to transfer its exact content.

Core object version is `1`; a field `schema_version: Version` appears in each
manifest, descriptor, binding projection, receipt, inventory, and batch below.
The object tables define closed schemas directly. Their definitions are not
replaced by a vendor's schema with the same public name.

## R.2 Positions, endpoints, and ordering

| Object | Fields | Constraints |
| --- | --- | --- |
| `Position` | `time_ps: Tick`, `microstep: U64`, `phase: Version` | Phase 0=`BoundaryControl`, 1=`Publication`, 2=`Delivery`, 3=`Reaction`; no other baseline phase |
| `Endpoint` | `node_id: Id`, `port_id: Id`, `lane_id: Id` | All belong to admitted graph; ports never use host addresses |
| `OwnerRef` | `id: Id`, `participant_ids: IdSet`, `state_domain_ids: IdSet` | Exact declared public-node and mutable-domain coverage |
| `Bound` | `kind: string`, `position: Position or null`, `evidence: ContentRef or null` | Kinds `at`, `after`, `none_until_activation`, `unknown` |

`at` permits a not-yet-published event at exactly its position; `after` excludes
equality. Both require position and qualified evidence. `none_until_activation`
requires evidence of inactive production until a declared activation and a null
position. `unknown` has null position and no usable positive lookahead.
An empty queue is not an `after` or `none_until_activation` proof.

The `superdense-v1` global event key is
`(time_ps, microstep, phase, consumer_node_id, producer_node_id, source_sequence)`.
Endpoint IDs compare by ASCII octets; integer components compare numerically.
The phase/microstep evolution and causal closure are those of Chapter 03.
Per-provider native internal event order is preserved in its state; it is not
replaced by sorting internal events on this public key.

## R.3 Descriptor and port schemas

| `NodeDescriptor` field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | `Version` | `1` |
| `id` | `Id` | Semantic node identity |
| `roles` | `IdSet` | Role labels, e.g. `compute`, `block`, `filesystem`, `network-link`, `clock`, `external-adapter` |
| `model_ref` | `ContentRef` | Immutable selected model definition |
| `configuration_ref` | `ContentRef` | Complete resolved semantic parameters |
| `initialization_ref` | `ContentRef` | Initialization inputs/policy and provenance |
| `ports` | array of `PortDescriptor` | Sorted by port ID; no duplicate ID |
| `extensions` | object | Identity-bearing descriptor extensions |

The descriptor does not include live process handles or authority. Its hash is
`JsonHash(cnp.node-descriptor.v1, descriptor)` over every field above.

| `PortDescriptor` field | Type | Meaning |
| --- | --- | --- |
| `id` | `Id` | Node-local stable port ID |
| `lanes` | array of `LaneDescriptor` | Sorted by lane ID |
| `interface_id` | `Id` | Exact semantic family/version, e.g. `core.block/1` |
| `features` | `IdSet` | Selected features, not union of possible profiles |
| `configuration_ref` | `ContentRef` | Ordering, bounds, flow control, failure and state semantics |
| `extensions` | object | Identity-bearing extensions |

`LaneDescriptor` has `id: Id`, `direction: string` (`input` or `output`),
`payload_schema: SchemaRef`, `maximum_payload_bytes: U64`,
`maximum_pending_events: U64`, and `extensions`. Bidirectional interactions use
separate lanes. Family support does not substitute for a complete selected
payload schema. Port configuration contains ordering/durability/clock/IRQ
semantics required by Chapter 02; omission fails graph admission.

`ConnectionDescriptor` has `schema_version`, `id: Id`, `producer: Endpoint`,
`consumer: Endpoint`, `interface_id: Id`, `features: IdSet`,
`payload_schema: SchemaRef`, `minimum_latency_ps: U64`,
`policy_ref: ContentRef`, `capture_owner_id: Id`, and `extensions`.
`policy_ref` binds arbitration, visibility conversion, fault/latency effects,
flow control, and required causal bounds. A zero latency is literal zero and
requires the admitted same-time closure procedure.

## R.4 Capabilities and operating contract

`OperatingContract` has `schema_version`, `mode: string` (`exact` or
`quantized`), `scheduling_role: string` (`active`, `event_driven`, or
`autonomous`), `ordering_profile: string` (`superdense-v1`),
`policy_ref: ContentRef`, `resolution_ps: U64 or null`,
`phase_ps: U64 or null`, `facets: array<FacetSelection>`, and `extensions`.

Exact regular-grid profiles supply positive resolution and a phase smaller
than resolution. Nonuniform exact boundaries use null resolution/phase and a
bound qualified predecessor/successor policy. Quantized mode supplies its full
policy, including quantum, phase, input cut, actual hardware budget/overshoot,
publication, ongoing-device-activity, and deadline behavior; a picosecond scalar
alone is insufficient. Resolution refers to admitted representable boundaries,
not the precision of a clock register.

`FacetSelection` has `id: Id`, `version: Version`, `configuration_ref: ContentRef`,
`guarantees_ref: ContentRef`, and `extensions`. Facets are sorted by ID/version
and enumerate supported operations and their exact evidence schemas. The
baseline optional facets are `exact_execution`, `quantized_execution`,
`boundary_settlement`, `preservation`, `replay`, `fault`, `observation`,
`debug`, and role-specific facets. Selection never implies a facet not present.

`GuaranteeProfile` has `schema_version`, `repeatability: string`
(`qualified`, `nondeterministic`, `unqualified`), `capture_scope: string`
(`complete_model`, `architectural`, `none`), `continuation: string`
(`exact`, `best_effort`, `unsupported`), `durable_restart: bool`,
`isolated_fork: bool`, `conditional_replay: bool`,
`limitations_ref: ContentRef`, and `extensions`. A true capability requires
bound evidence; these axes are independent. `limitations_ref` describes actual
physical/scope constraints, including future exogenous input.

`CapabilityProfile` has `schema_version`, `facets: array<FacetSelection>`,
`devices_ref: ContentRef`, `requirements_ref: ContentRef`, and `extensions`.
The devices schema enumerates realized controller/transport/features/queues,
DMA/IRQ/reset/capture support, not merely display names. Requirements encode
host/model restrictions and allowed mode combinations. Unknown requirements
cannot be satisfied by assuming they are optional.

## R.5 Implementation and binding identity

`ImplementationIdentity` has `schema_version`, `implementation_id: Id`,
`artifacts: array<ArtifactIdentity>`, `model_definitions: array<ContentRef>`,
`formats: array<SchemaRef>`, and `extensions`.
`ArtifactIdentity` has `id: Id`, `role: Id`, `content: ContentRef`, and
`extensions`. Artifacts are sorted by ID and identify executable, adapter,
patch-set, firmware/model inputs as applicable. A version string or pathname
is not an implementation identity. Format refs are sorted by ID/version;
content sets sort by `(domain,digest)`.

`NodeBinding` has two fields, `compatibility: BindingCompatibility` and
`authority: LiveAuthority`, plus `extensions`. The extensions on this wrapper
are operational, negotiated, and excluded from durable compatibility; durable
extensions belong inside `compatibility`. The node binding hash is
`JsonHash(cnp.node-binding.v1, compatibility)`.

| `BindingCompatibility` field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | `Version` | `1` |
| `node_id` | `Id` | Descriptor's semantic ID |
| `descriptor_hash` | `HashRef` | Complete immutable descriptor |
| `implementation` | `ImplementationIdentity` | Selected implementation including accelerator/mode-sensitive artifacts |
| `profile_ref` | `ContentRef` | Complete selected machine/device/model profile |
| `configuration_ref` | `ContentRef` | All resolved parameters/defaults |
| `operating_contract` | `OperatingContract` | Selected timing/mode/facets |
| `execution_owner` | `OwnerRef` | Owner membership and domains |
| `capture_owner` | `OwnerRef` | Single authoritative capture membership/domains |
| `capabilities_ref` | `ContentRef` | `CapabilityProfile` |
| `guarantees_ref` | `ContentRef` | `GuaranteeProfile` |
| `qualification_refs` | array of `ContentRef` | Exact implementation/profile qualification basis |
| `extensions` | object | Durable identity-bearing extension parameters |

`LiveAuthority` has `schema_version`, `session_id`, `incarnation_id`,
`realization_id`, `activation_id: Id or null`, `world_generation: U64`,
`owner_generation: U64`, `input_epoch: Id`, `host_receipt: ContentRef`, and
`extensions`. IDs except nullable activation are `Id`. Generation is positive
for live owners; initial uncommitted world generation is `"0"`. Live authority
is authenticated by the host admission record. It cannot be supplied by an
unauthenticated vendor to mint custody. Fresh restore preserves compatibility
but creates new authority and explicitly rebinds input custody.

`OwnerBinding` has `schema_version`, `owner: OwnerRef`, `owner_roles: IdSet`
(`execution`, `capture`, or both), `node_bindings: array<NodeBindingRef>`,
`ownership_ref: ContentRef`, and `extensions`. Its identity is
`JsonHash(cnp.owner-binding.v1, owner_binding)`. Node bindings sort by node ID;
every owner participant appears exactly once, with no undeclared member or
missing authoritative domain. Ownership binds indivisible execution/capture
constraints. Owner-scoped requests use this hash rather than selecting one
child view's binding hash.

`WorldBinding` has `schema_version`, `scenario_ref: ContentRef`,
`node_bindings: array<NodeBindingRef>`, `connections: array<ConnectionDescriptor>`,
`ownership_ref: ContentRef`, `coordinator_contract_ref: ContentRef`,
`ordering_profile: string`, `initialization_ref: ContentRef`, and `extensions`.
`NodeBindingRef` has `node_id: Id`, `binding_hash: HashRef`, and `extensions`.
The world binding hash covers every field of `WorldBinding`. Arrays sort by
node ID or connection ID; it never contains live incarnation IDs or receipts.
`ownership_ref` enumerates unique state domains, their owners, dependencies,
and internal/external component views. The coordinator contract binds its
timing, state, arbitration, and compatibility schema.

## R.6 Provider manifests and realized output

`ProviderManifest` has `schema_version`, `provider_id: Id`,
`implementation: ImplementationIdentity`, `protocol_versions: IdSet`,
`supported_profiles: array<NodeManifest>`, `extensions_supported: IdSet`,
`qualification_refs: array<ContentRef>`, and `extensions`.

`NodeManifest` has `schema_version`, `profile_id: Id`, `roles: IdSet`,
`configuration_schema: SchemaRef`, `allowed_combinations_ref: ContentRef`,
`port_templates_ref: ContentRef`, `state_formats: array<SchemaRef>`,
`operation_facets: array<FacetSelection>`, and `extensions`. Allowed combinations
fully enumerate or constrain which mode/device/facet selections can coexist.
All references are verified portable content, not out-of-band tribal knowledge.

`RealizationManifest` has `schema_version`, `realization_id: Id`,
`provider_manifest: ContentRef`, `descriptors: array<NodeDescriptor>`,
`bindings: array<NodeBinding>`, `owners: array<OwnerRef>`,
`owner_bindings: array<OwnerBinding>`, and `extensions`.
Descriptors/bindings sort by node ID. Owners and owner bindings sort by owner
ID. Owners include both
execution and capture owners with their declared domains. Separate owner roles
can use the same ID only when the ownership schema establishes the same owner.
Every requested node appears exactly once; a realized extra node must be
declared and admitted rather than silently omitted from the graph.

`ResourceLimits` has `cpu_budget_ns`, `memory_bytes`, `writable_bytes`,
`processes`, `descriptors`, `pending_events`, `content_bytes`, and
`maximum_operations`, all `U64`, plus `extensions`. Zero means no allowance,
not unlimited; any unlimited policy requires a separate host-admitted facet.
The provider can refuse insufficient limits; it cannot weaken installed limits.

## R.7 Events, input custody, and observations

`Event` has `schema_version`, `id: Id`, `source: Endpoint`,
`destination: Endpoint`, `position: Position`, `stage: string`
(`publication` or `delivery`), `publication_position: Position`,
`delivery_position: Position or null`, `source_sequence: U64`,
`causal_parent_ids: IdSet`, `payload: ContentRef`,
`provenance_ref: ContentRef`, and `extensions`. Event IDs are scoped to the
admitted logical producer node, not a host socket. Public source sequence is
monotonically unique across all ports, lanes, connections, and recipient fanout
copies of that node. Its counter is captured; native FIFO/request sequences
remain separate provenance. Fanout copies use distinct public sequences with
shared causal lineage. The selected connection schema
defines payload and conversion policy. Causal parents bind same-time reactions;
root events have an empty set under the Chapter 03 root-input policy. For a
publication-stage event, publication position equals `position`; delivery
position may remain null until the admitted
connection computes it. Delivery requires nonnull delivery position equal to
`position` and retains the original publication position. A link emitting a new
event uses its own ID and causal parent rather than overwriting the original
producer's publication time. Provisional publication is not delivered input.

`InputBatch` has `schema_version`, `execution_owner_id: Id`,
`input_epoch: Id`, `batch_id: Id`, `batch_sequence: U64`,
`events: array<Event>`, and `extensions`. Events use admitted order;
`batch_hash` is external and hashes the complete batch in
`cnp.input-batch.v1`. The input request reconstructs this object from envelope
owner and body fields. It cannot change an event's timestamp to match the
consumer's preferred boundary.

`InputAuthorization` has `schema_version`, `execution_owner_id: Id`,
`owner_generation: U64`, `input_epoch: Id`, `input_watermark: U64`,
`closed_input_prefix: Position`, `closure_kind: string` (`before` or `through`),
`arbitration_ref: ContentRef`, `bound_evidence_refs: array<ContentRef>`, and
`extensions`. Complete due input and upstream evidence justify the prefix;
the integer watermark alone does not prove that no earlier input can arrive.

`ObservationBatch` has `schema_version`, `execution_owner_id: Id`,
`owner_binding_hash: HashRef`, `world_binding_hash: HashRef`,
`activation_id: Id`, `world_generation: U64`,
`owner_generation: U64`, `operation_id: Id`, `grant_id: Id or null`,
`first_sequence: U64`, `last_sequence: U64`, `events: array<Event>`,
`visibility: string` (`staged` or `committed`),
`measurement_ref: ContentRef`, and `extensions`. An empty batch has both
sequence fields `"0"`. Nonempty batches contain every producer observation
in that contiguous range, including explicit loss/failure reports where the
admitted physical contract can lose observations. Staged visibility does not
authorize peer delivery. Measurement records distinguish logical publication
coordinates from physical measurement/uncertainty.

`PendingInventory` has `schema_version`, `execution_owner_id: Id`,
`owner_binding_hash: HashRef`, `world_binding_hash: HashRef`,
`activation_id: Id or null`, `world_generation: U64`,
`operation_id: Id or null`, `grant_id: Id or null`,
`owner_generation: U64`, `revision: U64`, `complete: bool`,
`input_watermark: U64`, `input_epoch: Id`,
`entries: array<PendingEntry>`, and `extensions`.
`PendingEntry` has `id: Id`, `kind: string` (`input`, `output`, `timer`, `io`,
`native_operation`), `owner_id: Id`, `deadline: Bound`,
`state_ref: ContentRef`, and `extensions`. Entries sort by ID. The state ref
uses the selected facet's schema for actual custody, partial publication,
device state, and native receipt. Incomplete inventory cannot prove absence.

## R.8 Stop, closure, and activation receipts

`StopReceipt` has `schema_version`, `session_id: Id`, `incarnation_id: Id`,
`owner_binding_hash: HashRef`, `world_binding_hash: HashRef`,
`activation_id: Id`, `world_generation: U64`, `execution_owner_id: Id`,
`owner_generation: U64`, `operation_id: Id`, `grant_id: Id or null`,
`participant_ids: IdSet`, `mode: string`, `ordering_profile: string`,
`reached: Position or null`, `production_prefix: Position`,
`prefix_kind: string` (`before` or `through`),
`output_lower_bounds: array<PortBound>`,
`physical_stop: string` (`paused`, `input_blocked`, `observation_closed`,
`failed_contained`), `cause: Id`, `input_custody: ContentRef`,
`pending_inventory: ContentRef`, `observation_batch: ContentRef`,
`physical_measurement_ref: ContentRef`, `evidence_refs: array<ContentRef>`, and
`extensions`. Null reached position is legal only for autonomous observation
contracts. An observation window closed while hardware continues cannot claim
`paused`. Prefix closure respects same-time microsteps and phases.

`PortBound` has `endpoint: Endpoint`, `bound: Bound`, and `extensions`.
The array sorts by `(node_id,port_id,lane_id)` and contains every admitted output
lane exactly once, including explicit unknown bounds. No bound inferred for
one port can authorize a different port. Per-port receipts retain their actual
qualified proof scope and generation.

The exact-run terminal result's `reached` and receipt MUST agree. An exact stop
at its limit is permitted only as a pure administrative park; no transition at
or beyond the exclusive limit is executed. Atomic native work straddling the
limit requires a preservable split or refusal before effects. A pending
input-blocked park cannot claim semantic closure through its unresolved input.

`ActivationManifest` has `schema_version`, `transaction_id: Id`,
`activation_id: Id`, `world_generation: U64`, `gate_id: Id`,
`world_binding_hash: HashRef`, `owners: array<PreparedOwner>`,
`coordinator_state_ref: ContentRef`, and `extensions`.
`PreparedOwner` has `owner_id: Id`, `incarnation_id: Id`,
`owner_generation: U64`, `prepared_token: Id`, `binding_hashes: array<HashRef>`,
`ready_receipt: ContentRef`, and `extensions`. Owner records sort by owner ID.
All hashes sort by `(domain,digest)` and must resolve to admitted node bindings.
Global generation commit is a host transaction; provider readiness does not
grant execution or promise simultaneous physical starts.

`ControlReceipt` has `schema_version`, `kind: string` (`input_custody`,
`closed_gate`, `activation_ready`, `unchanged_cut`, `cleanup`, `admission`),
`session_id: Id`, `incarnation_id: Id`, `request_id: Id`,
`operation_id: Id or null`, `owner_ids: IdSet`, `world_generation: U64`,
`record_ref: ContentRef`, `issuer: string` (`provider` or `host`), and
`extensions`. The record's selected schema contains the complete facts for the
kind. Provider-issued claims are distinct from host-authenticated receipts;
neither substitutes for profile qualification.

Every independent observation, inventory, and stop blob binds its complete
owner/world compatibility hashes, live generation and applicable operation.
Null operation ID is permitted only for an explicitly unscoped stopped
inventory. Null grant ID is permitted for an admitted operation not originating
from an execution grant, such as pause or shutdown, and for that unscoped
inventory. Grant-originated records retain the original grant ID. Consumers
validate these fields against actual admitted custody.
Historical receipt bytes preserved in a capture remain evidence of the old
incarnation; fresh restore creates authenticated new live authority rather than
using those bytes as permission to execute.

Baseline `record_ref` content is a closed object with `schema_version: 1`,
`extensions`, and the following fields. `evidence_refs` is an array of bounded
native-proof content references using the selected facet's schema; copying
common fields cannot manufacture those native proofs.

| Receipt kind | Required record fields |
| --- | --- |
| `input_custody` | `execution_owner_id: Id`, `owner_generation: U64`, `input_epoch: Id`, `input_watermark: U64`, `batch_hashes: array<HashRef>`, `pending_inventory: ContentRef`, `evidence_refs` |
| `closed_gate` | `gate_id: Id`, `prepared_token: Id`, `owner_ids: IdSet`, `gate_closed: true`, `physical_status_ref: ContentRef`, `evidence_refs` |
| `activation_ready` | `activation_id: Id`, `world_generation: U64`, `gate_id: Id`, `prepared_token: Id`, `world_binding_hash: HashRef`, `owner_ids: IdSet`, `gate_closed: true`, `evidence_refs` |
| `unchanged_cut` | `cut: Position`, `event_ordinal: U64`, `before_state_digest: HashRef`, `after_state_digest: HashRef`, `before_progress_ref: ContentRef`, `after_progress_ref: ContentRef`, `owner_ids: IdSet`, `evidence_refs` |
| `cleanup` | `owner_ids: IdSet`, `resource_inventory_ref: ContentRef`, `disposition: string` (`released`, `quarantined`, `retained`), `supervisor_receipt: ContentRef or null`, `evidence_refs` |
| `admission` | `realization_id: Id`, `binding_hashes: array<HashRef>`, `world_binding_hash: HashRef`, `measured_artifacts: array<ArtifactIdentity>`, `qualification_refs: array<ContentRef>`, `resource_limits: ResourceLimits`, `evidence_refs` |

Progress refs carry complete facet progress/retirement/native-event counters;
equal architectural digests alone do not prove no hidden mutation. Cleanup
inventory enumerates every owned process, mapping, mutable file, descriptor,
and external-device authority with its terminal state and custody. Released
requires proven native termination; quarantined requires authenticated nonnull
supervisor custody. Supplemental evidence is qualified for the exact profile.

## R.9 Capture manifests

`CaptureManifest` has `schema_version`, `capture_id: Id`,
`world_binding_hash: HashRef`, `scenario_ref: ContentRef`,
`preservation_contract: Id`, `cut: Position`, `event_ordinal: U64`,
`ordering_profile: string`, `guarantees_ref: ContentRef`,
`coordinator_state_ref: ContentRef`, `owners: array<CapturedOwner>`,
`immutable_refs: array<ContentRef>`, `provenance_ref: ContentRef`, and
`extensions`. A complete world capture includes every authoritative domain;
an owner-local capture cannot certify the graph-wide manifest by itself.

`CapturedOwner` has `capture_owner_id: Id`, `participant_ids: IdSet`,
`state_domain_ids: IdSet`, `binding_hashes: array<HashRef>`,
`state_schema: SchemaRef`, `representation: string`
(`durable` or `retained_source`), `state_ref: ContentRef or null`,
`retained_source_ref: ContentRef or null`, `dependencies: IdSet`,
`capture_receipt: ContentRef`, and `extensions`.
Exactly one state representation is nonnull. Retained-source content identifies
an authenticated live lease/owner, its scope and expiry; it is not an implicit
process pointer or durable artifact. Durable-restart mode refuses that
representation. Capture receipts bind unchanged cut and complete domain
coverage, including pending input streams and native event order.

World state compatibility uses immutable binding identities. Capture manifests
do not authorize reuse of saved live incarnation tokens. Fresh restore validates
all compatibility content before staging new live authorities, authenticates
their custody, and produces a new activation manifest.

## R.10 Validation and extensibility

**[CN-IPC-39]** Every core object MUST satisfy its closed schema, canonical
identity rule, range limits, sorted-set rule, and referenced-content validation
before it can authorize progress, visibility, or state activation. Providers
MUST NOT treat a syntactically valid content reference as evidence that the
referenced object exists or has its declared semantics.

**[CN-IPC-40]** A selected facet's schema MUST define its operation argument,
result, error, and evidence records completely. Unknown required schemas,
missing bound schema content, unsupported operations, and unknown mandatory
constraints MUST fail admission. A family or facet label alone is insufficient
vendor interoperability.

These tables define the baseline portable core, not all possible device
protocols or native model-state formats. A vendor extending those formats
publishes complete versioned schemas and semantic specifications through the
manifest mechanism. It cannot change the meaning of a baseline field or erase
a baseline guarantee by choosing a schema with looser validation.
