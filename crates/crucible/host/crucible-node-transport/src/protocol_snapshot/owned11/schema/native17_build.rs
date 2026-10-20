//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(ArtifactIdentity {
    id: Id,
    role: Id,
    content: ContentRef,
    extensions: Extensions,
});

native17_struct!(BindingCompatibility {
    schema_version: Version,
    node_id: Id,
    descriptor_hash: HashRef,
    implementation: ImplementationIdentity,
    profile_ref: ContentRef,
    configuration_ref: ContentRef,
    operating_contract: OperatingContract,
    execution_owner: OwnerRef,
    capture_owner: OwnerRef,
    capabilities_ref: ContentRef,
    guarantees_ref: ContentRef,
    qualification_refs: Vec<ContentRef>,
    extensions: Extensions,
});

native17_struct!(ContentRef {
    hash: HashRef,
    length: U64,
    media_type: String,
});

native17_struct!(ExtensionSelection {
    declaration: ContentRef,
    identifier: Id,
    semantic_version: SemanticVersion,
    schema_digest: HashRef,
});

native17_struct!(FacetSelection {
    id: Id,
    version: Version,
    configuration_ref: ContentRef,
    guarantees_ref: ContentRef,
    extensions: Extensions,
});

native17_struct!(HashRef {
    algorithm: String,
    domain: String,
    digest: String,
});

native17_struct!(ImplementationIdentity {
    schema_version: Version,
    implementation_id: Id,
    artifacts: Vec<ArtifactIdentity>,
    model_definitions: Vec<ContentRef>,
    formats: Vec<SchemaRef>,
    extensions: Extensions,
});

native17_struct!(LaneDescriptor {
    id: Id,
    direction: Direction,
    payload_schema: SchemaRef,
    maximum_payload_bytes: U64,
    maximum_pending_events: U64,
    extensions: Extensions,
});

native17_struct!(LiveAuthority {
    schema_version: Version,
    session_id: Id,
    incarnation_id: Id,
    realization_id: Id,
    activation_id: Option<Id>,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: Id,
    host_receipt: ContentRef,
    extensions: Extensions,
});

native17_struct!(NodeBinding {
    compatibility: BindingCompatibility,
    authority: LiveAuthority,
    extensions: Extensions,
});

native17_struct!(NodeBindingRef {
    node_id: Id,
    binding_hash: HashRef,
    extensions: Extensions,
});

native17_struct!(NodeDescriptor {
    schema_version: Version,
    id: Id,
    roles: IdSet,
    model_ref: ContentRef,
    configuration_ref: ContentRef,
    initialization_ref: ContentRef,
    ports: Vec<PortDescriptor>,
    extensions: Extensions,
});

native17_struct!(NodeManifest {
    schema_version: Version,
    profile_id: Id,
    roles: IdSet,
    configuration_schema: SchemaRef,
    allowed_combinations_ref: ContentRef,
    port_templates_ref: ContentRef,
    state_formats: Vec<SchemaRef>,
    operation_facets: Vec<FacetSelection>,
    extensions: Extensions,
});

native17_struct!(OperatingContract {
    schema_version: Version,
    mode: OperatingMode,
    scheduling_role: SchedulingRole,
    ordering_profile: String,
    policy_ref: ContentRef,
    resolution_ps: Option<U64>,
    phase_ps: Option<U64>,
    facets: Vec<FacetSelection>,
    extensions: Extensions,
});

native17_struct!(OwnerBinding {
    schema_version: Version,
    owner: OwnerRef,
    owner_roles: IdSet,
    node_bindings: Vec<NodeBindingRef>,
    ownership_ref: ContentRef,
    extensions: Extensions,
});

native17_struct!(OwnerRef {
    id: Id,
    participant_ids: IdSet,
    state_domain_ids: IdSet,
});

native17_struct!(PacketConnectedHostSelection {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    owner: OwnerBinding,
    prepared_token: Id,
    initial_node: Value,
});

native17_struct!(PacketControlSelection {
    provider: ProviderManifest,
    realization: RealizationManifest,
    realize: RealizeRequest,
    prepared_token: Id,
    admission: Id,
    transaction: Id,
    gate: Id,
    world: HashRef,
    admission_receipt: ContentRef,
});

native17_struct!(PacketNative5CoordinatorInstallation {
    schema: String,
    participants: Vec<PacketControlSelection>,
    host: PacketConnectedHostSelection,
    template: Value,
});

native17_struct!(PortDescriptor {
    id: Id,
    lanes: Vec<LaneDescriptor>,
    interface_id: Id,
    features: IdSet,
    configuration_ref: ContentRef,
    extensions: Extensions,
});

native17_struct!(ProviderManifest {
    schema_version: Version,
    provider_id: Id,
    implementation: ImplementationIdentity,
    protocol_versions: IdSet,
    supported_profiles: Vec<NodeManifest>,
    extensions_supported: IdSet,
    qualification_refs: Vec<ContentRef>,
    extensions: Extensions,
});

native17_struct!(RealizationManifest {
    schema_version: Version,
    realization_id: Id,
    provider_manifest: ContentRef,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerRef>,
    owner_bindings: Vec<OwnerBinding>,
    extensions: Extensions,
});

native17_struct!(RealizeRequest {
    realization_id: Id,
    configuration: ContentRef,
    requested_node_ids: IdSet,
    resource_limits: ResourceLimits,
    extensions: Extensions,
});

native17_struct!(ResourceLimits {
    cpu_budget_ns: U64,
    memory_bytes: U64,
    writable_bytes: U64,
    processes: U64,
    descriptors: U64,
    pending_events: U64,
    content_bytes: U64,
    maximum_operations: U64,
    extensions: Extensions,
});

native17_struct!(SchemaRef {
    id: Id,
    version: Version,
    definition: ContentRef,
    extensions: Extensions,
});

native17_struct!(SemanticVersion {
    major: U64,
    minor: U64,
    patch: U64,
    prerelease: Option<String>,
    build: Option<String>,
});

native17_struct!(crate::client::ClientOriginal {
    request: crate::envelope::Envelope,
    identity: HashRef,
    response: Option<crate::envelope::Envelope>,
});

native17_struct!(crate::handshake::Limits {
    frame_bytes: U64,
    nesting: U64,
    requests: U64,
    journal_entries: U64,
    blob_chunk_bytes: U64,
});

use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use serde_json::Map;

fn check_envelope_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    super::super::envelope::ValidatedHistoricalEnvelope::validate(
        input,
        ledger.rows.clone(),
        ledger.limits,
    )
    .map(|_| ())
}

native17_struct!(@guard check_envelope_data; Envelope {
    protocol: String,
    message: MessageKind,
    session_id: Nullable<Id>,
    incarnation_id: Nullable<Id>,
    node_id: Nullable<Id>,
    execution_owner_id: Nullable<Id>,
    capture_owner_id: Nullable<Id>,
    request_id: Nullable<Id>,
    operation_id: Nullable<Id>,
    sequence: U64,
    method: Method,
    body: Map<String, Value>,
    extensions: Extensions,
});
