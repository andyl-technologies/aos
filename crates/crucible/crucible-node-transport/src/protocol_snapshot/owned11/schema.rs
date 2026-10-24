//! Reconstructs the actual typed declaration, binding and coordinator fields.
//!
//! Every fixed struct uses its source serde field order and the same exhaustive
//! capacity traversal. Portable LiveAuthority/NodeBinding data never creates a
//! ConnectionAuthority, measured source token or fresh native registration.

use super::typed::{HistoricalType, Ledger, historical_struct, invalid, plain_string};
use crate::ProviderError;
use crate::bodies::RealizeRequest;
use crate::reference_packet::{
    control::PacketControlSelection,
    coordinator::{PacketConnectedHostSelection, PacketNative5CoordinatorInstallation},
};
use crucible_node_format::*;
use serde_json::Value;

historical_struct!(ArtifactIdentity {
    id: Id,
    role: Id,
    content: ContentRef,
    extensions: Extensions,
});

historical_struct!(BindingCompatibility {
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

historical_struct!(ContentRef {
    hash: HashRef,
    length: U64,
    media_type: String,
});

historical_struct!(ExtensionSelection {
    declaration: ContentRef,
    identifier: Id,
    semantic_version: SemanticVersion,
    schema_digest: HashRef,
});

historical_struct!(FacetSelection {
    id: Id,
    version: Version,
    configuration_ref: ContentRef,
    guarantees_ref: ContentRef,
    extensions: Extensions,
});

historical_struct!(HashRef {
    algorithm: String,
    domain: String,
    digest: String,
});

historical_struct!(ImplementationIdentity {
    schema_version: Version,
    implementation_id: Id,
    artifacts: Vec<ArtifactIdentity>,
    model_definitions: Vec<ContentRef>,
    formats: Vec<SchemaRef>,
    extensions: Extensions,
});

historical_struct!(LaneDescriptor {
    id: Id,
    direction: Direction,
    payload_schema: SchemaRef,
    maximum_payload_bytes: U64,
    maximum_pending_events: U64,
    extensions: Extensions,
});

historical_struct!(LiveAuthority {
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

historical_struct!(NodeBinding {
    compatibility: BindingCompatibility,
    authority: LiveAuthority,
    extensions: Extensions,
});

historical_struct!(NodeBindingRef {
    node_id: Id,
    binding_hash: HashRef,
    extensions: Extensions,
});

historical_struct!(NodeDescriptor {
    schema_version: Version,
    id: Id,
    roles: IdSet,
    model_ref: ContentRef,
    configuration_ref: ContentRef,
    initialization_ref: ContentRef,
    ports: Vec<PortDescriptor>,
    extensions: Extensions,
});

historical_struct!(NodeManifest {
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

historical_struct!(OperatingContract {
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

historical_struct!(OwnerBinding {
    schema_version: Version,
    owner: OwnerRef,
    owner_roles: IdSet,
    node_bindings: Vec<NodeBindingRef>,
    ownership_ref: ContentRef,
    extensions: Extensions,
});

historical_struct!(OwnerRef {
    id: Id,
    participant_ids: IdSet,
    state_domain_ids: IdSet,
});

historical_struct!(PacketConnectedHostSelection {
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    owner: OwnerBinding,
    prepared_token: Id,
    initial_node: Value,
});

historical_struct!(PacketControlSelection {
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

historical_struct!(PacketNative5CoordinatorInstallation {
    schema: String,
    participants: Vec<PacketControlSelection>,
    host: PacketConnectedHostSelection,
    template: Value,
});

historical_struct!(PortDescriptor {
    id: Id,
    lanes: Vec<LaneDescriptor>,
    interface_id: Id,
    features: IdSet,
    configuration_ref: ContentRef,
    extensions: Extensions,
});

historical_struct!(ProviderManifest {
    schema_version: Version,
    provider_id: Id,
    implementation: ImplementationIdentity,
    protocol_versions: IdSet,
    supported_profiles: Vec<NodeManifest>,
    extensions_supported: IdSet,
    qualification_refs: Vec<ContentRef>,
    extensions: Extensions,
});

historical_struct!(RealizationManifest {
    schema_version: Version,
    realization_id: Id,
    provider_manifest: ContentRef,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerRef>,
    owner_bindings: Vec<OwnerBinding>,
    extensions: Extensions,
});

historical_struct!(RealizeRequest {
    realization_id: Id,
    configuration: ContentRef,
    requested_node_ids: IdSet,
    resource_limits: ResourceLimits,
    extensions: Extensions,
});

historical_struct!(ResourceLimits {
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

historical_struct!(SchemaRef {
    id: Id,
    version: Version,
    definition: ContentRef,
    extensions: Extensions,
});

historical_struct!(SemanticVersion {
    major: U64,
    minor: U64,
    patch: U64,
    prerelease: Option<String>,
    build: Option<String>,
});

macro_rules! historical_unit_enum {
    ($type:ty { $($text:literal => $variant:ident),+ $(,)? }) => {
        impl HistoricalType for $type {
            fn read(input: &[u8], _: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let value = match plain_string(input)? { $($text => Self::$variant,)+ _ => return Err(invalid()) };
                Ok(build.then_some(value))
            }
        }
    };
}

historical_unit_enum!(Direction { "input" => Input, "output" => Output });
historical_unit_enum!(OperatingMode { "exact" => Exact, "quantized" => Quantized });
historical_unit_enum!(SchedulingRole { "active" => Active, "event_driven" => EventDriven, "autonomous" => Autonomous });

impl HistoricalType for crate::envelope::Envelope {
    fn borrowed_header_counter_scratch_data() -> usize {
        std::mem::size_of::<Option<Self>>()
            + std::mem::size_of::<Result<Option<Self>, ProviderError>>()
            + super::envelope::borrowed_validation_counter_scratch_data()
    }

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = super::envelope::ValidatedHistoricalEnvelope::validate(
            input,
            ledger.rows.clone(),
            ledger.limits,
        )?;
        ledger.rows = plan.remaining_records();
        if build {
            Ok(Some(plan.reconstruct()?))
        } else {
            Ok(None)
        }
    }
}

historical_struct!(crate::client::ClientOriginal {
    request: crate::envelope::Envelope,
    identity: HashRef,
    response: Option<crate::envelope::Envelope>,
});

historical_struct!(crate::handshake::Limits {
    frame_bytes: U64,
    nesting: U64,
    requests: U64,
    journal_entries: U64,
    blob_chunk_bytes: U64,
});

mod native17_build;
