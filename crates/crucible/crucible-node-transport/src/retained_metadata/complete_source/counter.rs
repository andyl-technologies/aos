//! Names concrete borrowed views in the actual immutable Source observer.
//!
//! Exhaustive field tuples follow the defining ObserveMetadata destructures.
//! The generic-container controls name each actual child family independently;
//! recursive compiler frames and allocator controls remain separate quantities.

use super::*;
use std::mem::size_of;

fn fields_bytes<T: 'static, R>(_: impl FnOnce(&'static T) -> R) -> usize {
    size_of::<R>()
}

fn container_bytes<T: 'static>() -> usize {
    size_of::<&'static T>()
        + size_of::<&'static Vec<T>>()
        + size_of::<std::slice::Iter<'static, T>>()
        + size_of::<&'static Option<T>>()
        + size_of::<Option<&'static T>>()
        + size_of::<&'static Box<T>>()
        + size_of::<Result<(), ProviderError>>()
}

impl RetainedCompleteSourceMetadata<'_> {
    /// Names fixed controls in its exact borrowed typed observation.
    ///
    /// This names the observer, actual returned facts, exhaustive struct field
    /// views and concrete child/container alternatives. It grants no constructor
    /// storage or authority and does not serialize or walk an actual owner.
    pub fn counter_scratch_data() -> usize {
        let roots = size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<usize>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<(&String, &Value)>();
        roots
            + container_bytes::<crate::envelope::Envelope>()
            + fields_bytes(|value: &'static crate::envelope::Envelope| {
                let crate::envelope::Envelope {
                    protocol,
                    message,
                    session_id,
                    incarnation_id,
                    node_id,
                    execution_owner_id,
                    capture_owner_id,
                    request_id,
                    operation_id,
                    sequence,
                    method,
                    body,
                    extensions,
                } = value;
                (
                    protocol,
                    message,
                    session_id,
                    incarnation_id,
                    node_id,
                    execution_owner_id,
                    capture_owner_id,
                    request_id,
                    operation_id,
                    sequence,
                    method,
                    body,
                    extensions,
                )
            })
            + container_bytes::<crate::client::ClientOriginal>()
            + fields_bytes(|value: &'static crate::client::ClientOriginal| {
                let crate::client::ClientOriginal {
                    request,
                    identity,
                    response,
                } = value;
                (request, identity, response)
            })
            + container_bytes::<ArtifactIdentity>()
            + fields_bytes(|value: &'static ArtifactIdentity| {
                let ArtifactIdentity {
                    id,
                    role,
                    content,
                    extensions,
                } = value;
                (id, role, content, extensions)
            })
            + container_bytes::<BindingCompatibility>()
            + fields_bytes(|value: &'static BindingCompatibility| {
                let BindingCompatibility {
                    schema_version,
                    node_id,
                    descriptor_hash,
                    implementation,
                    profile_ref,
                    configuration_ref,
                    operating_contract,
                    execution_owner,
                    capture_owner,
                    capabilities_ref,
                    guarantees_ref,
                    qualification_refs,
                    extensions,
                } = value;
                (
                    schema_version,
                    node_id,
                    descriptor_hash,
                    implementation,
                    profile_ref,
                    configuration_ref,
                    operating_contract,
                    execution_owner,
                    capture_owner,
                    capabilities_ref,
                    guarantees_ref,
                    qualification_refs,
                    extensions,
                )
            })
            + container_bytes::<ContentRef>()
            + fields_bytes(|value: &'static ContentRef| {
                let ContentRef {
                    hash,
                    length,
                    media_type,
                } = value;
                (hash, length, media_type)
            })
            + container_bytes::<ExtensionSelection>()
            + fields_bytes(|value: &'static ExtensionSelection| {
                let ExtensionSelection {
                    declaration,
                    identifier,
                    semantic_version,
                    schema_digest,
                } = value;
                (declaration, identifier, semantic_version, schema_digest)
            })
            + container_bytes::<FacetSelection>()
            + fields_bytes(|value: &'static FacetSelection| {
                let FacetSelection {
                    id,
                    version,
                    configuration_ref,
                    guarantees_ref,
                    extensions,
                } = value;
                (id, version, configuration_ref, guarantees_ref, extensions)
            })
            + container_bytes::<HashRef>()
            + fields_bytes(|value: &'static HashRef| {
                let HashRef {
                    algorithm,
                    domain,
                    digest,
                } = value;
                (algorithm, domain, digest)
            })
            + container_bytes::<ImplementationIdentity>()
            + fields_bytes(|value: &'static ImplementationIdentity| {
                let ImplementationIdentity {
                    schema_version,
                    implementation_id,
                    artifacts,
                    model_definitions,
                    formats,
                    extensions,
                } = value;
                (
                    schema_version,
                    implementation_id,
                    artifacts,
                    model_definitions,
                    formats,
                    extensions,
                )
            })
            + container_bytes::<LaneDescriptor>()
            + fields_bytes(|value: &'static LaneDescriptor| {
                let LaneDescriptor {
                    id,
                    direction,
                    payload_schema,
                    maximum_payload_bytes,
                    maximum_pending_events,
                    extensions,
                } = value;
                (
                    id,
                    direction,
                    payload_schema,
                    maximum_payload_bytes,
                    maximum_pending_events,
                    extensions,
                )
            })
            + container_bytes::<LiveAuthority>()
            + fields_bytes(|value: &'static LiveAuthority| {
                let LiveAuthority {
                    schema_version,
                    session_id,
                    incarnation_id,
                    realization_id,
                    activation_id,
                    world_generation,
                    owner_generation,
                    input_epoch,
                    host_receipt,
                    extensions,
                } = value;
                (
                    schema_version,
                    session_id,
                    incarnation_id,
                    realization_id,
                    activation_id,
                    world_generation,
                    owner_generation,
                    input_epoch,
                    host_receipt,
                    extensions,
                )
            })
            + container_bytes::<NodeBinding>()
            + fields_bytes(|value: &'static NodeBinding| {
                let NodeBinding {
                    compatibility,
                    authority,
                    extensions,
                } = value;
                (compatibility, authority, extensions)
            })
            + container_bytes::<NodeBindingRef>()
            + fields_bytes(|value: &'static NodeBindingRef| {
                let NodeBindingRef {
                    node_id,
                    binding_hash,
                    extensions,
                } = value;
                (node_id, binding_hash, extensions)
            })
            + container_bytes::<NodeDescriptor>()
            + fields_bytes(|value: &'static NodeDescriptor| {
                let NodeDescriptor {
                    schema_version,
                    id,
                    roles,
                    model_ref,
                    configuration_ref,
                    initialization_ref,
                    ports,
                    extensions,
                } = value;
                (
                    schema_version,
                    id,
                    roles,
                    model_ref,
                    configuration_ref,
                    initialization_ref,
                    ports,
                    extensions,
                )
            })
            + container_bytes::<NodeManifest>()
            + fields_bytes(|value: &'static NodeManifest| {
                let NodeManifest {
                    schema_version,
                    profile_id,
                    roles,
                    configuration_schema,
                    allowed_combinations_ref,
                    port_templates_ref,
                    state_formats,
                    operation_facets,
                    extensions,
                } = value;
                (
                    schema_version,
                    profile_id,
                    roles,
                    configuration_schema,
                    allowed_combinations_ref,
                    port_templates_ref,
                    state_formats,
                    operation_facets,
                    extensions,
                )
            })
            + container_bytes::<OperatingContract>()
            + fields_bytes(|value: &'static OperatingContract| {
                let OperatingContract {
                    schema_version,
                    mode,
                    scheduling_role,
                    ordering_profile,
                    policy_ref,
                    resolution_ps,
                    phase_ps,
                    facets,
                    extensions,
                } = value;
                (
                    schema_version,
                    mode,
                    scheduling_role,
                    ordering_profile,
                    policy_ref,
                    resolution_ps,
                    phase_ps,
                    facets,
                    extensions,
                )
            })
            + container_bytes::<OwnerBinding>()
            + fields_bytes(|value: &'static OwnerBinding| {
                let OwnerBinding {
                    schema_version,
                    owner,
                    owner_roles,
                    node_bindings,
                    ownership_ref,
                    extensions,
                } = value;
                (
                    schema_version,
                    owner,
                    owner_roles,
                    node_bindings,
                    ownership_ref,
                    extensions,
                )
            })
            + container_bytes::<OwnerRef>()
            + fields_bytes(|value: &'static OwnerRef| {
                let OwnerRef {
                    id,
                    participant_ids,
                    state_domain_ids,
                } = value;
                (id, participant_ids, state_domain_ids)
            })
            + container_bytes::<PacketConnectedHostSelection>()
            + fields_bytes(|value: &'static PacketConnectedHostSelection| {
                let PacketConnectedHostSelection {
                    descriptor,
                    binding,
                    owner,
                    prepared_token,
                    initial_node,
                } = value;
                (descriptor, binding, owner, prepared_token, initial_node)
            })
            + container_bytes::<PacketControlSelection>()
            + fields_bytes(|value: &'static PacketControlSelection| {
                let PacketControlSelection {
                    provider,
                    realization,
                    realize,
                    prepared_token,
                    admission,
                    transaction,
                    gate,
                    world,
                    admission_receipt,
                } = value;
                (
                    provider,
                    realization,
                    realize,
                    prepared_token,
                    admission,
                    transaction,
                    gate,
                    world,
                    admission_receipt,
                )
            })
            + container_bytes::<PacketNative5CoordinatorInstallation>()
            + fields_bytes(|value: &'static PacketNative5CoordinatorInstallation| {
                let PacketNative5CoordinatorInstallation {
                    schema,
                    participants,
                    host,
                    template,
                } = value;
                (schema, participants, host, template)
            })
            + container_bytes::<PortDescriptor>()
            + fields_bytes(|value: &'static PortDescriptor| {
                let PortDescriptor {
                    id,
                    lanes,
                    interface_id,
                    features,
                    configuration_ref,
                    extensions,
                } = value;
                (
                    id,
                    lanes,
                    interface_id,
                    features,
                    configuration_ref,
                    extensions,
                )
            })
            + container_bytes::<ProviderManifest>()
            + fields_bytes(|value: &'static ProviderManifest| {
                let ProviderManifest {
                    schema_version,
                    provider_id,
                    implementation,
                    protocol_versions,
                    supported_profiles,
                    extensions_supported,
                    qualification_refs,
                    extensions,
                } = value;
                (
                    schema_version,
                    provider_id,
                    implementation,
                    protocol_versions,
                    supported_profiles,
                    extensions_supported,
                    qualification_refs,
                    extensions,
                )
            })
            + container_bytes::<RealizationManifest>()
            + fields_bytes(|value: &'static RealizationManifest| {
                let RealizationManifest {
                    schema_version,
                    realization_id,
                    provider_manifest,
                    descriptors,
                    bindings,
                    owners,
                    owner_bindings,
                    extensions,
                } = value;
                (
                    schema_version,
                    realization_id,
                    provider_manifest,
                    descriptors,
                    bindings,
                    owners,
                    owner_bindings,
                    extensions,
                )
            })
            + container_bytes::<RealizeRequest>()
            + fields_bytes(|value: &'static RealizeRequest| {
                let RealizeRequest {
                    realization_id,
                    configuration,
                    requested_node_ids,
                    resource_limits,
                    extensions,
                } = value;
                (
                    realization_id,
                    configuration,
                    requested_node_ids,
                    resource_limits,
                    extensions,
                )
            })
            + container_bytes::<ResourceLimits>()
            + fields_bytes(|value: &'static ResourceLimits| {
                let ResourceLimits {
                    cpu_budget_ns,
                    memory_bytes,
                    writable_bytes,
                    processes,
                    descriptors,
                    pending_events,
                    content_bytes,
                    maximum_operations,
                    extensions,
                } = value;
                (
                    cpu_budget_ns,
                    memory_bytes,
                    writable_bytes,
                    processes,
                    descriptors,
                    pending_events,
                    content_bytes,
                    maximum_operations,
                    extensions,
                )
            })
            + container_bytes::<SchemaRef>()
            + fields_bytes(|value: &'static SchemaRef| {
                let SchemaRef {
                    id,
                    version,
                    definition,
                    extensions,
                } = value;
                (id, version, definition, extensions)
            })
            + container_bytes::<SemanticVersion>()
            + fields_bytes(|value: &'static SemanticVersion| {
                let SemanticVersion {
                    major,
                    minor,
                    patch,
                    prerelease,
                    build,
                } = value;
                (major, minor, patch, prerelease, build)
            })
            + container_bytes::<crate::reference_service::InstalledContent>()
            + fields_bytes(
                |value: &'static crate::reference_service::InstalledContent| {
                    let crate::reference_service::InstalledContent { reference, bytes } = value;
                    (reference, bytes)
                },
            )
            + container_bytes::<crate::handshake::Limits>()
            + fields_bytes(|value: &'static crate::handshake::Limits| {
                let crate::handshake::Limits {
                    frame_bytes,
                    nesting,
                    requests,
                    journal_entries,
                    blob_chunk_bytes,
                } = value;
                (
                    frame_bytes,
                    nesting,
                    requests,
                    journal_entries,
                    blob_chunk_bytes,
                )
            })
            + container_bytes::<CapabilityProfile>()
            + fields_bytes(|value: &'static CapabilityProfile| {
                let CapabilityProfile {
                    schema_version,
                    facets,
                    devices_ref,
                    requirements_ref,
                    extensions,
                } = value;
                (
                    schema_version,
                    facets,
                    devices_ref,
                    requirements_ref,
                    extensions,
                )
            })
            + container_bytes::<GuaranteeProfile>()
            + fields_bytes(|value: &'static GuaranteeProfile| {
                let GuaranteeProfile {
                    schema_version,
                    repeatability,
                    capture_scope,
                    continuation,
                    durable_restart,
                    isolated_fork,
                    conditional_replay,
                    limitations_ref,
                    extensions,
                } = value;
                (
                    schema_version,
                    repeatability,
                    capture_scope,
                    continuation,
                    durable_restart,
                    isolated_fork,
                    conditional_replay,
                    limitations_ref,
                    extensions,
                )
            })
            + container_bytes::<PacketProgramDefinition>()
            + fields_bytes(|value: &'static PacketProgramDefinition| {
                let PacketProgramDefinition { schema, events } = value;
                (schema, events)
            })
            + container_bytes::<PacketEvent>()
            + fields_bytes(|value: &'static PacketEvent| {
                let PacketEvent {
                    id,
                    evaluation,
                    completion,
                    payload,
                } = value;
                (id, evaluation, completion, payload)
            })
            + container_bytes::<PacketConnectedDefinition>()
            + fields_bytes(|value: &'static PacketConnectedDefinition| {
                let PacketConnectedDefinition {
                    schema,
                    connections,
                    output,
                } = value;
                (schema, connections, output)
            })
            + container_bytes::<PacketInputConnection>()
            + fields_bytes(|value: &'static PacketInputConnection| {
                let PacketInputConnection {
                    id,
                    policy,
                    producer,
                    consumer,
                    delay_ps,
                } = value;
                (id, policy, producer, consumer, delay_ps)
            })
            + container_bytes::<Position>()
            + fields_bytes(|value: &'static Position| {
                let Position {
                    time_ps,
                    microstep,
                    phase,
                } = value;
                (time_ps, microstep, phase)
            })
            + container_bytes::<Endpoint>()
            + fields_bytes(|value: &'static Endpoint| {
                let Endpoint {
                    node_id,
                    port_id,
                    lane_id,
                } = value;
                (node_id, port_id, lane_id)
            })
            + container_bytes::<String>()
            + container_bytes::<Id>()
            + container_bytes::<Bytes>()
            + container_bytes::<Value>()
            + container_bytes::<U64>()
            + container_bytes::<bool>()
            + container_bytes::<u8>()
            + container_bytes::<u16>()
            + container_bytes::<u32>()
            + container_bytes::<u64>()
            + container_bytes::<usize>()
            + container_bytes::<Phase>()
            + container_bytes::<Repeatability>()
            + container_bytes::<CaptureScope>()
            + container_bytes::<Continuation>()
            + container_bytes::<Direction>()
            + container_bytes::<OperatingMode>()
            + container_bytes::<SchedulingRole>()
            + container_bytes::<crate::envelope::MessageKind>()
            + container_bytes::<crate::envelope::Method>()
            + size_of::<[usize; 2]>()
            + size_of::<[usize; 4]>()
    }
}
