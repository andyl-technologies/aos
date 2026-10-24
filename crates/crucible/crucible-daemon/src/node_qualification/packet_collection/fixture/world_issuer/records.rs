//! Interprets complete original three-owner policy objects with compiled rules.
//!
//! The full roster is checked before member interpretation. There is no copied
//! singleton qualification or arbitrary vendor predicate callback. The shared
//! inventory covers exactly three independent domains and their actual owners.

use std::collections::BTreeSet;

use crucible_engine::{
    node_adapters::cnp::CnpSemanticSource,
    node_admission::{
        CoordinatorPolicy, ObjectState, OwnershipPolicy, PortPolicy, ScenarioRequirements,
    },
};
use crucible_node_format::{ContentRef, HashRef, SchemaRef, Validate, canonical};
use crucible_node_transport::reference_packet::{PacketProgramDefinition, contracts};

use super::super::super::scope;
use super::super::issuer::records::{decode, validate_port, validate_program};
use super::{PacketWorldIndependentGraphRequest, QualificationError, refused};

pub(super) struct Validated {
    pub(super) requirements: HashRef,
    pub(super) schemas: Vec<SchemaRef>,
    pub(super) proof: ContentRef,
}

/// Encodes the compiled independent three-owner interpretation without authority.
///
/// # Errors
/// Reports finite canonical encoding failure for the fixed specification.
pub fn packet_world_independent_graph_contract() -> Result<Vec<u8>, QualificationError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-independent-graph/2",
        "purpose":"three-owner collecting-only; no ordinary Node behavioral acceptance",
        "programme":"three independently validated two-callback output-only programs; nine complete original windows per owner",
        "port":"three separate opaque-octet output lanes; exact Publication, Credit, <=32 payload bytes each, no ingress",
        "inventory":"exactly three native participants, independent mutable future-affecting domains, one original execution/capture owner per participant; no internal or transport connections",
        "capture":"all-false limitation only; no capture, continuation, restart, fork, replay or procedure qualification",
        "coordinator":"one superdense-v1 world, initial zero cut, complete actual post-Arm Ready roster; no predicted preparation or external input",
        "current":"same original source-owned policy revision plus all original peer/host/source file descriptors; owner Drop revokes",
        "native":"separate original native handles, registrar/process/kernel/source and UnixDatagram oracle; nine-window result does not complete normative class coverage"
    }))?)
}

pub(super) fn validate(
    request: &PacketWorldIndependentGraphRequest<'_>,
) -> Result<Validated, QualificationError> {
    if request.content.len() > 128 {
        return Err(refused());
    }
    let extent = request.content.values().try_fold(0usize, |sum, body| {
        if body.len() > 1024 * 1024 {
            return Err(refused());
        }
        sum.checked_add(body.len()).ok_or_else(refused)
    })?;
    if extent > 2 * 1024 * 1024 {
        return Err(refused());
    }
    // All three source/measurement and original body associations are bounded
    // before schema parsing, canonical allocation or retained owner copies.
    for source in &request.sources {
        let selected = source.installation();
        scope::encoded_size(
            &(
                request.world,
                request.requirements,
                &selected.provider,
                &selected.descriptor,
                &selected.binding,
                &selected.owner,
            ),
            1024 * 1024,
        )?;
    }
    scope::encoded_size(&request.measurements, 3 * 65_536)?;
    scope::encoded_size(request.coordinator, 65_536)?;
    for (reference, body) in request.content {
        reference.verify(body)?;
    }
    request.world.validate()?;
    let world = request.world.identity()?;
    if request.world.node_bindings.len() != 3
        || !request.world.connections.is_empty()
        || !request.world.extensions.is_empty()
        || request.world.ordering_profile != "superdense-v1"
        || request.coordinator.participants.len() != 3
    {
        return Err(refused());
    }

    let requirements = canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
    let original: ScenarioRequirements = decode(request.content, &request.world.scenario_ref)?;
    let nodes: Vec<_> = request
        .sources
        .iter()
        .map(|source| source.installation().descriptor.id.clone())
        .collect();
    if nodes.iter().collect::<BTreeSet<_>>().len() != 3
        || canonical::json_hash("cnp.admission-requirements.v1", &original)? != requirements
        || original.deterministic
        || original.exact_capture
        || original.exact_continuation
        || original.durable_restart
        || original.isolated_fork
        || !original.accepted_quantized_nodes.is_empty()
        || !original.accepted_visibility_conversions.is_empty()
        || original.accepted_nondeterministic_nodes != nodes
        || original.accepted_limited_state_nodes != nodes
    {
        return Err(refused());
    }

    let proof_bytes = packet_world_independent_graph_contract()?;
    let proof = canonical::content_ref(&proof_bytes, "application/json")?;
    if request.content.get(&proof) != Some(&proof_bytes) {
        return Err(refused());
    }
    let inventory: OwnershipPolicy = decode(request.content, &request.world.ownership_ref)?;
    if inventory.schema_version != 1
        || inventory.domains.len() != 3
        || inventory.objects.len() != 3
        || inventory.capture_owners.len() != 3
        || !inventory.internal_dependencies.is_empty()
        || inventory.inventory_proof_ref != proof
    {
        return Err(refused());
    }
    let coordinator: CoordinatorPolicy =
        decode(request.content, &request.world.coordinator_contract_ref)?;
    if coordinator.schema_version != 1
        || coordinator.state_closure_ref != proof
        || coordinator.operational_policy_ref != proof
        || coordinator.maximum_microsteps_per_instant.get() != 1024
        || !coordinator.same_time_closure.is_empty()
        || !coordinator.external_inputs.is_empty()
    {
        return Err(refused());
    }

    let mut schemas = Vec::new();
    schemas.try_reserve_exact(12).map_err(|_| refused())?;
    let mut owners = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for (index, source) in request.sources.iter().enumerate() {
        source
            .authenticate_collecting_world_scope(request.coordinator)
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        let selected = source.installation();
        selected.provider.validate()?;
        selected.descriptor.validate()?;
        selected.binding.validate()?;
        selected.owner.validate()?;
        let owner = &selected.owner.owner;
        if selected.world_binding_hash != world
            || selected.provider.implementation.artifacts.len() != 1
            || selected.provider.implementation.artifacts[0].role.as_str() != "executable"
            || selected.provider.implementation.artifacts[0].content
                != request.measurements[index].peer.content
            || request.measurements[index].host != request.measurements[0].host
            || selected.owner.node_bindings.len() != 1
            || selected.owner.node_bindings[0] != request.world.node_bindings[index]
            || owner.participant_ids != [selected.descriptor.id.clone()]
            || owner.state_domain_ids.len() != 1
            || selected.descriptor.ports.len() != 1
            || !owners.insert(owner.id.clone())
            || !domains.insert(owner.state_domain_ids[0].clone())
        {
            return Err(refused());
        }
        let programme: PacketProgramDefinition =
            decode(request.content, &selected.descriptor.model_ref)?;
        validate_program(&programme)?;
        if selected.descriptor.configuration_ref != selected.descriptor.model_ref
            || selected.descriptor.initialization_ref != selected.descriptor.model_ref
        {
            return Err(refused());
        }
        let port: PortPolicy = decode(
            request.content,
            &selected.descriptor.ports[0].configuration_ref,
        )?;
        validate_port(&port, selected)?;
        validate_member(&inventory, selected, &proof)?;
        schemas.extend(validate_schemas(request, selected)?);
    }
    // The whole initialization is an explicit roster, not a member program hash.
    let initialization: Vec<ContentRef> =
        decode(request.content, &request.world.initialization_ref)?;
    if initialization
        != request
            .sources
            .iter()
            .map(|source| source.installation().descriptor.initialization_ref.clone())
            .collect::<Vec<_>>()
    {
        return Err(refused());
    }
    Ok(Validated {
        requirements,
        schemas,
        proof,
    })
}

fn validate_member(
    inventory: &OwnershipPolicy,
    selected: &crucible_engine::node_adapters::cnp::CnpSemanticInstallation,
    proof: &ContentRef,
) -> Result<(), QualificationError> {
    let owner = &selected.owner.owner;
    let domain = inventory
        .domains
        .iter()
        .find(|row| row.id == owner.state_domain_ids[0])
        .ok_or_else(refused)?;
    let object = inventory
        .objects
        .iter()
        .find(|row| row.id == selected.descriptor.id)
        .ok_or_else(refused)?;
    let capture = inventory
        .capture_owners
        .iter()
        .find(|row| row.owner_id == owner.id)
        .ok_or_else(refused)?;
    if domain.capture_owner_id != owner.id
        || domain.execution_owner_ids != [owner.id.clone()]
        || !domain.future_affecting
        || object.node_ids != [selected.descriptor.id.clone()]
        || !object.future_affecting
        || object.state
            != (ObjectState::Mutable {
                domain_id: domain.id.clone(),
            })
        || capture.complete_model
        || capture.unchanged_cut
        || capture.exact_continuation
        || capture.durable_restart
        || capture.isolated_fork
        || !capture.dependencies.is_empty()
        || &capture.cut_procedure_ref != proof
    {
        return Err(refused());
    }
    Ok(())
}

fn validate_schemas(
    request: &PacketWorldIndependentGraphRequest<'_>,
    selected: &crucible_engine::node_adapters::cnp::CnpSemanticInstallation,
) -> Result<Vec<SchemaRef>, QualificationError> {
    let semantics = contracts::immediate_packet_contract().map_err(native)?;
    let ingress = contracts::world_ingress_contract().map_err(native)?;
    let semantics_ref = canonical::content_ref(&semantics, "application/json")?;
    let ingress_ref = canonical::content_ref(&ingress, "application/json")?;
    if request.content.get(&semantics_ref) != Some(&semantics)
        || request.content.get(&ingress_ref) != Some(&ingress)
    {
        return Err(refused());
    }
    let names = [
        ("source-owned.packet-ingress/3", 3, &ingress_ref),
        ("source-owned.packet-octets/1", 1, &semantics_ref),
        ("source-owned.packet-program/1", 1, &semantics_ref),
        ("source-owned.packet-receipt/2", 2, &semantics_ref),
    ];
    let formats = &selected.provider.implementation.formats;
    if formats.len() != 4
        || formats
            .iter()
            .zip(names)
            .any(|(format, (id, version, definition))| {
                format.id.as_str() != id
                    || format.version != version
                    || &format.definition != definition
                    || !format.extensions.is_empty()
            })
    {
        return Err(refused());
    }
    Ok(formats.clone())
}

fn native(error: crucible_node_transport::ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
