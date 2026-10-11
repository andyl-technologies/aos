//! Interprets actual packet policy objects with the fixed compiled source rules.
//!
//! This validator accepts only the known exact output-only program and original
//! singleton ownership. It does not delegate to vendor-provided validators or
//! infer support from schema labels, catalog membership or advertised classes.

use std::collections::BTreeMap;

use crucible::{
    node_adapters::cnp::CnpSemanticSource,
    node_admission::{
        CoordinatorPolicy, FlowControl, LaneVisibility, ObjectState, OwnershipPolicy, PortPolicy,
        ScenarioRequirements,
    },
};
use crucible_node_contract::{ContentRef, HashRef, Phase, SchemaRef, Validate, canonical};
use crucible_node_provider::reference_packet::{PacketProgramDefinition, contracts};
use serde::de::DeserializeOwned;

use super::{PacketGraphPredicate, PacketIndependentGraphRequest, QualificationError};

pub(super) struct Validated {
    pub(super) requirements: HashRef,
    pub(super) schemas: Vec<SchemaRef>,
    pub(super) predicates: Vec<PacketGraphPredicate>,
}

/// Encodes the complete interpretation owned by the independent packet issuer.
///
/// The body documents its actual compiled predicates. Decoding it or possessing
/// its content identity cannot construct the original policy owner or lease.
///
/// # Errors
/// Reports bounded canonical encoding failure for the fixed specification.
pub fn packet_independent_graph_contract() -> Result<Vec<u8>, QualificationError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-independent-graph/1",
        "purpose":"collecting-only; no ordinary Node behavioral acceptance",
        "source":"source-owned.packet-native/2",
        "programme":"exactly two native callbacks; first private, second output; actual full original source validates native inventories and grants",
        "port":"one wire_tx/output opaque-octet lane, <=32 bytes, exact Publication visibility, Credit, at most one pending output",
        "inventory":"one source-native participant, one mutable future-affecting domain, original single capture/execution owner; complete native/source journals and socket custody remain in that original owner",
        "capture":"none; no complete capture, continuation, restart, fork, replay or procedure authority",
        "coordinator":"superdense-v1, <=1024 microsteps per instant, no external ingress, no zero-time cycles, authentic original common operation/publication/ACK custody",
        "independent_current":"actual host owner revision and original measured source files; revocation or Drop refuses every retained wrapper",
        "native_current":"separate actual original SDK registrar/process/kernel/owner conjunction before dispatch; this policy does not issue native authority"
    }))?)
}

pub(super) fn validate(
    request: &PacketIndependentGraphRequest<'_>,
) -> Result<Validated, QualificationError> {
    let selected = request.source.installation();
    if request.content.len() > 64 {
        return Err(refused());
    }
    let body_bytes = request.content.values().try_fold(0usize, |total, body| {
        if body.len() > 1024 * 1024 {
            return Err(refused());
        }
        total.checked_add(body.len()).ok_or_else(refused)
    })?;
    // Eight visible association extents include original request, issuer and
    // wrapper ownership, evidence return and typed/canonical validation views.
    // Backend-private allocations and allocator transient peaks are excluded.
    if body_bytes > 1024 * 1024 {
        return Err(refused());
    }
    super::super::super::scope::encoded_size(
        &(
            request.world,
            request.requirements,
            &selected.provider,
            &selected.descriptor,
            &selected.binding,
            &selected.owner,
            request.measurements,
        ),
        1024 * 1024,
    )?;
    for (reference, body) in request.content {
        reference.verify(body)?;
    }
    selected.provider.validate()?;
    selected.descriptor.validate()?;
    selected.binding.validate()?;
    selected.owner.validate()?;
    request.world.validate()?;
    if selected.provider.implementation.artifacts.len() != 1
        || selected.provider.implementation.artifacts[0].role.as_str() != "executable"
        || selected.provider.implementation.artifacts[0].content
            != request.measurements.peer.content
        || request.world.identity()? != selected.world_binding_hash
        || request.world.node_bindings != selected.owner.node_bindings
        || !request.world.connections.is_empty()
        || !request.world.extensions.is_empty()
        || request.world.ordering_profile != "superdense-v1"
        || selected.owner.owner.participant_ids != [selected.descriptor.id.clone()]
        || selected.owner.owner.state_domain_ids.len() != 1
        || selected.descriptor.ports.len() != 1
    {
        return Err(refused());
    }

    let requirements = canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
    let original: ScenarioRequirements = decode(request.content, &request.world.scenario_ref)?;
    if canonical::json_hash("cnp.admission-requirements.v1", &original)? != requirements
        || original.deterministic
        || original.exact_capture
        || original.exact_continuation
        || original.durable_restart
        || original.isolated_fork
        || !original.accepted_quantized_nodes.is_empty()
        || !original.accepted_visibility_conversions.is_empty()
        || original.accepted_nondeterministic_nodes != [selected.descriptor.id.clone()]
        || original.accepted_limited_state_nodes != [selected.descriptor.id.clone()]
    {
        return Err(refused());
    }

    let program: PacketProgramDefinition = decode(request.content, &selected.descriptor.model_ref)?;
    validate_program(&program)?;
    if selected.descriptor.configuration_ref != selected.descriptor.model_ref
        || selected.descriptor.initialization_ref != selected.descriptor.model_ref
        || request.world.initialization_ref != selected.descriptor.model_ref
    {
        return Err(refused());
    }
    let proof_bytes = packet_independent_graph_contract()?;
    let proof = canonical::content_ref(&proof_bytes, "application/json")?;
    if request.content.get(&proof) != Some(&proof_bytes) {
        return Err(refused());
    }
    let port = &selected.descriptor.ports[0];
    let interpretation: PortPolicy = decode(request.content, &port.configuration_ref)?;
    validate_port(&interpretation, selected)?;
    let inventory: OwnershipPolicy = decode(request.content, &request.world.ownership_ref)?;
    validate_inventory(&inventory, selected, &proof)?;
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
    let schemas = validate_schemas(request)?;
    let predicates = vec![
        PacketGraphPredicate::Scenario {
            scenario: request.world.scenario_ref.clone(),
        },
        PacketGraphPredicate::Port {
            port: port.id.clone(),
            policy: port.configuration_ref.clone(),
        },
        PacketGraphPredicate::Inventory {
            ownership: request.world.ownership_ref.clone(),
            proof: proof.clone(),
        },
        PacketGraphPredicate::NoPreservation {
            owner: selected.owner.owner.id.clone(),
            limitation: proof.clone(),
        },
        PacketGraphPredicate::Coordinator { policy: proof },
    ];
    Ok(Validated {
        requirements,
        schemas,
        predicates,
    })
}

fn validate_program(program: &PacketProgramDefinition) -> Result<(), QualificationError> {
    if program.schema != "source-owned.packet-program.v1" || program.events.len() != 2 {
        return Err(refused());
    }
    let private = &program.events[0];
    let output = &program.events[1];
    private.id.validate()?;
    output.id.validate()?;
    private.evaluation.validate()?;
    output.evaluation.validate()?;
    private.completion.validate()?;
    output.completion.validate()?;
    if private.id == output.id
        || private.payload.is_some()
        || private.evaluation != private.completion
        || private.evaluation.phase != Phase::Reaction
        || output.evaluation.phase != Phase::Reaction
        || private.evaluation >= output.evaluation
        || output.completion <= output.evaluation
        || output.completion.phase != Phase::Publication
        || output
            .payload
            .as_ref()
            .is_none_or(|payload| payload.as_slice().len() > 32)
    {
        return Err(refused());
    }
    Ok(())
}

fn validate_port(
    policy: &PortPolicy,
    selected: &crucible::node_adapters::cnp::CnpSemanticInstallation,
) -> Result<(), QualificationError> {
    if policy.schema_version != 1 || policy.lanes.len() != 1 {
        return Err(refused());
    }
    let lane = &policy.lanes[0];
    if lane.lane_id.as_str() != "output"
        || lane.ordering_ref != selected.descriptor.model_ref
        || lane.correlation_ref != selected.descriptor.model_ref
        || lane.flow_control != FlowControl::Credit
        || lane.maximum_pending_bytes.get() != 32
        || lane.visibility != LaneVisibility::Exact
        || lane.effect_phases != [1]
        || lane.minimum_lookahead_ps.get() != 0
        || policy.maximum_producers.get() != 0
        || policy.maximum_consumers.get() != 1
        || policy.arbitration_ref != selected.descriptor.model_ref
        || policy.execution_owner_id != selected.owner.owner.id
        || policy.state_domain_ids != selected.owner.owner.state_domain_ids
        || policy.internal
    {
        return Err(refused());
    }
    Ok(())
}

fn validate_inventory(
    inventory: &OwnershipPolicy,
    selected: &crucible::node_adapters::cnp::CnpSemanticInstallation,
    proof: &ContentRef,
) -> Result<(), QualificationError> {
    if inventory.schema_version != 1
        || inventory.domains.len() != 1
        || inventory.objects.len() != 1
        || inventory.capture_owners.len() != 1
        || !inventory.internal_dependencies.is_empty()
        || &inventory.inventory_proof_ref != proof
    {
        return Err(refused());
    }
    let owner = &selected.owner.owner;
    let domain = &inventory.domains[0];
    let object = &inventory.objects[0];
    let capture = &inventory.capture_owners[0];
    if domain.id != owner.state_domain_ids[0]
        || domain.capture_owner_id != owner.id
        || domain.execution_owner_ids != [owner.id.clone()]
        || !domain.future_affecting
        || object.id != selected.descriptor.id
        || object.node_ids != [selected.descriptor.id.clone()]
        || !object.future_affecting
        || object.state
            != (ObjectState::Mutable {
                domain_id: domain.id.clone(),
            })
        || capture.owner_id != owner.id
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
    request: &PacketIndependentGraphRequest<'_>,
) -> Result<Vec<SchemaRef>, QualificationError> {
    let selected = request.source.installation();
    let semantics = contracts::immediate_packet_contract().map_err(native)?;
    let semantics_ref = canonical::content_ref(&semantics, "application/json")?;
    let ingress = contracts::common_ingress_contract().map_err(native)?;
    let ingress_ref = canonical::content_ref(&ingress, "application/json")?;
    if request.content.get(&semantics_ref) != Some(&semantics)
        || request.content.get(&ingress_ref) != Some(&ingress)
    {
        return Err(refused());
    }
    let formats = &selected.provider.implementation.formats;
    let names = [
        ("source-owned.packet-ingress/2", 2, &ingress_ref),
        ("source-owned.packet-octets/1", 1, &semantics_ref),
        ("source-owned.packet-program/1", 1, &semantics_ref),
        ("source-owned.packet-receipt/2", 2, &semantics_ref),
    ];
    if formats.len() != names.len()
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

pub(super) fn decode<T: DeserializeOwned>(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<T, QualificationError> {
    let bytes = content.get(reference).ok_or_else(refused)?;
    if bytes.len() > 1024 * 1024 {
        return Err(refused());
    }
    reference.verify(bytes)?;
    let value = canonical::parse_json(bytes, 1024 * 1024)?;
    if canonical::canonical_json(&value)? != *bytes {
        return Err(refused());
    }
    serde_json::from_value(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(Into::into)
}

fn native(error: crucible_node_provider::ProviderError) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

fn refused() -> QualificationError {
    QualificationError::Refused(
        "independent packet policy requires actual fixed source interpretations",
    )
}
