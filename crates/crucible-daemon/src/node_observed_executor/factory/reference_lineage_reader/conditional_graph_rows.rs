//! Projects the exact source-created original world and bounded port contracts.
//!
//! This is a historical data codec, not graph admission. Source-generated bodies
//! must equal retained signed originals before any row is installed. Intermediate
//! binding hashes remain checked attestations; reconstruction body refs stay
//! positive and unknown original objects have no implicit leaves.

use crucible::node_admission::{
    ConnectionPolicy, CoordinatorPolicy, LaneVisibility, ObjectState, OwnershipPolicy, PortPolicy,
    VisibilityConversion,
};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::de::DeserializeOwned;

use super::{
    conditional_capture_records::insert,
    conditional_profile::{ConditionalProfile, encode},
    conditional_source::InspectionError,
    graph,
};

pub(super) fn install(
    target: &mut ConditionalProfile,
    profiles: &[ReferenceProfile],
    original: &graph::Definition,
) -> Result<(), InspectionError> {
    if profiles.len() != 3
        || target
            .construction_rows
            .len()
            .checked_add(32)
            .is_none_or(|n| n > 4096)
        || target
            .construction_rows
            .values()
            .try_fold(512usize, |n, edges| n.checked_add(edges.len()))
            .is_none_or(|n| n > 65_536)
        || original
            .content
            .values()
            .try_fold(0usize, |n, body| n.checked_add(body.len()))
            .is_none_or(|n| n > 64 * 1024 * 1024)
    {
        return Err("original graph codec credit exhausted".into());
    }
    let world_hash = original
        .world
        .identity()
        .map_err(InspectionError::from_error)?;
    if target
        .history
        .originals
        .values()
        .any(|source| source.transcript().origin.activation.world_binding_hash != world_hash)
    {
        return Err("original graph differs from MAC source worlds".into());
    }
    let mut world_edges = vec![
        original.world.scenario_ref.clone(),
        original.world.ownership_ref.clone(),
        original.world.coordinator_contract_ref.clone(),
        original.world.initialization_ref.clone(),
    ];
    for connection in &original.world.connections {
        world_edges.push(connection.policy_ref.clone());
        world_edges.push(connection.payload_schema.definition.clone());
        let policy: ConnectionPolicy = known(target, original, &connection.policy_ref)?;
        let mut edges = vec![policy.causal_proof_ref];
        match policy.visibility {
            VisibilityConversion::Direct => {}
            VisibilityConversion::PublicationPreserving { contract_ref }
            | VisibilityConversion::BoundarySampling { contract_ref }
            | VisibilityConversion::Adapter { contract_ref } => edges.push(contract_ref),
        }
        source_row(target, original, &connection.policy_ref, edges)?;
    }
    typed(target, &original.world, world_edges)?;
    typed(target, &original.requirements, Vec::new())?;

    let ownership: OwnershipPolicy = known(target, original, &original.world.ownership_ref)?;
    let mut ownership_edges = vec![ownership.inventory_proof_ref];
    for object in ownership.objects {
        if let ObjectState::Immutable { content_ref } = object.state {
            ownership_edges.push(content_ref);
        }
    }
    ownership_edges.extend(
        ownership
            .internal_dependencies
            .into_iter()
            .map(|value| value.proof_ref),
    );
    ownership_edges.extend(
        ownership
            .capture_owners
            .into_iter()
            .map(|value| value.cut_procedure_ref),
    );
    source_row(
        target,
        original,
        &original.world.ownership_ref,
        ownership_edges,
    )?;
    let coordinator: CoordinatorPolicy =
        known(target, original, &original.world.coordinator_contract_ref)?;
    let mut coordinator_edges = vec![
        coordinator.state_closure_ref,
        coordinator.operational_policy_ref,
    ];
    coordinator_edges.extend(
        coordinator
            .same_time_closure
            .into_iter()
            .map(|value| value.proof_ref),
    );
    source_row(
        target,
        original,
        &original.world.coordinator_contract_ref,
        coordinator_edges,
    )?;

    for profile in profiles {
        for port in &profile.descriptor.ports {
            let bytes = profile
                .content(&port.configuration_ref)
                .map_err(InspectionError::from_error)?;
            let policy: PortPolicy = decode(bytes)?;
            let mut edges = vec![policy.arbitration_ref];
            for lane in policy.lanes {
                edges.push(lane.ordering_ref);
                edges.push(lane.correlation_ref);
                if let LaneVisibility::Quantized { contract_ref, .. } = lane.visibility {
                    edges.push(contract_ref);
                }
            }
            row(target, &port.configuration_ref, bytes, edges)?;
        }
    }
    Ok(())
}

fn known<T: DeserializeOwned>(
    target: &ConditionalProfile,
    source: &graph::Definition,
    reference: &ContentRef,
) -> Result<T, InspectionError> {
    let bytes = source
        .content
        .get(reference)
        .ok_or("original source graph body absent")?;
    if target.content.get(reference) != Some(bytes) {
        return Err("original graph body differs from signed source".into());
    }
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    decode(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, InspectionError> {
    let value = canonical::parse_json(bytes, 65_536).map_err(InspectionError::from_error)?;
    if canonical::canonical_json(&value).map_err(InspectionError::from_error)? != bytes {
        return Err("original graph codec is not canonical".into());
    }
    serde_json::from_value(value).map_err(InspectionError::from_error)
}

fn source_row(
    target: &mut ConditionalProfile,
    source: &graph::Definition,
    reference: &ContentRef,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    let bytes = source
        .content
        .get(reference)
        .ok_or("original graph role absent")?;
    row(target, reference, bytes, dependencies)
}

fn typed(
    target: &mut ConditionalProfile,
    value: &impl serde::Serialize,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    let bytes = encode(value)?;
    let reference =
        canonical::content_ref(&bytes, "application/json").map_err(InspectionError::from_error)?;
    row(target, &reference, &bytes, dependencies)
}

fn row(
    target: &mut ConditionalProfile,
    reference: &ContentRef,
    bytes: &[u8],
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if target.content.get(reference).map(Vec::as_slice) != Some(bytes) {
        return Err("original graph codec body absent or changed".into());
    }
    insert(
        &mut target.construction_rows,
        reference.clone(),
        dependencies,
    )
    .map_err(InspectionError::from_error)
}
