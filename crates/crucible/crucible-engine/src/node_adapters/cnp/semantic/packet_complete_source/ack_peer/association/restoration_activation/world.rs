//! Checks the actual complete World publication before signing its assigned body.
//!
//! World authority comes only from the claim's retained opaque WorldActivation.
//! The uploaded manifest and coordinator must be the complete bodies of that
//! publication, including every original node and prepared owner. Equal target
//! labels or a caller-selected manifest cannot replace those owners.

use super::*;
use crate::node_contract::WorldActivation;
use crucible_node_format::ActivationManifest;
use crucible_node_transport::bodies::WorldActivateRequest;

pub(super) fn authenticate_world_command(
    source: &PacketCompleteSemanticSource,
    controller: &CnpController,
    command: &PacketRestorationActivationCommand,
    inputs: &OriginalInstalledRestorationActivationSigningInputs<'_>,
    maximum_manifest: usize,
) -> Result<(), RuntimeError> {
    match (command, inputs.world, inputs.phase) {
        (
            PacketRestorationActivationCommand::Arm(_),
            None,
            OriginalInstalledRestorationActivationPhase::Arm,
        ) => Ok(()),
        (
            PacketRestorationActivationCommand::WorldActivate(body),
            Some(world),
            OriginalInstalledRestorationActivationPhase::WorldActivate,
        ) => authenticate_world_manifest(source, controller, body, world, maximum_manifest),
        _ => Err(RuntimeError::ForeignAuthority),
    }
}

pub(super) fn authenticate_world_manifest(
    source: &PacketCompleteSemanticSource,
    controller: &CnpController,
    body: &WorldActivateRequest,
    world: &WorldActivation,
    maximum_manifest: usize,
) -> Result<(), RuntimeError> {
    let publication = world
        .prepared_publication_data()
        .ok_or(RuntimeError::UnsupportedFacet)?;
    publication.validate_coordinator()?;
    let owners = world
        .prepared_owners()
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let coordinator = world
        .coordinator_snapshot()
        .ok_or(RuntimeError::UnsupportedFacet)?;
    if publication.nodes() != world.node_preparations()
        || publication.prepared_owners() != owners
        || publication.coordinator_snapshot() != coordinator
        || world.node_preparations().is_empty()
        || owners.len() != world.record().owners.len()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let original = controller
        .content(&body.activation_manifest)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if original.len() > maximum_manifest {
        return Err(RuntimeError::ResourceLimit);
    }
    body.activation_manifest
        .verify(original)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let value = canonical::parse_json(original, maximum_manifest)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let encoded = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if encoded.as_slice() != original {
        return Err(RuntimeError::InvalidReceipt);
    }
    drop(encoded);
    let manifest: ActivationManifest =
        serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    let installation = source.installation();
    if manifest.schema_version != 1
        || manifest.transaction_id != installation.transaction
        || manifest.activation_id != world.record().activation_id
        || manifest.world_generation != world.record().generation
        || manifest.gate_id != installation.gate
        || manifest.world_binding_hash != world.record().world_binding_hash
        || manifest.owners.as_slice() != owners
        || manifest.coordinator_state_ref != coordinator.reference
        || !manifest.extensions.is_empty()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let bytes = controller
        .content(&manifest.coordinator_state_ref)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    manifest
        .coordinator_state_ref
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if bytes != coordinator.bytes.as_slice() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}
