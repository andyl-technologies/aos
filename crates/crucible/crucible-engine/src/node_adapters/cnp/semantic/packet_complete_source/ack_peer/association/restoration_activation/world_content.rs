//! Owns genuine World publication bytes before any signed upload assignment.
//!
//! The opaque World claim supplies the complete actual prepared publication.
//! This owner copies its coordinator and constructs the exact existing manifest;
//! labels or a caller-provided content reference cannot replace either body.

use super::*;
use crate::{node_contract::WorldActivation, node_scheduling::InputPayload};
use crucible_node_format::ActivationManifest;
use crucible_node_transport::bodies::WorldActivateRequest;

pub(super) struct WorldUploadBodies {
    pub(super) coordinator: InputPayload,
    pub(super) manifest: InputPayload,
}

impl WorldUploadBodies {
    /// Copies the same complete publication and constructs its exact manifest.
    ///
    /// # Errors
    /// Refuses absent or foreign prepared owners/coordinator, changed command
    /// identity, exhausted independent storage or failed canonical construction.
    pub(super) fn from_original_world(
        source: &PacketCompleteSemanticSource,
        world: &WorldActivation,
        command: &WorldActivateRequest,
        coordinator_maximum: usize,
        manifest_maximum: usize,
    ) -> Result<Self, RuntimeError> {
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
        if coordinator.bytes.len() > coordinator_maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        coordinator
            .reference
            .verify(&coordinator.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;

        let installation = source.installation();
        let manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: installation.transaction.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            gate_id: installation.gate.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            owners: owners.to_vec(),
            coordinator_state_ref: coordinator.reference.clone(),
            extensions: Default::default(),
        };
        let value = serde_json::to_value(&manifest).map_err(|_| RuntimeError::InvalidReceipt)?;
        let mut manifest_bytes = Vec::new();
        manifest_bytes
            .try_reserve_exact(manifest_maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        owner::write_bounded_value_into(&value, &mut manifest_bytes, manifest_maximum)?;
        let reference = canonical::content_ref(&manifest_bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // The real node computes this same reference as pure DATA before claim
        // issuance. Source never rewrites a foreign command to fit its owners.
        if reference != command.activation_manifest
            || command.transaction_id != installation.transaction
            || command.activation_id != world.record().activation_id
            || command.world_generation != world.record().generation
            || command.gate_id != installation.gate
            || command.world_binding_hash != world.record().world_binding_hash
            || !command.extensions.is_empty()
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let mut coordinator_bytes = Vec::new();
        coordinator_bytes
            .try_reserve_exact(coordinator.bytes.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        coordinator_bytes.extend_from_slice(&coordinator.bytes);
        Ok(Self {
            coordinator: InputPayload {
                reference: coordinator.reference.clone(),
                bytes: coordinator_bytes,
            },
            manifest: InputPayload {
                reference,
                bytes: manifest_bytes,
            },
        })
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<WorldUploadBodies>()
        + size_of::<Option<WorldUploadBodies>>()
        + size_of::<Result<WorldUploadBodies, RuntimeError>>()
        + size_of::<ActivationManifest>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Vec<u8>>()
        + size_of::<ContentRef>()
        + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
        + size_of::<&WorldActivation>()
        + size_of::<&WorldActivateRequest>()
        + size_of::<&crucible_node_format::PreparedOwner>()
        + size_of::<&InputPayload>()
        + size_of::<Option<&crate::node_contract::PreparedWorldPublication>>()
        + size_of::<Result<&crate::node_contract::PreparedWorldPublication, RuntimeError>>()
        + size_of::<Option<&[crucible_node_format::PreparedOwner]>>()
        + size_of::<Result<&[crucible_node_format::PreparedOwner], RuntimeError>>()
        + size_of::<Option<&InputPayload>>()
        + size_of::<Result<&InputPayload, RuntimeError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), RuntimeError>>()
}
