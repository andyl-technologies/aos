//! Retains the actual selected coordinator before any durable handoff.
//!
//! The private DATA projection is never published. Construction uses the same
//! issued context, real paused scheduler and original validated native ready
//! records. Failure preserves the first partial Value, byte bank and roster.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{
    ActivationPublisher, OriginalLineageRestoration, ValidatedNodePreparation,
};
use crate::node_scheduling::{InputPayload, PreparedSchedulingRestore};
use crucible_node_format::{Repeatability, canonical};

pub(super) struct OriginalRestorationCoordinatorOwner {
    started: bool,
    value: Option<serde_json::Value>,
    bytes: Vec<u8>,
    reference: Option<ContentRef>,
    nodes: Vec<ValidatedNodePreparation>,
}

impl OriginalRestorationCoordinatorOwner {
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            value: None,
            bytes: Vec::new(),
            reference: None,
            nodes: Vec::new(),
        }
    }

    // Keeps the actual owner private while its sibling compares the genuine
    // World publication. These are borrowed checks, without clones or getters
    // that could replace the retained coordinator with caller-provided data.
    pub(super) fn authenticate_original_publication_data(
        &self,
        world: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        let actual = world
            .coordinator_snapshot()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if actual.bytes != self.bytes
            || Some(&actual.reference) != self.reference.as_ref()
            || world.node_preparations() != self.nodes
            || world.prepared_publication_data().is_none()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    pub(super) fn publication_comparison_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&crate::node_contract::WorldActivation>()
            + size_of::<&InputPayload>()
            + size_of::<Option<&InputPayload>>()
            + size_of::<Result<&InputPayload, RuntimeError>>()
            + size_of::<Option<&ContentRef>>()
            + size_of::<&[ValidatedNodePreparation]>()
            + size_of::<&Vec<ValidatedNodePreparation>>()
            + size_of::<Option<&crate::node_contract::PreparedWorldPublication>>()
            + size_of::<Result<(), RuntimeError>>()
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            value,
            bytes,
            reference,
            nodes,
        } = self;
        let mut requested = checked_sum(
            &[
                bytes.capacity(),
                nodes
                    .capacity()
                    .checked_mul(size_of::<ValidatedNodePreparation>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        if let Some(value) = value {
            requested = checked_sum(&[requested, value.owned_storage()?], maximum)?;
        }
        if let Some(reference) = reference {
            requested = checked_sum(
                &[
                    requested,
                    NodeRuntime::capture_reference_storage(reference)?,
                ],
                maximum,
            )?;
        }
        for node in nodes {
            requested = checked_sum(
                &[
                    requested,
                    NodeRuntime::original_prepared_node_requested_storage_data(node, maximum)?,
                ],
                maximum,
            )?;
        }
        Ok(requested)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn retain_original_selected_coordinator_data(
        &self,
        plan: &InstalledConformancePlan,
        world: &crucible_node_format::WorldBinding,
        context: &OriginalLineageRestoration<'_>,
        scheduler: &PreparedSchedulingRestore,
        nodes: &[ValidatedNodePreparation],
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        let row = self
            .coordinator_construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_original_data(
            &self.archive,
            self.coordinator_target
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )?;
        if context.target() != &scope.target
            || nodes.len() != 4
            || nodes.iter().any(|node| node.prepared_owners().is_none())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        scheduler
            .validate_original_lineage_context(context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let host = self.archive.original_host_record_data()?;
        {
            let mut owner = self
                .coordinator_owner
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if owner.started {
                return Err(RuntimeError::OutstandingObligations);
            }
            owner.started = true;
            let value = (
                super::coordinator_projection::COORDINATOR_FORMAT,
                (
                    &scope.target.generation,
                    &scope.target.activation_id,
                    &scope.target.world_binding_hash,
                    &scope.target.owners,
                    &scope.target.boundary,
                ),
                world,
                self.archive.archive().artifact(),
                self.archive.archive().manifest(),
                self.archive.original_runtime_record_data()?,
                &host.scheduling,
                Repeatability::Unqualified,
                context.original_installed_publication_projection_data()?,
                scheduler.original_publication_data(),
                nodes,
            );
            // Requote the actual owner before creating its first owning bank.
            // The prospective range projection is not a serialization source.
            let (requested, encoded) =
                NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                    &value,
                    OriginalRestorationCoordinatorConstructionData::maximum_typed_slot_data(),
                    self.policy.maximum_requested_bytes,
                )?;
            if requested > row.retained_requested_bytes_data()
                || encoded > row.maximum_encoded_bytes_data()
            {
                return Err(RuntimeError::ResourceLimit);
            }
            owner.value =
                Some(serde_json::to_value(&value).map_err(|_| RuntimeError::InvalidReceipt)?);
            let OriginalRestorationCoordinatorOwner {
                value,
                bytes,
                reference,
                nodes: retained_nodes,
                started: _,
            } = &mut *owner;
            let value = value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            bytes
                .try_reserve_exact(encoded)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            canonical::canonical_json_to_writer(value, &mut *bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            if bytes.len() > row.maximum_encoded_bytes_data()
                || bytes.len() > crate::node_contract::MAXIMUM_ACTIVATION_COORDINATOR_BYTES
            {
                return Err(RuntimeError::ResourceLimit);
            }
            *reference = Some(
                canonical::content_ref(bytes, "application/json")
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            );
            retained_nodes
                .try_reserve_exact(nodes.len())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            retained_nodes.extend_from_slice(nodes);
            owner.retained_storage_data(self.policy.maximum_requested_bytes)?;
        }
        self.authenticate_original_complete_member_data(plan, scope)?;
        self.authenticate_original_publisher_member_data(plan, publisher)?;
        // The publisher owns its independent copies before a later durable
        // effect. Our first original remains retained even if the callback fails.
        {
            let owner = self
                .coordinator_owner
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            publisher.retain_restored_coordinator(
                &scope.target,
                owner.nodes.clone(),
                InputPayload {
                    reference: owner
                        .reference
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .clone(),
                    bytes: owner.bytes.clone(),
                },
            )?;
        }
        self.authenticate_original_publisher_member_data(plan, publisher)?;
        observation::authenticate_started_stage_data(
            &self.stage,
            WindowStage::TransactionAdmitted,
        )?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        self.whole_observation.require_observation();
        Ok(())
    }
}
