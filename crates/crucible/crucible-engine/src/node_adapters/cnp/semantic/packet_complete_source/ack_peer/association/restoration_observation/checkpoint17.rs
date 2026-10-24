//! Authenticates the immutable first Observe only when its real SDK cut wins.

use super::*;
use crate::node_contract::WorldActivation;
use crucible_node_format::U64;

impl PacketCompleteSemanticSource {
    pub(crate) fn original_first_observation_checkpoint_frontier17_data(
        &self,
        controller: &CnpController,
    ) -> Result<Option<U64>, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let Some(attempt) = original.restoration_observation.as_ref() else {
            return Ok(None);
        };
        attempt.authenticate_verified()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let pair = controller
            .original_completed_installed_restoration_observation(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(Some(pair.completed_frontier_data()))
    }

    pub(crate) fn with_original_first_observation_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_first_observation_typed_checkpoint17_data(
            controller,
            world,
            key,
            frontier,
            true,
            |record, _, measurement, frontier| {
                inspect(measurement, &record.native_receipt.native_record, frontier)
            },
        )
    }

    pub(crate) fn with_original_first_observation_typed_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        current: bool,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = original
            .restoration_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.authenticate_verified()?;
        if current {
            controller
                .authenticate_original_installed_restoration_observation_frontier_data(
                    emitter, frontier,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        } else {
            controller
                .authenticate_original_installed_restored_suffix_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        let pair = controller
            .original_completed_installed_restoration_observation(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if pair.completed_frontier_data() != frontier {
            return Err(RuntimeError::InvalidReceipt);
        }
        let request: PacketRestorationObservationRequest =
            serde::Deserialize::deserialize(attempt.value(0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let artifact: PacketRestorationObservationArtifact =
            serde::Deserialize::deserialize(attempt.value(1)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let binding = crucible_node_transport::reference_packet::service::complete_restore::activation::restoration_activation_scope_digest_data(&request.scope)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        attempt.authenticate_original(self, controller, binding)?;
        if artifact.request != request
            || pair.original().extensions.len() != 1
            || pair
                .original()
                .extensions
                .get(PACKET_RESTORATION_OBSERVE_FEATURE)
                != Some(attempt.value(1)?)
            || serde_json::to_value(pair.original()).map_err(|_| RuntimeError::InvalidReceipt)?
                != *attempt.value(2)?
            || serde_json::to_value(pair.response()).map_err(|_| RuntimeError::InvalidReceipt)?
                != *attempt.value(3)?
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let assigned = restoration_observe_assigned_request_digest(
            pair.original(),
            controller
                .original_native5_storage_facts()
                .map_err(|_| RuntimeError::ResourceLimit)?
                .maximum_frame_bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let context = PacketRestorationObservationContext {
            request,
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        verify_restoration_observe_proof_data(key, &context, &artifact.proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let measurement = effect::authenticate_terminal(
            pair.response_body_data(),
            &context.request,
            pair.original(),
        )?;
        let record = attempt.record()?;
        super::super::restored_checkpoint17::authenticate_world_record_data(self, record, world)?;
        let raw = controller
            .content(measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        measurement
            .verify(raw)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let underlying = controller
            .content(&record.native_receipt.native_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let authenticated = controller
            .authenticate_original_installed_restoration_observation_evidence_data(
                emitter, record, underlying,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !super::super::restored_checkpoint17::same_underlying_data(
            &authenticated,
            attempt.underlying()?,
        ) || attempt.scheduling()?.proof_ref != *measurement
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let result = inspect(record, attempt.underlying()?, measurement, frontier);
        if current {
            controller
                .authenticate_original_installed_restoration_observation_frontier_data(
                    emitter, frontier,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        } else {
            controller
                .authenticate_original_installed_restored_suffix_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_first_observation_checkpoint17_counter_scratch_data() -> usize {
        evidence::counter_scratch_data()
            + owner::counter_scratch_data()
            + std::mem::size_of::<PacketRestorationObservationRequest>()
            + std::mem::size_of::<PacketRestorationObservationArtifact>()
            + std::mem::size_of::<PacketRestorationObservationContext>()
            + std::mem::size_of::<[u8; 32]>()
            + std::mem::size_of::<crucible_node_format::Bytes>()
            + std::mem::size_of::<
                crucible_node_transport::protocol_snapshot::OriginalProtocolStorageFacts,
            >()
    }
}
