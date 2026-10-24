//! Lends the final grant-free Producer Observe at its actual saved SDK frontier.

use super::*;
use crate::node_contract::WorldActivation;

impl PacketCompleteSemanticSource {
    pub(crate) fn original_producer_checkpoint_frontier17_data(
        &self,
    ) -> Result<Option<U64>, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.require_verified_prefix_data()?;
        let Some(attempt) = history.attempts.last() else {
            return Ok(None);
        };
        Ok(Some(
            attempt
                .observe
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .completed_frontier_data()
                .ok_or(RuntimeError::InvalidReceipt)?,
        ))
    }

    pub(crate) fn with_original_producer_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.require_verified_prefix_data()?;
        let attempt = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.row.authenticate_owner_data(self, controller)?;
        if !attempt
            .admission
            .as_ref()
            .is_some_and(|admission| admission.activation().same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let sdk = attempt
            .observe
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if sdk.completed_frontier_data() != Some(frontier) {
            return Err(RuntimeError::InvalidReceipt);
        }
        proof::authenticate_checkpoint_data(&history, original, controller, emitter, key)?;
        let (record, _, measurement) = history.checkpoint_data(original)?;
        super::super::restored_checkpoint17::authenticate_world_record_data(self, record, world)?;
        let result = inspect(measurement, &record.native_receipt.native_record, frontier);
        sdk.authenticate_current_pair_data(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_producer_checkpoint17_counter_scratch_data() -> usize {
        proof::counter_scratch_data() + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
    }
}
