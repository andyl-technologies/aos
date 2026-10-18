//! Selects a recurring Observe by its saved completion and rechecks its full pair.

use super::*;
use crate::node_contract::WorldActivation;
use crucible_node_contract::U64;

impl PacketCompleteSemanticSource {
    pub(crate) fn original_current_observation_checkpoint_frontier17_data(
        &self,
    ) -> Result<Option<U64>, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        if history.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let Some(attempt) = history.attempts.last() else {
            return Ok(None);
        };
        if attempt.stage != Stage::Verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        let frontier = attempt
            .sdk
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .completed_frontier_data()
            .ok_or(RuntimeError::InvalidReceipt)?;
        Ok(Some(frontier))
    }

    pub(crate) fn with_original_current_observation_checkpoint17_data<R>(
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
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        let attempt = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.row.authenticate_owner_data(self, controller)?;
        if history.failed
            || attempt.stage != Stage::Verified
            || attempt.signature != Some(validation::signature_data(attempt, key)?)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if sdk.completed_frontier_data() != Some(frontier) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let (request, terminal, _) = sdk
            .authenticate_current_pair_data(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let record = attempt
            .record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let measurement = attempt
            .measurement
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let raw = controller
            .content(measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        measurement
            .verify(raw)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = controller
            .content(&record.native_receipt.native_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let authenticated = controller
            .authenticate_original_restored_suffix_receipt_data(
                emitter, request, terminal, request, record, bytes,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if attempt.underlying.as_ref().is_none_or(|underlying| {
            !super::super::super::restored_checkpoint17::same_underlying_data(
                underlying,
                &authenticated,
            )
        }) || attempt
            .scheduling
            .as_ref()
            .is_none_or(|scheduling| scheduling.proof_ref != *measurement)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        super::super::super::restored_checkpoint17::authenticate_world_record_data(
            self, record, world,
        )?;
        let result = inspect(measurement, &record.native_receipt.native_record, frontier);
        sdk.authenticate_current_pair_data(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_current_observation_checkpoint17_counter_scratch_data() -> usize {
        validation::counter_scratch_data()
            + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
    }
}
