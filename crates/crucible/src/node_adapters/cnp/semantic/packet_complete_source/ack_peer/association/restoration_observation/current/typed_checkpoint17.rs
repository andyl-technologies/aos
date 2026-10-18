//! Lends one retained recurring Observe's exact typed model under its Source MAC.

use super::*;
use crate::node_contract::WorldActivation;
use crucible_node_contract::U64;

impl PacketCompleteSemanticSource {
    pub(crate) fn with_original_current_observation_typed_checkpoint17_data<R>(
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
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        if history.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut candidates = history.attempts.iter().filter(|attempt| {
            attempt
                .sdk
                .as_ref()
                .and_then(OriginalRestoredSuffixHostAttempt::completed_frontier_data)
                == Some(frontier)
        });
        let attempt = candidates.next().ok_or(RuntimeError::OwnerUnavailable)?;
        if candidates.next().is_some()
            || attempt.stage != Stage::Verified
            || attempt.signature != Some(validation::signature_data(attempt, key)?)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.row.authenticate_owner_data(self, controller)?;
        let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let (request, terminal, _) = if current {
            sdk.authenticate_current_pair_data(controller, emitter)
        } else {
            sdk.authenticate_retained_pair_data(controller, emitter)
        }
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let record = attempt
            .record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let underlying = attempt
            .underlying
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
        let actual = controller
            .authenticate_original_restored_suffix_receipt_data(
                emitter, request, terminal, request, record, bytes,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !super::super::super::restored_checkpoint17::same_underlying_data(&actual, underlying)
            || attempt
                .scheduling
                .as_ref()
                .is_none_or(|scheduling| scheduling.proof_ref != *measurement)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        super::super::super::restored_checkpoint17::authenticate_world_record_data(
            self, record, world,
        )?;
        let result = inspect(record, underlying, measurement, frontier);
        if current {
            sdk.authenticate_current_pair_data(controller, emitter)
        } else {
            sdk.authenticate_retained_pair_data(controller, emitter)
        }
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}
