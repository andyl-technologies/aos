//! Lends exact retained Producer checkpoint bodies without reviving SDK currency.

use super::*;
use crate::node_contract::WorldActivation;

impl PacketCompleteSemanticSource {
    pub(crate) fn with_original_producer_typed_checkpoint17_data<R>(
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
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.require_verified_prefix_data()?;
        let mut candidates = history.attempts.iter().filter(|attempt| {
            attempt
                .observe
                .as_ref()
                .and_then(OriginalRestoredSuffixHostAttempt::completed_frontier_data)
                == Some(frontier)
        });
        let attempt = candidates.next().ok_or(RuntimeError::OwnerUnavailable)?;
        if candidates.next().is_some()
            || attempt.stage.get() != Stage::Verified
            || attempt.signature != Some(proof::signature_data(attempt, key)?)
            || !attempt
                .admission
                .as_ref()
                .is_some_and(|admission| admission.activation().same_authority(world))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.row.authenticate_owner_data(self, controller)?;
        let sdk = attempt
            .observe
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (request, terminal, _) = if current {
            sdk.authenticate_current_pair_data(controller, emitter)
        } else {
            sdk.authenticate_retained_pair_data(controller, emitter)
        }
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let record = attempt
            .checkpoint_record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let underlying = attempt
            .checkpoint_producer
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let measurement = attempt
            .checkpoint_measurement
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
        if !super::super::restored_checkpoint17::same_underlying_data(&actual, underlying) {
            return Err(RuntimeError::InvalidReceipt);
        }
        super::super::restored_checkpoint17::authenticate_world_record_data(self, record, world)?;
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
